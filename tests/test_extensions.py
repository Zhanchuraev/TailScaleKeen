import contextlib, copy, json, pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from panel.core import Error, Tailscale, write_json
from panel.devices import Devices
from panel.egress import Egress, MARK, CHAINS
from panel.routing import route_rows, rule_rows
from test_panel import FakeRunner


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = FakeRunner()
        self.cards = Devices(self.tmp.name, Tailscale(self.r))

    def tearDown(self):
        self.tmp.cleanup()

    def fields(self, ident="node-b", **kw):
        return {
            "id": ident,
            "revision": self.cards.list()[ident]["revision"],
            "notes": "тест",
            "url": "",
            **kw,
        }

    def test_notes_and_url_persist_across_reload(self):
        self.cards.save(self.fields(url="https://100.64.250.7:8092/"))
        saved = Devices(self.tmp.name, Tailscale(self.r)).list()["node-b"]
        self.assertEqual(saved["notes"], "тест")
        self.assertEqual(saved["url"], "https://100.64.250.7:8092/")

    def test_default_web_link_is_5252_for_self_and_peer(self):
        cards = self.cards.list()
        self.assertEqual(cards["self"]["url"], "http://100.64.250.11:5252/")
        self.assertEqual(cards["node-b"]["url"], "http://100.64.250.7:5252/")

    def test_notes_are_isolated_between_control_servers(self):
        self.cards.save(self.fields())
        self.r.prefs["ControlURL"] = "https://other.example.test"
        self.assertEqual(self.cards.list()["node-b"]["notes"], "")

    def test_stale_revision_does_not_overwrite_notes(self):
        f = self.fields()
        self.cards.save(f)
        with self.assertRaises(Error):
            self.cards.save(f)
        self.assertEqual(self.cards.list()["node-b"]["notes"], "тест")

    def test_url_rejects_script_credentials_and_other_devices(self):
        for url in [
            "javascript:alert(1)",
            "https://evil.test/",
            "http://100.64.250.12/",
            "http://user:secret@100.64.250.7/",
            "http://100.64.250.7:99999/",
        ]:
            with self.subTest(url=url), self.assertRaises(Error):
                self.cards.save(self.fields(url=url))

    def test_unknown_node_and_oversized_note_rejected(self):
        for f in [dict(self.fields(), id="unknown"), self.fields(notes="x" * 4001)]:
            with self.assertRaises(Error):
                self.cards.save(f)

    def test_empty_card_removes_saved_note(self):
        self.cards.save(self.fields())
        self.cards.save(self.fields(notes="", url=""))
        self.assertEqual(self.cards.list()["node-b"]["notes"], "")


class EgressRunner(FakeRunner):
    def run(self, args, **kw):
        self.calls.append(args)
        out = ""
        code = 0
        if args[0] == "ndmc":
            out = "ip policy Policy5\n    permit global OpkgTun0\n!\n"
        elif args[:1] == ["ip"]:
            if "rule" in args and "show" in args:
                out = "[]"
            elif "route" in args:
                out = (
                    "default via 192.0.2.1 dev eth4 metric 1000\n"
                    if "-4" in args and "default" in args
                    else ""
                )
        elif args[0] in ["iptables", "ip6tables"]:
            if "-C" in args:
                code = 1
            if args[-1] == "xkeen_force":
                out = "REDIRECT" if "nat" in args else "TPROXY"
        return subprocess.CompletedProcess(args, code, out, "")


class EgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = EgressRunner()
        self.e = Egress(self.tmp.name, self.r, root=self.tmp.name)
        self.policies = {
            "Policy0": {"description": "XKeen", "table4": 4096, "table6": 4096},
            "Policy5": {"description": "Headscale", "table4": 4106, "table6": 4106},
            "Policy6": {"description": "MegaFon", "table4": 4108, "table6": 4108},
        }
        self.patch = patch.object(self.e, "rci", return_value=self.policies)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_choices_exclude_policy_loop_to_this_tailscale(self):
        choices = self.e.choices()
        self.assertFalse(any(c["id"] == "policy:Policy5" for c in choices))
        self.assertTrue(any(c["id"] == "xkeen" and c["available"] for c in choices))
        self.assertTrue(any(c["id"] == "policy:Policy6" for c in choices))

    def test_system_default_is_passive(self):
        self.assertFalse(self.e.sync()["active"])
        self.assertEqual(self.r.calls, [])

    def test_xtables_wait_uses_syntax_supported_by_router_1_4_21(self):
        self.e.call(["iptables", "-t", "filter", "-S"], False)
        self.assertEqual(self.r.calls[-1][:3], ["iptables", "-w", "-t"])

    def test_unknown_target_cannot_inject_commands(self):
        for target in ["policy:Policy5", "x; reboot", "--help", 123]:
            with self.subTest(target=target), self.assertRaises(Error):
                self.e.plan({"target": target})

    def test_native_route_rules_are_marked_and_iif_scoped_with_no_fallback(self):
        choice = self.e.resolve("policy:Policy6")
        self.e.install_rules(choice, self.e.specs(choice))
        mutations = [c for c in self.r.calls if c[0] == "ip" and "add" in c]
        self.assertTrue(mutations)
        for c in mutations:
            self.assertIn("opkgtun0", c)
            self.assertIn(MARK, c)
        self.assertTrue(any("unreachable" in c for c in mutations))
        self.assertTrue(any("4108" in c and "-4" in c for c in mutations))
        self.assertFalse(
            any(c[0] == "ndmc" and not c[-1].startswith("show") for c in self.r.calls)
        )

    def test_proxy_uses_existing_force_chains_and_no_wan_routing_rule(self):
        choice = self.e.resolve("xkeen")
        self.e.install_rules(choice, self.e.specs(choice))
        self.assertTrue(any("xkeen_force" in c and "-A" in c for c in self.r.calls))
        self.assertFalse(
            any(c[0] == "ip" and "add" in c and "lookup" in c for c in self.r.calls)
        )
        self.assertFalse(any("OUTPUT" in c for c in self.r.calls))

    def test_private_lan_overlay_and_connected_routes_bypass_egress(self):
        self.assertIn("192.168.0.0/16", self.e.excluded(4))
        self.assertIn("100.64.0.0/10", self.e.excluded(4))
        self.assertIn("fc00::/7", self.e.excluded(6))

    def test_cleanup_never_flushes_other_firewall_chains(self):
        self.e.remove()
        for c in self.r.calls:
            if "-F" in c or "-X" in c:
                self.assertTrue(c[-1].startswith("TSP_EXIT_"))
            self.assertFalse(c[0] == "ip" and "flush" in c)

    def test_hold_guard_keeps_subnets_and_blocks_public_forwarding_during_change(self):
        self.e.hold(True)
        adds = [c for c in self.r.calls if "-A" in c and "TSP_EXIT_HOLD" in c]
        self.assertTrue(any("RETURN" in c and "192.168.0.0/16" in c for c in adds))
        self.assertTrue(any("REJECT" in c for c in adds))

    def test_local_public_address_is_excluded_without_addrtype_kernel_module(self):
        old = self.r.run

        def run(args, **kw):
            if args[:1] == ["ip"] and "all" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "local 198.51.100.7 dev eth4 table local scope host\n198.51.100.0/24 dev eth4 scope link\n",
                    "",
                )
            return old(args, **kw)

        self.r.run = run
        self.assertIn("198.51.100.7/32", self.e.excluded(4))
        self.assertIn("198.51.100.0/24", self.e.excluded(4))


class LegacyRoutingTests(unittest.TestCase):
    def test_route_parser_preserves_device_table_and_route_type(self):
        rows = route_rows(
            "default via 192.0.2.1 dev eth2.4 table 4108 metric 1000\nlocal 198.51.100.7 dev eth4 table local scope host\nunreachable default table 999\n"
        )
        self.assertEqual(rows[0]["dev"], "eth2.4")
        self.assertEqual(rows[0]["table"], "4108")
        self.assertEqual(rows[1]["type"], "local")
        self.assertEqual(rows[2]["type"], "unreachable")

    def test_rule_parser_keeps_scope_for_safe_removal(self):
        rows = rule_rows(
            "90: from all fwmark 0x5a000000/0xff000000 iif opkgtun0 lookup 4108\n91: from all fwmark 0x5a000000/0xff000000 iif opkgtun0 unreachable\n1162: from all fwmark 0xffffab0 lookup 4108\n"
        )
        self.assertEqual(rows[0]["iif"], "opkgtun0")
        self.assertEqual(rows[0]["fwmark"], "0x5a000000")
        self.assertEqual(rows[0]["fwmask"], "0xff000000")
        self.assertNotIn("table", rows[1])
        self.assertNotIn("iif", rows[2])


if __name__ == "__main__":
    unittest.main()
