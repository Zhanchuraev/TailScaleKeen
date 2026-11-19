import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from panel.core import Error, read_json
from panel.native import Native, unchanged_outside_interface


class Router:
    """A live TUN and the two distinct configuration stores on Keenetic."""

    def __init__(self):
        self.other = "hostname test\n"
        self.stanza = []
        self.saved = self.other
        self.active = True
        self.changes = []
        self.fail = None
        self.already_saved = False
        self.native_policy_denies = False

    def run(self, args, **kwargs):
        rc = 0
        out = ""
        if args[0] == Native.init:
            cmd = args[-1]
            self.changes.append(cmd)
            self.active = cmd == "start"
        elif args[0] == "ip":
            out = "default via 192.0.2.1 dev eth0 metric 1000\n"
        elif args[0] == "/opt/bin/tailscale":
            out = json.dumps({"BackendState": "Running", "Self": {"ID": "same", "Online": self.active}})
        else:
            cmd = args[-1]
            block = "interface OpkgTun0\n" + "".join("    " + line + "\n" for line in self.stanza) + "!\n"
            running = self.other + (block if self.stanza else "")
            if cmd == "show running-config":
                out = running
            elif cmd == "more startup-config":
                out = self.saved
            elif cmd == "show interface OpkgTun0":
                if self.stanza:
                    out = "id: OpkgTun0\ntype: OpkgTun\nconnected: yes"
                else:
                    rc, out = 123, "\x1b[KCommand::Base error[7405602]: argument parse error."
            else:
                self.changes.append(cmd)
                if cmd == "system configuration save":
                    if self.fail != cmd or self.already_saved:
                        self.saved = running
                elif cmd == "no interface OpkgTun0":
                    self.stanza.clear()
                elif cmd == "interface OpkgTun0":
                    if self.active:
                        return subprocess.CompletedProcess(args, 123, "Opkg::Interface::Tun error[1]: busy", "")
                    self.stanza = ["down"]
                elif cmd != self.fail:
                    suffix = cmd.removeprefix("interface OpkgTun0 ").replace('"', '')
                    if suffix == "up":
                        self.stanza.remove("down")
                    if suffix == "ip global 1" and self.native_policy_denies:
                        for index in range(4):
                            setting = f"ip policy Policy{index}\n    permit global ISP\n"
                            self.other = self.other.replace(setting, setting + "    no permit global OpkgTun0\n")
                    self.stanza.append(suffix)
            if cmd == self.fail:
                rc, out = 0, "Command::Base error[22]: rejected"
        return subprocess.CompletedProcess(args, rc, out, "")


class NativeCreationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = pathlib.Path(directory.name)
        self.router = Router()
        self.native = Native(self.state, self.router)
        self.native._running_tun = lambda: self.native.tun if self.router.active else None
        self.native._linux_tun_exists = lambda: self.router.active
        self.native.linked_policies = lambda: []

    def create(self):
        return self.native.create({"global": False, "save": True}, lambda message: None)

    def test_busy_tun_is_returned_to_same_client_before_save_and_repeat_is_read_only(self):
        n, r = self.native, self.router
        self.assertTrue(n.creation_plan({"global": False})["handoff"])
        self.assertEqual(r.changes, [])
        result = self.create()
        self.assertTrue(result["exists"] and result["managed"])
        self.assertTrue(r.active)
        self.assertEqual(r.changes[0], "stop")
        self.assertEqual(r.changes[-2:], ["start", "system configuration save"])
        self.assertNotIn("ip global", r.saved)
        self.assertIn("description Tailscale", r.saved)
        r.changes.clear()
        self.assertTrue(self.create()["noop"])
        self.assertFalse(r.changes)

    def test_foreign_tun_or_cli_errors_stop_before_any_change(self):
        self.native._running_tun = lambda: "opkgtun1"
        with self.assertRaises(Error):
            self.create()
        self.assertEqual(self.router.changes, [])
        self.native._linux_tun_exists = lambda: False
        self.router.fail = "show running-config"
        with self.assertRaises(Error):
            self.create()
        self.assertEqual(self.router.changes, [])

    def test_registers_last_in_priorities_when_public_uplink_has_higher_priority(self):
        r = self.router
        r.other += "interface XGigabitEthernet0\n    security-level public\n    ip global 700\n    up\n!\n"
        r.saved = r.other
        fields = self.native.default_fields()
        self.assertTrue(fields["global"])
        result = self.native.create(fields, lambda message: None)
        self.assertTrue(result["global"])
        self.assertIn("interface OpkgTun0 ip global 1", r.changes)
        self.assertNotIn("ip global auto", r.saved)
        self.assertTrue(r.saved.startswith(r.other))

    def test_new_priority_must_keep_existing_internet_routes(self):
        r = self.router
        r.other += "interface WAN\n    security-level public\n    ip global 800\n    up\n!\n"
        r.saved = r.other
        with patch.object(self.native, "_main_defaults", side_effect=[{"WAN"}, {"WAN", "OpkgTun0"}]), self.assertRaises(Error):
            self.native.create(self.native.default_fields(), lambda message: None)
        self.assertEqual(r.stanza, [])
        self.assertTrue(r.active)
        self.assertNotIn("system configuration save", r.changes)

    def test_firmware_additions_in_four_existing_policies_survive_save_retry(self):
        r = self.router
        r.other += "interface ISP\n    security-level public\n    ip global 700\n    up\n!\n"
        for index in range(4):
            r.other += f"ip policy Policy{index}\n    permit global ISP\n!\n"
        r.saved = r.other
        r.native_policy_denies = True
        options = self.native.default_fields()
        r.fail = "system configuration save"
        with self.assertRaises(Error):
            self.native.create(options, lambda msg: None)
        self.assertEqual(r.other.count("    no permit global OpkgTun0\n"), 4)
        self.assertTrue(r.active)
        r.fail = None
        r.changes.clear()
        self.native.create(options, lambda msg: None)
        self.assertEqual(r.changes, ["system configuration save"])
        self.assertEqual(r.saved.count("    no permit global OpkgTun0\n"), 4)

    def test_save_comparison_rejects_every_other_policy_change(self):
        header = "ip policy Policy0\n"
        uplink = "    permit global ISP\n"
        deny = "    no permit global OpkgTun0\n"
        before = header + uplink + "!\n"
        for after in (
            before + "ip policy Pending\n" + deny,
            before + "interface Other\n" + deny,
            header + uplink + deny + deny,
            header + uplink + "    permit global OpkgTun0\n",
            header + deny,
            header + uplink + "    no permit global OpkgTun1\n",
        ):
            with self.subTest(after=after):
                self.assertFalse(unchanged_outside_interface(before, after, "OpkgTun0", True))
        self.assertFalse(unchanged_outside_interface(before + deny, before, "OpkgTun0", True))

    def test_ambiguous_or_occupied_lowest_priority_falls_back_to_native_only(self):
        for setting in ("1", "auto", "700"):
            with self.subTest(setting=setting):
                self.router.other = "interface ISP\n    ip global " + setting + "\n!\n"
                if setting != "700":
                    self.router.other += "interface WAN\n    security-level public\n    ip global 400\n!\n"
                self.router.saved = self.router.other
                self.assertFalse(self.native.default_fields()["global"])
                with self.assertRaises(Error):
                    self.native.creation_plan({"global": True})
                self.assertFalse(self.router.changes)

    def test_rejected_creation_removes_only_new_object_and_restores_daemon(self):
        r = self.router
        r.fail = "interface OpkgTun0 ip mtu 1280"
        with self.assertRaises(Error):
            self.create()
        self.assertTrue(r.active)
        self.assertEqual(r.stanza, [])
        self.assertEqual(r.changes[-2:], ["no interface OpkgTun0", "start"])
        self.assertNotIn("save", " ".join(r.changes))

    def test_failed_restart_rolls_back_new_object_and_recovers_original_client(self):
        n, r = self.native, self.router
        real_start = n._start_client

        def fail_with_new_interface(before, log):
            if r.stanza:
                raise Error("new device busy")
            real_start(before, log)

        with patch.object(n, "_start_client", side_effect=fail_with_new_interface), self.assertRaises(Error):
            self.create()
        self.assertTrue(r.active)
        self.assertEqual(r.stanza, [])
        self.assertEqual(r.changes[-2:], ["no interface OpkgTun0", "start"])

    def test_interrupted_save_can_be_completed_without_stopping_again(self):
        r = self.router
        r.fail = "system configuration save"
        with self.assertRaises(Error):
            self.create()
        self.assertIn("pending", read_json(self.state / "integration.json"))
        self.assertTrue(r.active)
        self.assertEqual(r.saved, r.other)
        r.fail = None
        r.changes.clear()
        self.create()
        self.assertEqual(r.changes, ["system configuration save"])
        self.assertNotIn("pending", read_json(self.state / "integration.json"))

    def test_lost_reply_to_successful_save_uses_readback_on_retry(self):
        r = self.router
        r.fail = "system configuration save"
        r.already_saved = True
        with self.assertRaises(Error):
            self.create()
        self.assertIn("interface OpkgTun0", r.saved)
        r.fail = None
        r.changes.clear()
        self.create()
        self.assertFalse(r.changes)
