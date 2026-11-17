import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from panel.core import Error
from panel.lan_access import LanAccess


class LanAccessTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.runner = Mock()
        self.access = LanAccess(folder.name, self.runner, Mock(), "opkgtun0")
        self.runner.run.side_effect = lambda args, **kwargs: SimpleNamespace(stdout={
            ("ip", "-4", "-o", "addr", "show"): (
                "5: br0 inet 192.168.31.1/24 scope global br0\n"
                "6: br1 inet 192.168.32.1/24 scope global br1\n"
                "8: zt0 inet 192.168.41.1/24 scope global zt0\n"
            ),
            ("ip", "-4", "neigh", "show", "dev", "br0"): (
                "192.168.31.22 lladdr 00:01:02:03:04:05 REACHABLE\n"
            ),
            ("ip", "-4", "neigh", "show", "dev", "br1"): (
                "192.168.32.22 lladdr 00:01:02:03:04:06 REACHABLE\n"
            ),
            ("ndmc", "-c", "show interface"): (
                'Interface, name = "Home"\n  id: Bridge0\n  interface-name: Home\n  description: Основная\n'
                'Interface, name = "Guest"\n  id: Bridge1\n  interface-name: Guest\n  description: \n'
            ),
        }.get(tuple(args), ""))
        self.snapshot = {"backend_state": "Running", "online": True,
                         "prefs": {"AdvertiseRoutes": ["192.168.31.0/24"]}}
        self.selection = {"mode": "selected", "bridge": "br0",
                          "devices": ["192.168.31.22 00:01:02:03:04:05"],
                          "subnets": ["192.168.51.0/24"]}

    def test_selected_device_and_zero_tier_precedence(self):
        config = self.access.plan(self.selection, self.snapshot)
        self.assertEqual(self.access.management_rules(config),
                         {("from", "192.168.41.1", "lookup", "main")})
        guard = self.access.chain_rules("mangle", config, ("TSKL_PRE", "TSKL_PRE_ACCESS"))
        self.assertIn("-A TSKL_PRE -i br0 -d 192.168.51.0/24 -j TSKL_PRE_ACCESS", guard)
        self.assertIn("-A TSKL_PRE_ACCESS -s 192.168.31.22 -m mac --mac-source 00:01:02:03:04:05 -j ACCEPT", guard)
        self.assertEqual(guard[-1], "-A TSKL_PRE_ACCESS -j DROP")

    def test_local_and_mismatched_device_are_rejected(self):
        with self.assertRaises(Error):
            self.access.plan({**self.selection, "subnets": ["192.168.41.0/24"]}, self.snapshot)
        with self.assertRaises(Error):
            self.access.plan({**self.selection, "devices": ["192.168.31.22 00:01:02:03:04:06"]}, self.snapshot)

    def test_all_mode_is_still_limited_to_its_bridge_and_prefixes(self):
        config = self.access.plan({**self.selection, "mode": "all"}, self.snapshot)
        self.assertFalse(config["devices"])
        self.assertEqual(self.access.route_rules(config),
                         {("from", "all", "to", "192.168.51.0/24", "iif", "br0", "lookup", "52")})

    def test_segment_inventory_uses_router_labels_and_only_lan_bridges(self):
        self.assertEqual(self.access.segments(), [
            {"id": "br0", "name": "Основная", "networks": ["192.168.31.0/24"]},
            {"id": "br1", "name": "Guest", "networks": ["192.168.32.0/24"]},
        ])
        self.assertEqual([row["bridge"] for row in self.access.devices_on_bridges(["br1", "br0"])],
                         ["br0", "br1"])

    def test_device_rules_use_the_verified_ingress_segment(self):
        a = self.selection["devices"][0]
        b = "192.168.32.22 00:01:02:03:04:06"
        net_a, net_b = "192.168.51.0/24", "192.168.52.0/24"
        config = self.access.plan({"mode": "selected", "bridges": ["br0", "br1"],
                                   "devices": [a, b], "subnets": [net_a, net_b],
                                   "grants": {a: [net_a], b: [net_b]}}, self.snapshot)
        routes = self.access.route_rules(config)
        self.assertEqual({(r[1], r[3], r[5]) for r in routes},
                         {("192.168.31.22", net_a, "br0"), ("192.168.32.22", net_b, "br1")})
        rules = self.access.chain_rules("filter", config, ("TSKL_FWD", "TSKL_FWD_ACCESS"))
        self.assertIn(f"-A TSKL_FWD -i br+ -o opkgtun0 -d {net_a} -j DROP", rules)
        self.assertIn(f"-A TSKL_FWD_ACCESS -i br1 -s 192.168.32.22 -m mac --mac-source 00:01:02:03:04:06 -d {net_b} -o opkgtun0 -j ACCEPT", rules)
        self.assertFalse(any("-i br0 -s 192.168.32.22" in rule for rule in rules))

    def test_all_mode_limits_sources_per_segment_and_rejects_invalid_bridge(self):
        params = {"mode": "all", "bridges": ["br0", "br1"], "devices": [], "subnets": self.selection["subnets"]}
        config = self.access.plan(params, self.snapshot)
        self.assertEqual({rule[5] for rule in self.access.route_rules(config)}, {"br0", "br1"})
        rules = self.access.chain_rules("mangle", config, ("TSKL_PRE", "TSKL_PRE_ACCESS"))
        self.assertIn("-A TSKL_PRE_ACCESS -i br1 -s 192.168.32.0/24 -j ACCEPT", rules)
        self.assertNotIn("-A TSKL_PRE_ACCESS -i br0 -s 192.168.32.0/24 -j ACCEPT", rules)
        for bridge in ("zt0", "br99"):
            with self.assertRaises(Error):
                self.access.plan({**params, "bridges": ["br0", bridge]}, self.snapshot)

    def test_individual_routes_are_used_in_filter_nat_and_policy_routing(self):
        a = self.selection["devices"][0]
        b = "192.168.31.23 00:01:02:03:04:06"
        net_a, net_b = "192.168.51.0/24", "192.168.52.0/24"
        config = self.access.normalize({**self.selection, "devices": [a, b],
                                        "subnets": [net_a, net_b], "grants": {a: [net_a], b: [net_b]}})
        routes = self.access.route_rules(config)
        self.assertEqual({(rule[1], rule[3]) for rule in routes},
                         {("192.168.31.22", net_a), ("192.168.31.23", net_b)})
        for table, chains in (("mangle", ("TSKL_PRE", "TSKL_PRE_ACCESS")),
                              ("filter", ("TSKL_FWD", "TSKL_FWD_ACCESS")), ("nat", ("TSKL_NAT",))):
            for rule in self.access.chain_rules(table, config, chains):
                self.assertFalse(" -s 192.168.31.22 " in rule and f" -d {net_b} " in rule)
                self.assertFalse(" -s 192.168.31.23 " in rule and f" -d {net_a} " in rule)

    def test_empty_grant_keeps_the_cidr_guard_and_has_no_forward_rule(self):
        device = self.selection["devices"][0]
        config = self.access.normalize({**self.selection, "grants": {device: []}})
        self.assertFalse(self.access.route_rules(config))
        result = self.access.chain_rules("mangle", config, ("TSKL_PRE", "TSKL_PRE_ACCESS"))
        self.assertEqual(result, ["-A TSKL_PRE -i br0 -d 192.168.51.0/24 -j TSKL_PRE_ACCESS",
                                  "-A TSKL_PRE_ACCESS -j DROP"])

    def test_individual_rules_reject_unknown_and_overlapping_routes(self):
        device = self.selection["devices"][0]
        with self.assertRaises(Error):
            self.access.normalize({**self.selection, "grants": {device: ["192.168.61.0/24"]}})
        with self.assertRaises(Error):
            self.access.normalize({**self.selection, "subnets": ["192.168.0.0/16", "192.168.51.0/24"],
                                   "grants": {device: ["192.168.51.0/24"]}})
