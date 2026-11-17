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
        self.runner.run.side_effect = lambda args: SimpleNamespace(stdout={
            ("ip", "-4", "-o", "addr", "show"): (
                "5: br0 inet 192.168.31.1/24 scope global br0\n"
                "8: zt0 inet 192.168.41.1/24 scope global zt0\n"
            ),
            ("ip", "-4", "neigh", "show", "dev", "br0"): (
                "192.168.31.22 lladdr 00:01:02:03:04:05 REACHABLE\n"
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
