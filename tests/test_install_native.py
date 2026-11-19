import contextlib
import io
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from panel import install
from panel.core import Error, read_json, write_json


class NativeInstallTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.source = pathlib.Path(install.__file__).resolve().parents[1]
        self.state = self.root / "opt/etc/tailscale-panel"
        self.running = "interface Bridge0\n    description Home\n!"
        self.calls = []
        self.running_client = False
        self.starts_client = True
        self.native_error = None
        self.selected = None
        self.defaults = {"description": "Tailscale", "global": True, "save": True}
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(install, "at", lambda _, path: self.root / path.lstrip("/")))
        stack.enter_context(patch.object(install.os, "uname", create=True, return_value=SimpleNamespace(machine="aarch64")))
        stack.enter_context(patch.object(install, "require_space"))
        stack.enter_context(patch.object(install.socket, "socket"))
        stack.enter_context(patch.object(install.Runner, "run", side_effect=self.router_command))
        real_readlink = install.os.readlink
        stack.enter_context(patch.object(install.os, "readlink", side_effect=lambda path, *a, **kw:
            str(self.root / "opt/bin/tailscaled") if path == self.root / "proc/37/exe" else real_readlink(path, *a, **kw)))
        stack.enter_context(patch.object(install.subprocess, "run", side_effect=self.run_command))
        stack.enter_context(patch("panel.integration.Integration.install_hook"))
        stack.enter_context(patch.object(install, "client", side_effect=self.client))
        self.choose_defaults = stack.enter_context(patch.object(install.Native, "default_fields", return_value=self.defaults))
        stack.enter_context(patch.object(install.Native, "create", autospec=True, side_effect=self.register))

    def router_command(self, args, **kwargs):
        if args == [str(self.root / "opt/etc/init.d/S06tailscaled"), "start"]:
            self.calls.append(("S06tailscaled", "start"))
            if self.starts_client:
                self.daemon_process(install.init_tun(self.root / "opt/etc/init.d/S06tailscaled"))
            return SimpleNamespace(returncode=0)
        self.assertEqual(args, ["ndmc", "-c", "show running-config"])
        return SimpleNamespace(stdout=self.running, returncode=0)

    def run_command(self, args, **kwargs):
        if args == ["pidof", "tailscaled"]:
            return SimpleNamespace(stdout=b"37" if self.running_client else b"")
        self.calls.append((pathlib.Path(args[0]).name, args[1]))
        return SimpleNamespace(returncode=0)

    def client(self, root, archive, tun):
        self.calls.append(("client", tun))
        return {"changed": True}

    def register(self, native, fields, log):
        self.calls.append(("register", native.name))
        self.selected = fields
        self.assertTrue((self.root / "opt/etc/init.d/S06tailscaled").is_file())
        if self.native_error:
            raise self.native_error

    def invoke(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            install._install(self.source, **kwargs)

    def test_new_install_registers_free_tun_before_first_start(self):
        self.running += "\ninterface OpkgTun0\n    description Existing VPN\n!"
        (self.root / "sys/class/net/opkgtun1").mkdir(parents=True)
        self.invoke()
        self.assertEqual(self.calls, [("client", "opkgtun2"), ("register", "OpkgTun2"),
                                     ("S06tailscaled", "start"), ("S98tailscale-panel", "start")])
        self.choose_defaults.assert_called_once_with()
        self.assertEqual(self.selected, self.defaults)
        self.assertEqual(read_json(self.state / "config.json")["tun"], "opkgtun2")

    def daemon_process(self, tun):
        proc = self.root / "proc/37"
        proc.mkdir(parents=True)
        (proc / "comm").write_text("tailscaled\n")
        (proc / "cmdline").write_bytes(b"tailscaled\0--tun\0" + tun.encode() + b"\0")
        self.running_client = True

    def simulated_running_client(self):
        init = self.root / "opt/etc/init.d/S06tailscaled"
        init.parent.mkdir(parents=True)
        init.write_text('#!/bin/sh\nARGS="--tun=opkgtun4"\n')
        binaries = self.root / "opt/bin"
        binaries.mkdir()
        (binaries / "tailscale").touch()
        (binaries / "tailscaled").touch()
        self.daemon_process("opkgtun4")

    def test_panel_only_registers_daemon_tun_and_does_not_start_it_twice(self):
        self.simulated_running_client()
        self.invoke(panel_only=True)
        self.assertEqual(self.calls, [("register", "OpkgTun4"), ("S98tailscale-panel", "start")])
        self.assertIn("/opt/etc/init.d/S06tailscaled", read_json(self.state / "manifest.json")["adopted"])

    def test_respects_non_global_registration_when_no_safe_priority_is_available(self):
        self.defaults["global"] = False
        self.invoke()
        self.assertFalse(self.selected["global"])
        self.assertIn(("register", "OpkgTun0"), self.calls)

    def test_running_daemon_must_match_its_restart_script(self):
        self.simulated_running_client()
        proc = self.root / "proc/37/cmdline"
        for args in (b"tailscaled\0--tun=opkgtun5\0", b"tailscaled\0",
                     b"tailscaled\0--tun=opkgtun5\0--tun=opkgtun4\0"):
            with self.subTest(args=args):
                proc.write_bytes(args)
                with self.assertRaisesRegex(Error, "не совпадает"):
                    install.running_tun()

    def test_ambiguous_restart_script_is_rejected(self):
        self.simulated_running_client()
        init = self.root / "opt/etc/init.d/S06tailscaled"
        init.write_text('ARGS="--tun=opkgtun4"\nif feature; then ARGS="--tun=opkgtun5"; fi\n')
        with self.assertRaisesRegex(Error, "однозначно"):
            self.invoke(panel_only=True)
        self.assertFalse(self.calls)

    def test_init_exit_zero_without_daemon_does_not_report_success(self):
        self.starts_client = False
        with patch.object(install.time, "sleep"), self.assertRaisesRegex(Error, "Не подтверждён"):
            self.invoke()
        self.assertNotIn(("S98tailscale-panel", "start"), self.calls)
        self.assertFalse((self.state / "config.json").exists())

    def test_registration_failure_leaves_existing_panel_running_and_retries_same_tun(self):
        target = self.root / "opt/share/tailscale-panel"
        target.mkdir(parents=True)
        (target / "previous").touch()
        self.native_error = Error("Unrelated pending changes")
        with self.assertRaisesRegex(Error, "pending changes"):
            self.invoke()
        self.assertEqual(self.calls, [("client", "opkgtun0"), ("register", "OpkgTun0")])
        self.assertTrue((target / "previous").exists())
        self.assertFalse((self.state / "config.json").exists())
        self.native_error = None
        self.calls.clear()
        self.invoke()
        self.assertEqual(self.calls[:2], [("client", "opkgtun0"), ("register", "OpkgTun0")])
        manifest = read_json(self.state / "manifest.json")
        self.assertIn("/opt/etc/init.d/S06tailscaled", manifest["created"])
        self.assertNotIn("/opt/etc/init.d/S06tailscaled", manifest["adopted"])

    def test_orphaned_config_cannot_claim_another_tunnel(self):
        write_json(self.state / "config.json", {"tun": "opkgtun3"})
        self.running += "\ninterface OpkgTun3\n    description Other VPN\n!"
        with self.assertRaisesRegex(Error, "занят"):
            self.invoke()
        self.assertFalse(self.calls)

    def test_missing_config_output_does_not_assume_number_zero_is_available(self):
        self.running = "Command::Base error: unavailable"
        with self.assertRaisesRegex(Error, "интерфейсы"):
            self.invoke()
        self.assertFalse(self.calls)
