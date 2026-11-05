import copy, hashlib, http.client, json, pathlib, subprocess, tempfile, threading, time, unittest
import io
import contextlib
from unittest.mock import patch
from panel.core import Error, Tailscale, write_json
from panel.native import Native
from panel.service import Service
from panel.server import App, Handler, Server, password_hash, password_check
from panel.uninstall import Purger
from panel.updates import Updater
from panel.install import extract_client

PREFS = {
    "ControlURL": "https://headscale.example.test",
    "RouteAll": True,
    "CorpDNS": False,
    "ExitNodeID": "node-exit",
    "ExitNodeIP": "",
    "ExitNodeAllowLANAccess": True,
    "Hostname": "keenetic-test",
    "AdvertiseRoutes": ["192.168.10.0/24"],
    "AdvertiseTags": [],
    "ShieldsUp": False,
    "RunSSH": False,
    "RunWebClient": False,
    "NoSNAT": False,
    "NoStatefulFiltering": True,
    "NetfilterMode": 1,
    "WantRunning": True,
    "Persist": {"PrivateNodeKey": "must-not-leak"},
}
STATUS = {
    "Version": "1.104.5-test",
    "BackendState": "Running",
    "Self": {
        "ID": "self",
        "HostName": "keenetic-test",
        "Online": True,
        "TailscaleIPs": ["100.64.250.11"],
    },
    "Peer": {
        "key-a": {
            "ID": "node-exit",
            "HostName": "exit-a",
            "Online": True,
            "ExitNodeOption": True,
            "TailscaleIPs": ["100.64.250.12"],
        },
        "key-b": {
            "ID": "node-b",
            "HostName": "exit-b",
            "Online": True,
            "ExitNodeOption": True,
            "TailscaleIPs": ["100.64.250.7"],
        },
        "key-c": {
            "ID": "offline",
            "Online": False,
            "ExitNodeOption": True,
            "TailscaleIPs": ["100.64.250.99"],
        },
    },
    "Health": [],
}
NATIVE = "interface OpkgTun0\n    description Tailscale\n    security-level public\n    ip mtu 1280\n    up\n!\n"


class FakeRunner:
    def __init__(self):
        self.prefs = copy.deepcopy(PREFS)
        self.status = copy.deepcopy(STATUS)
        self.calls = []
        self.native = NATIVE

    def run(self, args, timeout=20, check=True):
        self.calls.append(args)
        if args[0].endswith("tailscale"):
            if args[1:] == ["status", "--json"]:
                out = json.dumps(self.status)
            elif args[1:] == ["debug", "prefs"]:
                out = json.dumps(self.prefs)
            elif args[1:] == ["version"]:
                out = "1.104.5\n"
            else:
                out = ""
        elif args[:2] == ["ndmc", "-c"]:
            out = self.native
        else:
            out = ""
        return subprocess.CompletedProcess(args, 0, out, "")


class PreferenceTests(unittest.TestCase):
    def setUp(self):
        self.r = FakeRunner()
        self.ts = Tailscale(self.r)

    def test_private_prefs_never_returned(self):
        self.assertNotIn("Persist", self.ts.snapshot()["prefs"])
        self.assertNotIn("must-not-leak", json.dumps(self.ts.snapshot()))

    def test_exit_switch_only_changes_selected_node(self):
        args, changes = self.ts.set_args({"exit_node": "node-b"})
        self.assertEqual(
            args, ["--exit-node=100.64.250.7", "--exit-node-allow-lan-access=true"]
        )
        self.assertEqual(self.r.prefs, PREFS)

    def test_clear_exit_also_clears_allow_lan(self):
        self.assertEqual(
            self.ts.set_args({"exit_node": ""})[0],
            ["--exit-node=", "--exit-node-allow-lan-access=false"],
        )

    def test_exit_selection_rejects_unknown_and_offline(self):
        for node in ["unknown", "offline", "1.1.1.1", ";reboot"]:
            with self.subTest(node=node), self.assertRaises(Error):
                self.ts.set_args({"exit_node": node})

    def test_noop_does_not_run_set(self):
        self.assertEqual(
            self.ts.set_args(
                {
                    "hostname": "keenetic-test",
                    "accept_dns": False,
                    "exit_node": "node-exit",
                }
            )[0],
            [],
        )

    def test_routes_preserve_default_advertisements(self):
        self.r.prefs["AdvertiseRoutes"] += ["0.0.0.0/0", "::/0"]
        args, _ = self.ts.set_args({"routes": ["192.168.20.0/24"]})
        self.assertEqual(args, ["--advertise-routes=192.168.20.0/24,0.0.0.0/0,::/0"])

    def test_advertise_exit_does_not_replace_subnets(self):
        self.r.prefs["ExitNodeID"] = ""
        self.assertEqual(
            self.ts.set_args({"advertise_exit": True})[0],
            ["--advertise-exit-node=true"],
        )

    def test_advertise_exit_clears_selected_exit_in_same_change(self):
        args, changes = self.ts.set_args({"advertise_exit": True})
        self.assertEqual(
            set(args),
            {
                "--advertise-exit-node=true",
                "--exit-node=",
                "--exit-node-allow-lan-access=false",
            },
        )
        self.assertTrue(any(c["name"] == "Exit node" for c in changes))
        self.assertEqual(self.r.prefs, PREFS)

    def test_select_exit_clears_self_advertisement_in_same_change(self):
        self.r.prefs["AdvertiseRoutes"] += ["0.0.0.0/0", "::/0"]
        args, _ = self.ts.set_args({"exit_node": "node-b"})
        self.assertIn("--advertise-exit-node=false", args)
        with self.assertRaises(Error):
            self.ts.set_args({"advertise_exit": True, "exit_node": "node-b"})

    def test_routes_reject_host_bits_and_default(self):
        for routes in [["192.168.2.1/24"], ["0.0.0.0/0"], ["bad"]]:
            with self.subTest(routes=routes), self.assertRaises(Error):
                self.ts.set_args({"routes": routes})

    def test_no_shell_injection(self):
        for value in ["x; reboot", "$(reboot)", "x\nreboot", "--foo", "я"]:
            with self.subTest(value=value), self.assertRaises(Error):
                self.ts.set_args({"hostname": value})

    def test_wrong_type_and_unknown_setting(self):
        for fields in [
            {"accept_dns": "false"},
            {"routes": "192.168.1.0/24"},
            {"arbitrary_shell": "reboot"},
            {"netfilter": "evil"},
        ]:
            with self.subTest(fields=fields), self.assertRaises(Error):
                self.ts.set_args(fields)

    def test_native_adoption_is_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            n = Native(d, self.r)
            n.linked_policies = lambda: []
            result = n.create({}, lambda x: None)
            self.assertTrue(result["noop"])
            self.assertTrue(
                all("show " in x[-1] for x in self.r.calls if x[0] == "ndmc")
            )

    def test_native_sync_does_not_replace_existing_route(self):
        class R(FakeRunner):
            def run(self, args, **kw):
                if args[:3] == ["ip", "-4", "route"]:
                    self.calls.append(args)
                    return subprocess.CompletedProcess(
                        args, 0, "default dev opkgtun0 metric 1000\n", ""
                    )
                return super().run(args, **kw)

        r = R()
        with tempfile.TemporaryDirectory() as d:
            Native(d, r).sync_policies([{"table": 4106}], True)
        self.assertFalse(any("replace" in x for x in r.calls))

    def test_native_policy_remains_linked_without_runtime_tunnel_routes(self):
        self.r.native += (
            "ip policy Policy5\n    description Headscale\n"
            "    permit global OpkgTun0\n    no permit global Other\n!\n"
        )
        data = {"Policy5": {"description": "Headscale", "table4": 4106}}
        with tempfile.TemporaryDirectory() as d, patch(
            "panel.native.urllib.request.build_opener"
        ) as opener:
            opener.return_value.open.return_value = io.BytesIO(
                json.dumps(data).encode()
            )
            policies = Native(d, self.r).linked_policies()
        self.assertEqual(
            policies,
            [{"id": "Policy5", "name": "Headscale", "table": 4106, "metric": 1000}],
        )

    def test_native_create_rejects_unsaved_foreign_changes_before_mutation(self):
        class Pending(FakeRunner):
            def run(self, args, **kw):
                self.calls.append(args)
                text = (
                    "hostname changed\n"
                    if args[-1] == "show running-config"
                    else "hostname saved\n"
                )
                return subprocess.CompletedProcess(args, 0, text, "")

        r = Pending()
        with tempfile.TemporaryDirectory() as d, patch.object(
            Native, "linked_policies", return_value=[]
        ):
            with self.assertRaises(Error):
                Native(d, r).create({}, lambda _: None)
        self.assertFalse(any(c[-1].startswith("interface ") for c in r.calls))

    def test_native_failed_creation_removes_only_its_new_interface(self):
        class FailedCreate(FakeRunner):
            def __init__(self):
                super().__init__()
                self.native = "hostname router\n"

            def run(self, args, **kw):
                command = args[-1]
                if args[:2] == ["ndmc", "-c"] and command.startswith("interface "):
                    self.calls.append(args)
                    if command == "interface OpkgTun0":
                        self.native += NATIVE
                        return subprocess.CompletedProcess(args, 0, "", "")
                    return subprocess.CompletedProcess(
                        args, 0, "error[100]: denied", ""
                    )
                if command == "no interface OpkgTun0":
                    self.calls.append(args)
                    self.native = "hostname router\n"
                    return subprocess.CompletedProcess(args, 0, "", "")
                return super().run(args, **kw)

        r = FailedCreate()
        with tempfile.TemporaryDirectory() as d, patch.object(
            Native, "linked_policies", return_value=[]
        ):
            with self.assertRaises(Error):
                Native(d, r).create({}, lambda _: None)
        self.assertEqual(r.native, "hostname router\n")
        self.assertEqual(
            [c[-1] for c in r.calls if c[-1].startswith("no ")],
            ["no interface OpkgTun0"],
        )

    def test_plan_detects_concurrent_preference_change(self):
        with tempfile.TemporaryDirectory() as d:
            service = Service(d, self.r)
            p = service.plan("settings", {"accept_dns": True})
            self.r.prefs["Hostname"] = "changed-elsewhere"
            with self.assertRaises(Error):
                service.apply(p["id"])

    def test_policy_monitor_leaves_adopted_integration_alone(self):
        with tempfile.TemporaryDirectory() as d:
            s = Service(d, self.r)
            with patch.object(s.native, "sync_policies") as sync:
                s.maintain_policies()
                sync.assert_not_called()

    def test_policy_monitor_restores_configured_defaults_for_clean_install(self):
        with tempfile.TemporaryDirectory() as d:
            s = Service(d, self.r)
            s.config["managed_policy_sync"] = True
            with patch.object(s.native, "sync_policies") as sync, patch.object(
                s.native, "linked_policies", return_value=[{"table": 4106}]
            ), patch(
                "panel.service.operation_lock", return_value=contextlib.nullcontext()
            ):
                s.maintain_policies()
                sync.assert_called_once_with([{"table": 4106}], True)

    def test_diagnostics_only_known_peers(self):
        with tempfile.TemporaryDirectory() as d:
            s = Service(d, self.r)
            with self.assertRaises(Error):
                s.diagnostics("ping", "8.8.8.8")

    def test_new_control_server_does_not_inherit_old_exit(self):
        with tempfile.TemporaryDirectory() as d:
            s = Service(d, self.r)
            s.connect(
                {
                    "server": "https://new-control.example.test",
                    "hostname": "keenetic-test",
                },
                lambda _: None,
            )
            command = next(c for c in self.r.calls if "login" in c)
            self.assertIn("--exit-node=", command)
            self.assertIn("--exit-node-allow-lan-access=false", command)
            self.assertIn("--accept-routes=true", command)
            self.assertIn("--accept-dns=false", command)

    def test_backups_exclude_private_key_and_exit_override(self):
        with tempfile.TemporaryDirectory() as d:
            s = Service(d, self.r)
            b = s.backup_settings()
            text = json.dumps(b)
            self.assertNotIn("must-not-leak", text)
            self.assertNotIn("exit_node", b["settings"])
            self.assertNotIn("advertise_exit", b["settings"])
            self.assertEqual(b["settings"]["routes"], ["192.168.10.0/24"])


class AuthHTTPTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch('panel.server.operation_lock',lambda _:contextlib.nullcontext()).start()
        patch('panel.accounts.operation_lock',lambda _:contextlib.nullcontext()).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.state = pathlib.Path(self.tmp.name)
        write_json(
            self.state / "auth.json",
            {"username": "admin", "password_hash": password_hash("test-password-only")},
        )
        self.app = App(self.state, Service(self.state, FakeRunner()))
        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.app = self.app
        self.server.web = pathlib.Path(__file__).resolve().parents[1] / "web"
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ""
        self.csrf = ""

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def req(self, path, body=None, headers=None):
        h = {"Cookie": self.cookie}
        h.update(headers or {})
        if body is not None:
            h["Content-Type"] = "application/json"
            h.setdefault("X-CSRF-Token", self.csrf)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request(
                "GET" if body is None else "POST",
                path,
                json.dumps(body) if body is not None else None,
                h,
            )
            r = c.getresponse()
            data = r.read()
            cookie = r.getheader("Set-Cookie")
            if cookie:
                self.cookie = cookie.split(";")[0]
            try:
                data = json.loads(data)
            except ValueError:
                pass
            return r.status, data, dict(r.headers)
        finally:
            c.close()

    def anonymous(self):
        s, x, h = self.req("/api/session")
        self.csrf = x["csrf"]
        return x

    def login(self):
        self.anonymous()
        s, x, h = self.req(
            "/api/login", {"username": "admin", "password": "test-password-only"}
        )
        self.assertEqual(s, 200)
        self.csrf = x["csrf"]

    def test_api_requires_login(self):
        self.assertEqual(self.req("/api/dashboard")[0], 401)
        self.assertEqual(self.req("/api/devices")[0], 401)
        self.assertEqual(self.req("/api/egress")[0], 401)

    def test_authenticated_device_card_api_roundtrip(self):
        self.login()
        status, cards, _ = self.req("/api/devices")
        self.assertEqual(status, 200)
        status, card, _ = self.req(
            "/api/devices",
            {
                "id": "node-b",
                "notes": "Узел в офисе",
                "url": "http://100.64.250.7:8092/",
                "revision": cards["node-b"]["revision"],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.req("/api/devices")[1]["node-b"]["notes"], "Узел в офисе")
        self.assertEqual(
            self.req(
                "/api/devices",
                {
                    "id": "node-b",
                    "notes": "bad",
                    "url": "",
                    "revision": card["revision"],
                },
                headers={"X-CSRF-Token": "wrong"},
            )[0],
            403,
        )

    def test_login_and_session(self):
        self.login()
        status, data, headers = self.req("/api/dashboard")
        self.assertEqual(status, 200)
        self.assertNotIn("must-not-leak", json.dumps(data))

    def test_csrf_required_for_login(self):
        self.anonymous()
        self.csrf = "bad"
        self.assertEqual(
            self.req(
                "/api/login", {"username": "admin", "password": "test-password-only"}
            )[0],
            403,
        )

    def test_cross_origin_rejected(self):
        self.anonymous()
        self.assertEqual(
            self.req(
                "/api/login",
                {"username": "admin", "password": "test-password-only"},
                {"Origin": "https://other.invalid"},
            )[0],
            403,
        )

    def test_post_requires_auth_and_csrf(self):
        self.login()
        self.assertEqual(
            self.req("/api/backups", {}, headers={"X-CSRF-Token": "bad"})[0], 403
        )

    def test_safe_cookie_headers(self):
        self.anonymous()
        _, _, headers = self.req("/api/session")
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_static_path_traversal(self):
        self.assertEqual(self.req("/static/../../etc/passwd")[0], 404)

    def test_invalid_password(self):
        self.anonymous()
        self.assertEqual(
            self.req("/api/login", {"username": "admin", "password": "wrong"})[0], 401
        )

    def test_logout_revokes_session(self):
        self.login()
        self.assertEqual(self.req("/api/logout", {})[0], 200)
        self.assertEqual(self.req("/api/dashboard")[0], 401)

    def test_native_noop_plan(self):
        self.login()
        self.app.service.native.linked_policies = lambda: []
        s, x, h = self.req(
            "/api/actions/plan", {"action": "native_create", "params": {}}
        )
        self.assertEqual(s, 200)
        self.assertEqual(x["commands"], [])


class PurgeTests(unittest.TestCase):
    def test_purge_removes_owned_state_and_keeps_other_apps(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            state = root / "opt/etc/tailscale-panel"
            state.mkdir(parents=True)
            write_json(state / "config.json", {"tun": "opkgtun0"})
            (state / "secret-key").write_text("private")
            xkeen = root / "opt/etc/xray/configs/04_outbounds.json"
            xkeen.parent.mkdir(parents=True)
            xkeen.write_text("preserve-me")
            client = root / "opt/bin/tailscale"
            client.parent.mkdir(parents=True)
            client.write_text("client")
            key = root / "opt/var/tailscaled.state"
            key.parent.mkdir(parents=True)
            key.write_text("machine-key")
            p = Purger(state, root=d)
            plan = p.plan()
            self.assertIn("/opt/var/tailscaled.state", plan["paths"])
            result = p.purge()
            self.assertTrue(result["purged"])
            self.assertFalse(client.exists())
            self.assertFalse(key.exists())
            self.assertFalse(state.exists())
            self.assertEqual(xkeen.read_text(), "preserve-me")

    def test_shared_smb_helper_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            state = root / "opt/etc/tailscale-panel"
            state.mkdir(parents=True)
            p = root / "opt/etc/init.d/S07tailscale-policy"
            p.parent.mkdir(parents=True)
            p.write_text(
                '#!/bin/sh\nTS_TABLE="52"\nHOME_SMB_IP="10.0.0.1"\nhome_smb_run() { echo preserved; }\nHEADSCALE_POLICY_TABLE="123"\n# unrelated TS body\n'
            )
            Purger(state, root=d).purge()
            kept = root / "opt/etc/init.d/S07zerotier-smb"
            self.assertTrue(kept.exists())
            self.assertIn("home_smb_run", kept.read_text())
            self.assertNotIn("HEADSCALE_POLICY_TABLE", kept.read_text())
            self.assertFalse(p.exists())

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Purger(pathlib.Path(d) / "opt/etc/tailscale-panel", root=d)
            with self.assertRaises(Error):
                p.path("/opt/../../outside/file")

    def test_archive_symlink_not_used_as_client(self):
        import io, tarfile

        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w:gz") as t:
            m = tarfile.TarInfo("tailscale_x/tailscale")
            m.type = tarfile.SYMTYPE
            m.linkname = "/etc/passwd"
            t.addfile(m)
        with tempfile.TemporaryDirectory() as d, self.assertRaises(Error):
            extract_client(b.getvalue(), pathlib.Path(d))

    def test_invalid_update_checksum_stops_before_service_stop(self):
        with tempfile.TemporaryDirectory() as d:
            r = FakeRunner()
            ts = Tailscale(r)
            ts.snapshot = lambda *a, **k: {
                "self": {"ID": ""},
                "backend_state": "NeedsLogin",
                "prefs": {},
            }
            n = Native(d, r)
            n.linked_policies = lambda: []
            u = Updater(d, ts, n, r)
            u.check = lambda: {
                "available": True,
                "latest": "1.105.0",
                "archive": "tailscale_1.105.0_arm64.tgz",
            }
            with patch("panel.updates.platform.machine", return_value="aarch64"), patch(
                "panel.updates.download", side_effect=[b"archive", b"bad-checksum"]
            ), self.assertRaises(Error):
                u.update(lambda x: None)
            self.assertFalse(any("stop" in x for x in r.calls))


if __name__ == "__main__":
    unittest.main()
