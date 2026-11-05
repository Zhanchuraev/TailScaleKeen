import contextlib, http.client, json, pathlib, socket, tempfile, time, unittest, io
from unittest.mock import patch
import test_panel as base
from panel.server import App, Server, Handler, password_hash
from panel.accounts import Accounts
from panel.access import Ports
from panel.core import Error, write_json, read_json
from panel.service import Service
from panel.install import _install
import panel.install as installer_module


class AccountHTTPTests(unittest.TestCase):
    setUp = base.AuthHTTPTests.setUp
    tearDown = base.AuthHTTPTests.tearDown
    req = base.AuthHTTPTests.req
    anonymous = base.AuthHTTPTests.anonymous
    login = base.AuthHTTPTests.login

    def test_panel_update_endpoints_require_auth_and_hide_transaction_secrets(self):
        write_json(self.state / "panel-update/transaction.json", {"state": "done", "token": "sentinel-token", "files": {"secret": "hash"}, "message": "updated", "version": "1.0.0"})
        status, result, _ = self.req("/api/panel-update-status")
        self.assertEqual(status, 401)
        status, result, _ = self.req("/api/session")
        self.assertNotIn("sentinel-token", json.dumps(result))
        self.assertNotIn("files", result["panel_update"])
        self.login()
        status, result, _ = self.req("/api/panel-update-status")
        self.assertEqual(status, 200)
        self.assertNotIn("token", result)
        self.assertNotIn("files", result)

    def test_update_preview_works_without_tailscale_and_rejects_custom_source(self):
        self.login()
        self.app.service.panel_updater.check = lambda *args: {"latest": "9.0.0", "available": True}
        self.app.service.ts.snapshot = lambda *args: (_ for _ in ()).throw(Error("client unavailable"))
        status, result, _ = self.req("/api/actions/plan", {"action": "update_panel", "params": {}})
        self.assertEqual(status, 200)
        self.assertEqual(result["changes"][0]["after"], "9.0.0")
        self.assertEqual(self.req("/api/actions/plan", {"action": "update_panel", "params": {"url": "https://example.test"}})[0], 400)
        self.assertEqual(self.req("/api/actions/apply", {"plan_id": result["id"]}, headers={"X-CSRF-Token": "wrong"})[0], 403)

    def test_active_panel_update_blocks_configuration_changes(self):
        self.login()
        write_json(self.state / "panel-update/transaction.json", {"state": "installing", "started_at": time.time()})
        self.assertEqual(self.req("/api/backups", {})[0], 409)
        self.assertEqual(self.req("/api/panel-port/begin", {"port": 8193})[0], 409)

    def setup_fields(self, **changes):
        d = {
            "username": "owner",
            "password": "new-private-test-pass",
            "password_confirm": "new-private-test-pass",
        }
        d.update(changes)
        return d

    def test_setup_without_code_requires_confirmation_and_is_once(self):
        self.app.accounts.reset()
        self.anonymous()
        self.assertEqual(
            self.req("/api/setup", self.setup_fields(password_confirm="different"))[0],
            400,
        )
        self.assertFalse(self.app.accounts.read())
        fields = self.setup_fields()
        status, result, _ = self.req("/api/setup", fields)
        self.assertEqual(status, 200)
        self.csrf = result["csrf"]
        self.assertFalse((self.state / "setup.token").exists())
        self.assertEqual(self.req("/api/dashboard")[0], 200)
        self.assertEqual(self.req("/api/setup", fields)[0], 409)
        self.assertNotIn(fields["password"], (self.state / "auth.json").read_text())

    def test_six_digit_password_is_allowed_and_five_digits_rejected(self):
        self.app.accounts.reset()
        self.anonymous()
        self.assertEqual(
            self.req(
                "/api/setup",
                self.setup_fields(password="12345", password_confirm="12345"),
            )[0],
            400,
        )
        self.assertEqual(
            self.req(
                "/api/setup",
                self.setup_fields(password="123456", password_confirm="123456"),
            )[0],
            200,
        )

    def test_external_auth_is_detached_without_modification(self):
        external = self.state / "xkeen-auth.json"
        write_json(
            external,
            {
                "username": "xkeen",
                "password_hash": password_hash("xkeen-only-test-password"),
            },
        )
        original = external.read_bytes()
        write_json(
            self.state / "config.json", {"auth_source": str(external), "port": 8092}
        )
        app = App(self.state, Service(self.state, base.FakeRunner()))
        self.assertFalse(app.auth_record())
        self.assertNotIn("auth_source", read_json(self.state / "config.json"))
        self.assertEqual(external.read_bytes(), original)

    def test_password_requires_current_confirmation_and_rotates_all_sessions(self):
        self.login()
        old_cookie = self.cookie
        other, _ = self.app.create_session("admin")
        fields = {
            "username": "new-owner",
            "current_password": "wrong",
            "password": "new-private-test-pass",
            "password_confirm": "new-private-test-pass",
        }
        self.assertEqual(self.req("/api/password", fields)[0], 403)
        fields["current_password"] = "test-password-only"
        fields["password_confirm"] = "different"
        self.assertEqual(self.req("/api/password", fields)[0], 400)
        fields["password_confirm"] = fields["password"]
        status, result, _ = self.req("/api/password", fields)
        self.assertEqual(status, 200)
        self.csrf = result["csrf"]
        self.assertNotEqual(old_cookie, self.cookie)
        self.assertIsNone(self.app.session(other))
        self.assertEqual(
            self.req("/api/dashboard", headers={"Cookie": old_cookie})[0], 401
        )
        self.assertEqual(self.req("/api/dashboard")[0], 200)
        self.assertEqual(self.app.accounts.read()["username"], "new-owner")

    def test_reset_revokes_existing_sessions_without_restart(self):
        self.login()
        self.app.accounts.reset()
        self.assertFalse((self.state / "auth.json").exists())
        self.assertFalse(self.app.accounts.read().get("username"))
        self.assertFalse((self.state / "setup.token").exists())
        self.assertEqual(self.req("/api/dashboard")[0], 401)
        self.assertFalse(self.anonymous()["configured"])
        self.assertEqual(
            self.req(
                "/api/setup",
                self.setup_fields(
                    username="another-owner",
                    password="654321",
                    password_confirm="654321",
                ),
            )[0],
            200,
        )

    def test_session_in_another_process_invalidated_after_change(self):
        other = App(self.state, Service(self.state, base.FakeRunner()))
        token, _ = other.create_session("admin")
        self.login()
        self.req(
            "/api/password",
            {
                "current_password": "test-password-only",
                "password": "new-private-test-pass",
                "password_confirm": "new-private-test-pass",
            },
        )
        self.assertIsNone(other.session(token))

    def test_setup_and_account_require_csrf(self):
        self.app.accounts.reset()
        self.anonymous()
        self.assertEqual(
            self.req("/api/setup", self.setup_fields(), {"X-CSRF-Token": "wrong"})[0],
            403,
        )

    def test_bruteforce_is_limited(self):
        self.anonymous()
        for _ in range(10):
            self.assertEqual(
                self.req("/api/login", {"username": "unknown", "password": "wrong"})[0],
                401,
            )
        self.assertEqual(
            self.req("/api/login", {"username": "unknown", "password": "wrong"})[0], 429
        )

    def test_ssh_reset_clears_failed_attempts_for_setup(self):
        self.anonymous()
        self.app.failures["127.0.0.1"] = [time.time()] * 10
        self.app.accounts.reset()
        self.anonymous()
        self.assertEqual(self.req("/api/setup", self.setup_fields())[0], 200)


class PortHTTPTests(unittest.TestCase):
    req = base.AuthHTTPTests.req
    anonymous = base.AuthHTTPTests.anonymous
    login = base.AuthHTTPTests.login

    def setUp(self):
        base.AuthHTTPTests.setUp(self)
        self.server.shutdown()
        self.thread.join()

        def factory(port):
            s = Server(("127.0.0.1", port), Handler)
            s.app = self.app
            s.web = self.server.web
            return s

        self.app.ports = Ports(self.app, factory, self.server, timeout=2)
        self.login()

    def tearDown(self):
        self.app.ports.close_all()
        self.tmp.cleanup()

    def free_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_occupied_port_and_invalid_values_do_not_change_current(self):
        for invalid in [True, 80, 65536, "8092", 0]:
            self.assertEqual(
                self.req("/api/panel-port/begin", {"port": invalid})[0], 400
            )
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen()
            self.assertEqual(
                self.req("/api/panel-port/begin", {"port": s.getsockname()[1]})[0], 409
            )
        self.assertEqual(self.app.ports.current, self.port)

    def test_confirmation_only_from_new_listener_and_persists(self):
        old = self.port
        new = self.free_port()
        status, p, _ = self.req("/api/panel-port/begin", {"port": new})
        self.assertEqual(status, 200)
        self.assertNotEqual(read_json(self.state / "config.json").get("port"), new)
        self.assertEqual(self.req("/api/panel-port/confirm", {"id": p["id"]})[0], 409)
        self.port = new
        self.assertEqual(self.req("/api/session")[0], 200)
        self.assertEqual(self.req("/api/panel-port/confirm", {"id": p["id"]})[0], 200)
        self.assertEqual(read_json(self.state / "config.json")["port"], new)
        self.assertEqual(self.app.service.config["port"], new)

    def test_timeout_keeps_old_listener_and_does_not_persist(self):
        new = self.free_port()
        self.req("/api/panel-port/begin", {"port": new})
        deadline = time.monotonic() + 4
        while self.app.ports.status()["pending"] and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIsNone(self.app.ports.status()["pending"])
        self.assertEqual(self.req("/api/session")[0], 200)
        self.assertNotEqual(read_json(self.state / "config.json").get("port"), new)

    def test_cancel_is_authenticated_and_reverts(self):
        new = self.free_port()
        self.req("/api/panel-port/begin", {"port": new})
        self.assertEqual(
            self.req("/api/panel-port/cancel", {}, headers={"Cookie": ""})[0], 401
        )
        self.assertEqual(self.req("/api/panel-port/cancel", {})[0], 200)
        self.assertIsNone(self.app.ports.status()["pending"])


class InstallerAccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.state = self.root / "opt/etc/tailscale-panel"
        self.source = pathlib.Path(installer_module.__file__).resolve().parents[1]

    def install(self, **kwargs):
        with patch(
            "panel.install.client", return_value={"version": "test", "changed": False}
        ), contextlib.redirect_stdout(io.StringIO()):
            return _install(self.source, root=str(self.root), **kwargs)

    def test_clean_install_creates_setup_and_reinstall_preserves_account(self):
        self.install()
        self.assertFalse((self.state / "setup.token").exists())
        self.assertTrue((self.state / "account-state.json").is_file())
        self.assertFalse((self.state / "auth.json").exists())
        Accounts(self.state).setup(
            {
                "username": "owner",
                "password": "private-test-password",
                "password_confirm": "private-test-password",
            }
        )
        old = (self.state / "auth.json").read_bytes()
        self.install()
        self.assertEqual((self.state / "auth.json").read_bytes(), old)
        self.assertFalse((self.state / "setup.token").exists())

    def test_legacy_migration_preserves_external_credentials(self):
        external = self.root / "xkeen-auth.json"
        write_json(
            external, {"username": "other", "password_hash": "external-sentinel"}
        )
        before = external.read_bytes()
        write_json(
            self.state / "config.json", {"auth_source": str(external), "port": 8092}
        )
        self.install()
        self.assertEqual(external.read_bytes(), before)
        self.assertNotIn("auth_source", read_json(self.state / "config.json"))
        self.assertFalse((self.state / "setup.token").exists())
        self.assertFalse((self.state / "auth.json").exists())

    def test_shared_auth_option_is_rejected(self):
        with self.assertRaises(Error):
            self.install(auth_source="/opt/etc/xkeen-ui/auth.json")
