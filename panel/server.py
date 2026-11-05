"""Authenticated LAN management server, no framework or build runtime required."""

import argparse, base64, collections, hashlib, hmac, http.cookies, http.server, json, mimetypes, os, pathlib, re, secrets, signal, threading, time, urllib.parse
from .core import Error, VERSION, read_json, write_json
from .service import Service


from .accounts import Accounts, password_hash, password_check
from .core import operation_lock


class App:
    def __init__(self, state, service=None):
        self.state = pathlib.Path(state)
        self.service = service or Service(state)
        self.service.panel_updater.recover()
        self.accounts = Accounts(self.state)
        self.accounts.ensure()
        self.config = read_json(self.state / "config.json")
        self.sessions = {}
        self.failures = collections.defaultdict(list)
        self.failure_epoch = self.accounts.epoch()
        self.mutex = threading.RLock()
        self.login_lock = threading.BoundedSemaphore(2)
        self.stopping = False

    def auth_record(self):
        return self.accounts.read()

    def session(self, token):
        with self.mutex:
            record = self.sessions.get(token)
            if (
                record
                and record["expires"] > time.time()
                and (
                    not record["user"]
                    or (
                        self.accounts.revision()
                        and record.get("auth_revision") == self.accounts.revision()
                    )
                )
            ):
                return record
            self.sessions.pop(token, None)
            return None

    def create_session(self, user=None):
        with self.mutex:
            self.sessions = {
                k: v for k, v in self.sessions.items() if v["expires"] > time.time()
            }
            if len(self.sessions) > 128:
                self.sessions.pop(next(iter(self.sessions)))
            token = secrets.token_urlsafe(32)
            record = {
                "auth_revision": self.accounts.revision(),
                "user": user,
                "csrf": secrets.token_urlsafe(32),
                "expires": time.time() + 8 * 3600,
            }
            self.sessions[token] = record
            return token, record

    def throttled(self, ip, action):
        with self.mutex:
            epoch = self.accounts.epoch()
            if epoch != self.failure_epoch:
                self.failures.clear()
                self.failure_epoch = epoch
            self.failures[ip] = [t for t in self.failures[ip] if time.time() - t < 300]
            if len(self.failures[ip]) >= 10:
                raise Error("Слишком много попыток. Повторите через 5 минут.", 429)
        if not self.login_lock.acquire(False):
            raise Error("Вход временно занят. Повторите через несколько секунд.", 429)
        try:
            return action()
        except Error as exc:
            with self.mutex:
                self.failures[ip].append(time.time())
            self.service.event("account_attempt_failed", {"status": exc.status})
            raise
        finally:
            self.login_lock.release()

    def login(self, ip, username, password):
        def attempt():
            with operation_lock(self.state):
                auth = self.auth_record()
                valid_password = password_check(auth.get("password_hash", ""), password)
                if (
                    not isinstance(username, str)
                    or len(username) > 100
                    or not hmac.compare_digest(
                        username.encode(), auth.get("username", "").encode()
                    )
                    or not valid_password
                ):
                    raise Error("Неверный логин или пароль", 401)
                result = self.create_session(username)
                self.failures.pop(ip, None)
                return result

        return self.throttled(ip, attempt)

    def setup_account(self, ip, fields):
        def attempt():
            with operation_lock(self.state):
                self.accounts.setup(fields)
                with self.mutex:
                    self.sessions.clear()
                self.service.event("account_created")
                return self.create_session(fields["username"])

        return self.throttled(ip, attempt)

    def change_account(self, ip, fields):
        def attempt():
            with operation_lock(self.state):
                user = self.accounts.change(fields)
                with self.mutex:
                    self.sessions.clear()
                self.service.event("account_changed")
                return self.create_session(user)

        return self.throttled(ip, attempt)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TailScaleKeen/" + VERSION
    sys_version = ""

    @property
    def app(self):
        return self.server.app

    def log_message(self, fmt, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def send(
        self,
        status,
        data,
        content_type="application/json; charset=utf-8",
        cookie=None,
        download=None,
    ):
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False).encode()
        elif isinstance(data, str):
            data = data.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if download:
            self.send_header(
                "Content-Disposition", 'attachment; filename="' + download + '"'
            )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def current(self):
        try:
            c = http.cookies.SimpleCookie()
            c.load(self.headers.get("Cookie", ""))
            token = c["ts_panel"].value if "ts_panel" in c else ""
            return token, self.app.session(token)
        except http.cookies.CookieError:
            return "", None

    def cookie(self, token):
        return (
            "ts_panel=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
        )

    def body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise Error("Неверный размер запроса")
        if not 0 < n <= 1024 * 1024:
            raise Error("Недопустимый размер запроса", 413)
        if self.headers.get_content_type() != "application/json":
            raise Error("Ожидается JSON", 415)
        try:
            x = json.loads(self.rfile.read(n))
        except (ValueError, UnicodeError):
            raise Error("Повреждённый JSON")
        if not isinstance(x, dict):
            raise Error("Ожидается объект JSON")
        return x

    def require(self, post=False):
        token, session = self.current()
        if not session or not session["user"]:
            raise Error("Войдите в панель", 401)
        if post:
            self.csrf(session)
        return token, session

    def csrf(self, session):
        origin = self.headers.get("Origin")
        if origin:
            p = urllib.parse.urlsplit(origin)
            if p.netloc != self.headers.get("Host") or p.scheme not in [
                "http",
                "https",
            ]:
                raise Error("Запрос с другого сайта запрещён", 403)
        token = self.headers.get("X-CSRF-Token", "")
        if not session or not token or not hmac.compare_digest(token, session["csrf"]):
            raise Error("Проверка сессии не пройдена. Обновите страницу.", 403)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if path in ["/", "/login"]:
                self.send(
                    200,
                    (self.server.web / "index.html").read_bytes(),
                    "text/html; charset=utf-8",
                )
                return
            if path.startswith("/static/"):
                relative = path[len("/static/") :]
                if relative not in [
                    "app.js",
                    "app.css",
                    "keenetic.css",
                    "favicon.svg",
                    "fonts/Roboto.ttf",
                    "fonts/OFL.txt",
                ]:
                    raise Error("Файл не найден", 404)
                p = self.server.web / relative
                mime = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
                self.send(200, p.read_bytes(), mime + "; charset=utf-8")
                return
            if path == "/api/session":
                token, s = self.current()
                cookie = None
                if not s:
                    token, s = self.app.create_session()
                    cookie = self.cookie(token)
                self.send(
                    200,
                    {
                        "authenticated": bool(s["user"]),
                        "user": s["user"],
                        "csrf": s["csrf"],
                        "configured": bool(self.app.auth_record().get("password_hash")),
                        "version": VERSION,
                        "panel_update": {k: v for k, v in self.app.service.panel_updater.status().items() if k in {"state", "version", "message"}},
                    },
                    cookie=cookie,
                )
                return
            self.require()
            service = self.app.service
            if path == "/api/dashboard":
                data = service.dashboard()
            elif path == "/api/native":
                data = service.native.status()
            elif path == "/api/egress":
                data = service.egress.status()
            elif path == "/api/devices":
                data = service.devices.list()
            elif path == "/api/panel-settings":
                data = {
                    "username": self.app.auth_record().get("username", ""),
                    **(
                        self.app.ports.status()
                        if hasattr(self.app, "ports")
                        else {
                            "port": self.app.config.get("port", 8092),
                            "pending": None,
                        }
                    ),
                }
            elif path == "/api/updates":
                data = service.updater.check()
            elif path == "/api/panel-updates":
                data = service.panel_updater.check(query.get("fresh") == ["1"])
            elif path == "/api/panel-update-status":
                data = service.panel_updater.status()
            elif path == "/api/jobs":
                data = service.jobs.list()
            elif path.startswith("/api/jobs/"):
                data = service.jobs.get(path.split("/")[-1])
            elif path == "/api/logs":
                data = service.logs(query.get("kind", ["panel"])[0])
            elif path == "/api/backups":
                data = service.backups()
            elif path.startswith("/api/backups/"):
                ident = path.split("/")[-1]
                data = service.get_backup(ident)
                self.send(200, data, download="tailscale-settings-" + ident + ".json")
                return
            elif path == "/api/uninstall-plan":
                from .uninstall import Purger

                data = Purger(self.app.state, service.runner).plan()
            else:
                raise Error("Страница не найдена", 404)
            self.send(200, data)
        except Error as e:
            self.send(e.status, {"error": str(e)})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            self.send(
                500,
                {
                    "error": "Внутренняя ошибка панели. Подробности доступны администратору."
                },
            )

    def do_POST(self):
        try:
            if self.app.stopping:
                raise Error(
                    "Панель завершает работу. Дождитесь завершения текущей операции.",
                    503,
                )
            path = urllib.parse.urlsplit(self.path).path
            data = self.body()
            if self.app.service.panel_updater.active() and path == "/api/setup":
                raise Error("Дождитесь обновления панели перед созданием учётной записи", 409)
            if path in ["/api/login", "/api/setup"]:
                old, s = self.current()
                self.csrf(s)
                if path == "/api/setup":
                    token, session = self.app.setup_account(
                        self.client_address[0], data
                    )
                else:
                    token, session = self.app.login(
                        self.client_address[0],
                        data.get("username", ""),
                        data.get("password", ""),
                    )
                self.app.sessions.pop(old, None)
                self.send(
                    200,
                    {
                        "authenticated": True,
                        "user": session["user"],
                        "csrf": session["csrf"],
                    },
                    cookie=self.cookie(token),
                )
                return
            token, s = self.require(True)
            service = self.app.service
            if service.panel_updater.active() and path != "/api/logout":
                raise Error("Обновляется панель. Дождитесь завершения и войдите снова.", 409)
            if path == "/api/logout":
                self.app.sessions.pop(token, None)
                self.send(
                    200,
                    {"ok": True},
                    cookie="ts_panel=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                )
                return
            if path == "/api/actions/plan":
                result = service.plan(data.get("action", ""), data.get("params", {}))
            elif path == "/api/actions/apply":
                result = service.apply(data.get("plan_id", ""))
            elif path == "/api/diagnostics":
                result = service.diagnostics(
                    data.get("kind", ""), data.get("target", "")
                )
            elif path == "/api/devices":
                result = service.devices.save(data)
            elif path == "/api/backups":
                result = service.backup_settings()
            elif path == "/api/backups/import":
                item = data.get("backup")
                if (
                    not isinstance(item, dict)
                    or item.get("schema") != 1
                    or not isinstance(item.get("settings"), dict)
                ):
                    raise Error("Неверный формат копии")
                service.ts.set_args(item["settings"])
                ident = secrets.token_hex(12)
                item = {
                    "id": ident,
                    "schema": 1,
                    "created_at": int(time.time()),
                    "settings": item["settings"],
                    "note": "Импортировано пользователем",
                }
                write_json(service.state / "backups" / (ident + ".json"), item)
                result = item
            elif path == "/api/backups/delete":
                item = service.get_backup(data.get("backup", ""))
                (service.state / "backups" / (item["id"] + ".json")).unlink()
                result = {"ok": True}
            elif path == "/api/password":
                token, session = self.app.change_account(self.client_address[0], data)
                self.send(
                    200,
                    {
                        "ok": True,
                        "authenticated": True,
                        "user": session["user"],
                        "csrf": session["csrf"],
                    },
                    cookie=self.cookie(token),
                )
                return
            elif path.startswith("/api/panel-port/"):
                if not hasattr(self.app, "ports"):
                    raise Error("Смена порта недоступна в тестовом сервере", 503)
                if path == "/api/panel-port/begin":
                    result = self.app.ports.begin(data.get("port"))
                elif path == "/api/panel-port/confirm":
                    result = self.app.ports.confirm(
                        data.get("id"), self.server.server_address[1]
                    )
                elif path == "/api/panel-port/cancel":
                    result = self.app.ports.cancel()
                else:
                    raise Error("Действие не найдено", 404)
            else:
                raise Error("Действие не найдено", 404)
            self.send(200, result)
        except Error as e:
            self.send(e.status, {"error": str(e)})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            self.send(
                500,
                {
                    "error": "Не удалось выполнить действие. Проверьте состояние перед повтором."
                },
            )


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 24
    allow_reuse_address = True

    def __init__(self, *args, **kw):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kw)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/opt/etc/tailscale-panel")
    args = parser.parse_args()
    app = App(args.state)
    config = app.config
    web = pathlib.Path(__file__).resolve().parents[1] / "web"
    server = Server(
        (config.get("bind", "0.0.0.0"), int(config.get("port", 8092))), Handler
    )
    server.app = app
    server.web = web
    from .access import Ports

    def factory(port):
        listener = Server((config.get("bind", "0.0.0.0"), port), Handler)
        listener.app = app
        listener.web = web
        return listener

    app.ports = Ports(app, factory, server)
    app.service.jobs.recover()
    stopped = threading.Event()
    finished = threading.Event()

    def maintain():
        last_error = None
        while not stopped.wait(20):
            try:
                app.service.maintain_policies()
                app.service.panel_updater.recover()
                app.service.maintain_egress()
                last_error = None
            except Exception as exc:
                # Never log response bodies or preference secrets.
                kind = type(exc).__name__
                if kind != last_error:
                    app.service.event("policy_sync_failed", {"kind": kind})
                    last_error = kind

    threading.Thread(target=maintain, daemon=True).start()

    def stop(signum, frame):
        app.stopping = True
        stopped.set()

        def finish():
            app.service.jobs.lock.acquire()
            app.service.jobs.lock.release()
            app.ports.close_all()
            finished.set()

        threading.Thread(target=finish, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    finished.wait()


if __name__ == "__main__":
    main()
