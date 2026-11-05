"""A temporary second listener verifies a port change before committing it."""

import secrets, threading, time
from .core import Error, read_json, write_json


class Ports:
    def __init__(self, app, factory, primary, timeout=120):
        self.app = app
        self.factory = factory
        self.current = primary.server_address[1]
        self.servers = {self.current: primary}
        self.pending = None
        self.timer = None
        self.timeout = timeout
        self.lock = threading.RLock()
        self.start(primary)

    @staticmethod
    def start(server):
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
        ).start()

    @staticmethod
    def close(server):
        server.shutdown()
        server.server_close()

    def status(self):
        with self.lock:
            return {
                "port": self.current,
                "pending": dict(self.pending) if self.pending else None,
            }

    def begin(self, port):
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1024 <= port <= 65535
        ):
            raise Error("Порт: целое число от 1024 до 65535.")
        with self.lock:
            if self.pending:
                raise Error(
                    "Уже проверяется другой порт. Дождитесь завершения или отмените проверку.",
                    409,
                )
            if port == self.current:
                return {"port": port, "unchanged": True}
            try:
                server = self.factory(port)
            except OSError:
                raise Error("Порт занят или недоступен. Выберите другой.", 409)
            self.servers[port] = server
            self.start(server)
            self.pending = {
                "id": secrets.token_hex(16),
                "old_port": self.current,
                "new_port": port,
                "expires_at": int(time.time() + self.timeout),
            }
            self.timer = threading.Timer(
                self.timeout, self.cancel, args=(self.pending["id"],)
            )
            self.timer.daemon = True
            self.timer.start()
            return dict(self.pending)

    def confirm(self, ident, local_port):
        with self.lock:
            p = self.pending
            if (
                not p
                or p["id"] != ident
                or local_port != p["new_port"]
                or time.time() >= p["expires_at"]
            ):
                raise Error(
                    "Проверка порта истекла или выполнена с прежнего адреса.", 409
                )
            config = read_json(self.app.state / "config.json")
            config["port"] = p["new_port"]
            write_json(self.app.state / "config.json", config)
            self.app.config = config
            self.app.service.config = config
            self.current = p["new_port"]
            old = self.servers.pop(p["old_port"])
            self.pending = None
            self.timer.cancel()
            self.timer = None
        threading.Thread(target=self.close, args=(old,), daemon=True).start()
        self.app.service.event("panel_port_changed", {"port": self.current})
        return {"ok": True, "port": self.current}

    def cancel(self, ident=None):
        with self.lock:
            if not self.pending or (ident is not None and self.pending["id"] != ident):
                return {"port": self.current}
            new = self.servers.pop(self.pending["new_port"])
            self.pending = None
            if self.timer:
                self.timer.cancel()
                self.timer = None
        self.close(new)
        return {"port": self.current}

    def close_all(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None
            servers = list(self.servers.values())
            self.servers = {}
            self.pending = None
        for server in servers:
            self.close(server)
