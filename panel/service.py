import copy, hashlib, ipaddress, json, os, pathlib, platform, re, secrets, subprocess, threading, time
from .core import (
    Error,
    Jobs,
    Runner,
    Tailscale,
    VERSION,
    read_json,
    scrub,
    validate_server,
    write_json,
    operation_lock,
)
from .native import Native
from .updates import Updater
from .egress import Egress
from .devices import Devices
from .lan_access import LanAccess


class Service:
    def __init__(self, state, runner=None):
        self.state = pathlib.Path(state)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config = read_json(self.state / "config.json")
        self.runner = runner or Runner()
        self.ts = Tailscale(self.runner)
        self.native = Native(
            self.state, self.runner, self.config.get("tun", "opkgtun0")
        )
        self.updater = Updater(self.state, self.ts, self.native, self.runner)
        from .panel_update import PanelUpdater
        self.panel_updater = PanelUpdater(self.state)
        self.jobs = Jobs(self.state)
        self.egress = Egress(self.state, self.runner, self.native.tun)
        from .integration import Integration
        self.integration = Integration(self.state, self.runner, self.native.tun)
        self.devices = Devices(self.state, self.ts)
        self.lan_access = LanAccess(self.state, self.runner, self.ts, self.native.tun)
        self.plans = {}
        self.plans_lock = threading.RLock()
        self.audit_lock = threading.Lock()
        self.health_lock = threading.Lock()
        self.health_cached = None
        self.health_at = 0
        self.audit = self.state / "audit.jsonl"

    def maintain_policies(self):
        """For clean installs, restore configured policy defaults after native events.

        Existing owner-specific policy scripts keep full ownership when adopted.
        """
        if not self.config.get("managed_policy_sync") or not self.jobs.lock.acquire(
            False
        ):
            return
        try:
            with operation_lock(self.state):
                snap = self.ts.snapshot(True)
                if snap["backend_state"] == "Running" and snap["online"]:
                    self.integration.sync(snap)
                    self.native.sync_policies(
                        self.native.linked_policies(),
                        bool(snap["prefs"].get("ExitNodeID")),
                    )
        finally:
            self.jobs.lock.release()

    def maintain_egress(self):
        if self.egress.current()["target"] == "system" or not self.jobs.lock.acquire(
            False
        ):
            return
        try:
            with operation_lock(self.state):
                self.egress.sync()
        finally:
            self.jobs.lock.release()

    def maintain_lan_access(self):
        if not self.lan_access.needs_recovery() or not self.jobs.lock.acquire(False):
            return
        try:
            with operation_lock(self.state):
                self.lan_access.recover()
        finally:
            self.jobs.lock.release()

    def event(self, event, details=None):
        with self.audit_lock:
            if self.audit.exists() and self.audit.stat().st_size > 512 * 1024:
                self.audit.replace(self.state / "audit.previous.jsonl")
            fd = os.open(self.audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                os.chmod(self.audit, 0o600)
                f.write(json.dumps({"at": int(time.time()), "event": event,
                                   "details": details or {}}, ensure_ascii=False) + "\n")

    def health(self):
        from .health import inspect
        with self.health_lock:
            if self.health_cached is None or time.monotonic() - self.health_at > 5:
                self.health_cached = inspect(self)
                self.health_at = time.monotonic()
            return self.health_cached

    def prune_plans(self):
        with self.plans_lock:
            for key, item in list(self.plans.items()):
                if item["expires"] <= time.time():
                    item.get("params", {}).pop("auth_key", None)
                    self.plans.pop(key, None)

    def remember_plan(self, ident, record):
        with self.plans_lock:
            self.prune_plans()
            if len(self.plans) >= 32:
                raise Error("Слишком много ожидающих изменений. Закройте лишние окна или подождите три минуты.", 429)
            self.plans[ident] = record

    def cancel_plan(self, ident):
        if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise Error("Неверный предварительный просмотр")
        with self.plans_lock:
            item = self.plans.pop(ident, None)
            if item:
                item.get("params", {}).pop("auth_key", None)
        return {"ok": True}

    def dashboard(self):
        try:
            s = self.ts.snapshot()
        except Error as e:
            s = {
                "backend_state": "Unavailable",
                "online": False,
                "health": [str(e)],
                "peers": [],
                "prefs": {},
                "self": {},
                "version": "",
                "exit_advertised": False,
                "auth_url": "",
            }
        lan_policy = self.lan_access.current()
        return {
            "panel_version": VERSION,
            "tailscale": s,
            "devices": self.devices.list(s),
            "lan_access": lan_policy,
            "lan_access_revision": self.policy_revision(lan_policy),
            "jobs": self.jobs.list()[:8],
            "metrics": self.metrics(s),
            "system": {
                "architecture": platform.machine(),
                "kernel": platform.release(),
                "uptime": self.uptime(),
            },
            "config": {
                "tun": self.native.tun,
                "port": self.config.get("port", 8092),
                "auth_source": "Отдельная учётная запись панели",
            },
        }

    def uptime(self):
        try:
            return int(float(pathlib.Path("/proc/uptime").read_text().split()[0]))
        except Exception:
            return 0

    def metrics(self, snapshot):
        result = {}
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,16}", self.native.tun):
            for key in ["rx_bytes", "tx_bytes"]:
                try:
                    result[key] = int(
                        (
                            pathlib.Path("/sys/class/net")
                            / self.native.tun
                            / "statistics"
                            / key
                        ).read_text()
                    )
                except (OSError, ValueError):
                    pass
        if len(result) != 2:
            result = {
                "rx_bytes": sum(int(x.get("RxBytes") or 0) for x in snapshot["peers"]),
                "tx_bytes": sum(int(x.get("TxBytes") or 0) for x in snapshot["peers"]),
            }
        return result

    @staticmethod
    def policy_revision(policy):
        return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()

    def check_lan_settings(self, fields):
        if self.lan_access.current()["mode"] != "off" and (
            fields.get("accept_routes") is False or fields.get("exit_node")
        ):
            raise Error("Сначала отключите политику доступа из LAN", 409)

    def plan(self, action, params, lan_revision=None):
        if not isinstance(params, dict):
            raise Error("Параметры должны быть объектом")
        if self.panel_updater.active():
            raise Error("Панель обновляется. Дождитесь завершения и войдите снова.", 409)
        self.prune_plans()
        if action == "update_panel":
            if params:
                raise Error("Это действие не принимает параметров")
            info = self.panel_updater.check(True)
            if not info["available"]:
                raise Error("Установлена актуальная версия панели")
            pid = secrets.token_hex(16)
            transaction = secrets.token_hex(12)
            self.remember_plan(pid, {"action": action, "params": {"version": info["latest"]}, "transaction": transaction, "expires": time.time() + 180})
            return {"id": pid, "transaction": transaction, "version": info["latest"], "action": action, "changes": [{"name": "TailScaleKeen", "before": VERSION, "after": info["latest"]}],
                    "commands": [], "message": "Код панели будет загружен из официального репозитория проекта и проверен. Панель перезапустится; войдите снова. Клиент Tailscale и его настройки сохранятся.", "expires_in": 180}
        changes = []
        commands = []
        message = ""
        native_revision = None
        egress_revision = None
        saved_policy = None
        s = self.ts.snapshot(True)
        revision = hashlib.sha256(json.dumps(s["prefs"], sort_keys=True).encode()).hexdigest()
        if action == "lan_access":
            existing = self.lan_access.current()
            if lan_revision is not None and lan_revision != self.policy_revision(existing):
                raise Error("Правила доступа изменились после открытия страницы. Обновите список и проверьте свой выбор.", 409)
            wanted = self.lan_access.plan(params, s)
            saved_policy = existing
            modes = {"off": "Выключено", "selected": "По устройствам", "all": "Все устройства выбранных сегментов"}
            changes = [
                {"name": "Доступ из LAN", "before": modes[existing["mode"]], "after": modes[wanted["mode"]]},
                {"name": "Сегменты LAN",
                 "before": self.lan_access.bridges(existing) if existing["mode"] != "off" else [],
                 "after": self.lan_access.bridges(wanted) if wanted["mode"] != "off" else []},
                {"name": "Подсети", "before": existing["subnets"], "after": wanted["subnets"]},
            ]
            if "bridges" in wanted and "bridges" not in existing:
                changes.append({"name": "Через Tailscale из остальных сегментов",
                                "before": "По системным правилам", "after": "Закрыто к указанным подсетям"})
            previous_grants = self.lan_access.grants(existing)
            grants = self.lan_access.grants(wanted)
            changes.extend({"name": device, "before": previous_grants.get(device, []),
                            "after": grants.get(device, [])}
                           for device in sorted(previous_grants.keys() | grants.keys()))
            changes = [change for change in changes if change["before"] != change["after"]]
            message = "Проверьте выбранные сегменты и разрешённые подсети."
        elif action == "settings":
            self.check_lan_settings(params)
            args, changes = self.ts.set_args(params, s)
            commands = [["tailscale", "set", *args]] if args else []
            message = (
                "Изменятся только выбранные параметры. Остальные настройки сохранятся."
            )
            if params.get("advertise_exit"):
                message = "Роутер объявит себя выходным узлом. Затем разрешите Exit node в консоли Tailscale/Headscale."
        elif action == "egress":
            result = self.egress.plan(params)
            commands, changes, message = (
                result["commands"],
                result["changes"],
                result["message"],
            )
            egress_revision = result["revision"]
        elif action == "native_create":
            p = self.native.creation_plan(params)
            commands = p["commands"]
            changes = p["changes"]
            message = p["message"]
            native_revision = p.get("native_revision")
        elif action == "connect":
            if set(params) - {"server", "hostname", "auth_key"}:
                raise Error("Неизвестный параметр подключения")
            server = validate_server(
                params.get("server", "https://controlplane.tailscale.com")
            )
            name = params.get("hostname", s["prefs"].get("Hostname") or "keenetic")
            if not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", name
            ):
                raise Error("Неверное имя узла")
            key = params.get("auth_key", "")
            if (
                not isinstance(key, str)
                or len(key) > 2048
                or any(c in key for c in "\r\n\x00")
            ):
                raise Error("Неверный ключ регистрации")
            changes = [
                {
                    "name": "Сервер управления",
                    "before": s["prefs"].get("ControlURL"),
                    "after": server,
                },
                {
                    "name": "Имя узла",
                    "before": s["prefs"].get("Hostname"),
                    "after": name,
                },
            ]
            if server.rstrip("/") != (s["prefs"].get("ControlURL") or "").rstrip(
                "/"
            ) and s["prefs"].get("ExitNodeID"):
                changes.append(
                    {
                        "name": "Exit node прежней сети",
                        "before": s["prefs"]["ExitNodeID"],
                        "after": "Отключён при смене сети",
                    }
                )
            commands = [
                [
                    "tailscale",
                    "login",
                    "--login-server=" + server,
                    "--hostname=" + name,
                    "--auth-key=file:[protected]" if key else "(вход через браузер)",
                ]
            ]
            message = "Создаётся вход в выбранную сеть. При смене сервера существующий доступ по Tailscale может прерваться."
        elif action in ["disconnect", "resume", "restart", "logout", "update_client"]:
            if params:
                raise Error("Это действие не принимает параметров")
            text = {
                "disconnect": "Временно отключить Tailscale, сохранив ключи и настройки",
                "resume": "Возобновить подключение с существующими настройками",
                "restart": "Перезапустить клиент без удаления устройства",
                "logout": "Выйти из сети. Для следующего подключения потребуется вход",
                "update_client": "Установить последний стабильный клиент с проверкой SHA256 и сохранением идентичности",
            }
            message = text[action]
            changes = [
                {"name": "Действие", "before": s["backend_state"], "after": message}
            ]
        elif action == "restore":
            if set(params) != {"backup"}:
                raise Error("Выберите резервную копию")
            backup = self.get_backup(params["backup"])
            self.check_lan_settings(backup["settings"])
            _, changes = self.ts.set_args(backup["settings"], s)
            message = "Будут восстановлены только настройки клиента, без замены ключей устройства."
        else:
            raise Error("Неизвестное действие")
        pid = secrets.token_hex(16)
        self.remember_plan(pid, {
            "action": action,
            "params": copy.deepcopy(params),
            "revision": revision,
            "native_revision": native_revision,
            "egress_revision": egress_revision,
            "lan_revision": saved_policy,
            "expires": time.time() + 180,
        })
        return {
            "id": pid,
            "action": action,
            "changes": changes,
            "commands": commands,
            "message": message,
            "expires_in": 180,
        }

    def apply(self, pid):
        if not isinstance(pid, str) or not re.fullmatch(r"[a-f0-9]{32}", pid):
            raise Error("Не найден предварительный просмотр", 404)
        with self.plans_lock:
            plan = self.plans.pop(pid, None)
        if not plan or plan["expires"] < time.time():
            raise Error(
                "Предварительный просмотр истёк. Проверьте изменения ещё раз.", 409
            )
        if self.panel_updater.active():
            raise Error("Обновление панели уже выполняется", 409)
        if plan["action"] != "update_panel" and self.ts.revision() != plan["revision"]:
            raise Error(
                "Настройки изменились после просмотра. Сформируйте новый план.", 409
            )
        action = plan["action"]
        params = plan["params"]
        if action == "egress" and self.egress.plan(params)["revision"] != plan.get(
            "egress_revision"
        ):
            raise Error("Выход изменился после предпросмотра", 409)
        if action == "native_create" and plan.get("native_revision"):
            from .native import normalize

            if (
                hashlib.sha256(
                    normalize(self.native.cli("show running-config")).encode()
                ).hexdigest()
                != plan["native_revision"]
            ):
                raise Error("Настройки роутера изменились после просмотра", 409)

        def work(log):
            # Jobs owns operation_lock here: recheck after acquiring it, not just
            # in the HTTP thread before the worker was scheduled.
            if action != "update_panel" and self.ts.revision() != plan["revision"]:
                raise Error("Настройки изменились перед выполнением. Сформируйте новый план.", 409)
            if action == "egress" and self.egress.plan(params)["revision"] != plan.get("egress_revision"):
                raise Error("Выход изменился перед выполнением. Сформируйте новый план.", 409)
            if action == "native_create" and plan.get("native_revision"):
                from .native import normalize
                if hashlib.sha256(normalize(self.native.cli("show running-config")).encode()).hexdigest() != plan["native_revision"]:
                    raise Error("Настройки роутера изменились перед выполнением. Сформируйте новый план.", 409)
            self.event("action_started", {"action": action})
            policies = self.native.linked_policies() if action in {"settings", "restore", "restart"} else []
            if action == "update_panel":
                result = self.panel_updater.prepare(log, params["version"], plan["transaction"])
            elif action == "lan_access":
                if self.lan_access.current() != plan.get("lan_revision"):
                    raise Error("Список доступа изменился. Обновите предпросмотр.", 409)
                result = self.lan_access.change(params, log)
            elif action == "settings":
                self.check_lan_settings(params)
                result = self.ts.apply_settings(params, log)
                self.native.sync_policies(
                    policies, bool(result["snapshot"]["prefs"].get("ExitNodeID"))
                )
            elif action == "native_create":
                result = self.native.create(params, log)
            elif action == "egress":
                result = self.egress.apply(params, log)
            elif action == "connect":
                result = self.connect(params, log)
            elif action == "disconnect":
                self.ts.run("down", timeout=35)
                self.ts.invalidate()
                result = {"message": "Клиент отключён, настройки сохранены"}
            elif action == "resume":
                result = self.local_patch({"WantRunning": True})
                self.ts.invalidate()
            elif action == "restart":
                self.runner.run(
                    ["/opt/etc/init.d/S06tailscaled", "restart"], timeout=100
                )
                self.ts.invalidate()
                snap = self.updater.wait_ready({"backend_state": "Running"})
                self.native.sync_policies(
                    policies, bool(snap["prefs"].get("ExitNodeID"))
                )
                result = {"message": "Клиент перезапущен"}
            elif action == "logout":
                self.ts.run("logout", timeout=35)
                self.ts.invalidate()
                result = {"message": "Выполнен выход из сети"}
            elif action == "update_client":
                result = self.updater.update(log)
            elif action == "restore":
                settings = self.get_backup(params["backup"])["settings"]
                self.check_lan_settings(settings)
                result = self.ts.apply_settings(settings, log)
                self.native.sync_policies(
                    policies, bool(result["snapshot"]["prefs"].get("ExitNodeID"))
                )
            else:
                raise Error("Недопустимое действие")
            self.ts.invalidate()
            self.event("action_done", {"action": action})
            return result

        return self.jobs.start(
            {
                "settings": "Настройки клиента",
                "egress": "Выход для клиентов Exit node",
                "lan_access": "Доступ локальных устройств",
                "native_create": "Подключение Keenetic",
                "connect": "Подключение к сети",
                "disconnect": "Отключение клиента",
                "resume": "Возобновление",
                "restart": "Перезапуск",
                "logout": "Выход из сети",
                "update_client": "Обновление клиента",
                "update_panel": "Обновление TailScaleKeen",
                "restore": "Восстановление настроек",
            }[action],
            work,
            **({"job_id": plan["transaction"], "update_version": params["version"]} if action == "update_panel" else {}),
        )

    def local_patch(self, fields):
        import http.client, socket

        path = next(
            (
                p
                for p in [
                    "/var/run/tailscale/tailscaled.sock",
                    "/opt/var/run/tailscale/tailscaled.sock",
                ]
                if pathlib.Path(p).exists()
            ),
            None,
        )
        if not path:
            raise Error("Сокет клиента не найден", 503)

        class UnixHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(15)
                self.sock.connect(path)

        c = UnixHTTP("local-tailscaled.sock")
        try:
            body = json.dumps({**fields, **{k + "Set": True for k in fields}})
            c.request(
                "PATCH",
                "/localapi/v0/prefs",
                body,
                {"Content-Type": "application/json"},
            )
            r = c.getresponse()
            r.read()
            if r.status != 200:
                raise Error("Клиент отклонил возобновление", 502)
        finally:
            c.close()
        return {"message": "Подключение возобновлено"}

    def connect(self, params, log):
        snap = self.ts.snapshot(True)
        p = snap["prefs"]
        server = validate_server(
            params.get("server", "https://controlplane.tailscale.com")
        )
        same_server = server.rstrip("/") == (p.get("ControlURL") or "").rstrip("/")
        args = [
            "login",
            "--login-server=" + server,
            "--hostname=" + params.get("hostname", "keenetic"),
            "--timeout=20s",
        ]
        # login has defaults; explicitly carry all the existing forwarding/security preferences.
        mapping = {
            "CorpDNS": "accept-dns",
            "RouteAll": "accept-routes",
            "ExitNodeAllowLANAccess": "exit-node-allow-lan-access",
            "ShieldsUp": "shields-up",
            "RunSSH": "ssh",
        }
        for key, flag in mapping.items():
            value = bool(p.get(key))
            if key == "ExitNodeAllowLANAccess" and not same_server:
                value = False
            args.append("--" + flag + "=" + str(value).lower())
        args += [
            "--netfilter-mode="
            + {0: "off", 1: "nodivert", 2: "on"}.get(p.get("NetfilterMode"), "on"),
            "--snat-subnet-routes=" + str(not bool(p.get("NoSNAT"))).lower(),
            "--stateful-filtering="
            + str(not bool(p.get("NoStatefulFiltering"))).lower(),
        ]
        routes = p.get("AdvertiseRoutes") or []
        args.append("--advertise-exit-node=" + str(snap["exit_advertised"]).lower())
        args.append(
            "--advertise-routes="
            + ",".join(x for x in routes if x not in ["0.0.0.0/0", "::/0"])
        )
        old_exit = next(
            (n for n in snap["peers"] if n["ID"] == p.get("ExitNodeID")), None
        )
        if not same_server:
            args.append("--exit-node=")
        elif old_exit:
            args.append("--exit-node=" + old_exit["TailscaleIPs"][0])
        if p.get("AdvertiseTags"):
            args.append("--advertise-tags=" + ",".join(p["AdvertiseTags"]))
        tmp = None
        try:
            if params.get("auth_key"):
                tmp = self.state / (".auth-" + secrets.token_hex(10))
                fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w") as secret:
                    secret.write(params["auth_key"])
                args.append("--auth-key=file:" + str(tmp))
            log("Ожидание регистрации устройства")
            q = self.ts.run(*args, timeout=30, check=False)
            if params.get("auth_key"):
                q.stdout = q.stdout.replace(params["auth_key"], "[hidden]")
                q.stderr = q.stderr.replace(params["auth_key"], "[hidden]")
            self.ts.invalidate()
            s = self.ts.snapshot(True)
            active_server = (s["prefs"].get("ControlURL") or "").rstrip("/")
            if q.returncode == 0 and s["backend_state"] == "Running" and active_server == server:
                return {"message": "Устройство подключено"}
            url = s.get("auth_url") or next(
                iter(re.findall(r"(?m)^[ \t]*(https://[^\s]+)[ \t]*$", q.stdout + "\n" + q.stderr)), ""
            )
            if url:
                return {
                    "message": "Откройте ссылку для подтверждения входа",
                    "auth_url": url,
                    "needs_login": True,
                }
            raise Error(scrub(q.stderr or "Клиент пока не подтвердил подключение к выбранному серверу"), 502)
        finally:
            params.pop("auth_key", None)
            if tmp:
                tmp.unlink(missing_ok=True)

    def diagnostics(self, kind, target=""):
        if kind == "netcheck":
            args = ["/opt/bin/tailscale", "netcheck"]
            timeout = 40
        elif kind in ["ping", "tsmp"]:
            allowed = {
                ip
                for p in self.ts.snapshot(True)["peers"]
                for ip in (p["TailscaleIPs"] or [])
            }
            if not isinstance(target, str) or target not in allowed:
                raise Error("Выберите известный узел сети")
            args = [
                "/opt/bin/tailscale",
                "ping",
                "--c=3",
                "--timeout=5s",
                "--until-direct=false",
                target,
            ]
            if kind == "tsmp":
                args.insert(2, "--tsmp")
            timeout = 25
        elif kind == "routes":
            args = ["ip", "-4", "rule", "show"]
            timeout = 10
        elif kind == "exit":
            args = [
                "curl",
                "-q",
                "--noproxy",
                "*",
                "--interface",
                self.native.tun,
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "-sS",
                "-o",
                "/dev/null",
                "-w",
                "HTTP %{http_code}; %{time_total} s",
                "https://www.google.com/generate_204",
            ]
            timeout = 20
        else:
            raise Error("Неизвестная проверка")

        def work(log):
            q = self.runner.run(args, timeout=timeout, check=False)
            text = scrub(q.stdout + q.stderr)
            log(text)
            return {"exit": q.returncode, "output": text}

        return self.jobs.start("Диагностика: " + kind, work)

    def backup_settings(self):
        p = self.ts.snapshot(True)["prefs"]
        settings = {
            "accept_dns": bool(p.get("CorpDNS")),
            "accept_routes": bool(p.get("RouteAll")),
            "shields_up": bool(p.get("ShieldsUp")),
            "ssh": bool(p.get("RunSSH")),
            "webclient": bool(p.get("RunWebClient")),
            "snat": not bool(p.get("NoSNAT")),
            "stateful": not bool(p.get("NoStatefulFiltering")),
            "netfilter": {0: "off", 1: "nodivert", 2: "on"}.get(
                p.get("NetfilterMode"), "on"
            ),
            "routes": [
                x
                for x in p.get("AdvertiseRoutes") or []
                if x not in ["0.0.0.0/0", "::/0"]
            ],
        }
        if p.get("Hostname"):
            settings["hostname"] = p["Hostname"]
        # Exit selection and default advertisements are restored with separate explicit controls.
        ident = secrets.token_hex(12)
        record = {
            "id": ident,
            "created_at": int(time.time()),
            "schema": 1,
            "settings": settings,
            "server": p.get("ControlURL"),
            "note": "Ключ устройства не включён; Exit node выбирается отдельно",
        }
        write_json(self.state / "backups" / (ident + ".json"), record)
        self.event("backup_created", {"id": ident})
        return record

    def backups(self):
        return [
            read_json(p)
            for p in sorted(
                (self.state / "backups").glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if re.fullmatch(r"[a-f0-9]{24}\.json", p.name)
        ]

    def get_backup(self, ident):
        if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{24}", ident):
            raise Error("Копия не найдена", 404)
        x = read_json(self.state / "backups" / (ident + ".json"))
        if not x or x.get("schema") != 1:
            raise Error("Копия не найдена", 404)
        return x

    def logs(self, kind):
        choices = {
            "panel": [self.audit, self.state / "audit.previous.jsonl"],
            "client": [
                pathlib.Path("/opt/var/log/tailscaled.log"),
                pathlib.Path("/opt/var/lib/tailscale/tailscaled.log1.txt"),
                pathlib.Path("/opt/var/tailscale/tailscaled.log1.txt"),
            ],
        }
        if kind not in choices:
            raise Error("Неизвестный журнал")
        found = []
        for p in choices[kind]:
            if p.is_file():
                with p.open("rb") as f:
                    f.seek(max(0, p.stat().st_size - 60000))
                    text = f.read(60000).decode(errors="replace")
                found.append({"name": p.name, "text": scrub(text)})
        return found or [
            {
                "name": kind,
                "text": "Записей пока нет. Для проверки соединения откройте диагностику.",
            }
        ]
