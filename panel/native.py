"""Narrow Keenetic OpkgTun operations. Existing interfaces are adopted read-only."""

import hashlib, json, pathlib, re, time, urllib.request
from .core import Error, Runner, read_json, write_json

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CLI_ERROR = re.compile(r"^\s*(?:(?:[\w:.-]+\s+)?error\[|command failed\b|(?:no such|invalid) command\b)", re.I | re.M)


def normalize(text):
    return "\n".join(
        x.rstrip()
        for x in ANSI.sub("", text).splitlines()
        if x.strip() and not x.lstrip().startswith(("!", "#"))
    )


def blocks(text):
    result = {}
    name = None
    for line in ANSI.sub("", text).splitlines():
        if line.startswith("interface "):
            name = line.split()[1]
            result[name] = [line]
        elif name and (line.startswith(" ") or line.strip() == "!"):
            result[name].append(line)
        else:
            name = None
    return {k: "\n".join(v) for k, v in result.items()}


def without_interface(config, name):
    """Compare every other setting before a global Keenetic configuration save."""
    result = []
    skip = False
    for line in normalize(config).splitlines():
        if not line[0].isspace():
            skip = line == "interface " + name
        if not skip:
            result.append(line)
    return "\n".join(result)


def unchanged_outside_interface(before, after, name, allow_policy_denies=False):
    original = without_interface(before, name)
    current = without_interface(after, name)
    if original == current:
        return True
    if not allow_policy_denies:
        return False
    # Keenetic appends an explicit deny for a newly global interface to each
    # pre-existing policy that does not use it. Only that exact addition is OK.
    header = re.compile(r"ip policy [\w-]+", re.ASCII)
    deny = "    no permit global " + name
    policies = set()
    existing_denies = set()
    section = ""
    for line in original.splitlines():
        if not line[0].isspace():
            section = line
            if header.fullmatch(section):
                policies.add(section)
        elif line == deny:
            existing_denies.add(section)
    allowed = policies - existing_denies
    retained = []
    section = ""
    for line in current.splitlines():
        if not line[0].isspace():
            section = line
        elif line == deny and section in allowed:
            allowed.remove(section)
            continue
        retained.append(line)
    return retained == original.splitlines()


class Native:
    init = "/opt/etc/init.d/S06tailscaled"

    def __init__(self, state, runner=None, tun="opkgtun0"):
        self.state = pathlib.Path(state)
        self.runner = runner or Runner()
        self.tun = tun

    @property
    def name(self):
        if not re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", self.tun):
            raise Error("Для интеграции нужен интерфейс OpkgTun0…OpkgTun15")
        return "OpkgTun" + self.tun[7:]

    def cli(self, command, check=True):
        result = self.runner.run(["ndmc", "-c", command], timeout=20, check=False)
        output = ANSI.sub("", result.stdout)
        if check and (result.returncode or CLI_ERROR.search(output + "\n" + (result.stderr or ""))):
            raise Error("Keenetic отклонил команду: " + command, 502)
        if command in ("show running-config", "more startup-config") and not normalize(output):
            raise Error("Keenetic вернул пустую конфигурацию: " + command, 502)
        return output

    def status(self):
        try:
            name = self.name
            running = self.cli("show running-config")
            b = blocks(running).get(name, "")
            info = self.cli("show interface " + name, False)
            return {
                "available": True,
                "name": name,
                "tun": self.tun,
                "exists": bool(b),
                "priority_available": not b and self._priority_available(running),
                "description": next(
                    iter(re.findall(r"^\s+description\s+(.+)", b, re.M)), "Tailscale"
                ),
                "connected": bool(re.search(r"connected:\s+yes", info)),
                "global": bool(re.search(r"\bip global\b", b)),
                "mtu": next(iter(re.findall(r"ip mtu (\d+)", b)), "1280"),
                "config": b,
                "managed": bool(b and self._ownership().get("created")),
                "policies": self.linked_policies(),
            }
        except Error as e:
            return {
                "available": False,
                "error": str(e),
                "name": "OpkgTun",
                "exists": False,
                "policies": [],
            }

    def _ownership(self):
        record = read_json(self.state / "integration.json")
        return record if record.get("name") == self.name and record.get("tun") == self.tun else {}

    def _priority_available(self, running):
        public_uplink = False
        for name, stanza in blocks(running).items():
            if name == self.name:
                continue
            global_line = re.search(r"^\s+ip global(?:[ \t]+([^\r\n]*))?$", stanza, re.M)
            if not global_line:
                continue
            priority = (global_line.group(1) or "").strip()
            if not priority.isdigit() or not 1 < int(priority) <= 65534:
                return False
            if not name.startswith("OpkgTun") and re.search(r"^\s+security-level public\s*$", stanza, re.M):
                public_uplink = True
        if not public_uplink:
            return False
        routes = self.runner.run(["ip", "-4", "route", "show", "table", "main", "default"], check=False)
        devices = re.findall(r"^default\b[^\n]*?\bdev\s+([^\s]+)", routes.stdout, re.M)
        return routes.returncode == 0 and bool(devices) and all(not dev.startswith("opkgtun") for dev in devices)

    def default_fields(self):
        running = self.cli("show running-config")
        return {"description": "Tailscale", "save": True,
                "global": self.name not in blocks(running) and self._priority_available(running)}

    def _main_defaults(self):
        # Lifetimes and cache counters can change during a TUN handoff; only
        # compare the interfaces, next hops and metrics of actual defaults.
        routes = set()
        for family in ("-4", "-6"):
            result = self.runner.run(["ip", family, "route", "show", "table", "main", "default"], check=False)
            if result.returncode:
                if family == "-4":
                    raise Error("Не удалось проверить основной маршрут интернета", 502)
                routes.add((family, "unavailable"))
                continue
            for line in result.stdout.splitlines():
                fields = line.split()
                if fields and fields[0] == "default":
                    routes.add((family,) + tuple((key, fields[idx + 1]) for idx, key in enumerate(fields[:-1])
                                                if key in {"dev", "via", "metric", "nexthop"}))
        return routes

    def _linux_tun_exists(self):
        return pathlib.Path("/sys/class/net", self.tun).exists()

    def _running_tun(self):
        from .install import running_tun
        return running_tun()

    def _handoff_required(self):
        if not self._linux_tun_exists():
            return False
        if self._running_tun() != self.tun:
            raise Error("Linux-интерфейс " + self.tun + " занят. Принадлежность службе Tailscale не подтверждена.", 409)
        return True

    def _client_status(self):
        result = self.runner.run(["/opt/bin/tailscale", "status", "--json"], timeout=5, check=False)
        try:
            status = json.loads(result.stdout)
            state = status["BackendState"]
            if state not in {"Running", "NeedsLogin", "NeedsMachineAuth", "Stopped"}:
                raise ValueError()
            own = status.get("Self") or {}
            return state, own.get("ID"), bool(own.get("Online"))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise Error("Tailscale не подтвердил состояние клиента", 503)

    def _start_client(self, before, log):
        active = self._running_tun()
        if active not in (None, self.tun):
            raise Error("Служба Tailscale теперь использует другое устройство", 409)
        if active is None:
            log("Возобновление службы Tailscale")
            self.runner.run([self.init, "start"], timeout=65)
        until = time.monotonic() + 65
        while True:
            try:
                state, identity, online = self._client_status()
                if (state == before[0] and (not before[1] or identity == before[1])
                        and (not before[2] or online) and self._running_tun() == self.tun):
                    return
            except Error:
                pass
            if time.monotonic() >= until:
                raise Error("После запуска Tailscale не подтвердил прежнее состояние и узел", 503)
            time.sleep(1)

    def _confirm_name_free(self):
        result = self.runner.run(["ndmc", "-c", "show interface " + self.name], timeout=20, check=False)
        output = ANSI.sub("", result.stdout + "\n" + (result.stderr or ""))
        if result.returncode in (0, 123) and re.search(
            r"(?:error\[7405602\]: argument parse error|(?:no such|unknown) interface)", output, re.I
        ):
            return
        if re.search(r"^\s*(?:id|interface-name):\s*" + re.escape(self.name) + r"\s*$", output, re.M):
            raise Error("Имя уже занято интерфейсом Keenetic вне running-config: " + self.name, 409)
        raise Error("Keenetic не подтвердил доступность имени " + self.name, 502)

    def linked_policies(self):
        try:
            # A policy remains linked while no exit node is selected, even though
            # its runtime default route has disappeared from the RCI response.
            configured = set()
            current = None
            for line in self.cli("show running-config").splitlines():
                match = re.fullmatch(r"ip policy ([A-Za-z0-9_-]{1,32})", line)
                if match:
                    current = match[1]
                elif line and not line.startswith(" ") and line.strip() != "!":
                    current = None
                elif current and line.strip() == "permit global " + self.name:
                    configured.add(current)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            data = json.loads(
                opener.open("http://127.0.0.1:79/rci/show/ip/policy", timeout=3).read()
            )
            result = []
            for key, v in data.items():
                if not isinstance(v, dict):
                    continue
                route = v.get("route4", {}).get("route", [])
                if key in configured or any(
                    x.get("interface") == self.name for x in route
                ):
                    result.append(
                        {
                            "id": key,
                            "name": v.get("description", key),
                            "table": v.get("table4"),
                            "metric": next(
                                (
                                    x.get("metric", 1000)
                                    for x in route
                                    if x.get("interface") == self.name
                                    and x.get("destination") == "0.0.0.0/0"
                                ),
                                1000,
                            ),
                        }
                    )
            return result
        except Exception:
            return []

    def creation_plan(self, fields):
        if set(fields) - {"description", "mtu", "global", "save"}:
            raise Error("Неизвестный параметр подключения")
        running = self.cli("show running-config")
        existing = blocks(running).get(self.name)
        pending = self._ownership().get("pending") if existing else None
        if existing and not pending:
            return {
                "commands": [],
                "changes": [],
                "message": "Подключение "
                + self.name
                + " уже существует; его настройки сохранены",
                "noop": True,
            }
        if not existing:
            self._confirm_name_free()
        if pending:
            fields = pending
        description = fields.get("description", "Tailscale")
        mtu = fields.get("mtu", 1280)
        if not isinstance(description, str) or not re.fullmatch(
            r"[\w .()-]{1,50}", description, re.UNICODE
        ):
            raise Error("Недопустимое имя подключения")
        if type(mtu) is not int or not 1280 <= mtu <= 1500:
            raise Error("MTU должен быть в диапазоне 1280–1500")
        for key in ["global", "save"]:
            if key in fields and type(fields[key]) is not bool:
                raise Error("Неверный переключатель " + key)
        startup = self.cli("more startup-config")
        if not existing and self.name in blocks(startup):
            raise Error("В сохранённой конфигурации это имя уже занято: " + self.name, 409)
        if fields.get("save", True) and not unchanged_outside_interface(
            startup, running, self.name, allow_policy_denies=bool(pending and fields.get("global"))
        ):
            raise Error(
                "В роутере есть другие несохранённые изменения. Сохраните их в родной панели и повторите.",
                409,
            )
        priority_available = self._priority_available(running)
        use_priority = fields.get("global", priority_available)
        if use_priority and not priority_available:
            raise Error("Нельзя безопасно добавить подключение последним в приоритеты. Создайте его без этой опции.", 409)
        settings = {
            "description": description, "mtu": mtu,
            "global": use_priority, "save": fields.get("save", True),
        }
        suffixes = self._missing_settings(existing or "", settings, recovering=bool(existing))
        command = "interface " + self.name
        commands = [] if existing else [command]
        commands.extend(command + " " + suffix for suffix in suffixes)
        saved = blocks(startup).get(self.name, "")
        if settings["save"] and (not existing or suffixes or normalize(existing) != normalize(saved)):
            commands.append("system configuration save")
        handoff = not existing and self._handoff_required()
        return {
            "commands": commands,
            "changes": [
                {
                    "name": "Подключение Keenetic",
                    "before": "Отсутствует",
                    "after": self.name + " / " + description,
                }
            ],
            "native_revision": hashlib.sha256(normalize(running).encode()).hexdigest(),
            "settings": settings,
            "handoff": handoff,
            "noop": False,
            "message": ("Tailscale кратковременно отключится на время регистрации занятого TUN. " if handoff else "")
            + ("Подключение появится в «Приоритетах подключений» с низшим приоритетом 1."
               if use_priority else "Подключение будет зарегистрировано без участия в приоритетах интернета."),
        }

    def _missing_settings(self, block, settings, recovering=False):
        description = settings["description"]
        expected = [
            'description "' + description + '"', "security-level public",
            "ip mtu " + str(settings["mtu"]), "ip tcp adjust-mss pmtu",
        ]
        if settings["global"]:
            expected.append("ip global 1")
        expected.append("up")
        actual = {line.strip() for line in normalize(block).splitlines()[1:]}
        if "description " + description in actual:
            actual.discard("description " + description)
            actual.add(expected[0])
        for line in list(actual):
            if line.startswith("ip global") and (not settings["global"] or line != "ip global 1"):
                raise Error("Приоритет подключения отличается от запрошенного", 409)
        if recovering and actual.difference(expected, {"down"}):
            raise Error("Прерванное подключение изменено в Keenetic. Проверьте его настройки.", 409)
        return [line for line in expected if line not in actual]

    def create(self, fields, log):
        plan = self.creation_plan(fields)
        if plan["noop"]:
            return plan
        name = self.name
        settings = plan["settings"]
        running = self.cli("show running-config")
        if hashlib.sha256(normalize(running).encode()).hexdigest() != plan["native_revision"]:
            raise Error("Конфигурация Keenetic изменилась. Повторите создание подключения.", 409)
        startup = self.cli("more startup-config")
        new = name not in blocks(running)
        if new:
            if name in blocks(startup):
                raise Error("Сохранённое подключение изменилось. Повторите проверку.", 409)
            write_json(self.state / "backups/native-before-create.json", {
                "running": running, "startup": startup, "interface": name,
            })
        owner_path = self.state / "integration.json"
        previous_owner = read_json(owner_path)
        owner = {"name": name, "tun": self.tun, "created": True, "description": settings["description"]}
        created = False
        saving = False
        before_client = None
        client_restored = False
        start_attempted = False
        original_defaults = self._main_defaults() if settings["global"] else None
        try:
            if new and self._handoff_required():
                if not plan["handoff"]:
                    raise Error("Состояние TUN изменилось. Повторите проверку.", 409)
                before_client = self._client_status()
                log("Краткая остановка Tailscale для регистрации " + name)
                self.runner.run([self.init, "stop"], timeout=65)
                if self._running_tun() is not None or self._linux_tun_exists():
                    raise Error("Клиент не освободил Linux-интерфейс " + self.tun, 409)
            for command in plan["commands"]:
                if command == "system configuration save":
                    break
                log("Настройка " + name)
                self.cli(command)
                if new and command == "interface " + name:
                    created = True
                    write_json(owner_path, {**owner, "pending": settings})
            final = self.cli("show running-config")
            final_block = blocks(final).get(name, "")
            if not final_block or self._missing_settings(final_block, settings):
                raise Error("Keenetic не подтвердил запрошенные настройки " + name, 502)
            info = self.cli("show interface " + name)
            named = re.search(r"^\s*(?:id|interface-name):\s*" + re.escape(name) + r"\s*$", info, re.M)
            if not named or not re.search(r"^\s*type:\s*OpkgTun\s*$", info, re.M):
                raise Error("Keenetic не подтвердил регистрацию " + name + " как OpkgTun", 502)
            if before_client is not None:
                start_attempted = True
                self._start_client(before_client, log)
                client_restored = True
            if original_defaults is not None and self._main_defaults() != original_defaults:
                raise Error("После добавления подключения изменился основной маршрут интернета", 409)
            if settings["save"]:
                current_running = self.cli("show running-config")
                if (normalize(blocks(current_running).get(name, "")) != normalize(final_block)
                        or not unchanged_outside_interface(startup, current_running, name, settings["global"])
                        or normalize(self.cli("more startup-config")) != normalize(startup)):
                    raise Error("Есть другие несохранённые изменения Keenetic. Сохранение остановлено.", 409)
                if normalize(final_block) != normalize(blocks(startup).get(name, "")):
                    # Even if the CLI response is lost, save may have taken effect.
                    # Leave the verified interface and its ownership record for the retry.
                    saving = True
                    self.cli("system configuration save")
                    for delay in (0, 0.3, 0.7, 1, 2, 3):
                        if delay:
                            time.sleep(delay)
                        if normalize(blocks(self.cli("more startup-config")).get(name, "")) == normalize(final_block):
                            break
                    else:
                        raise Error("Keenetic пока не подтвердил сохранение " + name + ". Повторите проверку.", 502)
            write_json(owner_path, owner)
            return self.status()
        except Exception:
            if created and not saving:
                current = blocks(self.cli("show running-config")).get(name, "")
                if current:
                    # Leave any settings added by an external administrator alone.
                    self._missing_settings(current, settings, recovering=True)
                    active_tun = self._running_tun() if self._linux_tun_exists() else None
                    if before_client is not None and active_tun is None:
                        client_restored = False
                    if active_tun and (active_tun != self.tun or not start_attempted):
                        raise Error("После создания интерфейс занял другой запуск Tailscale. Автоматический откат остановлен.", 409)
                    if active_tun == self.tun:
                        client_restored = False
                        self.runner.run([self.init, "stop"], timeout=65)
                        if self._running_tun() is not None:
                            raise Error("Tailscale не остановился. Подключение сохранено для повторной проверки.", 409)
                    self.cli("no interface " + name)
                    if name in blocks(self.cli("show running-config")):
                        raise Error("Keenetic не подтвердил откат " + name, 502)
                if previous_owner:
                    write_json(owner_path, previous_owner)
                else:
                    owner_path.unlink(missing_ok=True)
            raise
        finally:
            if before_client is not None and not client_restored:
                self._start_client(before_client, log)

    def sync_policies(self, policies, has_exit):
        """Repair only defaults already associated with this tunnel before an operation."""
        for p in policies:
            table = p.get("table")
            if type(table) is not int or not 1 <= table < 2**31:
                continue
            existing = self.runner.run(
                ["ip", "-4", "route", "show", "table", str(table), "default"],
                check=False,
            ).stdout
            if has_exit:
                if existing.strip():
                    continue
                metric = p.get("metric", 1000)
                if type(metric) is not int or not 0 <= metric < 2**31:
                    metric = 1000
                self.runner.run(
                    [
                        "ip",
                        "-4",
                        "route",
                        "replace",
                        "default",
                        "dev",
                        self.tun,
                        "table",
                        str(table),
                        "metric",
                        str(metric),
                    ]
                )
            elif re.search(r"\bdev " + re.escape(self.tun) + r"\b", existing):
                self.runner.run(
                    [
                        "ip",
                        "-4",
                        "route",
                        "del",
                        "default",
                        "dev",
                        self.tun,
                        "table",
                        str(table),
                    ],
                    check=False,
                )
