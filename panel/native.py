"""Narrow Keenetic OpkgTun operations. Existing interfaces are adopted read-only."""

import hashlib, json, pathlib, re, urllib.request
from .core import Error, Runner, read_json, write_json


def normalize(text):
    return "\n".join(
        x.rstrip()
        for x in re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).splitlines()
        if x.strip() and not x.lstrip().startswith(("!", "#"))
    )


def blocks(text):
    result = {}
    name = None
    for line in text.splitlines():
        if line.startswith("interface "):
            name = line.split()[1]
            result[name] = [line]
        elif name and (line.startswith(" ") or line.strip() == "!"):
            result[name].append(line)
        else:
            name = None
    return {k: "\n".join(v) for k, v in result.items()}


class Native:
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
        return self.runner.run(["ndmc", "-c", command], timeout=20, check=check).stdout

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
                "description": next(
                    iter(re.findall(r"^\s+description\s+(.+)", b, re.M)), "Tailscale"
                ),
                "connected": bool(re.search(r"connected:\s+yes", info)),
                "global": bool(re.search(r"\bip global\b", b)),
                "mtu": next(iter(re.findall(r"ip mtu (\d+)", b)), "1280"),
                "config": b,
                "managed": read_json(self.state / "integration.json").get(
                    "created", False
                ),
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
        status = self.status()
        if not status["available"]:
            raise Error("Keenetic CLI недоступен")
        if status["exists"]:
            return {
                "commands": [],
                "changes": [],
                "message": "Подключение "
                + self.name
                + " уже существует; его настройки сохранены",
                "noop": True,
            }
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
        running = self.cli("show running-config")
        startup = self.cli("more startup-config")
        if fields.get("save", True) and normalize(running) != normalize(startup):
            raise Error(
                "В роутере есть другие несохранённые изменения. Сохраните их в родной панели и повторите.",
                409,
            )
        commands = [
            "interface " + self.name,
            "interface " + self.name + ' description "' + description + '"',
            "interface " + self.name + " security-level public",
            "interface " + self.name + " ip mtu " + str(mtu),
            "interface " + self.name + " ip tcp adjust-mss pmtu",
        ]
        if fields.get("global", True):
            commands.append("interface " + self.name + " ip global auto")
        commands.append("interface " + self.name + " up")
        if fields.get("save", True):
            commands.append("system configuration save")
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
            "noop": False,
            "message": "Подключение появится в списке соединений. Устройства назначаются ему в политиках подключений Keenetic.",
        }

    def create(self, fields, log):
        plan = self.creation_plan(fields)
        if plan["noop"]:
            return plan
        running = self.cli("show running-config")
        write_json(
            self.state / "backups/native-before-create.json",
            {
                "running": running,
                "startup": self.cli("more startup-config"),
                "interface": self.name,
            },
        )
        created = False
        try:
            for command in plan["commands"]:
                log("Настройка " + self.name)
                out = self.cli(command)
                if re.search(
                    r"(?:error\[|command failed|no such command|invalid command)",
                    out,
                    re.I,
                ):
                    raise Error("Keenetic отклонил команду: " + command)
                created = True
            if self.name not in blocks(self.cli("show running-config")):
                raise Error("Подключение не появилось после создания")
            write_json(
                self.state / "integration.json",
                {
                    "name": self.name,
                    "tun": self.tun,
                    "created": True,
                    "description": fields.get("description", "Tailscale"),
                },
            )
            return self.status()
        except Exception:
            if created and self.name in blocks(self.cli("show running-config")):
                self.cli("no interface " + self.name, False)
            raise

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
