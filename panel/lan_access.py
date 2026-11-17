"""Limit forwarded IPv4 access to explicitly selected tailnet subnets."""
import ipaddress
import re
import shlex
import time
from pathlib import Path

from .core import Error, read_json, write_json

HOOK = Path("/opt/etc/ndm/netfilter.d/94-tailscalekeen-lan.sh")
HOOK_TEXT = "#!/bin/sh\n/opt/bin/tailscalekeen lan-access-sync >/dev/null 2>&1\n"
PRIORITY = "67"
MGMT_PRIORITY = "66"
TABLES = {
    "mangle": ("PREROUTING", "TSKL_PRE", "TSKL_PRE_ACCESS"),
    "filter": ("FORWARD", "TSKL_FWD", "TSKL_FWD_ACCESS"),
    "nat": ("POSTROUTING", "TSKL_NAT"),
}


class LanAccess:
    def __init__(self, state, runner, tailscale, tun):
        self.path = Path(state) / "lan-access.json"
        self.runner, self.ts, self.tun = runner, tailscale, tun

    def current(self):
        return read_json(self.path, {"mode": "off", "bridge": "br0", "devices": [], "subnets": []})

    def normalize(self, fields):
        required = {"mode", "bridge", "devices", "subnets"}
        if set(fields) - {"grants"} != required:
            raise Error("Укажите режим, интерфейс LAN, устройства и подсети")
        mode = fields["mode"]
        if mode not in ("off", "selected", "all"):
            raise Error("Неизвестный режим доступа")
        if mode == "off":
            return {"mode": "off", "bridge": "br0", "devices": [], "subnets": []}
        bridge, devices, subnets = fields["bridge"], fields["devices"], fields["subnets"]
        if not isinstance(bridge, str) or not re.fullmatch(r"br[0-9]{1,3}", bridge):
            raise Error("Укажите LAN-интерфейс, например br0")
        if not isinstance(devices, list) or not isinstance(subnets, list):
            raise Error("Неверный список устройств или подсетей")
        if len(devices) > 16 or not 1 <= len(subnets) <= 64:
            raise Error("Допустимо до 16 устройств и от 1 до 64 подсетей")
        if mode == "selected" and not devices:
            raise Error("Добавьте хотя бы одно устройство с IPv4 и MAC")
        try:
            entries = []
            for row in devices if mode == "selected" else []:
                if not isinstance(row, str):
                    raise ValueError()
                addr, mac = row.split()
                mac = mac.lower().replace("-", ":")
                if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                    raise ValueError()
                entries.append(str(ipaddress.IPv4Address(addr)) + " " + mac)
            nets = {ipaddress.IPv4Network(item) for item in subnets if isinstance(item, str)}
            if not nets or any(not n.prefixlen or n.is_multicast or n.is_loopback or n.is_link_local for n in nets):
                raise ValueError()
            if not all(isinstance(item, str) for item in subnets):
                raise ValueError()
        except (ValueError, TypeError):
            raise Error("Используйте формат «IPv4 MAC» и корректные IPv4-подсети") from None
        if len({x.split()[0] for x in entries}) != len(entries):
            raise Error("Один IP-адрес должен соответствовать одному устройству")
        ordered_nets = sorted(nets)
        config = {"mode": mode, "bridge": bridge, "devices": sorted(entries),
                  "subnets": [str(n) for n in ordered_nets]}
        if mode == "selected" and "grants" in fields:
            grants = fields["grants"]
            if not isinstance(grants, dict) or set(grants) != set(entries):
                raise Error("Укажите список разрешённых подсетей для каждого устройства")
            if any(a.overlaps(b) for i, a in enumerate(ordered_nets) for b in ordered_nets[i + 1:]):
                raise Error("Для индивидуальных правил укажите непересекающиеся подсети")
            available = set(config["subnets"])
            for routes in grants.values():
                if (not isinstance(routes, list) or len(routes) > 64
                    or any(not isinstance(route, str) or route not in available for route in routes)):
                    raise Error("Разрешения должны ссылаться на подсети из списка выше")
            config["grants"] = {row: sorted(set(grants[row])) for row in config["devices"]}
        return config

    @staticmethod
    def grants(config):
        if config["mode"] != "selected":
            return {}
        return config.get("grants", dict.fromkeys(config["devices"], config["subnets"]))

    def neighbors(self, bridge):
        if not re.fullmatch(r"br[0-9]{1,3}", bridge):
            raise Error("Укажите LAN-интерфейс, например br0")
        output = self.runner.run(["ip", "-4", "neigh", "show", "dev", bridge]).stdout
        pattern = r"^(\d+\.\d+\.\d+\.\d+)\s+lladdr\s+((?:[a-f0-9]{2}:){5}[a-f0-9]{2})"
        return dict(re.findall(pattern, output.lower(), re.M))

    def local_devices(self, bridge):
        neighbors = self.neighbors(bridge)
        hotspot = self.runner.run(["ndmc", "-c", "show ip hotspot"], check=False).stdout
        names = {}
        for entry in re.split(r"(?m)^\s*host:\s*$", hotspot):
            mac = re.search(r"(?m)^\s*mac:\s*(\S+)\s*$", entry)
            name = re.search(r"(?m)^\s*name:[ \t]+([^\r\n]+)", entry)
            if mac and name:
                names[mac[1].lower()] = name[1].strip()[:80]
        return [{"ip": ip, "mac": mac, "name": names.get(mac, ip)}
                for ip, mac in sorted(neighbors.items(), key=lambda row: ipaddress.IPv4Address(row[0]))][:128]

    def verify_selection(self, config, snapshot):
        if snapshot["backend_state"] != "Running" or not snapshot["online"]:
            raise Error("Сначала подключите роутер к сети Tailscale")
        if snapshot["prefs"].get("ExitNodeID"):
            raise Error("Отключите внешний Exit Node перед настройкой доступа к подсетям")
        addresses = self.runner.run(["ip", "-4", "-o", "addr", "show"]).stdout
        pairs = [(line.split()[1], ipaddress.IPv4Interface(line.split()[3]))
                 for line in addresses.splitlines() if len(line.split()) > 3 and line.split()[2] == "inet"]
        local = {iface.network for _, iface in pairs}
        local.update(ipaddress.IPv4Network(n) for n in (snapshot["prefs"].get("AdvertiseRoutes") or [])
                     if ":" not in n and n != "0.0.0.0/0")
        for item in config["subnets"]:
            if any(ipaddress.IPv4Network(item).overlaps(network) for network in local):
                raise Error("Подсеть пересекается с подключённой или объявленной сетью: " + item)
        bridge = config["bridge"]
        lan = [iface.network for dev, iface in pairs if dev == bridge]
        if not lan:
            raise Error("У выбранного интерфейса LAN отсутствует IPv4")
        neighbors = self.neighbors(bridge)
        current = self.current()
        saved = current["devices"] if current["bridge"] == bridge else []
        for row in config["devices"]:
            addr, mac = row.split()
            if not any(ipaddress.IPv4Address(addr) in network for network in lan):
                raise Error("Устройство находится за другим интерфейсом: " + addr)
            observed = neighbors.get(addr)
            if observed != mac and (observed or row not in saved):
                raise Error("Роутер пока не подтвердил пару IP и MAC для " + addr)
        return {
            "zero_tier_sources": sorted(str(iface.ip) for dev, iface in pairs
                                        if re.fullmatch(r"zt[a-zA-Z0-9]+", dev)),
            "lan_sources": [str(network) for network in sorted(set(lan))],
        }

    def plan(self, params, snapshot):
        config = self.normalize(params)
        if config["mode"] == "selected" and "grants" not in config and "grants" in self.current():
            raise Error("Обновите страницу и проверьте индивидуальные разрешения", 409)
        if config["mode"] != "off":
            config.update(self.verify_selection(config, snapshot))
        return config

    def route_rules(self, config):
        if config["mode"] == "off":
            return set()
        if config["mode"] == "all":
            pairs = [("all", net) for net in config["subnets"]]
        else:
            pairs = [(row.split()[0], net) for row, nets in self.grants(config).items() for net in nets]
        return {("from", source, "to", subnet, "iif", config["bridge"], "lookup", "52")
                for source, subnet in pairs}

    def management_rules(self, config):
        return {("from", str(ipaddress.IPv4Address(addr)), "lookup", "main")
                for addr in config.get("zero_tier_sources", []) if config["mode"] != "off"}

    def live_rules(self, priority=PRIORITY):
        dump = self.runner.run(["ip", "-4", "rule", "show"]).stdout
        return {tuple(line.split()[1:]) for line in dump.splitlines() if line.startswith(priority + ":")}

    def rule_changes(self, config, previous):
        pairs = ((MGMT_PRIORITY, self.management_rules), (PRIORITY, self.route_rules))
        for priority, wanted in pairs:
            live = self.live_rules(priority)
            desired = wanted(config)
            if live - desired - wanted(previous):
                raise Error("Приоритет маршрутизации " + priority + " уже занят")
            yield priority, live, desired

    @staticmethod
    def owned_jump(chain, target):
        return ["-A", chain, "-j", target]

    def table(self, table, config, previous):
        parent, *chains = TABLES[table]
        live = self.runner.run(["iptables", "-w", "-t", table, "-S"]).stdout
        rows = [shlex.split(line) for line in live.splitlines()]
        declared = {row[1] for row in rows if row and row[0] == "-N"}
        existing = set(chains) & declared
        pending = config["mode"] != "off"
        if previous["mode"] == "off" and existing:
            raise Error("Имя цепочки доступа уже используется")
        jump = self.owned_jump(parent, chains[0])
        count = sum(row == jump for row in rows)
        if any("-j" in row and row[-1] in chains and row[1] not in chains and row != jump for row in rows):
            raise Error("Обнаружена чужая ссылка на цепочку доступа")
        if not pending and not existing:
            return []
        commands = ["-D " + " ".join(jump[1:])] * count
        commands += ["-F " + chain for chain in chains if chain in existing]
        if not pending:
            return commands + ["-X " + chain for chain in chains if chain in existing]
        create = [f":{chain} - [0:0]" for chain in chains]
        commands += [f"-I {parent} 1 -j {chains[0]}"]
        return create + commands + self.chain_rules(table, config, chains)

    def chain_rules(self, table, config, chains):
        bridge = config["bridge"]
        chosen = [(row.split(), nets) for row, nets in self.grants(config).items()]
        if config["mode"] == "all":
            sources = [(["-s", net], net, config["subnets"]) for net in config["lan_sources"]]
        else:
            sources = [(["-s", ip, "-m", "mac", "--mac-source", mac], ip, nets) for (ip, mac), nets in chosen]
        head = chains[0]
        if table == "nat":
            return [" ".join([f"-A {head} -o {self.tun}", "-s", ip,
                              "-d", net, "-j MASQUERADE"])
                    for _, ip, nets in sources for net in nets]
        guard = chains[1]
        rules = [f"-A {head} -i {bridge} -d {net} -j {guard}" for net in config["subnets"]]
        if table == "filter":
            rules += [f"-A {head} -i {self.tun} -o {bridge} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
        allow = ["-o", self.tun] if table == "filter" else []
        for match, _, nets in sources:
            # The parent chain already checks the catalog. Use one rule for a full grant.
            limits = [[]] if set(nets) == set(config["subnets"]) else [["-d", net] for net in nets]
            rules += [" ".join([f"-A {guard}", *match, *limit, *allow, "-j ACCEPT"]) for limit in limits]
        return rules + [f"-A {guard} -j DROP"]

    def payload(self, config, previous):
        parts = []
        for table in TABLES:
            commands = self.table(table, config, previous)
            if commands:
                parts.extend(["*" + table, *commands, "COMMIT"])
        return "\n".join(parts) + "\n" if parts else ""

    def restore(self, payload, test=False):
        if payload:
            args = ["iptables-restore", "--noflush"] + (["--test"] if test else [])
            self.runner.run(args, timeout=45, input_text=payload)

    def sync(self, config=None, previous=None):
        config = self.current() if config is None else config
        previous = config if previous is None else previous
        if config["mode"] == previous["mode"] == "off":
            return
        changes = list(self.rule_changes(config, previous))
        payload = self.payload(config, previous)
        self.restore(payload, test=True)
        self.restore(payload)
        for priority, actual, desired in changes:
            for rule in sorted(actual - desired):
                self.runner.run(["ip", "-4", "rule", "del", "pref", priority, *rule])
            for rule in sorted(desired - actual):
                self.runner.run(["ip", "-4", "rule", "add", "pref", priority, *rule])

    def change(self, fields, log):
        prior = self.current()
        snapshot = self.ts.snapshot(True)
        wanted = self.plan(fields, snapshot)
        if HOOK.exists() and HOOK.read_text() != HOOK_TEXT:
            raise Error("Путь сетевого обработчика уже занят")
        accepted = bool(snapshot["prefs"].get("RouteAll"))
        if wanted["mode"] != "off":
            wanted["restore_accept_routes"] = prior.get("restore_accept_routes", accepted)
        # Validate the full kernel transaction before writing the desired state.
        if wanted["mode"] != "off" or prior["mode"] != "off":
            list(self.rule_changes(wanted, prior))
            self.restore(self.payload(wanted, prior), test=True)
        write_json(self.path, wanted)
        try:
            self.sync(wanted, prior)
            new_accept = wanted["mode"] != "off" or prior.get("restore_accept_routes", accepted)
            if new_accept != accepted:
                self.ts.run("set", "--accept-routes=" + str(new_accept).lower())
                self.ts.invalidate()
            if wanted["mode"] != "off":
                self.verify_routes(wanted["subnets"])
                if not HOOK.exists():
                    HOOK.write_text(HOOK_TEXT)
                    HOOK.chmod(0o755)
        except Exception:
            write_json(self.path, prior)
            self.sync(prior, wanted)
            self.ts.run("set", "--accept-routes=" + str(accepted).lower())
            self.ts.invalidate()
            raise
        log("Политика доступа локальных устройств применена")
        return {"message": "Правила доступа сохранены", "lan_access": wanted}

    def verify_routes(self, desired):
        for _ in range(12):
            output = self.runner.run(["ip", "-4", "route", "show", "table", "52"], check=False).stdout
            active = {line.split()[0] for line in output.splitlines() if f" dev {self.tun} " in line + " "}
            missing = set(desired) - active
            if not missing:
                return
            time.sleep(1)
        raise Error("Tailscale не выдал маршруты: " + ", ".join(sorted(missing)))

    def remove(self):
        prior = self.current()
        self.sync({"mode": "off"}, prior)
        if HOOK.exists() and HOOK.read_text() == HOOK_TEXT:
            HOOK.unlink()

    def recover(self):
        config = self.current()
        if config["mode"] == "off":
            return
        if all(live == desired for _, live, desired in self.rule_changes(config, config)):
            for table, (parent, first, *_) in TABLES.items():
                rows = self.runner.run(["iptables", "-w", "-t", table, "-S", parent]).stdout.splitlines()
                rules = [line for line in rows if line.startswith("-A ")]
                if not rules or rules[0] != f"-A {parent} -j {first}":
                    break
            else:
                return
        self.sync(config)
