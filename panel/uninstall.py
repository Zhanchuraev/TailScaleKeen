"""Explicit purge of Tailscale and this panel, preserving shared Entware components."""

import ipaddress, json, os, pathlib, re, shlex, shutil
from .core import Error, Runner, read_json
from .install import at
from .native import blocks, normalize
from .routing import route_rows, rule_rows

PATHS = [
    "/opt/etc/init.d/S06tailscaled",
    "/opt/etc/init.d/S07tailscale-policy",
    "/opt/etc/init.d/S98tailscale-panel",
    "/opt/etc/ndm/netfilter.d/95-tailscale-policy.sh",
    "/opt/etc/ndm/netfilter.d/99-tailscale.sh",
    "/opt/etc/ndm/netfilter.d/96-tailscale-panel.sh",
    "/opt/etc/ndm/netfilter.d/zz-tailscale-panel-egress.sh",
    "/opt/bin/tailscale",
    "/opt/bin/tailscaled",
    "/opt/bin/.tailscale.panel-new",
    "/opt/bin/.tailscaled.panel-new",
    "/opt/bin/.tailscale.new",
    "/opt/bin/.tailscaled.new",
    "/opt/bin/.tailscale.restore",
    "/opt/bin/.tailscaled.restore",
    "/opt/sbin/tailscale",
    "/opt/sbin/tailscaled",
    "/opt/var/tailscaled.state",
    "/opt/var/tailscaled.state.tmp",
    "/opt/var/lib/tailscale",
    "/opt/var/tailscale",
    "/opt/etc/tailscale",
    "/opt/var/run/tailscale",
    "/var/run/tailscale",
    "/opt/var/run/tailscale-panel.pid",
    "/opt/var/log/tailscale-panel.log",
    "/opt/var/log/tailscale-panel.log.1",
    "/opt/var/log/tailscaled.log",
    "/opt/var/log/tailscaled.log.1",
    "/opt/etc/tailscale-panel",
    "/opt/share/tailscale-panel",
    "/opt/share/.tailscale-panel-new",
    "/opt/share/.tailscale-panel-previous",
    "/opt/tmp/tailscale-panel-client-stage",
    "/opt/bin/tailscale-panel",
    "/opt/bin/tailscalekeen",
]


class Purger:
    def __init__(self, state="/opt/etc/tailscale-panel", runner=None, root="/"):
        self.state = pathlib.Path(state)
        self.runner = runner or Runner()
        self.root = str(pathlib.Path(root).resolve())
        self.config = read_json(self.state / "config.json")
        self.tun = self.config.get("tun", "opkgtun0")
        if not re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", self.tun):
            raise Error("Не удалось безопасно определить интерфейс Tailscale")

    def path(self, p):
        q = at(self.root, p)
        if self.root != "/" and not q.parent.resolve().is_relative_to(
            pathlib.Path(self.root).resolve()
        ):
            raise Error("Путь удаления выходит за тестовый каталог")
        return q

    def preserve_smb(self, apply=False):
        p = self.path("/opt/etc/init.d/S07tailscale-policy")
        if not p.is_file():
            return None
        s = p.read_text()
        if "HOME_SMB_IP=" not in s:
            return None
        if "HEADSCALE_POLICY_TABLE=" not in s:
            raise Error(
                "В политике есть дополнительные настройки; безопасный разбор не удался"
            )
        prefix = s[s.index("HOME_SMB_IP=") : s.index("HEADSCALE_POLICY_TABLE=")]
        if re.search(r"\b(?:TS_IF|TS_TABLE)\b", prefix):
            raise Error("Нельзя отделить дополнительные правила от Tailscale")
        out = self.path("/opt/etc/init.d/S07zerotier-smb")
        text = (
            "#!/bin/sh\nPATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin\n"
            + prefix
            + '\ncase "$1" in\nstart) home_smb_run sync;;\nstop) home_smb_run clear;;\nrestart) home_smb_run clear && home_smb_run sync;;\n*) exit 0;;\nesac\n'
        )
        if out.exists() and out.read_text() != text:
            raise Error("Уже существует другая служба S07zerotier-smb")
        if apply:
            out.write_text(text)
            out.chmod(0o755)
        return "/opt/etc/init.d/S07zerotier-smb"

    def plan(self):
        paths = [p for p in PATHS if self.path(p).exists() or self.path(p).is_symlink()]
        extras = []
        for folder, pattern in [
            ("/opt/var/log", "tailscaled.log*"),
            ("/opt/var/log", "tailscale.log*"),
            ("/opt/var/run", "tailscaled.pid"),
        ]:
            d = self.path(folder)
            if d.is_dir():
                extras.extend(
                    (
                        "/" + str(p.relative_to(self.root)).lstrip("/")
                        if self.root != "/"
                        else str(p)
                    )
                    for p in d.glob(pattern)
                )
        return {
            "command": "tailscalekeen uninstall --purge",
            "scope": "Панель, клиент, ключ устройства, настройки, журналы и интеграция Tailscale на этом роутере",
            "paths": sorted(set(paths + extras)),
            "native_interface": "OpkgTun" + self.tun[7:],
            "exclusive_policies": self.exclusive_policies(),
            "preserved_helpers": [x for x in [self.preserve_smb()] if x],
            "shared_packages_preserved": [
                "Entware",
                "Python",
                "curl",
                "XKeen",
                "ZeroTier",
            ],
            "server_record": "Сохранённая запись устройства на сервере Tailscale/Headscale удаляется в его административной консоли.",
            "external_archives": "Пользовательские архивы других программ и копии вне каталогов панели не изменяются.",
        }

    def exclusive_policies(self):
        if self.root != "/":
            return []
        text = self.runner.run(
            ["ndmc", "-c", "show running-config"], check=False
        ).stdout
        current = None
        found = {}
        for line in text.splitlines():
            m = re.fullmatch(r"ip policy ([A-Za-z0-9_-]{1,32})", line)
            if m:
                current = m[1]
                found[current] = []
            elif line and not line.startswith(" ") and line.strip() != "!":
                current = None
            if current:
                found[current].append(line)
        result = []
        name = "OpkgTun" + self.tun[7:]
        for policy, lines in found.items():
            permits = re.findall(r"^\s+permit global ([^\s]+)", "\n".join(lines), re.M)
            if permits == [name]:
                result.append(policy)
        return result

    def cleanup_kernel(self):
        # Remove exact rules referring to this device or the conventional Tailscale chains.
        for tool in ["iptables", "ip6tables"]:
            for table in ["filter", "nat", "mangle"]:
                result = self.runner.run([tool, "-t", table, "-S"], check=False)
                for line in result.stdout.splitlines():
                    try:
                        args = shlex.split(line)
                    except ValueError:
                        continue
                    if not args or args[0] != "-A":
                        continue
                    if self.tun in args or any(x.startswith("ts-") for x in args if x):
                        self.runner.run(
                            [tool, "-t", table, "-D", *args[1:]], check=False
                        )
                for line in result.stdout.splitlines():
                    if re.fullmatch(r"-N ts-[A-Za-z0-9_-]+", line):
                        chain = line.split()[1]
                        self.runner.run([tool, "-t", table, "-F", chain], check=False)
                        self.runner.run([tool, "-t", table, "-X", chain], check=False)
        legacy = self.path("/opt/etc/init.d/S07tailscale-policy")
        if legacy.is_file():
            source = legacy.read_text()
            # Adopt only exact legacy NAT entries for this tailnet prefix, never arbitrary shell text.
            for line in source.splitlines():
                m = re.match(
                    r"\s*(iptables(?:\s+-t\s+(?:nat|filter|mangle))?\s+-C\s+[^;&|]+?)\s+2>/dev/null",
                    line,
                )
                if not m:
                    continue
                args = shlex.split(m.group(1))
                if "100.64.0.0/10" in args and not any("$" in x for x in args):
                    args[args.index("-C")] = "-D"
                    self.runner.run(args, check=False)
            if "ip rule add pref 5200 lookup main" in source:
                self.runner.run(
                    ["ip", "-4", "rule", "del", "pref", "5200", "lookup", "main"],
                    check=False,
                )
            if "ip rule add pref 5 fwmark 0x80000/0xff0000 lookup main" in source:
                self.runner.run(
                    [
                        "ip",
                        "-4",
                        "rule",
                        "del",
                        "pref",
                        "5",
                        "fwmark",
                        "0x80000/0xff0000",
                        "lookup",
                        "main",
                    ],
                    check=False,
                )
            nets = set(
                re.findall(r"ip rule add pref 7 to ([\d./]+) lookup main", source)
            )
            for group in re.findall(r"for net in ([^;\n]+); do", source):
                nets.update(x for x in group.split() if re.fullmatch(r"[\d./]+", x))
            for net in nets:
                try:
                    net = str(ipaddress.ip_network(net))
                except ValueError:
                    continue
                self.runner.run(
                    [
                        "ip",
                        "-4",
                        "rule",
                        "del",
                        "pref",
                        "7",
                        "to",
                        net,
                        "lookup",
                        "main",
                    ],
                    check=False,
                )
        table = "52"
        legacy = self.path("/opt/etc/init.d/S07tailscale-policy")
        if legacy.exists():
            found = re.search(r'^TS_TABLE="?(\d+)"?', legacy.read_text(), re.M)
            if found:
                table = found[1]
        for family in ["-4", "-6"]:
            result = self.runner.run(["ip", family, "rule", "show"], check=False)
            try:
                rules = rule_rows(result.stdout)
            except ValueError:
                rules = []
            for rule in rules:
                if str(rule.get("table")) == table:
                    pref = rule.get("priority")
                    if type(pref) is int:
                        self.runner.run(
                            [
                                "ip",
                                family,
                                "rule",
                                "del",
                                "pref",
                                str(pref),
                                "lookup",
                                table,
                            ],
                            check=False,
                        )
            self.runner.run(
                ["ip", family, "route", "flush", "table", table], check=False
            )
            result = self.runner.run(
                ["ip", family, "route", "show", "table", "all"], check=False
            )
            try:
                routes = route_rows(result.stdout)
            except ValueError:
                routes = []
            for route in routes:
                if route.get("dev") == self.tun:
                    t = str(route.get("table", "main"))
                    dst = route.get("dst", "default")
                    if re.fullmatch(r"(?:\d+|main|default|local)", t) and re.fullmatch(
                        r"[a-fA-F0-9:./]+|default", dst
                    ):
                        self.runner.run(
                            [
                                "ip",
                                family,
                                "route",
                                "del",
                                dst,
                                "dev",
                                self.tun,
                                "table",
                                t,
                            ],
                            check=False,
                        )

    def purge(self):
        plan = self.plan()
        if self.root == "/":
            running = self.runner.run(["ndmc", "-c", "show running-config"]).stdout
            startup = self.runner.run(["ndmc", "-c", "more startup-config"]).stdout
            if normalize(running) != normalize(startup):
                raise Error(
                    "Сначала сохраните другие изменения в Keenetic; удаление пока не начиналось"
                )
        self.preserve_smb(True)
        if self.root == "/":
            from .egress import Egress

            Egress(self.state, self.runner, self.tun).remove()
            from .integration import Integration
            Integration(self.state, self.runner, self.tun).remove()
            # Stop only the client here; manage.py stops the separate panel before this process.
            init = self.path("/opt/etc/init.d/S06tailscaled")
            if init.exists():
                self.runner.run([str(init), "stop"], timeout=90, check=False)
            if self.runner.run(["pidof", "tailscaled"], check=False).stdout.strip():
                raise Error("Tailscaled ещё работает; удаление остановлено")
            self.cleanup_kernel()
            name = "OpkgTun" + self.tun[7:]
            running = self.runner.run(
                ["ndmc", "-c", "show running-config"], check=False
            ).stdout
            for policy in plan["exclusive_policies"]:
                result = self.runner.run(
                    ["ndmc", "-c", "no ip policy " + policy], check=False
                )
                if result.returncode:
                    raise Error("Не удалось удалить выделенную политику " + policy)
            if name in blocks(running):
                result = self.runner.run(
                    ["ndmc", "-c", "no interface " + name], check=False
                )
                if result.returncode or name in blocks(
                    self.runner.run(
                        ["ndmc", "-c", "show running-config"], check=False
                    ).stdout
                ):
                    raise Error(
                        "Keenetic не удалил подключение "
                        + name
                        + "; остальные файлы сохранены для повторной попытки"
                    )
                self.runner.run(["ndmc", "-c", "system configuration save"])
            for pkg in ["tailscale", "tailscale_s"]:
                q = self.runner.run(["opkg", "status", pkg], check=False)
                if re.search(r"^Status:.* installed$", q.stdout, re.M):
                    self.runner.run(["opkg", "remove", pkg], timeout=120)
        removed = []
        # Keep the code and state until all other scoped paths are removed.
        paths = sorted(
            set(PATHS + plan["paths"]),
            key=lambda p: p
            in [
                "/opt/share/tailscale-panel",
                "/opt/etc/tailscale-panel",
                "/opt/bin/tailscale-panel",
            ],
        )
        for p in paths:
            q = self.path(p)
            if q.is_symlink() or q.is_file():
                q.unlink()
                removed.append(p)
            elif q.is_dir():
                shutil.rmtree(q)
                removed.append(p)
        leftovers = [
            p
            for p in plan["paths"]
            if self.path(p).exists() or self.path(p).is_symlink()
        ]
        if leftovers:
            raise Error("Не все файлы удалены: " + ", ".join(leftovers))
        return {
            "purged": True,
            "removed": removed,
            "remaining": [],
            "preserved_helpers": plan["preserved_helpers"],
        }
