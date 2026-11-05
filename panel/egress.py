"""Scoped egress for packets arriving FROM Tailscale clients, never router traffic.

Native connection policies remain owned by Keenetic. This module only selects
their routing tables for a private mark, or hands TCP/UDP to existing XKeen
force chains. Unmatched marked packets fail closed instead of using another WAN.
"""

import hashlib, ipaddress, json, pathlib, re, shlex, urllib.request, time
from .core import Error, read_json, write_json
from .routing import route_rows, rule_rows

MARK = "0x5a000000/0xff000000"
HOOK = "/opt/etc/ndm/netfilter.d/zz-tailscale-panel-egress.sh"
TAG = "tailscale-panel-egress"
CHAINS = {"mangle": "TSP_EXIT_MARK", "nat": "TSP_EXIT_NAT", "filter": "TSP_EXIT_FWD"}
PRIVATE = {
    4: [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ],
    6: ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"],
}


class Egress:
    def __init__(self, state, runner, tun="opkgtun0", root="/"):
        self.state = pathlib.Path(state)
        self.runner = runner
        self.tun = tun
        self.root = pathlib.Path(root)
        if not re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", tun):
            raise Error("Неизвестный TUN для выбора выхода")

    def call(self, args, check=True):
        if args[0] in ["iptables", "ip6tables"]:
            args = [args[0], "-w", *args[1:]]
        return self.runner.run(args, timeout=15, check=check)

    def rci(self, path):
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open("http://127.0.0.1:79/rci/" + path, timeout=4) as response:
            return json.loads(response.read())

    def current(self):
        return read_json(
            self.state / "egress.json",
            {"target": "system", "label": "Как настроено в роутере"},
        )

    def defaults(self, family, table):
        try:
            routes = route_rows(
                self.call(
                    [
                        "ip",
                        "-" + str(family),
                        "route",
                        "show",
                        "table",
                        str(table),
                        "default",
                    ],
                    False,
                ).stdout
            )
            return [
                r
                for r in routes
                if r.get("type", "unicast") == "unicast"
                and r.get("dev")
                and r["dev"] != self.tun
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", r["dev"])
            ]
        except (Error, ValueError):
            return []

    def proxy_ready(self, tool):
        nat = self.call([tool, "-t", "nat", "-S", "xkeen_force"], False)
        mangle = self.call([tool, "-t", "mangle", "-S", "xkeen_force"], False)
        return (
            nat.returncode == mangle.returncode == 0
            and "REDIRECT" in nat.stdout
            and "TPROXY" in mangle.stdout
        )

    def choices(self):
        result = [
            {
                "id": "system",
                "label": "Как настроено в роутере",
                "available": True,
                "kind": "system",
            }
        ]
        try:
            policies = self.rci("show/ip/policy")
            config = self.call(["ndmc", "-c", "show running-config"]).stdout
            own = "OpkgTun" + self.tun[7:]
            forbidden = set()
            name = None
            for line in config.splitlines():
                m = re.fullmatch(r"ip policy ([A-Za-z0-9_-]{1,32})", line)
                if m:
                    name = m[1]
                elif line and not line.startswith(" ") and line.strip() != "!":
                    name = None
                elif name and line.strip() == "permit global " + own:
                    forbidden.add(name)
            for key, p in policies.items():
                if (
                    not isinstance(p, dict)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", key)
                    or key in forbidden
                ):
                    continue
                t4, t6 = p.get("table4"), p.get("table6")
                if any(type(t) is not int or not 1 <= t < 2**31 for t in [t4, t6]):
                    continue
                r4, r6 = self.defaults(4, t4), self.defaults(6, t6)
                label = p.get("description") or key
                if str(label).lower() in ["xkeen", "xkeen_full"]:
                    # These are native transport tables; the force-proxy option is separate.
                    if str(label).lower() == "xkeen_full":
                        continue
                    label = "Основной провайдер — напрямую"
                result.append(
                    {
                        "id": "policy:" + key,
                        "label": str(label),
                        "kind": "policy",
                        "available": bool(r4),
                        "table4": t4,
                        "table6": t6,
                        "devices4": sorted({r["dev"] for r in r4}),
                        "devices6": sorted({r["dev"] for r in r6}),
                        "ipv6": bool(r6),
                    }
                )
            ready = self.proxy_ready("iptables")
            result.insert(
                1,
                {
                    "id": "xkeen",
                    "label": "XKeen — весь TCP/UDP через прокси",
                    "kind": "proxy",
                    "available": ready,
                    "ipv6": self.proxy_ready("ip6tables") if ready else False,
                },
            )
        except (Error, OSError, ValueError):
            pass
        return result

    def status(self):
        return {
            "current": self.current(),
            "choices": self.choices(),
            "runtime": read_json(self.state / "egress-runtime.json"),
        }

    def resolve(self, target, strict=True):
        if not isinstance(target, str):
            raise Error("Выберите выход для клиентов Exit node")
        item = next((x for x in self.choices() if x["id"] == target), None)
        if not item or (strict and not item["available"]):
            raise Error(
                "Выход недоступен. Для VPN создайте его политику подключений в Keenetic; Tailscale-петли исключены.",
                409,
            )
        return item

    def plan(self, params):
        if not isinstance(params, dict) or set(params) != {"target"}:
            raise Error("Неверный параметр выхода")
        choice = self.resolve(params["target"])
        old = self.current()
        return {
            "choice": choice,
            "changes": (
                []
                if old["target"] == choice["id"]
                else [
                    {
                        "name": "Интернет клиентов этого Exit node",
                        "before": old.get("label", old["target"]),
                        "after": choice["label"],
                    }
                ]
            ),
            "revision": hashlib.sha256(
                json.dumps(old, sort_keys=True).encode()
            ).hexdigest(),
            "commands": [["tailscale-panel", "egress", choice["id"]]],
            "message": "Изменится выход только интернет-трафика, пришедшего от клиентов Tailscale. LAN, связь между узлами и собственные подключения роутера сохраняются. При недоступности выбранного выхода автоматического перехода на другой провайдер нет. IPv6 без рабочего выхода блокируется.",
        }

    def excluded(self, family):
        result = set(PRIVATE[family])
        try:
            rows = route_rows(
                self.call(
                    ["ip", "-" + str(family), "route", "show", "table", "all"],
                    False,
                ).stdout
            )
            for row in rows:
                if (
                    row.get("dev") == self.tun
                    or row.get("scope") == "link"
                    or row.get("type") == "local"
                ):
                    try:
                        net = ipaddress.ip_network(row.get("dst", ""))
                        if net.version == family and net.prefixlen:
                            result.add(str(net))
                    except ValueError:
                        pass
        except (ValueError, Error):
            pass
        return sorted(result)

    def hold(self, enabled):
        for family, tool, src in [
            (4, "iptables", "100.64.0.0/10"),
            (6, "ip6tables", "fd7a:115c:a1e0::/48"),
        ]:
            chain = "TSP_EXIT_HOLD"
            args = [
                "-i",
                self.tun,
                "-s",
                src,
                "-m",
                "comment",
                "--comment",
                TAG + "-hold",
                "-j",
                chain,
            ]
            if enabled:
                if (
                    self.call(
                        [tool, "-t", "filter", "-C", "FORWARD", *args], False
                    ).returncode
                    == 0
                ):
                    continue
                self.call([tool, "-t", "filter", "-N", chain])
                for net in self.excluded(family):
                    self.call(
                        [tool, "-t", "filter", "-A", chain, "-d", net, "-j", "RETURN"]
                    )
                self.call([tool, "-t", "filter", "-A", chain, "-j", "REJECT"])
                self.call([tool, "-t", "filter", "-I", "FORWARD", "1", *args])
            else:
                self.call([tool, "-t", "filter", "-D", "FORWARD", *args], False)
                self.call([tool, "-t", "filter", "-F", chain], False)
                self.call([tool, "-t", "filter", "-X", chain], False)

    def remove(self, release_hold=True):
        """Remove only exact private-mark rules and chains tagged/owned by this panel."""
        for tool in ["iptables", "ip6tables"]:
            for table, chain in CHAINS.items():
                output = self.call([tool, "-t", table, "-S"], False).stdout
                for line in output.splitlines():
                    a = shlex.split(line)
                    if a[:1] == ["-A"] and (
                        TAG in a
                        or (
                            "-j" in a
                            and a[a.index("-j") + 1]
                            in [*CHAINS.values(), "TSP_EXIT_TCP"]
                        )
                    ):
                        self.call([tool, "-t", table, "-D", *a[1:]], False)
                for name in ([chain, "TSP_EXIT_TCP"] if table == "nat" else [chain]):
                    self.call([tool, "-t", table, "-F", name], False)
                    self.call([tool, "-t", table, "-X", name], False)
        for family in [4, 6]:
            try:
                rows = rule_rows(
                    self.call(["ip", "-" + str(family), "rule", "show"], False).stdout
                )
            except ValueError:
                rows = []
            for r in rows:
                if (
                    r.get("priority") not in [90, 91]
                    or r.get("iif", r.get("iifname")) != self.tun
                ):
                    continue
                if str(r.get("fwmark", "")).lower() not in [
                    "0x5a000000",
                    str(0x5A000000),
                ]:
                    continue
                self.call(
                    [
                        "ip",
                        "-" + str(family),
                        "rule",
                        "del",
                        "pref",
                        str(r["priority"]),
                        "iif",
                        self.tun,
                        "fwmark",
                        MARK,
                    ],
                    False,
                )
        (self.state / "egress-runtime.json").unlink(missing_ok=True)
        if release_hold:
            self.hold(False)

    def specs(self, choice):
        families = []
        for family, tool, source in [
            (4, "iptables", "100.64.0.0/10"),
            (6, "ip6tables", "fd7a:115c:a1e0::/48"),
        ]:
            proxy = choice["kind"] == "proxy"
            enabled = self.proxy_ready(tool) if proxy else True
            devices = choice.get("devices" + str(family), [])
            nat_ready = self.call([tool, "-t", "nat", "-S"], False).returncode == 0
            families.append(
                {
                    "family": family,
                    "tool": tool,
                    "source": source,
                    "proxy": proxy,
                    "enabled": enabled,
                    "devices": devices,
                    "nat": nat_ready,
                    "excluded": self.excluded(family),
                    "table": (
                        choice.get("table" + str(family))
                        if not proxy and nat_ready
                        else None
                    ),
                }
            )
        return families

    def install_rules(self, choice, specs):
        for f in specs:
            fam, tool, src = f["family"], f["tool"], f["source"]

            def rule(table, chain, *args):
                self.call([tool, "-t", table, "-A", chain, *args])

            def anchor(table, base, *args):
                self.call(
                    [
                        tool,
                        "-t",
                        table,
                        "-I",
                        base,
                        "1",
                        *args,
                        "-m",
                        "comment",
                        "--comment",
                        TAG,
                    ]
                )

            # Guards precede activation, and apply only to our private mark on this TUN.
            self.call(
                [
                    "ip",
                    "-" + str(fam),
                    "rule",
                    "add",
                    "pref",
                    "91",
                    "iif",
                    self.tun,
                    "fwmark",
                    MARK,
                    "unreachable",
                ]
            )
            if f["table"]:
                self.call(
                    [
                        "ip",
                        "-" + str(fam),
                        "rule",
                        "add",
                        "pref",
                        "90",
                        "iif",
                        self.tun,
                        "fwmark",
                        MARK,
                        "lookup",
                        str(f["table"]),
                    ]
                )
            for table in ["mangle", "filter"] + (["nat"] if f["nat"] else []):
                self.call([tool, "-t", table, "-N", CHAINS[table]])
            m = CHAINS["mangle"]
            for net in f["excluded"]:
                rule("mangle", m, "-d", net, "-j", "RETURN")
            rule("mangle", m, "-j", "MARK", "--set-xmark", "0x5a000000/0xffffffff")
            rule("mangle", m, "-j", "DSCP", "--set-dscp", "61" if f["proxy"] else "62")
            if f["proxy"] and f["enabled"]:
                rule("mangle", m, "-p", "udp", "-j", "xkeen_force")
            rule("mangle", m, "-j", "ACCEPT")
            if f["nat"]:
                n = CHAINS["nat"]
                if f["proxy"]:
                    if f["enabled"]:
                        rule("nat", n, "-p", "tcp", "-j", "xkeen_force")
                    anchor(
                        "nat",
                        "PREROUTING",
                        "-i",
                        self.tun,
                        "-s",
                        src,
                        "-m",
                        "mark",
                        "--mark",
                        MARK,
                        "-j",
                        n,
                    )
                else:
                    for dev in f["devices"]:
                        rule("nat", n, "-o", dev, "-j", "MASQUERADE")
                    anchor(
                        "nat",
                        "POSTROUTING",
                        "-s",
                        src,
                        "-m",
                        "mark",
                        "--mark",
                        MARK,
                        "-j",
                        n,
                    )
                    # Keep DNS and direct connections outside native proxy/DNS redirection.
                    anchor(
                        "nat",
                        "PREROUTING",
                        "-i",
                        self.tun,
                        "-s",
                        src,
                        "-m",
                        "mark",
                        "--mark",
                        MARK,
                        "-j",
                        "ACCEPT",
                    )
            for dev in f["devices"] if not f["proxy"] else []:
                rule("filter", CHAINS["filter"], "-o", dev, "-j", "ACCEPT")
            rule("filter", CHAINS["filter"], "-j", "REJECT")
            anchor(
                "filter",
                "FORWARD",
                "-i",
                self.tun,
                "-s",
                src,
                "-m",
                "mark",
                "--mark",
                MARK,
                "-j",
                CHAINS["filter"],
            )
            anchor(
                "filter",
                "FORWARD",
                "-o",
                self.tun,
                "-d",
                src,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            )
            anchor("mangle", "PREROUTING", "-i", self.tun, "-s", src, "-j", m)

    def sync(self, force=False):
        saved = self.current()
        if saved["target"] == "system":
            if force or (self.state / "egress-runtime.json").exists():
                self.remove()
            return {"active": False, "target": "system"}
        try:
            choice = self.resolve(saved["target"], False)
        except Error:
            choice = {
                "id": saved["target"],
                "kind": "policy",
                "label": saved.get("label", saved["target"]),
            }
        specs = self.specs(choice)
        fingerprint = hashlib.sha256(
            json.dumps([choice, specs], sort_keys=True).encode()
        ).hexdigest()
        old = read_json(self.state / "egress-runtime.json")
        alive = True
        for spec in specs:
            tool = spec["tool"]
            top = self.call([tool, "-t", "mangle", "-S", "PREROUTING"], False).stdout
            first = next((l for l in top.splitlines() if l.startswith("-A ")), "")
            alive = alive and CHAINS["mangle"] in first
            rules = rule_rows(
                self.call(
                    ["ip", "-" + str(spec["family"]), "rule", "show"], False
                ).stdout
            )
            owned = [
                r
                for r in rules
                if r.get("iif") == self.tun
                and r.get("fwmark") == "0x5a000000"
                and r.get("fwmask") == "0xff000000"
            ]
            alive = alive and any(r.get("priority") == 91 for r in owned)
            if spec["table"]:
                alive = alive and any(
                    r.get("priority") == 90
                    and str(r.get("table")) == str(spec["table"])
                    for r in owned
                )
            body = self.call(
                [tool, "-t", "mangle", "-S", CHAINS["mangle"]], False
            ).stdout
            expected = (
                len(spec["excluded"]) + 3 + int(spec["proxy"] and spec["enabled"])
            )
            alive = (
                alive
                and sum(l.startswith("-A ") for l in body.splitlines()) == expected
            )
            forward = self.call([tool, "-t", "filter", "-S", "FORWARD"], False).stdout
            alive = alive and TAG in forward and CHAINS["filter"] in forward
            if spec["nat"]:
                base = "PREROUTING" if spec["proxy"] else "POSTROUTING"
                nat = self.call([tool, "-t", "nat", "-S", base], False).stdout
                alive = alive and TAG in nat and CHAINS["nat"] in nat
        if force or old.get("fingerprint") != fingerprint or not alive:
            self.hold(True)
            for attempt in range(2):
                self.remove(False)
                try:
                    self.install_rules(choice, specs)
                    break
                except Error as exc:
                    self.remove(False)
                    # NDM can rebuild a table between individual xtables calls.
                    # Rebuild our scoped chains once; all other failures roll back.
                    if attempt or "No chain/target/match" not in str(exc):
                        raise
                    time.sleep(0.1)
            write_json(
                self.state / "egress-runtime.json",
                {
                    "fingerprint": fingerprint,
                    "target": saved["target"],
                    "active": True,
                    "ipv6": choice.get("ipv6", False),
                },
            )
            self.hold(False)
        return read_json(self.state / "egress-runtime.json")

    def apply(self, params, log):
        plan = self.plan(params)
        choice = plan["choice"]
        old = self.current()
        write_json(
            self.state / "egress.json",
            {"target": choice["id"], "label": choice["label"]},
        )
        try:
            log("Настройка выхода интернет-трафика клиентов Tailscale")
            self.sync(True)
            hook = self.root / HOOK.lstrip("/")
            if choice["id"] == "system":
                hook.unlink(missing_ok=True)
            else:
                hook.parent.mkdir(parents=True, exist_ok=True)
                hook.write_text(
                    "#!/bin/sh\n/opt/bin/tailscale-panel egress-sync >/dev/null 2>&1\n"
                )
                hook.chmod(0o755)
        except Exception:
            write_json(self.state / "egress.json", old)
            self.sync(True)
            raise
        return {
            "target": choice["id"],
            "label": choice["label"],
            "message": "Выход сохранён. Новые соединения используют выбранный путь.",
        }
