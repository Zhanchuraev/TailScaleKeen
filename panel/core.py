"""Small standard-library backend; never invoke a shell with request data."""

from __future__ import annotations
import contextlib, hashlib, ipaddress, json, os, pathlib, re, secrets, shlex, subprocess, threading, time, urllib.parse, urllib.request

VERSION = "1.1.2"
PREF_KEYS = (
    "ControlURL",
    "RouteAll",
    "CorpDNS",
    "ExitNodeID",
    "ExitNodeIP",
    "ExitNodeAllowLANAccess",
    "Hostname",
    "AdvertiseRoutes",
    "AdvertiseTags",
    "ShieldsUp",
    "RunSSH",
    "RunWebClient",
    "NoSNAT",
    "NoStatefulFiltering",
    "NetfilterMode",
    "WantRunning",
)
SECRET_RE = re.compile(
    r"(?:tskey-[A-Za-z0-9_-]+|(?:nodekey|privkey|machinekey):[a-fA-F0-9]+)"
)


def scrub(text):
    return SECRET_RE.sub("[hidden]", str(text))[-24000:]


def write_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + "." + secrets.token_hex(5))
    try:
        # Never create a briefly world-readable credentials/configuration file.
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path, default=None):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {} if default is None else default


class Error(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Runner:
    def run(self, args, timeout=20, check=True):
        env = {
            **os.environ,
            "PATH": "/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NO_PROXY": "127.0.0.1,localhost",
        }
        try:
            p = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise Error(
                "Команда не завершилась вовремя. Проверьте состояние перед повтором.",
                504,
            )
        except OSError:
            raise Error("Не найден компонент: " + str(args[0]), 503)
        if check and p.returncode:
            raise Error(scrub(p.stderr or p.stdout or "Ошибка команды"), 502)
        return p


class Tailscale:
    def __init__(self, runner=None, binary="/opt/bin/tailscale"):
        self.runner = runner or Runner()
        self.binary = binary
        self.cache = None
        self.cached_at = 0
        self.lock = threading.RLock()

    def run(self, *args, **kw):
        return self.runner.run([self.binary, *args], **kw)

    def snapshot(self, fresh=False):
        with self.lock:
            if not fresh and self.cache and time.monotonic() - self.cached_at < 3:
                return self.cache
            try:
                s = json.loads(self.run("status", "--json").stdout)
                p = json.loads(self.run("debug", "prefs").stdout)
            except (ValueError, Error) as e:
                raise Error("Tailscale недоступен: " + scrub(e), 503)
            p = {k: p.get(k) for k in PREF_KEYS}
            own = s.get("Self") or {}
            peers = []
            for peer in (s.get("Peer") or {}).values():
                peers.append(
                    {
                        k: peer.get(k)
                        for k in [
                            "ID",
                            "HostName",
                            "DNSName",
                            "OS",
                            "TailscaleIPs",
                            "Online",
                            "LastSeen",
                            "Active",
                            "RxBytes",
                            "TxBytes",
                            "CurAddr",
                            "Relay",
                            "ExitNode",
                            "ExitNodeOption",
                            "PrimaryRoutes",
                            "AllowedIPs",
                            "Tags",
                        ]
                    }
                )
            peers.sort(
                key=lambda x: (not x["Online"], (x["HostName"] or "").casefold())
            )
            routes = p.get("AdvertiseRoutes") or []
            exit_advertised = "0.0.0.0/0" in routes and "::/0" in routes
            r = {
                "version": s.get("Version", ""),
                "backend_state": s.get("BackendState", "Unknown"),
                "online": bool(own.get("Online")),
                "self": {
                    k: own.get(k)
                    for k in [
                        "ID",
                        "HostName",
                        "DNSName",
                        "OS",
                        "TailscaleIPs",
                        "RxBytes",
                        "TxBytes",
                        "ExitNodeOption",
                    ]
                },
                "peers": peers,
                "health": s.get("Health") or [],
                "prefs": p,
                "auth_url": s.get("AuthURL", ""),
                "tailnet": s.get("CurrentTailnet") or {},
                "exit_advertised": exit_advertised,
                "updated_at": int(time.time()),
            }
            self.cache = r
            self.cached_at = time.monotonic()
            return r

    def invalidate(self):
        self.cache = None

    def revision(self):
        return hashlib.sha256(
            json.dumps(self.snapshot(True)["prefs"], sort_keys=True).encode()
        ).hexdigest()

    def set_args(self, fields):
        s = self.snapshot(True)
        p = s["prefs"]
        args = []
        changes = []
        bools = {
            "accept_dns": ("CorpDNS", "accept-dns", False),
            "accept_routes": ("RouteAll", "accept-routes", False),
            "allow_lan": (
                "ExitNodeAllowLANAccess",
                "exit-node-allow-lan-access",
                False,
            ),
            "shields_up": ("ShieldsUp", "shields-up", False),
            "ssh": ("RunSSH", "ssh", False),
            "webclient": ("RunWebClient", "webclient", False),
            "snat": ("NoSNAT", "snat-subnet-routes", True),
            "stateful": ("NoStatefulFiltering", "stateful-filtering", True),
        }
        allowed = set(bools) | {
            "hostname",
            "exit_node",
            "advertise_exit",
            "routes",
            "netfilter",
        }
        if not isinstance(fields, dict) or not set(fields) <= allowed:
            raise Error("Неизвестный параметр настройки")
        fields = dict(fields)
        if fields.get("advertise_exit") is True:
            if fields.get("exit_node"):
                raise Error("Нельзя одновременно использовать и объявлять Exit node")
            if p.get("ExitNodeID"):
                fields["exit_node"] = ""
                fields["allow_lan"] = False
        elif fields.get("exit_node") and s["exit_advertised"]:
            fields["advertise_exit"] = False
        if fields.get("allow_lan") and not fields.get("exit_node", p.get("ExitNodeID")):
            raise Error("Доступ к LAN настраивается при выбранном Exit node")
        for key, value in fields.items():
            if key in bools:
                if type(value) is not bool:
                    raise Error("Ожидается переключатель: " + key)
                pref, flag, inverse = bools[key]
                old = not bool(p.get(pref)) if inverse else bool(p.get(pref))
                if old != value:
                    args.append("--" + flag + "=" + str(value).lower())
                    changes.append({"name": key, "before": old, "after": value})
            elif key == "hostname":
                if not isinstance(value, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", value
                ):
                    raise Error(
                        "Имя узла: латиница, цифры, точка и дефис, до 63 знаков"
                    )
                if value != p.get("Hostname"):
                    args.append("--hostname=" + value)
                    changes.append(
                        {
                            "name": "Имя узла",
                            "before": p.get("Hostname"),
                            "after": value,
                        }
                    )
            elif key == "netfilter":
                if value not in ["on", "nodivert", "off"]:
                    raise Error("Неверный режим netfilter")
                old = {0: "off", 1: "nodivert", 2: "on"}.get(p.get("NetfilterMode"))
                if old != value:
                    args.append("--netfilter-mode=" + value)
                    changes.append({"name": "Netfilter", "before": old, "after": value})
            elif key == "exit_node":
                if not isinstance(value, str):
                    raise Error("Неверный Exit node")
                node = next(
                    (
                        n
                        for n in s["peers"]
                        if value
                        and value in [n["ID"], *(n["TailscaleIPs"] or [])]
                        and n["ExitNodeOption"]
                    ),
                    None,
                )
                if value and not node:
                    raise Error("Узел не объявлен как доступный Exit node")
                if node and not node["Online"]:
                    raise Error("Выходной узел сейчас не в сети")
                wanted_id = node["ID"] if node else ""
                if wanted_id != (p.get("ExitNodeID") or ""):
                    address = (
                        next(
                            (x for x in node["TailscaleIPs"] if ":" not in x),
                            node["TailscaleIPs"][0],
                        )
                        if node
                        else ""
                    )
                    args.append("--exit-node=" + address)
                    changes.append(
                        {
                            "name": "Exit node",
                            "before": p.get("ExitNodeID") or "Не используется",
                            "after": node["HostName"] if node else "Не используется",
                        }
                    )
                    if node and "allow_lan" not in fields:
                        args.append("--exit-node-allow-lan-access=true")
                    if (
                        not node
                        and p.get("ExitNodeAllowLANAccess")
                        and "allow_lan" not in fields
                    ):
                        args.append("--exit-node-allow-lan-access=false")
            elif key == "advertise_exit":
                if type(value) is not bool:
                    raise Error("Неверный переключатель Exit node")
                if value != s["exit_advertised"]:
                    args.append("--advertise-exit-node=" + str(value).lower())
                    changes.append(
                        {
                            "name": "Раздавать интернет через этот роутер",
                            "before": s["exit_advertised"],
                            "after": value,
                        }
                    )
            elif key == "routes":
                if not isinstance(value, list) or len(value) > 64:
                    raise Error("Ожидается список из не более 64 подсетей")
                try:
                    nets = sorted(
                        set(
                            str(ipaddress.ip_network(x.strip(), strict=True))
                            for x in value
                        )
                    )
                except (ValueError, AttributeError):
                    raise Error(
                        "Подсети должны быть в виде 192.168.10.0/24 или fd00::/64"
                    )
                if any(ipaddress.ip_network(x).prefixlen == 0 for x in nets):
                    raise Error(
                        "Для маршрута по умолчанию используйте переключатель Exit node"
                    )
                old = sorted(
                    x
                    for x in (p.get("AdvertiseRoutes") or [])
                    if x not in ["0.0.0.0/0", "::/0"]
                )
                if nets != old:
                    preserved = [
                        x
                        for x in (p.get("AdvertiseRoutes") or [])
                        if x in ["0.0.0.0/0", "::/0"]
                    ]
                    args.append("--advertise-routes=" + ",".join(nets + preserved))
                    changes.append(
                        {"name": "Объявляемые подсети", "before": old, "after": nets}
                    )
        if "advertise_exit" in fields and "routes" in fields:
            raise Error("Сохраните подсети и режим Exit node отдельными действиями")
        return args, changes

    def apply_settings(self, fields, log):
        args, changes = self.set_args(fields)
        if args:
            log("Применение выбранных настроек")
            self.run("set", *args, timeout=40)
            self.invalidate()
        return {"changes": changes, "snapshot": self.snapshot(True)}


class Jobs:
    def __init__(self, state):
        self.state = pathlib.Path(state)
        self.path = self.state / "jobs"
        self.path.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def recover(self):
        for p in self.path.glob("*.json"):
            old = read_json(p)
            if old.get("state") == "running":
                old["state"] = "interrupted"
                old["error"] = (
                    "Панель была перезапущена. Проверьте состояние перед повтором."
                )
                write_json(p, old)

    def list(self):
        items = [read_json(p) for p in self.path.glob("*.json")]
        return sorted(items, key=lambda x: x.get("started_at", 0), reverse=True)[:30]

    def prune(self):
        items = [(p, read_json(p)) for p in self.path.glob("*.json")]
        items.sort(key=lambda pair: pair[1].get("started_at", 0), reverse=True)
        for p, item in items[100:]:
            if item.get("state") != "running":
                p.unlink(missing_ok=True)

    def get(self, jid):
        if not re.fullmatch(r"[0-9a-f]{24}", jid):
            raise Error("Задание не найдено", 404)
        p = self.path / (jid + ".json")
        if not p.exists():
            raise Error("Задание не найдено", 404)
        return read_json(p)

    def start(self, label, fn):
        if not self.lock.acquire(False):
            raise Error("Другая операция ещё выполняется", 409)
        try:
            self.prune()
            jid = secrets.token_hex(12)
            p = self.path / (jid + ".json")
            record = {
                "id": jid,
                "label": label,
                "state": "running",
                "started_at": time.time(),
                "log": [],
            }
            write_json(p, record)
        except Exception:
            self.lock.release()
            raise

        def worker():
            try:
                with operation_lock(self.state):

                    def log(text):
                        record["log"].append(
                            {"at": int(time.time()), "text": scrub(text)}
                        )
                        record["log"] = record["log"][-80:]
                        write_json(p, record)

                    record["result"] = fn(log)
                    record["state"] = "done"
            except Exception as e:
                record["state"] = "error"
                record["error"] = scrub(e)
            finally:
                record["finished_at"] = time.time()
                try:
                    write_json(p, record)
                finally:
                    self.lock.release()

        try:
            threading.Thread(target=worker, name="tailscale-panel-job", daemon=True).start()
        except Exception:
            try:
                record.update(state="error", error="Не удалось запустить операцию. Проверьте состояние перед повтором.", finished_at=time.time())
                with contextlib.suppress(OSError):
                    write_json(p, record)
            finally:
                self.lock.release()
            raise
        return record


@contextlib.contextmanager
def operation_lock(state):
    import fcntl

    path = pathlib.Path(state) / ".operation.lock"
    with path.open("a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("Выполняется другая операция Tailscale", 409)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def validate_server(url):
    if not isinstance(url, str) or len(url) > 300:
        raise Error("Неверный URL сервера")
    p = urllib.parse.urlsplit(url)
    if (
        p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.query
        or p.fragment
    ):
        raise Error("Укажите HTTPS-адрес сервера без логина, пароля и параметров")
    return url.rstrip("/")


def download(url, limit=160 * 1024 * 1024):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(
        urllib.request.Request(
            url, headers={"User-Agent": "TailScaleKeen/" + VERSION}
        ),
        timeout=35,
    ) as f:
        if urllib.parse.urlsplit(f.geturl()).scheme != "https":
            raise Error("Небезопасное перенаправление загрузки")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise Error("Превышен допустимый размер загрузки")
    return data
