"""Bounded, read-only support report built from an explicit privacy allowlist.

Never include raw preferences, status JSON, addresses, hostnames, control URLs,
notes, logs, environment variables, account names, hashes or keys in this report.
"""

import pathlib, re, shutil, stat, time
from .core import Error, VERSION, read_json


def version(value):
    match = re.match(r"^(\d{1,4}\.\d{1,4}\.\d{1,4})(?:\b|[-+])", str(value))
    return match[1] if match else ""


def inspect(service, root="/"):
    root = pathlib.Path(root)
    checks = []
    def add(key, label, ok, good, bad):
        checks.append({"id": key, "label": label, "state": "ok" if ok else "warn",
                       "detail": good if ok else bad})
    try:
        snap = service.ts.snapshot()
    except Error:
        snap = {"backend_state": "Unavailable", "online": False, "peers": [],
                "prefs": {}, "health": [], "version": ""}
    backend = snap.get("backend_state")
    if backend not in {"Running", "Stopped", "NeedsLogin", "NeedsMachineAuth", "Starting", "Unavailable", "NoState"}:
        backend = "Unknown"
    add("connected", "Подключение Tailscale", backend == "Running" and snap.get("online"),
        "Клиент подключён к сети", "Клиент отключён, не вошёл в сеть или ожидает соединения")
    add("client_health", "Предупреждения клиента", not snap.get("health"),
        "Tailscale не сообщает о проблемах", "Откройте системный монитор: клиент сообщает о проблемах")
    versions = {"panel": VERSION, "running": version(snap.get("version", ""))}
    for key, args in {"cli": ["/opt/bin/tailscale", "version"],
                      "daemon_file": ["/opt/bin/tailscaled", "--version"]}.items():
        try:
            result = service.runner.run(args, timeout=10, check=False)
            versions[key] = version(result.stdout.splitlines()[0]) if result.returncode == 0 and result.stdout else ""
        except Error:
            versions[key] = ""
    add("versions", "Версии клиента и демона", bool(versions["cli"]) and len({versions[k] for k in ["cli", "daemon_file", "running"]}) == 1,
        "CLI, файл демона и работающий клиент совпадают", "Версии различаются или компонент недоступен; проверьте обновление клиента")
    tun = service.native.tun
    tun_exists = bool(re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", tun)) and (root / "sys/class/net" / tun).is_dir()
    add("tun", "Сетевой интерфейс", tun_exists, "Интерфейс клиента существует", "Интерфейс клиента пока не создан")
    add("account", "Учётная запись панели", bool(read_json(service.state / "auth.json").get("password_hash")),
        "Настроена отдельная учётная запись", "Первоначальная настройка ещё не завершена")
    secure = True
    for path in [service.state, service.state / "auth.json", service.state / "config.json"]:
        try:
            mode = path.lstat().st_mode
            secure = secure and not stat.S_ISLNK(mode) and not mode & 0o077
        except OSError:
            secure = False
    add("permissions", "Доступ к файлам настроек", secure,
        "Каталог и учётные данные доступны только владельцу", "Проверьте права каталога и файлов через SSH")
    free = shutil.disk_usage(service.state).free
    add("space", "Место для обновлений", free >= 240 * 1024 * 1024,
        "Достаточно места для безопасного обновления клиента", "Для обновления клиента нужно 240 МиБ свободного места")
    resources = {"free_bytes": free, "panel_rss_bytes": None, "panel_threads": None}
    try:
        proc = (root / "proc/self/status").read_text()
        rss = re.search(r"^VmRSS:\s+(\d+) kB$", proc, re.M)
        threads = re.search(r"^Threads:\s+(\d+)$", proc, re.M)
        if rss: resources["panel_rss_bytes"] = int(rss[1]) * 1024
        if threads: resources["panel_threads"] = int(threads[1])
    except OSError:
        pass
    return {"schema": 1, "created_at": int(time.time()), "checks": checks,
            "versions": versions, "backend_state": backend,
            "network": {"peers": len(snap.get("peers", [])),
                        "online_peers": sum(bool(x.get("Online")) for x in snap.get("peers", [])),
                        "advertised_subnets": sum(x not in ["0.0.0.0/0", "::/0"] for x in snap.get("prefs", {}).get("AdvertiseRoutes") or []),
                        "health_warning_count": len(snap.get("health") or [])},
            "resources": resources,
            "privacy": "Без адресов, имён устройств, сервера управления, заметок, журналов и ключей"}
