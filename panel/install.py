"""Install a bundled release and register its Tailscale tunnel in KeeneticOS."""

import argparse, hashlib, io, json, os, pathlib, re, secrets, shutil, socket, subprocess, tarfile, time
from .core import Error, Runner, VERSION, download, read_json, write_json
from .native import Native, blocks

TS_BASE = "https://pkgs.tailscale.com/stable/"


def at(root, path):
    return pathlib.Path(root) / path.lstrip("/")


def require_space(root, megabytes):
    folder = at(root, "/opt")
    if not folder.exists():
        folder = pathlib.Path(root)
    if shutil.disk_usage(folder).free < megabytes * 1024 * 1024:
        raise Error("Недостаточно места в Entware: требуется не менее " + str(megabytes) + " МБ")


def install_launchers(root, source):
    for command in ["tailscalekeen", "tailscale-panel"]:
        wrapper = at(root, "/opt/bin/" + command)
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text('#!/bin/sh\nexport PYTHONDONTWRITEBYTECODE=1\ncd /opt/share/tailscale-panel || exit 1\nexec /opt/bin/python3 -m panel.manage "$@"\n')
        wrapper.chmod(0o755)
    init = at(root, "/opt/etc/init.d/S98tailscale-panel")
    init.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pathlib.Path(source) / "scripts/S98tailscale-panel", init)
    init.chmod(0o755)


def init_tun(init):
    """Read a literal TUN from the supported Entware service without executing it."""
    script = "\n".join(line for line in init.read_text().splitlines() if not line.lstrip().startswith("#"))
    values = set(re.findall(r"""(?<![\w-])--tun(?:=|[ \t]+)["']?([^\s"';\\]+)""", script))
    if len(values) != 1:
        raise Error("Не удалось однозначно определить TUN существующей службы S06tailscaled")
    value = values.pop()
    if not re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", value):
        raise Error("Неподдерживаемый TUN существующей службы S06tailscaled")
    return value


def running_tun(root="/"):
    """Identify exactly one running Entware-managed daemon before any stop/start."""
    processes = []
    for directory in at(root, "/proc").glob("[0-9]*"):
        try:
            if (directory / "comm").read_text().strip() != "tailscaled":
                continue
            args = (directory / "cmdline").read_bytes().decode().split("\0")
            exe = os.readlink(directory / "exe").removesuffix(" (deleted)")
            processes.append((args, exe))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, UnicodeError) as exc:
            raise Error("Не удалось проверить работающий процесс tailscaled") from exc
    if not processes:
        return None
    if len(processes) != 1:
        raise Error("Найдено несколько tailscaled; автоматическая установка остановлена")
    args, exe = processes[0]
    init = at(root, "/opt/etc/init.d/S06tailscaled")
    if pathlib.Path(exe).resolve() != at(root, "/opt/bin/tailscaled").resolve() or not init.is_file():
        raise Error("Существующий клиент использует неподдерживаемую схему запуска")
    flags = set()
    for i, arg in enumerate(args):
        if arg.startswith("--tun="):
            flags.add(arg.split("=", 1)[1])
        elif arg == "--tun":
            flags.add(args[i + 1] if i + 1 < len(args) else "")
    expected = init_tun(init)
    if flags != {expected}:
        raise Error("TUN службы S06tailscaled не совпадает с работающим клиентом")
    return expected


def detect_tun(config, root="/"):
    """Adopt one supported daemon or choose an unused native TUN for a clean install."""
    init = at(root, "/opt/etc/init.d/S06tailscaled")
    detected = running_tun(root)
    if not init.is_file() and any(at(root, p).exists() for p in ["/opt/bin/tailscale", "/opt/bin/tailscaled", "/opt/sbin/tailscale", "/opt/sbin/tailscaled"]):
        raise Error("Клиент найден без поддерживаемой службы S06tailscaled; автоматическая замена остановлена")
    if detected is None and init.is_file():
        detected = init_tun(init)
    value = config.get("tun") or detected
    if config.get("tun") and detected and config["tun"] != detected:
        raise Error("TUN панели не совпадает с работающим клиентом")
    if value and not re.fullmatch(r"opkgtun(?:[0-9]|1[0-5])", value):
        raise Error("Поддерживаются только OpkgTun0…OpkgTun15")
    if detected:
        return value
    p = Runner().run(["ndmc", "-c", "show running-config"], check=False)
    used = blocks(p.stdout)
    if p.returncode or not used:
        raise Error("Не удалось прочитать интерфейсы KeeneticOS для выбора свободного OpkgTun")
    for index in range(16):
        tun = "opkgtun" + str(index)
        if value and value != tun:
            continue
        if "OpkgTun" + str(index) not in used and not at(root, "/sys/class/net/" + tun).exists():
            return tun
    if value:
        raise Error("Сохранённый TUN уже занят, а служба Tailscale не найдена: " + value)
    raise Error("Свободный OpkgTun не найден")


def ensure_client_running(init, expected):
    actual = running_tun()
    if actual is None:
        Runner().run([str(init), "start"], timeout=65)
        for _ in range(20):
            actual = running_tun()
            if actual is not None:
                break
            time.sleep(0.25)
    if actual != expected:
        raise Error("Не подтверждён запуск tailscaled с интерфейсом " + expected)


def extract_client(blob, destination):
    destination.mkdir(parents=True, exist_ok=True)
    binaries = {"tailscale", "tailscaled"}
    found = set()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r|*") as archive:
        for entry in archive:
            name = pathlib.PurePosixPath(entry.name).name
            if name not in binaries:
                continue
            if not entry.isfile() or name in found:
                raise Error("Неожиданный состав архива клиента")
            p = destination / name
            with archive.extractfile(entry) as member, p.open("wb") as output:
                shutil.copyfileobj(member, output, length=256 * 1024)
            p.chmod(0o755)
            found.add(name)
    if found != binaries:
        raise Error("Неожиданный состав архива клиента")


def client(root, archive_path=None, tun="opkgtun0"):
    target = at(root, "/opt/bin")
    current = target / "tailscale"
    meta = json.loads(download(TS_BASE + "?mode=json", 1024 * 1024))
    v = meta["TarballsVersion"]
    name = meta["Tarballs"]["arm64"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", v) or name != "tailscale_" + v + "_arm64.tgz":
        raise Error("Неверный каталог Tailscale")
    if current.exists() and (target / "tailscaled").exists():
        p = subprocess.run(
            [str(current), "version"], capture_output=True, text=True, timeout=15
        )
        daemon = subprocess.run([str(target / "tailscaled"), "--version"], capture_output=True, text=True, timeout=15)
        if p.returncode == 0 and p.stdout.splitlines()[:1] == [v] and daemon.returncode == 0 and daemon.stdout.splitlines()[:1] == [v]:
            return {"version": v, "changed": False}
    if root == "/" and current.exists():
        # Reuse the same transactional updater as the panel, keeping an existing state/identity.
        from .core import Runner, Tailscale
        from .native import Native
        from .updates import Updater

        state = at(root, "/opt/etc/tailscale-panel")
        runner = Runner()
        ts = Tailscale(runner)
        return Updater(state, ts, Native(state, runner, tun), runner).update(
            lambda x: print(x, flush=True), force=True
        )
    require_space(root, 240)
    blob = pathlib.Path(archive_path).read_bytes() if archive_path else download(TS_BASE + name)
    h = hashlib.sha256(blob).hexdigest()
    checksum = download(TS_BASE + name + ".sha256", 8192).decode().strip()
    if not re.fullmatch(r"[a-fA-F0-9]{64}(?:\s+\*?" + re.escape(name) + r")?", checksum) or h != checksum.split()[0].lower():
        raise Error("SHA256 клиента не совпадает")
    stage = at(root, "/opt/tmp/tailscale-panel-client-stage")
    stage.mkdir(parents=True, exist_ok=True)
    extract_client(blob, stage)
    target.mkdir(parents=True, exist_ok=True)
    for name in ["tailscale", "tailscaled"]:
        p = target / name
        tmp = p.with_name("." + name + ".new")
        shutil.copy2(stage / name, tmp)
        os.replace(tmp, p)
    shutil.rmtree(stage)
    return {"version": v, "changed": True, "archive_sha256": h}


def install(
    source, root="/", auth_source=None, port=8092, no_start=False, archive=None, panel_only=False
):
    from .core import operation_lock

    state = at(root, "/opt/etc/tailscale-panel")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with operation_lock(state):
        return _install(source, root, auth_source, port, no_start, archive, panel_only)


def _install(
    source, root="/", auth_source=None, port=8092, no_start=False, archive=None, panel_only=False
):
    source = pathlib.Path(source).resolve()
    if root != "/":
        root = str(pathlib.Path(root).resolve())
    target = at(root, "/opt/share/tailscale-panel")
    state = at(root, "/opt/etc/tailscale-panel")
    if (
        not (source / "panel/server.py").is_file()
        or not (source / "web/app.js").is_file()
    ):
        raise Error("Неполный дистрибутив панели")
    if root == "/" and os.uname().machine not in ["aarch64", "arm64"]:
        raise Error("Требуется Entware aarch64-k3.10")
    if not 1024 <= port <= 65535:
        raise Error("Порт должен быть в диапазоне 1024–65535")
    require_space(root, 64)
    if root == "/" and not (state / "config.json").exists():
        with socket.socket() as s:
            s.bind(("0.0.0.0", port))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    config = read_json(state / "config.json")
    if root == "/":
        config["tun"] = detect_tun(config)
    from .panel_update import PanelUpdater
    if PanelUpdater(state).active():
        raise Error("Сначала дождитесь завершения обновления панели", 409)
    manifest = read_json(
        state / "manifest.json", {"schema": 1, "created": [], "adopted": []}
    )
    if auth_source:
        raise Error(
            "У панели теперь отдельная учётная запись. Устанавливайте без --auth-source."
        )
    legacy_auth = bool(config.pop("auth_source", None))
    config.update(
        {
            "port": config.get("port", port),
            "bind": config.get("bind", "0.0.0.0"),
            "tun": config.get("tun", "opkgtun0"),
            "version": VERSION,
        }
    )
    config.setdefault(
        "managed_policy_sync",
        not any(
            at(root, p).is_file()
            for p in [
                "/opt/etc/init.d/S07tailscale-policy",
                "/opt/etc/ndm/netfilter.d/95-tailscale-policy.sh",
                "/opt/etc/ndm/netfilter.d/99-tailscale.sh",
            ]
        ),
    )
    for p in [
        "/opt/etc/init.d/S06tailscaled",
        "/opt/etc/init.d/S07tailscale-policy",
        "/opt/etc/ndm/netfilter.d/95-tailscale-policy.sh",
        "/opt/etc/ndm/netfilter.d/99-tailscale.sh",
    ]:
        file = at(root, p)
        if file.is_file() and p not in manifest["created"] and p not in manifest["adopted"]:
            manifest["adopted"].append(p)
    if panel_only and not at(root, "/opt/bin/tailscale").is_file():
        raise Error("Для --panel-only нужен установленный клиент Tailscale")
    client_result = {"changed": False, "preserved": True} if panel_only else client(root, archive, config["tun"])
    init = at(root, "/opt/etc/init.d/S06tailscaled")
    if not init.exists():
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_text(
            '#!/bin/sh\nENABLED=yes\nPROCS=tailscaled\nARGS="--state=/opt/var/tailscaled.state --statedir=/opt/var/lib/tailscale --tun=' + config["tun"] + '"\nPREARGS="nohup"\nDESC=$PROCS\nPATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin\n. /opt/etc/init.d/rc.func\n'
        )
        init.chmod(0o755)
        manifest["created"].append("/opt/etc/init.d/S06tailscaled")
        write_json(state / "manifest.json", manifest)
    if root == "/":
        native = Native(state, tun=config["tun"])
        native.create(native.default_fields(), lambda message: print(message, flush=True))
        print("Подключение KeeneticOS: " + native.name, flush=True)
        if not no_start:
            ensure_client_running(init, config["tun"])
    write_json(state / "config.json", config)
    if source != target:
        stage = at(root, "/opt/share/.tailscale-panel-new")
        previous = at(root, "/opt/share/.tailscale-panel-previous")
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, exist_ok=True)
        for name in ["panel", "web", "scripts"]:
            shutil.copytree(
                source / name,
                stage / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        for name in [
            "install.sh",
            "README.ru.md",
            "README.md",
            "CHANGELOG.md",
            "SECURITY.md",
            "THIRD_PARTY.md",
            "LICENSE",
            "VERSION",
        ]:
            if (source / name).is_file():
                shutil.copy2(source / name, stage / name)
        if target.exists():
            if root == "/":
                subprocess.run(
                    ["/opt/etc/init.d/S98tailscale-panel", "stop"],
                    timeout=250,
                    check=True,
                )
            if previous.exists():
                shutil.rmtree(previous)
            os.rename(target, previous)
        os.rename(stage, target)
    install_launchers(root, source)
    if config.get("managed_policy_sync"):
        from .integration import Integration
        from .core import Runner
        Integration(state, Runner(), config["tun"], root).install_hook()
    from .accounts import Accounts

    if legacy_auth:
        Accounts(state).reset(locked=True)
    else:
        Accounts(state).ensure(locked=True)
    for path in [
        "/opt/share/tailscale-panel",
        "/opt/etc/tailscale-panel",
        "/opt/bin/tailscale-panel",
        "/opt/bin/tailscalekeen",
        "/opt/etc/init.d/S98tailscale-panel",
    ]:
        if path not in manifest["created"]:
            manifest["created"].append(path)
    manifest["client"] = client_result
    manifest["version"] = VERSION
    write_json(state / "manifest.json", manifest)
    if root == "/" and not no_start:
        subprocess.run(
            ["/opt/etc/init.d/S98tailscale-panel", "start"], timeout=35, check=True
        )
    print(
        json.dumps(
            {
                "installed": True,
                "panel_version": VERSION,
                "port": config["port"],
                "client": client_result,
                "auth_source": "local",
                "root": root,
            }
        ),
        flush=True,
    )
    return client_result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--root", default="/")
    p.add_argument("--auth-source")
    p.add_argument("--port", type=int, default=8092)
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--client-archive")
    p.add_argument("--panel-only", action="store_true")
    a = p.parse_args()
    try:
        install(a.source, a.root, a.auth_source, a.port, a.no_start, a.client_archive, a.panel_only)
    except Error as exc:
        p.exit(1, f"Установка TailScaleKeen остановлена. {exc}\n")


if __name__ == "__main__":
    main()
