import hashlib, io, json, os, pathlib, platform, re, shutil, tarfile, tempfile, time
from .core import Error, download, read_json, write_json

BASE = "https://pkgs.tailscale.com/stable/"


class Updater:
    def __init__(self, state, ts, native, runner):
        self.state = pathlib.Path(state)
        self.ts = ts
        self.native = native
        self.runner = runner

    def check(self):
        meta = json.loads(download(BASE + "?mode=json", 1024 * 1024))
        version = meta.get("TarballsVersion", "")
        archive = meta.get("Tarballs", {}).get("arm64", "")
        if (
            not re.fullmatch(r"\d+\.\d+\.\d+", version)
            or archive != "tailscale_" + version + "_arm64.tgz"
        ):
            raise Error("Неожиданный формат официального каталога Tailscale")
        current = self.ts.run("version", check=False).stdout.splitlines()
        current = current[0] if current else ""
        return {
            "current": current,
            "latest": version,
            "available": current != version,
            "archive": archive,
            "source": BASE,
            "checked_at": int(time.time()),
        }

    def update(self, log, force=False):
        info = self.check()
        if not info["available"] and not force:
            return {
                "message": "Уже установлен последний стабильный клиент",
                "version": info["latest"],
                "changed": False,
            }
        if platform.machine().lower() not in ["aarch64", "arm64"]:
            raise Error("Эта сборка установщика поддерживает aarch64/arm64")
        if shutil.disk_usage(self.state).free < 240 * 1024 * 1024:
            raise Error(
                "Для безопасного обновления требуется не менее 240 МиБ свободного места"
            )
        before = None
        try:
            before = self.ts.snapshot(True)
        except Error:
            pass
        states = [
            pathlib.Path(p)
            for p in [
                "/opt/var/tailscaled.state",
                "/opt/var/lib/tailscale/tailscaled.state",
                "/opt/var/tailscale/tailscaled.state",
            ]
            if pathlib.Path(p).is_file()
        ]

        def fingerprint():
            return {
                str(p): hashlib.sha256(
                    str(read_json(p).get("_machinekey", "")).encode()
                ).hexdigest()
                for p in states
                if read_json(p).get("_machinekey")
            }

        identity = fingerprint()
        if before and before["self"].get("ID") and not identity:
            raise Error(
                "Не найден файл идентичности существующего клиента. Обновление остановлено до замены файлов."
            )
        policies = self.native.linked_policies()
        log("Получение официального клиента " + info["latest"])
        blob = download(BASE + info["archive"])
        checksum = download(BASE + info["archive"] + ".sha256", 8192).decode().strip()
        h = hashlib.sha256(blob).hexdigest()
        if not re.fullmatch(r"[a-fA-F0-9]{64}(?:\s+\*?" + re.escape(info["archive"]) + r")?", checksum) or h != checksum.split()[0].lower():
            raise Error("Контрольная сумма архива Tailscale не совпадает")
        root = self.state / "client-update"
        root.mkdir(exist_ok=True)
        candidate = root / "candidate"
        candidate.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(blob)) as t:
            for name in ["tailscale", "tailscaled"]:
                members = [
                    m
                    for m in t
                    if pathlib.PurePosixPath(m.name).name == name and m.isfile()
                ]
                if len(members) != 1:
                    raise Error("Неверный состав архива Tailscale")
                p = candidate / name
                p.write_bytes(t.extractfile(members[0]).read())
                p.chmod(0o755)
        if (
            self.runner.run(
                [str(candidate / "tailscale"), "version"]
            ).stdout.splitlines()[0]
            != info["latest"]
        ):
            raise Error("Версия в архиве не совпадает с каталогом")
        saved = root / "previous"
        saved.mkdir(exist_ok=True)
        had = {}
        saved_states = {}
        for i, p in enumerate(states):
            q = saved / ("state-" + str(i) + ".private.json")
            shutil.copy2(p, q)
            q.chmod(0o600)
            saved_states[p] = q
        for name in ["tailscale", "tailscaled"]:
            p = pathlib.Path("/opt/bin") / name
            had[name] = p.exists()
            if p.exists():
                shutil.copy2(p, saved / name)
        init = "/opt/etc/init.d/S06tailscaled"
        log("Клиент проверен, установка с сохранением ключа устройства")
        self.runner.run([init, "stop"], timeout=65, check=False)
        if self.runner.run(["pidof", "tailscaled"], check=False).stdout.strip():
            raise Error(
                "Не удалось остановить прежний daemon; файлы клиента не заменены"
            )
        try:
            for name in ["tailscale", "tailscaled"]:
                p = pathlib.Path("/opt/bin") / name
                tmp = p.with_name("." + name + ".panel-new")
                shutil.copy2(candidate / name, tmp)
                tmp.chmod(0o755)
                os.replace(tmp, p)
            self.runner.run([init, "start"], timeout=65)
            after = self.wait_ready(before)
            if after.get("version", "").split("-")[0] != info["latest"]:
                raise Error("Daemon не перешёл на новую версию; выполняется откат")
            pid = self.runner.run(["pidof", "tailscaled"]).stdout.strip()
            if (
                not pid.isdecimal()
                or hashlib.sha256(
                    pathlib.Path("/proc/" + pid + "/exe").read_bytes()
                ).hexdigest()
                != hashlib.sha256(
                    pathlib.Path("/opt/bin/tailscaled").read_bytes()
                ).hexdigest()
            ):
                raise Error("Работающий daemon не совпадает с новым бинарником")
            if fingerprint() != identity:
                raise Error("Ключ устройства изменился; выполняется откат")
            if before:
                if before["self"].get("ID") != after["self"].get("ID") or before[
                    "self"
                ].get("TailscaleIPs") != after["self"].get("TailscaleIPs"):
                    raise Error("Идентичность узла изменилась; выполняется откат")
                if before["prefs"] != after["prefs"]:
                    raise Error("Настройки клиента изменились; выполняется откат")
            self.native.sync_policies(
                policies, bool((after or {}).get("prefs", {}).get("ExitNodeID"))
            )
        except Exception:
            self.runner.run([init, "stop"], timeout=65, check=False)
            for p, q in saved_states.items():
                tmp = p.with_name("." + p.name + ".restore")
                shutil.copy2(q, tmp)
                os.replace(tmp, p)
            for name in ["tailscale", "tailscaled"]:
                p = pathlib.Path("/opt/bin") / name
                if had[name]:
                    tmp = p.with_name("." + name + ".restore")
                    shutil.copy2(saved / name, tmp)
                    os.replace(tmp, p)
                else:
                    p.unlink(missing_ok=True)
            self.runner.run([init, "start"], timeout=65, check=False)
            self.ts.invalidate()
            raise
        finally:
            shutil.rmtree(candidate, ignore_errors=True)
        write_json(
            root / "receipt.json",
            {
                "version": info["latest"],
                "archive_sha256": h,
                "installed_at": int(time.time()),
            },
        )
        log("Обновление завершено, настройки сохранены")
        return {"changed": True, "version": info["latest"], "archive_sha256": h}

    def wait_ready(self, before):
        for _ in range(35):
            self.ts.invalidate()
            try:
                s = self.ts.snapshot(True)
                if (
                    not before
                    or before["backend_state"] != "Running"
                    or s["backend_state"] == "Running"
                    and s["online"]
                ):
                    return s
            except Error:
                pass
            time.sleep(2)
        raise Error("Клиент не вернулся в рабочее состояние")
