"""Detached panel-only updater: pinned source, atomic swap, health check, rollback."""

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import time
from .core import Error, VERSION, operation_lock, read_json, write_json
from .releases import release_info, fetch_release


class PanelUpdater:
    def __init__(self, state):
        self.state = pathlib.Path(state)
        self.root = self.state / "panel-update"
        self.journal = self.root / "transaction.json"
        self.cache = None

    def status(self):
        r = read_json(self.journal)
        return {k: v for k, v in r.items() if k not in {"token", "files", "before_config", "before_manifest"}}

    def active(self):
        r = read_json(self.journal)
        return r.get("state") in {"prepared", "installing", "checking"}

    def recover(self):
        record = read_json(self.journal)
        if not self.active() or time.time() - record.get("started_at", time.time()) < 60:
            return
        pid = record.get("worker_pid")
        try:
            if type(pid) is int and b"panel.panel_update" in pathlib.Path("/proc", str(pid), "cmdline").read_bytes():
                return
        except OSError:
            pass
        record.update(state="error", message="Процесс обновления прерван. Проверьте версию и службу панели через SSH перед повтором.")
        record.pop("token", None)
        write_json(self.journal, record)

    def check(self, fresh=False):
        if not fresh and self.cache and time.time() - self.cache["checked_at"] < 300:
            return self.cache
        self.cache = release_info()
        return self.cache

    def prepare(self, log, version=None):
        if self.state.resolve() != pathlib.Path("/opt/etc/tailscale-panel").resolve():
            raise Error("Самообновление доступно только для установленной панели в штатном каталоге")
        if self.active():
            raise Error("Обновление панели уже запущено", 409)
        info = self.check(True)
        if version and info["latest"] != version:
            raise Error("Релиз изменился. Проверьте обновления ещё раз.", 409)
        if not info["available"]:
            return {"changed": False, "message": "Установлена актуальная версия панели"}
        if shutil.disk_usage(self.state).free < 64 * 1024 * 1024:
            raise Error("Для обновления панели требуется 64 МБ свободного места")
        self.root.mkdir(mode=0o700, exist_ok=True)
        candidate = self.root / "candidate"
        if candidate.exists():
            shutil.rmtree(candidate)
        log("Загрузка релиза TailScaleKeen " + info["latest"] + " и проверка SHA256")
        manifest = fetch_release(info, candidate)
        # Compile without executing any of the downloaded module top-level code.
        for p in (candidate / "panel").glob("*.py"):
            compile(p.read_bytes(), str(p), "exec")
        token = secrets.token_hex(16)
        record = {"id": secrets.token_hex(12), "token": token, "state": "prepared",
                  "from_version": VERSION, "version": info["latest"],
                  "files": manifest["files"],
                  "started_at": int(time.time()), "message": "Архив проверен, ожидается перезапуск панели"}
        write_json(self.journal, record)
        try:
            # Worker waits for the HTTP job's operation_lock; never restart from its own request thread.
            with open(os.devnull, "wb") as sink:
                worker = subprocess.Popen([sys.executable, "-m", "panel.panel_update", "--apply", "--state", str(self.state)],
                                 cwd=candidate, stdin=subprocess.DEVNULL, stdout=sink, stderr=sink,
                                 start_new_session=True, close_fds=True,
                                 env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            record["worker_pid"] = worker.pid
            write_json(self.journal, record)
        except Exception:
            record.update(state="error", message="Не удалось запустить обновление панели")
            write_json(self.journal, record)
            raise
        log("Панель будет перезапущена. Клиент Tailscale продолжит работу. После обновления войдите снова.")
        return {"panel_update": True, "transaction": record["id"], "version": info["latest"], "message": record["message"]}


def health(port, version, configured, timeout=25):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            c.request("GET", "/api/session")
            r = c.getresponse()
            data = json.loads(r.read(65536))
            if r.status == 200 and data.get("version") == version and data.get("configured") == configured:
                return True
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            c.close()
        time.sleep(0.5)
    return False


def apply_staged(state, token, root="/", control=None, probe=None):
    """root/control/probe permit a real filesystem rollback test without live services."""
    state = pathlib.Path(state)
    task = PanelUpdater(state)
    candidate = task.root / "candidate"
    prefix = pathlib.Path(root)
    target = prefix / "opt/share/tailscale-panel"
    stage = target.with_name(".tailscale-panel-new")
    previous = target.with_name(".tailscale-panel-previous")
    init = prefix / "opt/etc/init.d/S98tailscale-panel"
    control = control or (lambda action: subprocess.run([str(init), action], timeout=250, check=True))
    probe = probe or health
    record = read_json(task.journal)
    if record.get("token") != token or record.get("state") != "prepared":
        raise Error("Нет подготовленного обновления панели")
    # Verify the staged bytes independently of the network download.
    manifest = {str(p.relative_to(candidate)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in candidate.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    if manifest != record.get("files") or (candidate / "VERSION").read_text().strip() != record["version"]:
        record.update(state="error", message="Подготовленные файлы обновления изменились; установка не начиналась")
        record.pop("token", None)
        write_json(task.journal, record)
        raise Error("Подготовленные файлы обновления изменились")
    before = {}
    for name in ["config.json", "manifest.json", "auth.json", "account-state.json"]:
        p = state / name
        before[name] = p.read_bytes() if p.exists() else None
    configured = bool(read_json(state / "auth.json").get("password_hash"))
    config = read_json(state / "config.json")
    port = int(config.get("port", 8092))
    extras = [init, prefix / "opt/bin/tailscale-panel", prefix / "opt/bin/tailscalekeen"]
    extra_before = {p: (p.read_bytes(), p.stat().st_mode & 0o777) if p.exists() else None for p in extras}
    stopped = swapped = moved_previous = False
    try:
        record.update(state="installing", message="Установка проверенного кода панели")
        write_json(task.journal, record)
        control("stop")
        stopped = True
        if stage.exists():
            shutil.rmtree(stage)
        shutil.copytree(candidate, stage)
        if previous.exists():
            shutil.rmtree(previous)
        if target.exists():
            os.rename(target, previous)
            moved_previous = True
        os.rename(stage, target)
        swapped = True
        from .install import install_launchers
        install_launchers(prefix, target)
        config["version"] = record["version"]
        write_json(state / "config.json", config)
        installed = read_json(state / "manifest.json")
        installed["version"] = record["version"]
        write_json(state / "manifest.json", installed)
        record.update(state="checking", message="Проверка новой панели")
        write_json(task.journal, record)
        control("start")
        if not probe(port, record["version"], configured):
            raise Error("Новая панель не прошла проверку запуска")
        for name in ["auth.json", "account-state.json"]:
            p = state / name
            if (p.read_bytes() if p.exists() else None) != before[name]:
                raise Error("Учётная запись изменилась во время обновления")
        record.update(state="done", message="Панель обновлена, настройки и клиент сохранены", finished_at=int(time.time()))
    except Exception as exc:
        if stopped:
            with contextlib.suppress(Exception):
                control("stop")
        if swapped or moved_previous:
            if target.exists():
                shutil.rmtree(target)
            if moved_previous and previous.exists():
                os.rename(previous, target)
            for name in ["config.json", "manifest.json"]:
                p = state / name
                if before[name] is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_bytes(before[name]); p.chmod(0o600)
            for p, old in extra_before.items():
                if old is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_bytes(old[0]); p.chmod(old[1])
        restored = False
        if stopped:
            with contextlib.suppress(Exception):
                control("start")
                restored = probe(port, record["from_version"], configured)
        record.update(state="rolled_back" if restored else "error", finished_at=int(time.time()),
                      message="Обновление отменено; прежняя панель восстановлена" if restored else "Обновление не завершено; проверьте службу через SSH",
                      error=type(exc).__name__)
    finally:
        record.pop("token", None)
        write_json(task.journal, record)
        if record.get("state") in {"done", "rolled_back"}:
            shutil.rmtree(candidate, ignore_errors=True)
    return task.status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Error("Нужны права root")
    state = pathlib.Path(args.state)
    if state.resolve() != pathlib.Path("/opt/etc/tailscale-panel").resolve():
        raise Error("Обновление вне штатного каталога запрещено")
    token = read_json(state / "panel-update/transaction.json").get("token")
    if not isinstance(token, str) or len(token) != 32:
        raise Error("Нет подготовленного обновления")
    # Let the scheduling HTTP job finish before stopping the server.
    until = time.monotonic() + 60
    while True:
        try:
            with operation_lock(state):
                pass
            break
        except Error:
            if time.monotonic() >= until:
                raise
            time.sleep(0.25)
    try:
        apply_staged(state, token)
    except Exception as exc:
        task = PanelUpdater(state)
        record = read_json(task.journal)
        if record.get("token") == token:
            record.update(state="error", message="Обновление не началось; проверьте состояние панели через SSH", error=type(exc).__name__)
            record.pop("token", None)
            write_json(task.journal, record)


if __name__ == "__main__":
    main()
