"""Migrate two recognized legacy KGTS helper builds; leave other helpers alone.

The installed helper remains standalone. No LAN, exit node, table or mark is
copied from another router, and no runtime configuration belongs in this module.
"""
import hashlib, inspect, json, os, pathlib, re, tempfile, time
from .core import Error, Runner, read_json, write_json

POLICY = "/opt/etc/tailscale/policy.py"
INIT = "/opt/etc/init.d/S07tailscale-policy"
CONFIG = "/opt/etc/tailscale/integration.json"
OLD_POLICY = "42bdd40e2e32646c0c3a0e9281a6e7c4029c14ee2e9983e3b5fb947094e17591"
FIXED_POLICY = "03701380179354040876d672751ec67c226bd1ede0cf942d922623bba25fb949"
OLD_INIT = "8a70c53dabefea61dc846d1f27602af3bdc28df427af2a512cb5365d3b876c37"
FIXED_INIT = "75b9c173d05505a6f2d46d9572d3c44a170f545decf1cd5de68ecd6472fe3952"
NEEDLE = "p=json.load(urllib.request.urlopen('http://localhost:79/rci/show/ip/policy',timeout=8))[CFG['native_policy']]"


def policy_metadata(text, name):
    """Parse one named NDM policy; fail before any route command on ambiguity."""
    import re
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
        raise ValueError("Invalid native policy name")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    selected = []
    for section in re.split(r"^\s*policy, name = ", text, flags=re.M)[1:]:
        header, *lines = section.splitlines()
        match = re.fullmatch(r"([A-Za-z0-9_]+), description = (.*):\s*", header)
        if match and match[1] == name:
            selected.append((match[2], "\n".join(lines)))
    if len(selected) != 1:
        raise ValueError("Native policy missing or ambiguous")
    description, body = selected[0]
    tables = re.findall(r"^\s*table4:\s*(\d+)\s*$", body, re.M)
    marks = re.findall(r"^\s*mark:\s*((?:0x)?[0-9a-fA-F]+)\s*$", body, re.M)
    if len(tables) != 1 or len(marks) != 1:
        raise ValueError("Native policy metadata missing or ambiguous")
    table, mark = int(tables[0]), int(marks[0], 16)
    if not 1 <= table < 2**31 or not 0 <= mark < 2**32:
        raise ValueError("Native policy metadata out of range")
    return {"description": description, "table4": table, "mark": mark}


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def replace(path, blob, mode):
    fd, name = tempfile.mkstemp(prefix=".tailscalekeen-legacy-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.chmod(name, mode)
            f.write(blob); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        pathlib.Path(name).unlink(missing_ok=True)


class LegacyPolicy:
    def __init__(self, state, root="/", runner=None, control=None):
        self.state, self.root = pathlib.Path(state), pathlib.Path(root)
        self.runner = runner or Runner()
        self.paths = {"policy": self.root / POLICY.lstrip("/"), "init": self.root / INIT.lstrip("/")}
        self.directory = self.state / "legacy-policy-backup"
        self.journal = self.state / "legacy-policy-migration.json"
        self.control = control or self.service

    def service(self, action):
        if self.root != pathlib.Path("/"):
            return
        self.runner.run([INIT, action], timeout=25)
        if action == "stop":
            pid = pathlib.Path("/tmp/tailscale-policy.pid")
            if not pid.exists():
                return
            value = pid.read_text().strip()
            if not re.fullmatch(r"[0-9]+", value):
                raise Error("Не удалось проверить остановку старой интеграции")
            until = time.monotonic() + 6
            while True:
                try:
                    args = pathlib.Path("/proc", value, "cmdline").read_bytes().split(b'\0')
                except OSError:
                    break
                if POLICY.encode() not in args:
                    break
                if time.monotonic() >= until:
                    raise Error("Старый процесс интеграции не завершился")
                time.sleep(0.2)

    def restore(self, record):
        # Never overwrite an administrator's edit made after migration began.
        for name, path in self.paths.items():
            if digest(path.read_bytes()) not in {record["before"][name], record["after"][name]}:
                raise Error("Скрипт старой интеграции изменился; требуется проверка через SSH")
            if digest((self.directory / name).read_bytes()) != record["before"][name]:
                raise Error("Резервная копия старой интеграции повреждена")
        self.control("stop")
        for name, path in self.paths.items():
            replace(path, (self.directory / name).read_bytes(), record["modes"][name])
        self.control("start")

    def verify_started(self, started, metadata, timeout=6):
        until = time.monotonic() + timeout
        runtime = self.root / "tmp"
        while True:
            try:
                pid = (runtime / "tailscale-policy.pid").read_text().strip()
                if not re.fullmatch(r"[0-9]+", pid):
                    raise ValueError("Invalid service PID")
                args = (self.root / "proc" / pid / "cmdline").read_bytes().split(b'\0')
                statusfile = runtime / "tailscale-policy.status"
                status = read_json(statusfile)
                error = runtime / "tailscale-policy.last-error"
                if (POLICY.encode() in args and statusfile.stat().st_mtime >= started
                        and status.get("native_table") == metadata["table4"]
                        and status.get("native_mark") == metadata["mark"]
                        and (not error.exists() or error.stat().st_mtime < started)):
                    return
            except (OSError, ValueError, Error):
                pass
            if time.monotonic() >= until:
                raise Error("Не подтверждён запуск исправленной старой интеграции")
            time.sleep(0.2)

    def migrate(self):
        if any(not p.is_file() or p.is_symlink() or p.stat().st_size > 64*1024 for p in self.paths.values()):
            return {"state": "not_applicable"}
        old = {name: p.read_bytes() for name, p in self.paths.items()}
        hashes = {name: digest(b) for name, b in old.items()}
        record = read_json(self.journal)
        if record.get("state") == "pending":
            self.restore(record)
            record.update(state="rolled_back"); write_json(self.journal, record)
            return self.migrate()
        if record.get("state") == "done" and hashes == record.get("after"):
            return {"state": "already_compatible"}
        if hashes == {"policy": FIXED_POLICY, "init": FIXED_INIT}:
            return {"state": "already_compatible"}
        if hashes["policy"] not in {OLD_POLICY, FIXED_POLICY} or hashes["init"] != OLD_INIT:
            return {"state": "unrecognized_preserved"}
        config = read_json(self.root / CONFIG.lstrip("/"))
        result = self.runner.run(["ndmc", "-c", "show ip policy"], timeout=15)
        metadata = policy_metadata(result.stdout, config.get("native_policy"))
        source = old["policy"].decode("utf-8")
        if hashes["policy"] == OLD_POLICY:
            if source.count(NEEDLE) != 1 or source.count("def sync():") != 1:
                raise Error("Неожиданный формат старого скрипта")
            helper = inspect.getsource(policy_metadata) + "\ndef native_policy():\n return policy_metadata(run(['ndmc','-c','show ip policy']).stdout, CFG['native_policy'])\n\n"
            source = source.replace("def sync():", helper + "def sync():", 1).replace(NEEDLE, "p=native_policy()")
        init = old["init"].decode("utf-8")
        if init.count(' start|restart)\n') != 1 or init.count(' stop)\n') != 1:
            raise Error("Неожиданный формат старой службы")
        # The old stop branch already checks the exact helper process. Stop and
        # wait here; unlike its old restart alias, never launch over the old PID.
        init = init.replace(' start|restart)\n', ' start)\n', 1)
        restart = ''' restart)
  "$0" stop || exit $?
  _ts_policy_pid="$(cat /tmp/tailscale-policy.pid 2>/dev/null)"
  case "$_ts_policy_pid" in
   *[!0-9]*|'') ;;
   *)
    _ts_policy_wait=0
    while [ -r "/proc/$_ts_policy_pid/cmdline" ] && tr '\\0' ' ' < "/proc/$_ts_policy_pid/cmdline" | grep -Fq '/opt/etc/tailscale/policy.py'; do
     [ "$_ts_policy_wait" -lt 5 ] || exit 1
     sleep 1
     _ts_policy_wait=$((_ts_policy_wait + 1))
    done
   ;;
  esac
  "$0" start
 ;;
 stop)
'''
        init = init.replace(' stop)\n', restart, 1)
        compile(source, POLICY, "exec")
        new = {"policy": source.encode(), "init": init.encode()}
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        record = {"state": "pending", "before": hashes, "after": {n: digest(b) for n,b in new.items()},
                  "modes": {n: p.stat().st_mode & 0o777 for n,p in self.paths.items()}}
        for name, blob in old.items():
            replace(self.directory / name, blob, 0o600)
        write_json(self.journal, record)
        try:
            self.control("stop")
            started = time.time()
            for name, path in self.paths.items():
                if digest(path.read_bytes()) != hashes[name]:
                    raise Error("Старая интеграция изменилась во время установки")
                replace(path, new[name], record["modes"][name])
            self.control("start")
            if self.root == pathlib.Path("/"):
                self.verify_started(started, metadata)
            record["state"] = "done"; write_json(self.journal, record)
        except Exception:
            self.restore(record)
            record["state"] = "rolled_back"; write_json(self.journal, record)
            raise
        return {"state": "migrated", "rci_dependency_removed": True, "restart_fixed": True}


def migrate(state, root="/", runner=None, live=True):
    """An unrelated helper must never prevent installation of the panel."""
    if not live:
        return {"state": "deferred"}
    try:
        return LegacyPolicy(state, root, runner).migrate()
    except Exception as exc:
        return {"state": "needs_review", "error": type(exc).__name__}
