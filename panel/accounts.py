"""Independent local account and root-only first-run recovery."""

import hashlib, hmac, pathlib, re, secrets, contextlib
from .core import Error, read_json, write_json, operation_lock


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 600000
    ).hex()
    return "pbkdf2:sha256:600000$" + salt + "$" + digest


def password_check(stored, password):
    if (
        not isinstance(stored, str)
        or not isinstance(password, str)
        or len(password) > 256
    ):
        return False
    try:
        method, salt, digest = stored.split("$")
        parts = method.split(":")
        if (
            parts[:2] == ["pbkdf2", "sha256"]
            and len(parts) == 3
            and 100000 <= int(parts[2]) <= 2000000
        ):
            got = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), int(parts[2])
            ).hex()
        elif (
            parts[0] == "scrypt"
            and len(parts) == 4
            and 2 <= int(parts[1]) <= 65536
            and 1 <= int(parts[2]) <= 8
            and 1 <= int(parts[3]) <= 2
        ):
            got = hashlib.scrypt(
                password.encode(),
                salt=salt.encode(),
                n=int(parts[1]),
                r=int(parts[2]),
                p=int(parts[3]),
                maxmem=160 * 1024 * 1024,
            ).hex()
        else:
            return False
        return hmac.compare_digest(got, digest)
    except (ValueError, TypeError, IndexError, MemoryError):
        return False


def validate_account(username, password, confirmation):
    if not isinstance(username, str) or not re.fullmatch(r"[\w.-]{1,64}", username):
        raise Error("Логин: 1–64 буквы, цифры, точки, дефисы или подчёркивания.")
    if not isinstance(password, str) or not 6 <= len(password) <= 256:
        raise Error("Пароль: 6–256 знаков.")
    if not isinstance(confirmation, str) or not hmac.compare_digest(
        password.encode(), confirmation.encode()
    ):
        raise Error("Пароли не совпадают.")


class Accounts:
    def __init__(self, state):
        self.state = pathlib.Path(state)
        self.path = self.state / "auth.json"

    def read(self):
        return read_json(self.path)

    def revision(self):
        try:
            return hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError:
            return ""

    def ensure(self, locked=False):
        config = read_json(self.state / "config.json")
        if config.get("auth_source"):
            self.reset(locked=locked)
            return
        if (
            not self.read().get("password_hash")
            and not (self.state / "account-state.json").exists()
        ):
            self.reset(locked=locked)
        self.clear_old_setup()

    def epoch(self):
        return self.revision() + str(
            read_json(self.state / "account-state.json").get("generation", "")
        )

    def clear_old_setup(self):
        for name in ["setup.token", "setup.json"]:
            (self.state / name).unlink(missing_ok=True)

    def reset(self, locked=False):
        with contextlib.nullcontext() if locked else operation_lock(self.state):
            self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.state.chmod(0o700)
            write_json(
                self.state / "account-state.json", {"generation": secrets.token_hex(16)}
            )
            config = read_json(self.state / "config.json")
            if "auth_source" in config:
                config.pop("auth_source")
                write_json(self.state / "config.json", config)
            self.path.unlink(missing_ok=True)
            self.clear_old_setup()

    def setup(self, fields):
        # Caller holds operation_lock across setup and session creation.
        if self.read().get("password_hash"):
            raise Error("Панель уже настроена", 409)
        username = fields.get("username")
        password = fields.get("password")
        validate_account(username, password, fields.get("password_confirm"))
        write_json(
            self.path, {"username": username, "password_hash": password_hash(password)}
        )
        self.clear_old_setup()

    def change(self, fields):
        auth = self.read()
        if not password_check(
            auth.get("password_hash", ""), fields.get("current_password")
        ):
            raise Error("Неверный текущий пароль", 403)
        username = fields.get("username", auth.get("username"))
        password = fields.get("password")
        validate_account(username, password, fields.get("password_confirm"))
        write_json(
            self.path, {"username": username, "password_hash": password_hash(password)}
        )
        return username
