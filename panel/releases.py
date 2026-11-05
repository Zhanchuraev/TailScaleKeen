"""Public release contract. Only the fixed upstream repository is executable code."""

import hashlib
import io
import json
import pathlib
import re
import tarfile
import time
import urllib.error
from .core import Error, VERSION, download

REPOSITORY = "Zhanchuraev/TailScaleKeen"
ARCHIVE = "tailscalekeen.tar.gz"
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_UNPACKED = 20 * 1024 * 1024
DOCS = {"install.sh", "README.md", "README.ru.md", "LICENSE", "VERSION", "CHANGELOG.md", "SECURITY.md", "THIRD_PARTY.md"}


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,4}\.\d{1,4}\.\d{1,4}", value):
        raise Error("Неверная версия релиза")
    return tuple(map(int, value.split(".")))


def release_info():
    try:
        meta = json.loads(download("https://api.github.com/repos/" + REPOSITORY + "/releases/latest", 512 * 1024))
    except (OSError, ValueError, urllib.error.URLError):
        raise Error("Не удалось получить релиз GitHub. Проверьте DNS, время и доступ к GitHub.", 502)
    tag = meta.get("tag_name", "")
    latest = tag.removeprefix("v")
    version_tuple(latest)
    if tag != "v" + latest or meta.get("draft") or meta.get("prerelease"):
        raise Error("Неожиданный формат стабильного релиза")
    base = "https://github.com/" + REPOSITORY + "/releases/download/" + tag + "/"
    assets = {}
    for name in [ARCHIVE, ARCHIVE + ".sha256"]:
        matches = [a for a in meta.get("assets", []) if a.get("name") == name]
        if len(matches) != 1 or matches[0].get("browser_download_url") != base + name:
            raise Error("В релизе отсутствует проверенный установочный архив")
        assets[name] = base + name
    return {"current": VERSION, "latest": latest,
            "available": version_tuple(latest) > version_tuple(VERSION),
            "repository": REPOSITORY, "url": "https://github.com/" + REPOSITORY + "/releases/tag/" + tag,
            "assets": assets, "checked_at": int(time.time())}


def allowed_file(name):
    p = pathlib.PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or "\\" in name or str(p) != name:
        return False
    if name in DOCS:
        return True
    if len(p.parts) == 2 and p.parts[0] == "panel" and p.suffix == ".py":
        return True
    return name in {"web/app.js", "web/app.css", "web/keenetic.css", "web/index.html", "web/favicon.svg", "web/fonts/Roboto.ttf", "web/fonts/OFL.txt", "scripts/S98tailscale-panel"}


def unpack_release(blob, destination, expected_version=None):
    """Reject traversal, symlinks, duplicates and unmanifested files before writing."""
    if len(blob) > MAX_ARCHIVE:
        raise Error("Архив панели слишком большой")
    files = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile() or member.name in files or not (allowed_file(member.name) or member.name == "release-manifest.json"):
                    raise Error("Недопустимый файл в архиве панели")
                total += member.size
                if member.size < 0 or total > MAX_UNPACKED or len(files) >= 100:
                    raise Error("Превышен размер дистрибутива")
                files[member.name] = archive.extractfile(member).read()
    except (tarfile.TarError, OSError, EOFError):
        raise Error("Повреждённый архив панели")
    try:
        manifest = json.loads(files.pop("release-manifest.json"))
        version = files["VERSION"].decode().strip()
        version_tuple(version)
        if expected_version and version != expected_version:
            raise ValueError()
        if manifest["version"] != version or set(manifest["files"]) != set(files):
            raise ValueError()
        required = {"panel/server.py", "panel/install.py", "panel/panel_update.py", "panel/releases.py", "web/index.html", "web/app.js", "scripts/S98tailscale-panel", "install.sh", "LICENSE", "VERSION"}
        if not required <= set(files):
            raise ValueError()
        for name, content in files.items():
            if hashlib.sha256(content).hexdigest() != manifest["files"][name]:
                raise ValueError()
        # A stale version constant must not produce a successful update receipt.
        if ('VERSION = "' + version + '"').encode() not in files["panel/core.py"]:
            raise ValueError()
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise Error("Манифест или версия дистрибутива не совпадает")
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, content in files.items():
        p = destination / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        p.chmod(0o755 if name == "install.sh" or name.startswith("scripts/") else 0o644)
    return manifest


def fetch_release(info, destination):
    blob = download(info["assets"][ARCHIVE], MAX_ARCHIVE)
    checksum = download(info["assets"][ARCHIVE + ".sha256"], 1024).decode().strip()
    expected = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?" + re.escape(ARCHIVE), checksum)
    if not expected or hashlib.sha256(blob).hexdigest() != expected[1].lower():
        raise Error("Контрольная сумма релиза панели не совпадает")
    return unpack_release(blob, destination, info["latest"])
