"""Local device cards scoped to the current control server; no remote writes."""

import hashlib, json, pathlib, threading, time, urllib.parse
from .core import Error, read_json, write_json


class Devices:
    def __init__(self, state, tailscale):
        self.path = pathlib.Path(state) / "devices.json"
        self.ts = tailscale
        self.lock = threading.Lock()

    def known(self, snapshot=None):
        snap = snapshot if snapshot is not None else self.ts.snapshot(True)
        realm = hashlib.sha256(
            (snap["prefs"].get("ControlURL") or "").encode()
        ).hexdigest()
        own = {**snap["self"], "Online": snap["online"], "is_self": True}
        return realm, {str(n["ID"]): n for n in [own, *snap["peers"]] if n.get("ID")}

    @staticmethod
    def revision(record):
        return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def default_url(peer):
        addresses = peer.get("TailscaleIPs") or []
        ip = next((x for x in addresses if ":" not in x), next(iter(addresses), ""))
        return (
            "http://" + ("[" + ip + "]" if ":" in ip else ip) + ":5252/" if ip else ""
        )

    def list(self, snapshot=None):
        realm, peers = self.known(snapshot)
        saved = read_json(self.path).get(realm, {})
        return {
            key: {
                "notes": saved.get(key, {}).get("notes", ""),
                "url": saved.get(key, {}).get("url", "") or self.default_url(peer),
                "custom_url": saved.get(key, {}).get("url", ""),
                "revision": self.revision(saved.get(key, {})),
                "updated_at": saved.get(key, {}).get("updated_at"),
            }
            for key, peer in peers.items()
        }

    def save(self, fields):
        if not isinstance(fields, dict) or set(fields) != {
            "id",
            "notes",
            "url",
            "revision",
        }:
            raise Error("Неверные поля карточки устройства")
        realm, peers = self.known()
        key = fields["id"]
        if not isinstance(key, str) or key not in peers:
            raise Error("Устройство отсутствует в текущей сети", 404)
        notes, url = fields["notes"], fields["url"]
        if (
            not isinstance(notes, str)
            or len(notes) > 4000
            or any(ord(c) < 32 and c not in "\n\r\t" for c in notes)
        ):
            raise Error("Заметка: не более 4000 символов")
        if (
            not isinstance(url, str)
            or len(url) > 1000
            or any(c.isspace() or ord(c) < 32 for c in url)
        ):
            raise Error("Неверный адрес веб-интерфейса")
        if url:
            try:
                u = urllib.parse.urlsplit(url)
                port = u.port
                hosts = {
                    *(peers[key].get("TailscaleIPs") or []),
                    (peers[key].get("DNSName") or "").rstrip(".").lower(),
                }
                if (
                    u.scheme not in ["http", "https"]
                    or not u.hostname
                    or u.hostname.rstrip(".").lower() not in hosts
                    or u.username
                    or u.password
                    or (port is not None and not 1 <= port <= 65535)
                ):
                    raise ValueError()
            except ValueError:
                raise Error(
                    "Укажите HTTP(S)-адрес Tailscale этого устройства, без логина и пароля в ссылке"
                )
        with self.lock:
            all_saved = read_json(self.path)
            saved = all_saved.setdefault(realm, {})
            if fields["revision"] != self.revision(saved.get(key, {})):
                raise Error("Карточка изменена в другом окне. Откройте её заново.", 409)
            if not notes.strip() and not url:
                saved.pop(key, None)
            else:
                saved[key] = {
                    "notes": notes.strip(),
                    "url": url,
                    "updated_at": int(time.time()),
                }
            write_json(self.path, all_saved)
        return self.list()[key]
