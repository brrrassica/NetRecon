"""OUI vendor resolution.

Primary source: Wireshark-format manuf DB (packaged as data/manuf.txt, or an
explicit path from config). Fallback: api.macvendors.com (opt-in via config
``online_oui``), consulted only for OUIs missing from the local DB and cached
per-run.
"""

from __future__ import annotations

import re
import socket
from importlib import resources
from pathlib import Path

OUI_RE = re.compile(r"^([0-9A-Fa-f]{6})")


def default_manuf_path() -> Path:
    """Path of the packaged manuf.txt (works in editable + wheel installs)."""
    return Path(resources.files("netrecon") / "data" / "manuf.txt")  # type: ignore[arg-type]


def load_oui_db(path: str | Path | None = None) -> dict[str, str]:
    """Parse a Wireshark manuf file -> {6-hex OUI: vendor long name}."""
    db: dict[str, str] = {}
    p = Path(path) if path else default_manuf_path()
    if not p.exists():
        raise FileNotFoundError(f"OUI file missing: {p}")
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            parts = line.split("\t")
            raw = parts[0]
            name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
        else:
            parts = line.split(None, 1)
            raw, name = parts[0], (parts[1].strip() if len(parts) > 1 else "")
        # Wireshark manuf: first column is nn:nn:nn (or nn:nn:nn:xx:yy for
        # MA-M/MA-S). Strip separators, keep the first 6 hex digits for OUI.
        oui = re.sub(r"[^0-9A-Fa-f]", "", raw.split("/")[0])[:6].upper()
        if len(oui) == 6:
            db.setdefault(oui, name)
    return db


def normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").replace(".", "").upper()


class OuiResolver:
    """Resolve MAC -> vendor, with optional online fallback + per-run cache."""

    def __init__(self, db_path: str | Path | None = None, online: bool = True):
        self.db = load_oui_db(db_path) if db_path else load_oui_db()
        self.online = online
        self._cache: dict[str, str] = {}
        self._misses: set[str] = set()

    @property
    def entry_count(self) -> int:
        return len(self.db)

    def resolve(self, mac: str | None) -> str:
        if not mac:
            return ""
        oui = normalize_mac(mac)[:6]
        if len(oui) != 6:
            return ""
        if int(oui[:2], 16) & 0x02:  # locally administered / randomized
            return "Randomized/private MAC (not OUI-registered)"
        if oui in self._cache:
            return self._cache[oui]
        name = self.db.get(oui, "")
        if not name and self.online and oui not in self._misses:
            name = self._online_lookup(oui)
            if not name:
                self._misses.add(oui)
        self._cache[oui] = name
        return name

    @staticmethod
    def _online_lookup(oui: str) -> str:
        try:
            with socket.create_connection(("api.macvendors.com", 80), timeout=5) as s:
                s.sendall(
                    f"GET /{oui} HTTP/1.1\r\nHost: api.macvendors.com\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
                data = b""
                while True:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    data += chunk
            m = re.search(rb"\r\n\r\n(.*)", data, re.S)
            body = m.group(1).decode(errors="replace").strip() if m else ""
            if body and "<html" not in body.lower() and "error" not in body.lower():
                return body
        except OSError:
            pass
        return ""