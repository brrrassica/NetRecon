"""Configuration model for netrecon.

A JSON config file (default: ./netrecon.conf.json, or --config PATH) is layered
over built-in defaults. Every key may be overridden on the command line.

Schema overview::

    {
      "subnets": [
        {"cidr": "192.168.100.0/24", "vlan": "100", "label": "Homelab"},
        {"cidr": "192.168.101.0/24", "vlan": "101", "label": "IoT"}
      ],
      "ports": [22, 80, 443, ...],          # TCP ports to probe
      "http_ports": [80, 443, ...],         # ports that get an HTTP banner grab
      "connect_timeout": 0.35,              # TCP connect timeout (s)
      "ping_timeout": 1.0,                  # per-host ping timeout (s)
      "banner_timeout": 0.9,                # banner read timeout (s)
      "max_ping_workers": 120,              # thread pool sizes
      "max_scan_workers": 256,
      "max_banner_workers": 100,
      "oui_file": "/path/to/manuf.txt",     # Wireshark-format OUI DB (optional)
      "online_oui": true,                   # fall back to api.macvendors.com
      "exclude_ips": ["192.168.100.126"]    # IPs to skip in scan + report
    }
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# -- Defaults ---------------------------------------------------------------

DEFAULT_PORTS = [
    22, 53, 80, 139, 443, 445, 554, 1880, 1883, 2375, 2376, 3000,
    3306, 3389, 5000, 5432, 5601, 5900, 6053, 6379, 6668, 8000, 8006,
    8080, 8081, 8083, 8086, 8089, 8123, 8443, 8554, 8883, 8888, 8899,
    9000, 9001, 9090, 9091, 9100, 9200, 9443, 10000, 54321,
]

DEFAULT_HTTP_PORTS = [80, 443, 3000, 8000, 8080, 8123, 8443, 8883, 9000, 9090, 9200]

DEFAULTS: dict[str, Any] = {
    "subnets": [],
    "ports": list(DEFAULT_PORTS),
    "http_ports": list(DEFAULT_HTTP_PORTS),
    "connect_timeout": 0.35,
    "ping_timeout": 1.0,
    "banner_timeout": 0.9,
    "max_ping_workers": 120,
    "max_scan_workers": 256,
    "max_banner_workers": 100,
    "oui_file": None,
    "online_oui": True,
    "exclude_ips": [],
}

CONFIG_HINTS = [
    "./netrecon.conf.json",
    os.path.expanduser("~/.config/netrecon/netrecon.conf.json"),
]


# -- Loading helpers --------------------------------------------------------

def merge(base: dict, overlay: dict) -> dict:
    """Deep-ish merge: lists/scalars from overlay replace base, dicts recurse."""
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


def find_config(explicit: str | None) -> str | None:
    """Resolve config path: --config > $NETRECON_CONFIG > ./conf > ~/.config/conf."""
    if explicit:
        return explicit
    env = os.environ.get("NETRECON_CONFIG")
    if env and os.path.isfile(env):
        return env
    for hint in CONFIG_HINTS:
        if os.path.isfile(hint):
            return hint
    return None


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    """Return effective config dict: DEFAULTS < file < programmatic overrides."""
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    res = find_config(path)
    if res:
        try:
            with open(res, encoding="utf-8") as fh:
                file_cfg = json.load(fh)
            cfg = merge(cfg, file_cfg)
        except FileNotFoundError:
            pass
        except json.JSONDecodeError as e:
            raise SystemExit(f"[!] config parse error in {res}: {e}")
    if overrides:
        cfg = merge(cfg, overrides)
    return cfg


def dump_default_config(path: str) -> None:
    """Write a starter config file (documented, with empty subnet list)."""
    template = {
        "_help": (
            "netrecon config. Edit 'subnets' for your LAN(s). "
            "Every field is optional -- omit to use built-in defaults. "
            "Command-line flags override this file."
        ),
        "subnets": [
            {"cidr": "192.168.100.0/24", "vlan": "100", "label": "Homelab"},
            {"cidr": "192.168.101.0/24", "vlan": "101", "label": "IoT"},
        ],
    }
    body = json.dumps(template, indent=2) + "\n"
    p = Path(path)
    p.write_text(body, encoding="utf-8")
    print(f"[+] wrote starter config -> {p}")