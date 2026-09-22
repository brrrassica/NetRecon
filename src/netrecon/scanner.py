"""Core scanner: ICMP sweep + ARP capture + threaded TCP connect scan + banners.

Generalized from the homelab netmap scanner: subnets, ports, timeouts and
thread counts all come from the config dict; VLAN labels are taken from the
subnet entries instead of being hardcoded.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .oui import OuiResolver


# --------------------------------------------------------------------------- helpers

def local_ips() -> set[str]:
    """Best-effort list of this host's IPv4 addresses."""
    ips: set[str] = set()
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5
        ).stdout
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out):
            ip = m.group(1)
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    if not ips:  # fallback via UDP-connect trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # no traffic sent
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return ips


def ping_host(ip: str, timeout: float):
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), "-n", ip],
            capture_output=True, text=True, timeout=timeout + 2,
        ).stdout
        m = re.search(r"ttl=(\d+)", out)
        return ip, m is not None, (int(m.group(1)) if m else None)
    except Exception:
        return ip, False, None


def os_hint(ttl: int | None) -> str:
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix/Android (ttl<=64)"
    if ttl <= 128:
        return "Windows (ttl<=128)"
    return "Network device/router (ttl>128)"


def capture_arp() -> dict[str, str]:
    """Parse `ip neigh show` -> {ip: mac}. Only sees L2-reachable hosts."""
    macs: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return macs
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "dev":
            try:
                idx = parts.index("lladdr")
                macs[parts[0]] = parts[idx + 1]
            except ValueError:
                continue
    return macs


# --------------------------------------------------------------------------- port scan

def try_connect(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def banner_grab(ip: str, port: int, timeout: float, http_ports: set[int], ua: str = "netrecon") -> str:
    try:
        s = socket.create_connection((ip, port), timeout=min(timeout + 0.3, 2.0))
        s.settimeout(timeout)
        payload = b""
        if port in http_ports:
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: {ua}\r\n\r\n".encode())
        try:
            while len(payload) < 4096:
                chunk = s.recv(2048)
                if not chunk:
                    break
                payload += chunk
        except socket.timeout:
            pass
        s.close()
        text = payload.decode(errors="replace")
        first = text.splitlines()[0][:80] if text.splitlines() else ""
        m = re.search(r"(?im)^Server:\s*(.+)$", text)
        server = m.group(1).strip()[:60] if m else ""
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:60] if m else ""
        parts = [x for x in (first, server, title) if x]
        return " | ".join(dict.fromkeys(parts))[:200]
    except Exception:
        return ""


# --------------------------------------------------------------------------- main scan

def scan(cfg: dict, quiet: bool = False) -> dict:
    """Run a full scan per config; returns the results dict (also persisted by cli)."""
    out = {}
    log = (lambda *a: print(*a)) if not quiet else (lambda *a: None)

    subnets = cfg.get("subnets", []) or []
    ports = cfg.get("ports") or [22, 80, 443]
    http_ports = set(cfg.get("http_ports") or [80, 443])
    ct = float(cfg.get("connect_timeout", 0.35))
    pt = float(cfg.get("ping_timeout", 1.0))
    bt = float(cfg.get("banner_timeout", 0.9))
    n_ping = int(cfg.get("max_ping_workers", 120))
    n_scan = int(cfg.get("max_scan_workers", 256))
    n_banner = int(cfg.get("max_banner_workers", 100))

    # ---- build target list + vlan/site metadata per subnet
    targets: list[str] = []
    subnet_meta: list[dict] = []
    for entry in subnets:
        cidr = entry.get("cidr") or entry.get("subnet")
        if not cidr:
            continue
        net = ipaddress.ip_network(cidr, strict=False)
        vlan = str(entry.get("vlan") or entry.get("label") or "")
        subnet_meta.append({"cidr": cidr, "vlan": vlan, "label": entry.get("label", "")})
        targets.extend(str(h) for h in net.hosts())
    targets = sorted(set(targets))

    exclude = set(cfg.get("exclude_ips") or [])
    exclude |= local_ips()
    targets = [t for t in targets if t not in exclude]

    if not targets:
        raise SystemExit("[!] no targets to scan (check subnets + exclude_ips in config)")

    t0 = time.time()

    log(f"[*] netrecon v{__version__}")
    log(f"[*] Loading OUI DB ...")
    resolver = OuiResolver(db_path=cfg.get("oui_file"), online=bool(cfg.get("online_oui", True)))
    log(f"[*] {resolver.entry_count} OUIs loaded")

    log(f"[*] Ping sweep: {len(targets)} hosts ...")
    pinged: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=n_ping) as ex:
        for ip, up, ttl in ex.map(lambda t: ping_host(t, pt), targets):
            if up:
                pinged[ip] = ttl
    log(f"[+] {len(pinged)} hosts answered ICMP")

    log(f"[*] TCP port scan: {len(targets)}x{len(ports)} probes ...")
    open_map: dict[str, set[int]] = {}
    tasks = [(ip, p) for ip in targets for p in ports]

    def _probe(t):
        ip, p = t
        return ip, p, try_connect(ip, p, ct)

    with ThreadPoolExecutor(max_workers=n_scan) as ex:
        for ip, p, ok in ex.map(_probe, tasks):
            if ok:
                open_map.setdefault(ip, set()).add(p)
    log(f"[+] {len(open_map)} hosts have >=1 open service port")

    log("[*] Banner grabs ...")
    with ThreadPoolExecutor(max_workers=n_banner) as ex:
        futures = {ex.submit(banner_grab, ip, p, bt, http_ports): (ip, p)
                   for ip, ports_ in open_map.items() for p in ports_}
        banners = {}
        for f in futures:
            ip, p = futures[f]
            banners[(ip, p)] = f.result()

    log("[*] ARP capture ...")
    time.sleep(0.2)
    macs = capture_arp()

    # ---- merge everything
    def vlan_for(ip: str) -> str:
        for entry in subnet_meta:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(entry["cidr"], strict=False):
                return entry["vlan"]
        return ""

    hosts: dict[str, dict] = {}
    known = set(pinged.keys()) | set(open_map.keys())

    def fill(h: dict, ip: str) -> dict:
        h["ip"] = ip
        h["vlan"] = vlan_for(ip)
        return h

    for ip in known:
        mac = macs.get(ip, "")
        rec = {
            "ip": ip,
            "vlan": vlan_for(ip),
            "mac": mac,
            "vendor": resolver.resolve(mac),
            "icmp": ip in pinged,
            "ttl": pinged.get(ip),
            "os_hint": os_hint(pinged.get(ip)),
            "open_ports": {str(p): banners.get((ip, p), "") for p in sorted(open_map.get(ip, set()))},
            "port_count": len(open_map.get(ip, set())),
        }
        hosts[ip] = rec
    if macs:  # ARP-only neighbors (present on L2 but silent to probes)
        for ip, mac in macs.items():
            if ip in hosts or ip in exclude:
                continue
            if any(ipaddress.ip_address(ip) in ipaddress.ip_network(e["cidr"], strict=False) for e in subnet_meta):
                hosts[ip] = fill({
                    "mac": mac, "vendor": resolver.resolve(mac),
                    "icmp": False, "ttl": None, "os_hint": "",
                    "open_ports": {}, "port_count": 0,
                }, ip)

    ordered = dict(sorted(hosts.items(), key=lambda kv: (kv[1]["vlan"], ipaddress.ip_address(kv[0]))))

    meta = {
        "tool": "netrecon",
        "version": __version__,
        "scanned_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "duration_s": round(time.time() - t0, 2),
        "subnets": subnet_meta,
        "ports": sorted(ports),
        "exclude_ips": sorted(exclude),
        "oui_entries": resolver.entry_count,
        "online_oui_fallback": bool(cfg.get("online_oui", True)),
    }
    return {"_meta": meta, "hosts": ordered}


def save_results(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def load_results(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)