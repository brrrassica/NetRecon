"""Deterministic Markdown report generator (JSON -> network inventory).

Generalized from netmap's generate_report.py: sections, labels and exclusions
are driven by the scan's embedded ``_meta`` block, so no config file is needed
at report time. Service names can be extended via a ``services`` mapping in the
config (merged over the built-in guess map).
"""

from __future__ import annotations

import datetime

from .scanner import load_results

# -- built-in service guess map (extend via config["services"]) ------------
SERVICE_GUESS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 139: "NetBIOS/SMB", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 1880: "Node-RED", 1883: "MQTT", 2375: "Docker API", 2376: "Docker API TLS",
    3000: "Gitea/Grafana", 3306: "MySQL", 3389: "RDP", 5000: "HTTP-alt", 5432: "PostgreSQL",
    5601: "Kibana", 5900: "VNC", 6053: "ESPHome", 6379: "Redis", 6668: "Tuya smart-device",
    8000: "HTTP-alt", 8006: "Proxmox VE", 8080: "HTTP-alt", 8081: "HTTP-alt (Tasmota/Sonoff)",
    8083: "InfluxDB", 8086: "InfluxDB HTTP", 8089: "Open WebUI", 8123: "Home Assistant",
    8443: "HTTPS-alt", 8554: "RTSP-alt", 8883: "MQTT TLS", 8888: "HTTP-alt", 8899: "HTTP-alt",
    9000: "Portainer", 9001: "supervisord", 9090: "Prometheus", 9091: "HTTP-alt", 9100: "printer/export",
    9200: "Elasticsearch", 9443: "HTTPS-alt", 10000: "Webmin", 54321: "Xiaomi/Yeelight",
}


def _svc_guess(port: int, extra: dict) -> str:
    if port in extra:
        return str(extra[port])
    return SERVICE_GUESS.get(port, "?")


def _fmt_host(ip: str, h: dict, extra_svcs: dict) -> str:
    lines = []
    ports = h.get("open_ports", {})
    mac = h.get("mac") or "n/a"
    vendor = h.get("vendor") or "unknown"
    ttl = h.get("ttl")
    vlan = h.get("vlan") or ""
    osinfo = h.get("os_hint") or (f"ttl={ttl}" if ttl else "")

    header = f"### {ip}"
    if vlan:
        header += f"  `VLAN {vlan}`"
    lines.append(header)
    if mac != "n/a" or vendor != "unknown":
        lines.append(f"- **MAC**: `{mac}` — {vendor}")
    if osinfo:
        lines.append(f"- **OS hint**: {osinfo}")
    lines.append("- Responds to ICMP" if h.get("icmp") else "- ICMP: silent")
    if ports:
        lines.append("- **Open ports:**")
        for p in sorted(ports, key=int):
            b = ports[p]
            g = _svc_guess(int(p), extra_svcs)
            lines.append(f"  - `{p}` {g}" + (f" — *{b}*" if b else ""))
    else:
        lines.append("- No open ports detected (of scanned set)")
    return "\n".join(lines)


def generate_report(data: dict, extra_svcs: dict | None = None,
                    title: str = "Network Inventory") -> str:
    """Render scan results dict -> Markdown. Pure function (deterministic)."""
    extra_svcs = extra_svcs or {}
    hosts = data.get("hosts", data if data.get("_meta") is None else {})
    meta = data.get("_meta", {})
    subnets = meta.get("subnets", [])
    ports = meta.get("ports", [])
    exclude = set(meta.get("exclude_ips", []))

    rows = [
        f"# {title}",
        "",
        f"**Scan date:** {meta.get('scanned_at', datetime.datetime.now().isoformat(timespec='seconds'))}  ",
        "**Method:** pure-Python scanner (ICMP sweep + ARP capture + TCP connect scan + banner grab). No root used.",
        f"**Ports scanned ({len(ports)}):** " + ",".join(str(p) for p in ports),
        "",
    ]

    # group hosts by subnet cidr so sections match config labels
    def net_of(ip: str, entry: dict):
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(entry.get("cidr", ""), strict=False)

    sections: list[tuple[dict, list[tuple[str, dict]]]] = []
    seen: set[str] = set()
    for entry in subnets:
        member = [
            (ip, h) for ip, h in hosts.items()
            if ip not in exclude and net_of(ip, entry)
        ]
        member.sort(key=lambda t: int(t[0].split(".")[-1]))
        sections.append((entry, member))
        seen |= {ip for ip, _ in member}
    leftover = sorted((ip, h) for ip, h in hosts.items() if ip not in seen and ip not in exclude)

    # ---- summary
    rows.append("## Summary")
    rows.append("")
    total = sum(len(m) for _, m in sections)
    with_ports = sum(1 for _, m in sections for _, h in m if h.get("open_ports"))
    rows.append(f"- **Hosts discovered:** {total} ({sum(len(m) for _, m in sections)} in-scope) — {with_ports} with open service ports")
    rows.append(f"- **MAC vendors resolved:** {sum(1 for _, h in hosts.items() if h.get('vendor'))}")
    rows.append("")

    for entry, member in sections:
        label = entry.get("label") or entry.get("vlan") or entry.get("cidr", "?")
        cidr = entry.get("cidr", "?")
        rows.append(f"## {label} — {cidr}")
        rows.append("")
        if not member:
            rows.append("_No hosts found in this subnet._")
            rows.append("")
            continue
        note = []
        if not any(h.get("mac") for _, h in member):
            note.append(
                f"> Note: no MACs visible for **{cidr}** (routed segment?) — "
                "try `netrecon snmp <gateway>` to pull the ARP table, or run a probe host inside that subnet."
            )
        if note:
            rows.append(note[0])
            rows.append("")
        for ip, h in member:
            rows.append(_fmt_host(ip, h, extra_svcs))
            rows.append("")

    if leftover:
        rows.append("## Unmapped hosts")
        rows.append("")
        for ip, h in leftover:
            rows.append(_fmt_host(ip, h, extra_svcs))
            rows.append("")

    rows += [
        "## Known limitations",
        "",
        "- **UDP services not scanned** (mDNS 5353, SSDP 1900, CoAP 5683, NTP, SNMP) — may hide additional IoT listeners.",
        "- **MACs on routed segments are invisible** from other VLANs; SNMP on the gateway or an in-segment probe is required.",
        "- Randomized MACs (locally-administered) belong to phones/laptops with MAC privacy — identifiable only by watching association patterns.",
        "- Sleeping devices (WoWLAN, deep-sleep IoT) can be invisible to one-shot scans; repeat scans needed for a complete census.",
    ]
    if exclude:
        rows.append(f"- Excluded from report: {', '.join(sorted(exclude))} (self/configured).")
    return "\n".join(rows) + "\n"


def report_file(in_path: str, out_path: str, extra_svcs: dict | None = None,
                title: str = "Network Inventory", quiet: bool = False) -> None:
    data = load_results(in_path)
    md = generate_report(data, extra_svcs=extra_svcs, title=title)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    if not quiet:
        print(f"OK {out_path}")