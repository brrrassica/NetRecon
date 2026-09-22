"""netrecon command-line interface.

Subcommands:
  scan    run the full network survey (JSON output)
  report  render a scan results JSON into a Markdown inventory
  snmp    walk an SNMPv1 ARP table on a router/gateway (routed VLANs)
  init    write a starter config file
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import dump_default_config
from .scanner import load_results, save_results, scan
from .report import report_file
from .snmp import run_snmp


def _cmd_scan(args: argparse.Namespace) -> int:
    from .config import load_config

    overrides = {}
    if args.subnets:
        overrides["subnets"] = [_parse_subnet(s) for s in args.subnets]
    if args.ports:
        overrides["ports"] = _parse_ports(args.ports)
    if args.extra_port:
        overrides["ports"] = (overrides.get("ports") or []) + args.extra_port
    if args.http_ports:
        overrides["http_ports"] = _parse_ports(args.http_ports)
    if args.connect_timeout is not None:
        overrides["connect_timeout"] = args.connect_timeout
    if args.ping_timeout is not None:
        overrides["ping_timeout"] = args.ping_timeout
    if args.banner_timeout is not None:
        overrides["banner_timeout"] = args.banner_timeout
    if args.max_workers:
        overrides.update(max_scan_workers=args.max_workers,
                         max_ping_workers=args.max_workers,
                         max_banner_workers=args.max_workers)
    if args.oui_file:
        overrides["oui_file"] = args.oui_file
    if args.no_online_oui:
        overrides["online_oui"] = False
    if args.exclude:
        overrides["exclude_ips"] = list(args.exclude)

    cfg = load_config(args.config, overrides)
    data = scan(cfg, quiet=args.quiet)
    save_results(data, args.out)
    print(f"[*] Results -> {args.out}  ({data['_meta']['duration_s']}s)")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from .config import load_config

    cfg = load_config(args.config, None) if args.config else {}
    extra_svcs = cfg.get("services") if isinstance(cfg, dict) else None
    if args.title:
        title = args.title
    elif isinstance(cfg, dict) and cfg.get("report_title"):
        title = cfg["report_title"]
    else:
        title = "Network Inventory"
    report_file(args.input, args.out, extra_svcs=extra_svcs, title=title, quiet=args.quiet)
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    dump_default_config(args.out)
    return 0


def _cmd_snmp(args: argparse.Namespace) -> int:
    return run_snmp(args.target, args.community, timeout=args.timeout)


def _parse_subnet(s: str) -> dict:
    """Accept '192.168.1.0/24' or '192.168.1.0/24:lab' or '192.168.1.0/24@100'."""
    s = s.strip()
    label = None
    vlan = None
    if ":" in s and "/" in s:
        cidr, _, label = s.rpartition(":")
        label = label.strip() or None
    elif "@" in s:
        cidr, _, vlan = s.rpartition("@")
        vlan = vlan.strip() or None
    else:
        cidr = s
    entry = {"cidr": cidr}
    if label:
        entry["label"] = label
    if vlan:
        entry["vlan"] = vlan
    return entry


def _parse_ports(s: str) -> list[int]:
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="netrecon", description="Pure-stdlib LAN network mapper (no root)."
    )
    p.add_argument("--version", action="version", version=f"netrecon {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="{scan,report,snmp,init}")

    ps = sub.add_parser("scan", help="run the full survey: ping sweep + TCP scan + ARP + banners")
    ps.add_argument("--config", help="path to JSON config file")
    ps.add_argument("--subnets", nargs="+", metavar="CIDR[@VLAN|:LABEL]",
                    help="e.g. 192.168.100.0/24@100 192.168.101.0/24@101")
    ps.add_argument("--ports", help="comma list or ranges, e.g. 22,80,443,8000-8010")
    ps.add_argument("--extra-port", action="append", type=int, default=[],
                    help="single port to add to the scanned set (repeatable)")
    ps.add_argument("--http-ports", help="comma list of ports that get HTTP banner grabs")
    ps.add_argument("--connect-timeout", type=float)
    ps.add_argument("--ping-timeout", type=float)
    ps.add_argument("--banner-timeout", type=float)
    ps.add_argument("--max-workers", type=int, help="override all thread pool sizes")
    ps.add_argument("--oui-file", help="path to Wireshark-format manuf.txt")
    ps.add_argument("--no-online-oui", action="store_true", help="disable api.macvendors.com fallback")
    ps.add_argument("--exclude", action="append", default=[], help="IP to exclude (repeatable)")
    ps.add_argument("--out", default="scan_results.json", help="output JSON path")
    ps.add_argument("--quiet", action="store_true", help="suppress progress output")
    ps.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("report", help="render scan_results.json -> Markdown inventory")
    pr.add_argument("--config", help="path to JSON config (optional; for services/title)")
    pr.add_argument("--input", "-i", default="scan_results.json")
    pr.add_argument("--out", "-o", default="network_inventory.md")
    pr.add_argument("--title", help="report title")
    pr.add_argument("--quiet", action="store_true")
    pr.set_defaults(func=_cmd_report)

    pn = sub.add_parser("snmp", help="walk SNMPv1 ARP table on a router/gateway")
    pn.add_argument("target", help="IP of SNMP device (e.g. VLAN gateway)")
    pn.add_argument("community", nargs="?", default="public")
    pn.add_argument("--timeout", type=float, default=2.5)
    pn.set_defaults(func=_cmd_snmp)

    pi = sub.add_parser("init", help="write a starter netrecon.conf.json")
    pi.add_argument("--out", default="netrecon.conf.json")
    pi.set_defaults(func=_cmd_init)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())