"""Normalize scan results / reports so they can be diffed against goldens.

Removes fields that legitimately vary run-to-run or machine-to-machine:
  scan JSON  -> _meta.scanned_at, _meta.duration_s, _meta.exclude_ips
  report MD  -> the "**Scan date:**" line and the "Excluded from report:" line
"""

from __future__ import annotations

import json
import re


def normalize_scan(data: dict) -> dict:
    """Return a copy of the scan dict with run/machine-specific fields dropped."""
    out = json.loads(json.dumps(data))
    meta = out.get("_meta")
    if isinstance(meta, dict):
        meta.pop("scanned_at", None)
        meta.pop("duration_s", None)
        meta.pop("exclude_ips", None)  # includes the scanning host's own IP
        # sort hosts by (vlan, ip) so dict ordering is stable for text diff
        hosts = out.get("hosts", {})
        if isinstance(hosts, dict):
            ordered = dict(sorted(
                hosts.items(),
                key=lambda kv: (kv[1].get("vlan", ""), [int(x) for x in kv[0].split(".")]),
            ))
            out["hosts"] = ordered
    return out


def normalize_report(text: str) -> str:
    """Drop timestamp/exclusion lines from a rendered Markdown report."""
    lines = []
    for line in text.splitlines():
        if line.startswith("**Scan date:**"):
            continue
        if line.startswith("- Excluded from report:"):
            continue
        lines.append(line)
    return "\n".join(lines)


def load_scan(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
