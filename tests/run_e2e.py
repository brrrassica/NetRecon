#!/usr/bin/env python3
"""CLI-level end-to-end test: start the mock network, invoke the REAL
`netrecon scan` + `netrecon report` subprocesses, and diff the normalized
outputs against the golden fixtures.

Run from the repo root:
    python3 tests/run_e2e.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mocknet
import normalize as norm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
CONF = os.path.join(FIX, "e2e.conf.json")
GOLD_SCAN = os.path.join(FIX, "expected_scan.json")
GOLD_MD = os.path.join(FIX, "expected_inventory.md")

NETRECON = os.environ.get("NETRECON_BIN", "netrecon")


def run(cmd: list[str], cwd: str = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def main() -> int:
    net = mocknet.MockNet()
    net.start()
    failures = 0
    try:
        with tempfile.TemporaryDirectory() as tmp:
            scan_out = os.path.join(tmp, "scan.json")
            md_out = os.path.join(tmp, "inv.md")

            # 1) real CLI scan
            r = run([NETRECON, "scan", "--config", CONF, "--out", scan_out, "--quiet"])
            if r.returncode != 0:
                print(f"[FAIL] netrecon scan rc={r.returncode}\n{r.stdout}\n{r.stderr}")
                return 1
            got = norm.normalize_scan(json.load(open(scan_out)))
            with open(GOLD_SCAN, encoding="utf-8") as fh:
                expected = json.load(fh)
            if got == expected:
                print("[PASS] scan JSON matches golden fixture")
            else:
                failures += 1
                print("[FAIL] scan JSON differs from golden:")
                _diff(expected, got)

            # 2) real CLI report (config-driven services)
            r = run([NETRECON, "report", "--config", CONF,
                     "--input", scan_out, "--out", md_out, "--title", "Fixture Network Inventory",
                     "--quiet"])
            if r.returncode != 0:
                print(f"[FAIL] netrecon report rc={r.returncode}\n{r.stdout}\n{r.stderr}")
                return 1
            got_md = norm.normalize_report(open(md_out).read()).rstrip("\n")
            expected_md = open(GOLD_MD).read().rstrip("\n")
            if got_md == expected_md:
                print("[PASS] report MD matches golden fixture")
            else:
                failures += 1
                print("[FAIL] report MD differs from golden:")
                import difflib
                for line in difflib.unified_diff(expected_md.splitlines(), got_md.splitlines(),
                                                 "expected", "got", lineterm=""):
                    print("  " + line)
    finally:
        net.stop()

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


def _diff(expected, got):
    import difflib
    a = json.dumps(expected, indent=2, sort_keys=True).splitlines()
    b = json.dumps(got, indent=2, sort_keys=True).splitlines()
    for line in difflib.unified_diff(a, b, "expected", "got", lineterm=""):
        print("  " + line)


if __name__ == "__main__":
    sys.exit(main())
