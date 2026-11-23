"""Report generation tests: golden diff, services override, determinism."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import normalize as norm
from netrecon.cli import main as cli_main
from netrecon.report import SERVICE_GUESS, _svc_guess, generate_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
GOLDEN_MD = os.path.join(FIX, "expected_inventory.md")
GOLDEN_JSON = os.path.join(FIX, "expected_scan.json")

SERVICES = {"41022": "SSH", "41080": "HTTP", "41883": "MQTT",
            "46668": "Tuya smart-device", "48123": "HTTP"}


def _load_golden_scan():
    import json
    with open(GOLDEN_JSON, encoding="utf-8") as fh:
        return json.load(fh)


class TestSvcGuess(unittest.TestCase):
    def test_builtin(self):
        self.assertEqual(_svc_guess(1883, {}), "MQTT")
        self.assertEqual(_svc_guess(9000, {}), "Portainer")

    def test_config_override_int_and_str_keys(self):
        extra = {8123: "Home Assistant", "1883": "MQTT broker"}
        self.assertEqual(_svc_guess(8123, extra), "Home Assistant")
        self.assertEqual(_svc_guess(1883, extra), "MQTT broker")

    def test_unknown(self):
        self.assertEqual(_svc_guess(59999, {}), "?")


class TestReportGolden(unittest.TestCase):
    def test_report_matches_golden(self):
        # golden scan JSON was normalized (timestamps stripped); re-derive the
        # exact same normalized doc so we can diff the report body
        golden = _load_golden_scan()
        # rebuild a synthetic-but-identical host set (the golden hosts block is
        # complete) and pass _meta ports/subnets through
        synthetic = {
            "_meta": golden["_meta"],
            "hosts": golden["hosts"],
        }
        md = generate_report(synthetic, extra_svcs=SERVICES, title="Fixture Network Inventory")
        got = norm.normalize_report(md)
        with open(GOLDEN_MD, encoding="utf-8") as fh:
            expected = fh.read().rstrip("\n")
        self.assertEqual(got.rstrip("\n"), expected)

    def test_sections_present(self):
        golden = _load_golden_scan()
        md = generate_report({"_meta": golden["_meta"], "hosts": golden["hosts"]},
                             extra_svcs=SERVICES, title="Fixture Network Inventory")
        self.assertIn("## Mock-Lab — 127.0.0.1/32", md)
        self.assertIn("## Mock-IoT — 127.0.0.2/32", md)
        self.assertIn("`41022` SSH", md)
        self.assertIn("`41883` MQTT", md)
        self.assertIn("`46668` Tuya smart-device", md)

    def test_deterministic(self):
        golden = _load_golden_scan()
        doc = {"_meta": golden["_meta"], "hosts": golden["hosts"]}
        a = generate_report(doc, extra_svcs=SERVICES, title="T")
        b = generate_report(doc, extra_svcs=SERVICES, title="T")
        self.assertEqual(a, b)


class TestHostOrdering(unittest.TestCase):
    def _assert_numeric_order(self, md, ips):
        positions = [md.index(f"### {ip}") for ip in ips]
        self.assertEqual(positions, sorted(positions))

    def test_wide_subnet_sorted_numerically(self):
        hosts = {
            "10.0.100.1": {},
            "10.0.9.1": {},
            "10.0.10.1": {},
        }
        md = generate_report({
            "_meta": {"subnets": [{"cidr": "10.0.0.0/16", "label": "Wide"}]},
            "hosts": hosts,
        }, title="T")
        self._assert_numeric_order(md, ["10.0.9.1", "10.0.10.1", "10.0.100.1"])

    def test_leftover_hosts_sorted_numerically(self):
        hosts = {
            "10.0.100.1": {},
            "10.0.9.1": {},
            "10.0.10.1": {},
        }
        md = generate_report({"_meta": {}, "hosts": hosts}, title="T")
        self._assert_numeric_order(md, ["10.0.9.1", "10.0.10.1", "10.0.100.1"])


class TestUnmappedHostsSummary(unittest.TestCase):
    def test_unmapped_hosts_counted_in_summary(self):
        md = generate_report({
            "_meta": {"subnets": [{"cidr": "10.0.0.0/24", "label": "Lab"}]},
            "hosts": {
                "10.0.0.5": {"open_ports": {"80": "HTTP/1.0 200 OK"}},
                "10.0.1.7": {},
                "192.168.1.9": {"open_ports": {"443": ""}},
            },
        }, title="T")
        self.assertIn("## Unmapped hosts", md)
        self.assertIn(
            "**Hosts discovered:** 3 (1 in-scope) — 2 with open service ports", md)

    def test_raw_host_map_without_meta_counted(self):
        md = generate_report({
            "10.0.0.5": {"open_ports": {"80": "HTTP/1.0 200 OK"}},
            "10.0.0.6": {},
        }, title="T")
        self.assertIn("## Unmapped hosts", md)
        self.assertIn(
            "**Hosts discovered:** 2 (0 in-scope) — 1 with open service ports", md)


class TestOverlappingSubnets(unittest.TestCase):
    def test_host_appears_in_only_first_matching_subnet(self):
        hosts = {"10.0.0.5": {}}
        md = generate_report({
            "_meta": {"subnets": [
                {"cidr": "10.0.0.0/24", "label": "Narrow"},
                {"cidr": "10.0.0.0/16", "label": "Wide"},
            ]},
            "hosts": hosts,
        }, title="T")
        self.assertEqual(md.count("### 10.0.0.5"), 1)
        self.assertIn("**Hosts discovered:** 1", md)


class TestExcludedHostVendorSummary(unittest.TestCase):
    def test_excluded_host_vendor_not_counted(self):
        md = generate_report({
            "_meta": {"exclude_ips": ["10.0.0.2"]},
            "hosts": {
                "10.0.0.1": {"vendor": "Acme"},
                "10.0.0.2": {"vendor": "SecretCorp"},
            },
        }, title="T")
        self.assertIn("**MAC vendors resolved:** 1", md)


class TestReportCLIConfigDiscovery(unittest.TestCase):
    def test_report_discovers_default_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "netrecon.conf.json").write_text(json.dumps({
                "services": {"80": "CustomHTTP"},
                "report_title": "MyTitle",
            }), encoding="utf-8")
            scan = {
                "_meta": {"ports": [80]},
                "hosts": {"10.0.0.1": {"open_ports": {"80": "HTTP/1.0 200 OK"}}},
            }
            (root / "scan.json").write_text(json.dumps(scan), encoding="utf-8")
            old = os.getcwd()
            try:
                os.chdir(root)
                rc = cli_main(["report", "--input", "scan.json", "--out", "out.md", "--quiet"])
            finally:
                os.chdir(old)
            self.assertEqual(rc, 0)
            md = (root / "out.md").read_text(encoding="utf-8")
            self.assertIn("# MyTitle", md)
            self.assertIn("`80` CustomHTTP", md)

    def test_report_title_flag_overrides_discovered_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "netrecon.conf.json").write_text(json.dumps({
                "report_title": "MyTitle",
            }), encoding="utf-8")
            (root / "scan.json").write_text(json.dumps({"_meta": {}, "hosts": {}}), encoding="utf-8")
            old = os.getcwd()
            try:
                os.chdir(root)
                rc = cli_main(["report", "--input", "scan.json", "--out", "out.md",
                               "--title", "Override", "--quiet"])
            finally:
                os.chdir(old)
            self.assertEqual(rc, 0)
            md = (root / "out.md").read_text(encoding="utf-8")
            self.assertIn("# Override", md)
            self.assertNotIn("# MyTitle", md)


if __name__ == "__main__":
    unittest.main()
