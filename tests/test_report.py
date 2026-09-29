"""Report generation tests: golden diff, services override, determinism."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import normalize as norm
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


if __name__ == "__main__":
    unittest.main()
