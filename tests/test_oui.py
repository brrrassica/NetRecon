"""Tests for OUI vendor resolution against the fixture manuf DB."""

from __future__ import annotations

import os
import unittest

from netrecon.oui import OuiResolver, load_oui_db, normalize_mac

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANUF = os.path.join(ROOT, "tests", "fixtures", "manuf.txt")


class TestLoadOuiDb(unittest.TestCase):
    def test_fixture_entries(self):
        db = load_oui_db(MANUF)
        self.assertEqual(db["BC2411"], "Proxmox Server Solutions GmbH")
        self.assertEqual(db["E831CD"], "Espressif Inc.")
        self.assertEqual(db["A4CF12"], "Raspberry Pi Trading Ltd")
        self.assertEqual(db["001132"], "Fixture Vendor Alpha")

    def test_short_oid_format(self):
        # Wireshark MA-M/MA-S lines (extra cols) should not break parsing
        db = load_oui_db(MANUF)
        self.assertIn("BC2411", db)


class TestNormalizeMac(unittest.TestCase):
    def test_separators(self):
        self.assertEqual(normalize_mac("bc:24:11:71:a7:bf"), "BC241171A7BF")
        self.assertEqual(normalize_mac("bc-24-11-71-a7-bf"), "BC241171A7BF")
        self.assertEqual(normalize_mac("bc24.1171.a7bf"), "BC241171A7BF")


class TestResolve(unittest.TestCase):
    def setUp(self):
        self.r = OuiResolver(db_path=MANUF, online=False)

    def test_known_oui(self):
        self.assertEqual(self.r.resolve("bc:24:11:71:a7:bf"), "Proxmox Server Solutions GmbH")

    def test_unknown_oui(self):
        self.assertEqual(self.r.resolve("00:00:00:00:00:01"), "")

    def test_randomized_mac(self):
        # locally-administered bit set -> randomized/private
        self.assertEqual(self.r.resolve("02:00:00:00:00:01"),
                         "Randomized/private MAC (not OUI-registered)")

    def test_empty(self):
        self.assertEqual(self.r.resolve(""), "")
        self.assertEqual(self.r.resolve(None), "")


if __name__ == "__main__":
    unittest.main()
