"""Tests for OUI vendor resolution against the fixture manuf DB."""

from __future__ import annotations

import os
import unittest
from unittest import mock

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


class TestOnlineLookup(unittest.TestCase):
    def setUp(self):
        self.r = OuiResolver(db_path=MANUF, online=True)

    @staticmethod
    def _response(body: bytes, status: int = 200):
        resp = mock.Mock()
        resp.status = status
        resp.read.return_value = body
        return resp

    def test_lookup_uses_https_and_returns_vendor(self):
        resp = self._response(b"ASUSTek COMPUTER INC.")
        with mock.patch("netrecon.oui.urlopen", return_value=resp) as opened:
            self.assertEqual(self.r._online_lookup("D850E6"), "ASUSTek COMPUTER INC.")
        self.assertEqual(opened.call_args.args[0], "https://api.macvendors.com/D850E6")
        self.assertEqual(opened.call_args.kwargs["timeout"], 5)

    def test_lookup_rejects_non_200_response(self):
        resp = self._response(b"Fixture Vendor", status=301)
        with mock.patch("netrecon.oui.urlopen", return_value=resp):
            self.assertEqual(self.r._online_lookup("D850E6"), "")

    def test_miss_is_cached_per_run(self):
        with mock.patch("netrecon.oui.urlopen", side_effect=OSError("offline")) as opened:
            self.assertEqual(self.r.resolve("d8:50:e6:00:00:01"), "")
            self.assertEqual(self.r.resolve("d8:50:e6:00:00:02"), "")
        self.assertEqual(opened.call_count, 1)


if __name__ == "__main__":
    unittest.main()
