"""Tests for config loading/merging and CLI parse helpers (stdlib unittest)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from netrecon.config import DEFAULTS, load_config, merge
from netrecon.cli import _parse_ports, _parse_subnet

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")


class TestParseSubnet(unittest.TestCase):
    def test_plain_cidr(self):
        self.assertEqual(_parse_subnet("192.168.100.0/24"), {"cidr": "192.168.100.0/24"})

    def test_vlan_suffix(self):
        self.assertEqual(_parse_subnet("192.168.100.0/24@100"),
                         {"cidr": "192.168.100.0/24", "vlan": "100"})

    def test_label_suffix(self):
        self.assertEqual(_parse_subnet("192.168.100.0/24:Homelab"),
                         {"cidr": "192.168.100.0/24", "label": "Homelab"})


class TestParsePorts(unittest.TestCase):
    def test_list(self):
        self.assertEqual(_parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(_parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_mixed_and_whitespace(self):
        self.assertEqual(_parse_ports("22, 8000-8001, 443"), [22, 8000, 8001, 443])


class TestMerge(unittest.TestCase):
    def test_scalar_overwrite(self):
        self.assertEqual(merge({"a": 1, "b": 2}, {"a": 9}), {"a": 9, "b": 2})

    def test_list_replace(self):
        self.assertEqual(merge({"p": [1, 2]}, {"p": [3]}), {"p": [3]})

    def test_dict_recursion(self):
        self.assertEqual(merge({"n": {"a": 1, "b": 2}}, {"n": {"b": 3}}),
                         {"n": {"a": 1, "b": 3}})


class TestLoadConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config(None, {})
        self.assertEqual(cfg["connect_timeout"], DEFAULTS["connect_timeout"])
        self.assertIsInstance(cfg["ports"], list)

    def test_override_ordering(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"connect_timeout": 1.5, "ports": [22]}, fh)
            path = fh.name
        try:
            cfg = load_config(path, {"connect_timeout": 2.0})
            self.assertEqual(cfg["connect_timeout"], 2.0)   # override wins
            self.assertEqual(cfg["ports"], [22])            # file value kept
        finally:
            os.unlink(path)

    def test_fixture_config_loads(self):
        cfg = load_config(os.path.join(FIX, "e2e.conf.json"))
        self.assertEqual(len(cfg["subnets"]), 2)
        self.assertEqual(cfg["subnets"][0]["vlan"], "900")
        self.assertFalse(cfg["online_oui"])


if __name__ == "__main__":
    unittest.main()
