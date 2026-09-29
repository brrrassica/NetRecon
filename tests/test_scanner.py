"""End-to-end scanner tests against the loopback mock network.

Starts the deterministic MockNet, runs the real scan() pipeline, and compares
the normalized result against the golden fixture. Also covers ARP/MAC vendor
merge (via a patched ARP table, since loopback exposes no L2) and the
self-host exclusion logic.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mocknet
import normalize as norm
from netrecon.config import load_config
from netrecon.scanner import scan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
CONF = os.path.join(FIX, "e2e.conf.json")
GOLDEN = os.path.join(FIX, "expected_scan.json")


class ScanE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = mocknet.MockNet()
        cls.net.start()

    @classmethod
    def tearDownClass(cls):
        cls.net.stop()

    def test_scan_matches_golden(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        got = norm.normalize_scan(data)
        with open(GOLDEN, encoding="utf-8") as fh:
            expected = json.load(fh)
        self.assertEqual(got, expected)

    def test_hosts_discovered(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        hosts = data["hosts"]
        self.assertEqual(set(hosts), {"127.0.0.1", "127.0.0.2"})

    def test_vlan_labels(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        self.assertEqual(data["hosts"]["127.0.0.1"]["vlan"], "900")
        self.assertEqual(data["hosts"]["127.0.0.2"]["vlan"], "901")

    def test_ports_and_banners(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        h1 = data["hosts"]["127.0.0.1"]["open_ports"]
        self.assertEqual(h1["41022"], "SSH-2.0-OpenSSH_fixture")
        self.assertIn("mock-nginx/1.2.3", h1["41080"])
        self.assertIn("Fixture Web One", h1["41080"])
        self.assertEqual(h1["41883"], "")  # silent listener -> empty banner
        # closed probe must not appear
        self.assertNotIn("49999", h1)
        self.assertNotIn("49999", data["hosts"]["127.0.0.2"]["open_ports"])

    def test_icmp_ttl_os_hint(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        for ip, h in data["hosts"].items():
            self.assertTrue(h["icmp"])
            self.assertEqual(h["ttl"], 64)
            self.assertEqual(h["os_hint"], "Linux/Unix/Android (ttl<=64)")

    def test_arp_mac_vendor_merge(self):
        """ARP table (normally hidden on loopback) must resolve vendors from
        the fixture OUI DB and surface ARP-only silent hosts."""
        cfg = load_config(CONF)
        fake_arp = {
            "127.0.0.1": "bc:24:11:71:a7:bf",   # -> Proxmox (fixture OUI)
            "127.0.0.2": "e8:31:cd:12:34:56",   # -> Espressif (fixture OUI)
        }
        with mock.patch("netrecon.scanner.capture_arp", return_value=fake_arp):
            data = scan(cfg, quiet=True)
        hosts = data["hosts"]
        self.assertEqual(hosts["127.0.0.1"]["vendor"], "Proxmox Server Solutions GmbH")
        self.assertEqual(hosts["127.0.0.1"]["mac"], "bc:24:11:71:a7:bf")
        self.assertEqual(hosts["127.0.0.2"]["vendor"], "Espressif Inc.")

    def test_self_host_exclusion(self):
        """A host with an interface on this machine must be dropped from targets."""
        cfg = load_config(CONF)
        from netrecon import scanner as sc
        # Simulate this box holding 127.0.0.1 (it normally holds a LAN IP;
        # here we force the exclusion to prove the mechanism).
        with mock.patch.object(sc, "local_ips", return_value={"127.0.0.1"}):
            data = scan(cfg, quiet=True)
        self.assertNotIn("127.0.0.1", data["hosts"])
        self.assertIn("127.0.0.2", data["hosts"])

    def test_exclude_ips_recorded(self):
        cfg = load_config(CONF)
        data = scan(cfg, quiet=True)
        self.assertIn("192.168.100.126", data["_meta"]["exclude_ips"])  # this box


if __name__ == "__main__":
    unittest.main()
