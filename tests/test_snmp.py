"""Tests for the SNMPv1 BER codec and ARP-table parser (offline, deterministic)."""

from __future__ import annotations

import unittest
from unittest import mock

from netrecon.snmp import (
    OID_IPNETTOMEDIA,
    OID_SYSDESCR,
    build_getnext,
    decode_oid,
    enc_int,
    enc_len,
    enc_oid,
    enc_str,
    parse_response,
    read_arp_table,
    run_snmp,
    snmp_walk,
)


def _response(oid: str, tag: int, val: bytes) -> bytes:
    """Encode a one-varbind GET-NEXT-RESPONSE for a stub agent."""
    val_tlv = bytes([tag]) + enc_len(len(val)) + val
    vb_body = enc_oid(oid) + val_tlv
    vb = b"\x30" + enc_len(len(vb_body)) + vb_body
    vblist = b"\x30" + enc_len(len(vb)) + vb
    pdu_body = enc_int(1) + enc_int(0) + enc_int(0) + vblist
    pdu = b"\xa2" + enc_len(len(pdu_body)) + pdu_body
    inner = enc_int(0) + enc_str("public") + pdu
    return b"\x30" + enc_len(len(inner)) + inner


class _FakeSocket:
    def __init__(self, responses):
        self.responses = list(responses)

    def settimeout(self, timeout):
        pass

    def sendto(self, data, addr):
        pass

    def recvfrom(self, bufsize):
        return self.responses.pop(0), ("127.0.0.1", 161)

    def close(self):
        pass


class TestSnmpWalk(unittest.TestCase):
    def test_walk_column_stops_at_lexicographic_successor(self):
        # sysDescr column -> sysDescr.0, then sibling sysObjectID.0
        sock = _FakeSocket([
            _response("1.3.6.1.2.1.1.1.0", 0x04, b"stub agent"),
            _response("1.3.6.1.2.1.1.2.0", 0x06, b"\x2b\x06\x01"),
        ])
        with mock.patch("netrecon.snmp.socket.socket", return_value=sock):
            res = snmp_walk("127.0.0.1", "public", OID_SYSDESCR, timeout=0.1)
        self.assertEqual([oid for oid, _tag, _val in res],
                         ["1.3.6.1.2.1.1.1.0"])
        self.assertEqual(res[0][2], b"stub agent")

    def test_walk_prefix_is_exact_subtree(self):
        # base ...1.1.1 must not match the unrelated sibling ...1.1.10.0
        sock = _FakeSocket([
            _response("1.3.6.1.2.1.1.10.0", 0x04, b"wrong subtree"),
        ])
        with mock.patch("netrecon.snmp.socket.socket", return_value=sock):
            res = snmp_walk("127.0.0.1", "public", OID_SYSDESCR, timeout=0.1)
        self.assertEqual(res, [])

    def test_walk_stops_on_zero_length_endofmibview(self):
        # A real endOfMibView exception has tag 0x82 and a zero-length value.
        sock = _FakeSocket([
            _response("1.3.6.1.2.1.4.22.1.2.1", 0x82, b""),
            _response("1.3.6.1.2.1.4.22.1.2.1.1.1.1.1", 0x04, b"\x00" * 6),
        ])
        with mock.patch("netrecon.snmp.socket.socket", return_value=sock):
            res = snmp_walk("127.0.0.1", "public", OID_IPNETTOMEDIA, timeout=0.1)
        self.assertEqual(res, [])

    def test_walk_stops_on_non_monotonic_oid(self):
        oid = "1.3.6.1.2.1.4.22.1.2.1.1.1.1.1"
        sock = _FakeSocket([
            _response(oid, 0x04, b"\x00" * 6),
            _response(oid, 0x04, b"\x00" * 6),
        ])
        with mock.patch("netrecon.snmp.socket.socket", return_value=sock):
            res = snmp_walk("127.0.0.1", "public", OID_IPNETTOMEDIA, timeout=0.1)
        self.assertEqual(len(res), 1)

    def test_run_snmp_reaches_arp_read(self):
        with mock.patch(
            "netrecon.snmp.snmp_walk",
            return_value=[("1.3.6.1.2.1.1.1.0", 0x04, b"stub agent")],
        ) as walk, mock.patch(
            "netrecon.snmp.read_arp_table", return_value={}
        ) as arp:
            rc = run_snmp("127.0.0.1", timeout=0.1)
        self.assertEqual(rc, 0)
        walk.assert_called_once_with(
            "127.0.0.1", "public", OID_SYSDESCR, timeout=0.1
        )
        arp.assert_called_once_with("127.0.0.1", "public", 0.1)


class TestBerEncode(unittest.TestCase):
    def test_len_short(self):
        self.assertEqual(enc_len(5), b"\x05")

    def test_len_long(self):
        self.assertEqual(enc_len(0x80), b"\x81\x80")
        self.assertEqual(enc_len(0x1234), b"\x82\x12\x34")

    def test_int_positive(self):
        self.assertEqual(enc_int(0), b"\x02\x01\x00")
        self.assertEqual(enc_int(1), b"\x02\x01\x01")

    def test_int_highbit(self):
        # 128 needs a leading zero byte (sign bit)
        self.assertEqual(enc_int(128), b"\x02\x02\x00\x80")

    def test_str(self):
        self.assertEqual(enc_str("public"), b"\x04\x06public")

    def test_oid_roundtrip(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.4.22.1.2.1", "1.3.6.1.4.1.99999.1"):
            encoded = enc_oid(oid)
            self.assertEqual(encoded[0], 0x06)  # OID tag
            # parse back out of a TLV
            tag = encoded[0]
            ln = encoded[1]
            body = encoded[2:2 + ln]
            self.assertEqual(tag, 0x06)
            self.assertEqual(decode_oid(body), oid)


class TestBuildGetnext(unittest.TestCase):
    def test_packet_structure(self):
        pkt = build_getnext("public", "1.3.6.1.2.1.1.1.0", reqid=1)
        self.assertEqual(pkt[0], 0x30)          # outer SEQUENCE
        self.assertIn(b"public", pkt)            # community string present
        self.assertEqual(pkt.count(b"\xa1"), 1)  # GET-NEXT PDU tag
        self.assertEqual(pkt.count(b"\xa0"), 0)  # not a plain GET


class TestParseResponse(unittest.TestCase):
    def test_roundtrip(self):
        """Build a GET-NEXT-RESPONSE by hand with the encoder and ensure the
        decoder recovers the varbind (oid, type, value)."""
        # varbind-list is a SEQUENCE of varbind SEQUENCEs (each OID + value)
        oid = "1.3.6.1.2.1.4.22.1.2.2.192.168.101.19"
        vb_body = enc_oid(oid) + b"\x05\x00"
        vb = b"\x30" + enc_len(len(vb_body)) + vb_body              # varbind
        vblist = b"\x30" + enc_len(len(vb)) + vb                    # varbind-list
        pdu_body = enc_int(1) + enc_int(0) + enc_int(0) + vblist
        pdu = b"\xa2" + enc_len(len(pdu_body)) + pdu_body           # GET-NEXT-RESPONSE (0xa2)
        inner = enc_int(0) + enc_str("public") + pdu
        outer = b"\x30" + enc_len(len(inner)) + inner

        parsed = parse_response(outer)
        self.assertEqual(len(parsed), 1)
        got_oid, got_tag, got_val = parsed[0]
        self.assertEqual(got_oid, oid)
        self.assertEqual(got_tag, 0x05)
        self.assertEqual(got_val, b"")


class TestReadArpTable(unittest.TestCase):
    def test_parse_entries(self):
        # ipNetToMedia.2.<if>.<addr> -> MAC (octet string, 6 bytes)
        # ipNetToMedia.3.<if>.<addr> -> ip (ipAddress, 4 bytes)
        mac = bytes([0xbc, 0x24, 0x11, 0x71, 0xa7, 0xbf])
        vbs = [
            ("1.3.6.1.2.1.4.22.1.2.1.192.168.101.19", 0x04, mac),
            ("1.3.6.1.2.1.4.22.1.3.1.192.168.101.19", 0x40, bytes([192, 168, 101, 19])),
            ("1.3.6.1.2.1.4.22.1.2.1.192.168.101.29", 0x04, bytes([0xe8, 0x31, 0xcd, 1, 2, 3])),
            ("1.3.6.1.2.1.4.22.1.3.1.192.168.101.29", 0x40, bytes([192, 168, 101, 29])),
        ]
        with mock.patch("netrecon.snmp.snmp_walk", return_value=vbs):
            out = read_arp_table("192.168.100.1", timeout=1.0)
        self.assertEqual(out["192.168.101.19"], "bc:24:11:71:a7:bf")
        self.assertEqual(out["192.168.101.29"], "e8:31:cd:01:02:03")

    def test_ip_address_field_wins(self):
        """The ipNetToMedia.3 (ipAddress) column is authoritative for the key."""
        vbs = [
            ("1.3.6.1.2.1.4.22.1.2.1.192.168.101.44", 0x04, bytes([0xa4, 0xcf, 0x12, 0, 0, 1])),
            ("1.3.6.1.2.1.4.22.1.3.1.192.168.101.44", 0x40, bytes([192, 168, 101, 44])),
        ]
        with mock.patch("netrecon.snmp.snmp_walk", return_value=vbs):
            out = read_arp_table("192.168.100.1", timeout=1.0)
        self.assertEqual(out["192.168.101.44"], "a4:cf:12:00:00:01")


if __name__ == "__main__":
    unittest.main()
