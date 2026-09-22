"""Minimal SNMPv1 walker (stdlib only).

Used to read the ipNetToMedia (ARP) table from a router/gateway so MACs and
vendors can be resolved on *routed* segments (e.g. an IoT VLAN that the
scanning host has no L2 access to). Also reads sysDescr for device identity.

Usage: netrecon snmp TARGET_IP [community] [--timeout 2.5]
"""

from __future__ import annotations

import re
import socket
import sys

OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_IPNETTOMEDIA = "1.3.6.1.2.1.4.22.1.2"


# ---------------------------------------------------------------- BER encode

def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def enc_int(v: int) -> bytes:
    if v < 0x80:
        b = bytes([v])
    else:
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
    return b"\x02" + enc_len(len(b)) + b


def enc_str(s: str) -> bytes:
    b = s.encode()
    return b"\x04" + enc_len(len(b)) + b


def enc_oid(oid: str) -> bytes:
    nums = [int(p) for p in oid.split(".")]
    body = bytes([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        chunks = [n & 0x7F]
        n >>= 7
        while n:
            chunks.append((n & 0x7F) | 0x80)
            n >>= 7
        body += bytes(reversed(chunks))
    return b"\x06" + enc_len(len(body)) + body


def enc_null() -> bytes:
    return b"\x05\x00"


def build_getnext(community: str, oid: str, reqid: int) -> bytes:
    vb = enc_oid(oid) + enc_null()
    vb_seq = b"\x30" + enc_len(len(vb)) + vb
    pdu_body = enc_int(reqid) + enc_int(0) + enc_int(0) + vb_seq
    pdu = b"\xa1" + enc_len(len(pdu_body)) + pdu_body
    inner = enc_int(0) + enc_str(community) + pdu
    return b"\x30" + enc_len(len(inner)) + inner


# ---------------------------------------------------------------- BER decode

def parse_tlv(data: bytes):
    tag = data[0]
    l = data[1]
    hdr = 2
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[2:2 + n], "big")
        hdr = 2 + n
    return tag, data[hdr:hdr + l], data[hdr + l:]


def decode_oid(val: bytes) -> str:
    parts = [val[0] // 40, val[0] % 40]
    n = 0
    for b in val[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def parse_response(data: bytes):
    """Return list of (oid_str, tag, value_bytes)."""
    tag, val, rest = parse_tlv(data)   # outer SEQUENCE
    tag, ver, rest = parse_tlv(val)
    tag, comm, rest = parse_tlv(rest)
    tag, pdu, rest = parse_tlv(rest)   # GET-NEXT-RESPONSE
    tag, reqid, rest = parse_tlv(pdu)
    tag, err, rest = parse_tlv(rest)
    tag, idx, rest = parse_tlv(rest)
    tag, vbseq, rest = parse_tlv(rest)
    out = []
    while vbseq:
        tag, vb, vbseq = parse_tlv(vbseq)
        tag, oidv, rest2 = parse_tlv(vb)
        if tag != 0x06:
            break
        oid = decode_oid(oidv)
        if rest2:
            tag, valv, _ = parse_tlv(rest2)
        else:
            tag, valv = 0x05, b""
        out.append((oid, tag, valv))
    return out


# ---------------------------------------------------------------- walk

def snmp_walk(target: str, community: str, base_oid: str,
              timeout: float = 2.5, max_iter: int = 400):
    reqid = 1
    cur = base_oid
    results = []
    for _ in range(max_iter):
        pkt = build_getnext(community, cur, reqid)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (target, 161))
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        except OSError as e:
            print(f"  [!] SNMP error: {e}", file=sys.stderr)
            break
        finally:
            s.close()
        vbs = parse_response(data)
        if not vbs:
            break
        oid, tag, val = vbs[0]
        if tag == 0x82 and val == b"\x00\x00":   # endOfMibView
            break
        if not oid.startswith(base_oid.split(".0")[0]):
            break
        results.append((oid, tag, val))
        cur = oid
        reqid += 1
    return results


def read_arp_table(target: str, community: str = "public", timeout: float = 2.5) -> dict:
    """Return {ip: mac} pulled from the device's ipNetToMedia table."""
    arp = snmp_walk(target, community, OID_IPNETTOMEDIA, timeout=timeout)
    by_addr: dict[str, dict] = {}
    pat = re.compile(r"1\.3\.6\.1\.2\.1\.4\.22\.1\.(2|3)\.(\d+)\.([\d.]+)$")
    for oid, tag, val in arp:
        m = pat.match(oid)
        if not m:
            continue
        field, _if, addr = m.group(1), m.group(2), m.group(3)
        rec = by_addr.setdefault(addr, {})
        if field == "2" and tag == 0x04 and len(val) == 6:
            rec["mac"] = ":".join(f"{b:02x}" for b in val)
        elif field == "3" and tag == 0x40:
            rec["ip"] = ".".join(str(b) for b in val)
    return {info.get("ip", addr): info["mac"] for addr, info in by_addr.items() if "mac" in info}


def run_snmp(target: str, community: str = "public", timeout: float = 2.5) -> int:
    """CLI entry: print sysDescr + ARP table. Returns exit code."""
    print(f"[*] SNMP walk {target} community='{community}'")

    res = snmp_walk(target, community, OID_SYSDESCR, timeout=timeout)
    if not res:
        print("  [-] no SNMP reply (likely disabled/filtered)")
        return 1
    for oid, tag, val in res:
        if tag == 0x04:
            print(f"  sysDescr: {val.decode(errors='replace').strip()}")

    arp = read_arp_table(target, community, timeout)
    print(f"[*] ipNetToMedia entries: {len(arp)}")
    for ip, mac in sorted(arp.items()):
        print(f"  {ip:16s} {mac}")
    return 0


if __name__ == "__main__":
    sys.exit(run_snmp(
        sys.argv[1] if len(sys.argv) > 1 else "192.168.100.1",
        sys.argv[2] if len(sys.argv) > 2 else "public",
    ))