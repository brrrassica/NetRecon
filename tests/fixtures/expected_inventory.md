# Fixture Network Inventory

**Method:** pure-Python scanner (ICMP sweep + ARP capture + TCP connect scan + banner grab). No root used.
**Ports scanned (6):** 41022,41080,41883,46668,48123,49999

## Summary

- **Hosts discovered:** 2 (2 in-scope) — 2 with open service ports
- **MAC vendors resolved:** 0

## Mock-Lab — 127.0.0.1/32

> Note: no MACs visible for **127.0.0.1/32** (routed segment?) — try `netrecon snmp <gateway>` to pull the ARP table, or run a probe host inside that subnet.

### 127.0.0.1  `VLAN 900`
- **OS hint**: Linux/Unix/Android (ttl<=64)
- Responds to ICMP
- **Open ports:**
  - `41022` SSH — *SSH-2.0-OpenSSH_fixture*
  - `41080` HTTP — *HTTP/1.0 200 OK | mock-nginx/1.2.3 | Fixture Web One*
  - `41883` MQTT

## Mock-IoT — 127.0.0.2/32

> Note: no MACs visible for **127.0.0.2/32** (routed segment?) — try `netrecon snmp <gateway>` to pull the ARP table, or run a probe host inside that subnet.

### 127.0.0.2  `VLAN 901`
- **OS hint**: Linux/Unix/Android (ttl<=64)
- Responds to ICMP
- **Open ports:**
  - `46668` Tuya smart-device
  - `48123` HTTP — *HTTP/1.0 200 OK | mock-hass/0.1 | Fixture IoT Hub*

## Known limitations

- **UDP services not scanned** (mDNS 5353, SSDP 1900, CoAP 5683, NTP, SNMP) — may hide additional IoT listeners.
- **MACs on routed segments are invisible** from other VLANs; SNMP on the gateway or an in-segment probe is required.
- Randomized MACs (locally-administered) belong to phones/laptops with MAC privacy — identifiable only by watching association patterns.
- Sleeping devices (WoWLAN, deep-sleep IoT) can be invisible to one-shot scans; repeat scans needed for a complete census.
