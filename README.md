# netrecon

**Generalized, pure-stdlib LAN network mapper — no root required.**

`netrecon` sweeps one or more IPv4 subnets with ICMP, captures ARP/MAC entries
with OUI vendor resolution, runs a threaded TCP connect scan with light banner
grabbing, optionally walks an SNMPv1 ARP table on routed segments, and emits a
deterministic Markdown inventory.

It was extracted from the homelab-specific `netmap` scanner and generalized:
subnets, VLAN labels, port lists, timeouts, and thread counts are all
configurable — no code changes needed to scan a different network.

## Features

- **ICMP sweep** — threaded `ping` across every host in the configured CIDRs
- **ARP/MAC capture** — `ip neigh` reads L2 neighbors; **OUI vendor resolution**
  from a local Wireshark-format `manuf.txt` (packaged), with optional
  `api.macvendors.com` fallback for unknown OUIs
- **TCP connect scan** — threaded, no root, with per-connection timeouts
- **Banner grab** — HTTP status/server/title for web ports; raw first line for
  others (SSH, MQTT, etc.)
- **OS hint** — TTL-based fingerprinting (Linux vs Windows vs router)
- **SNMPv1 ARP walker** — `netrecon snmp <gateway>` pulls the ipNetToMedia
  table so you can resolve MACs/vendors on **routed segments** (e.g. an IoT
  VLAN the scanning host has no L2 access to)
- **Deterministic reports** — the same JSON always renders the same Markdown;
  sections, labels, and exclusions are driven by metadata embedded in the
  results file

## Requirements

- Linux (uses `ping`, `ip neigh`/`ip addr`)
- Python ≥ 3.11, **standard library only** (no pip dependencies at runtime)
- No root: uses ICMP echo (unprivileged ping) and TCP connect scans
- Internet access *only* if you enable the online OUI fallback

## Install

```bash
cd ~/netrecon
python3 -m pip install --user -e .      # editable install, user site
# or: python3 -m venv .venv && .venv/bin/pip install -e .
netrecon --version
```

## Quick start

```bash
# 1) write a starter config (or edit the one in this repo)
netrecon init --out netrecon.conf.json
#    - set "subnets": [{"cidr":"192.168.1.0/24","vlan":"10","label":"lab"}]

# 2) run the survey
netrecon scan --config netrecon.conf.json --out scan_results.json

# 3) render the Markdown inventory
netrecon report --input scan_results.json --out network_inventory.md
```

Or skip the config entirely with flags:

```bash
netrecon scan --subnets 192.168.100.0/24@100 192.168.101.0/24@101 \
              --ports 22,80,443,8000-8010 --out scan_results.json
```

## CLI reference

```
netrecon scan   [--config FILE] [--subnets CIDR[@VLAN|:LABEL] ...]
                [--ports 22,80,443,8000-8010] [--extra-port N ...]
                [--http-ports ...] [--connect-timeout S] [--ping-timeout S]
                [--banner-timeout S] [--max-workers N]
                [--oui-file PATH] [--no-online-oui] [--exclude IP ...]
                [--out scan_results.json] [--quiet]
netrecon report [--config FILE] [--input scan_results.json] [--out netinv.md]
                [--title "Network Inventory"] [--quiet]
netrecon snmp   TARGET_IP [community] [--timeout 2.5]
netrecon init   [--out netrecon.conf.json]
netrecon --version
```

### Config file

Auto-discovered from `./netrecon.conf.json` or
`~/.config/netrecon/netrecon.conf.json` (or `$NETRECON_CONFIG`), unless
`--config` is given. Every key is optional:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `subnets` | list of `{cidr, vlan?, label?}` | `[]` | Networks to scan; `vlan`/`label` appear in reports |
| `ports` | list[int] | 43 curated ports | TCP ports probed |
| `http_ports` | list[int] | subset of `ports` | Ports that get an HTTP banner grab |
| `connect_timeout` | float | 0.35 | TCP connect timeout (s) |
| `ping_timeout` | float | 1.0 | per-host ping timeout (s) |
| `banner_timeout` | float | 0.9 | banner read timeout (s) |
| `max_ping_workers` / `max_scan_workers` / `max_banner_workers` | int | 120 / 256 / 100 | thread pools |
| `oui_file` | str\|null | packaged `manuf.txt` | Wireshark-format OUI DB path |
| `online_oui` | bool | `true` | fall back to api.macvendors.com |
| `exclude_ips` | list[str] | `[]` | IPs skipped in scan + report (your own IPs are always excluded automatically) |
| `services` | dict[int→str] | built-in guess map | service name overrides for reports |

## Output

`scan_results.json`:

```json
{
  "_meta": {
    "tool": "netrecon", "version": "0.1.0",
    "scanned_at": "2026-09-22T03:35:00", "duration_s": 12.4,
    "subnets": [{"cidr": "192.168.100.0/24", "vlan": "100", "label": "Homelab"}],
    "ports": [22, 53, 80],
    "exclude_ips": ["192.168.100.126"],
    "oui_entries": 58321, "online_oui_fallback": true
  },
  "hosts": {
    "192.168.100.1": {
      "ip": "192.168.100.1", "vlan": "100", "mac": "f4:6b:8c:...",
      "vendor": "Cisco Systems, Inc", "icmp": true, "ttl": 64,
      "os_hint": "Linux/Unix/Android (ttl<=64)",
      "open_ports": {"80": "HTTP/1.1 200 OK | nginx"}, "port_count": 1
    }
  }
}
```

The report generator needs **only** the JSON — sections and labels come from
`_meta`, so results are reproducible even after the config changes.

## Routed (non-L2) segments

If a subnet is behind a router (like a dedicated IoT VLAN), the scanning host
cannot see MACs via ARP. Two options:

1. **SNMP ARP pull** — if the gateway answers SNMPv1 with community `public`:
   ```bash
   netrecon snmp 192.168.101.1
   #   sysDescr: ...
   #   ipNetToMedia entries: 12
   #   192.168.101.5     a4:ce:da:...
   ```
2. Run `netrecon` from a probe host *inside* that subnet.

## Updating the OUI database

The vendored DB is generated by TShark/Wireshark. Refresh it with:

```bash
curl -L https://www.wireshark.org/download/automated/data/manuf.gz | \
  gzip -dc > src/netrecon/data/manuf.txt
```

or point `oui_file` at your own copy.

## Known limitations

- **UDP services are not scanned** (mDNS 5353, SSDP 1900, CoAP 5683, NTP, SNMP)
- **MACs on routed segments are invisible** without SNMP or an in-segment probe
- **Randomized/private MACs** (locally-administered) can't be vendor-resolved
- **Sleeping devices** (WoWLAN, deep-sleep IoT) may miss one-shot scans — run
  weekly for a full census

## Relation to `netmap`

`netrecon` is the generalized successor of the homelab scanner in
`~/netmap` (which hardcoded `192.168.100.0/24` + `.101.0/24` and a fixed port
list). The `netmap` directory remains frozen as the baseline used by the
weekly automation; `netrecon` is the standalone, reusable version.

## License

MIT (see `pyproject.toml`). Personal-homelab tooling — use at your own risk.