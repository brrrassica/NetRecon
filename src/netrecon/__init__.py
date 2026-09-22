"""netrecon - generalized pure-stdlib LAN network mapper.

Sweep one or more IPv4 subnets with ICMP, capture ARP/MAC entries with OUI
vendor resolution, run a threaded TCP connect scan with light banner grabbing,
optionally walk an SNMPv1 ARP table on routed segments, and emit deterministic
JSON + Markdown inventory reports. No root required.
"""

__version__ = "0.1.0"