# `endpoint_mobility` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/endpoint_mobility/` are grounded in `fixtures/raw/FIELDS.md`, Splunk App for Stream 8.1.6 (`streams/arp`), Cisco DC Networking 1.2.2 / 2.0.10 (`cisco:dc:nd:endpoints`, `cisco:dc:aci:stats`, `cisco:dc:aci:class`, `cisco:dc:nexus9k:dme`), and the shared SC4S / NX-OS / ACI syslog contract (`frontend/src/protocols/shared/adapters/nxosSyslog.ts`).

## 1. Splunk Stream ARP (`stream_arp.ndjson`, `sourcetype="stream:arp"`)

| Field | Grounding | Meaning in `endpoint_mobility` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `stream:arp` | Splunk Stream ARP sourcetype |
| `src_ip`, `dest_ip` | `flow.c-ip`, `flow.s-ip` | Ethernet/ARP peer IPv4/IPv6 addresses |
| `src_mac`, `dest_mac` | `flow.c-mac`, `flow.s-mac` | Ethernet frame source/destination MAC addresses |
| `sender_ip`, `sender_mac` | `arp.sender-ip` / `arp_src_ip`, `arp.sender-mac` / `arp_src_mac` | ARP sender protocol/hardware address (coalesced in SPL) |
| `target_ip`, `target_mac` | `arp.target-ip` / `arp_dest_ip`, `arp.target-mac` / `arp_dest_mac` | ARP target protocol/hardware address (coalesced in SPL) |
| `arp_opcode`, `operation` | `arp.opcode` / `opcode` | ARP operation (`1`/request, `2`/reply; coalesced in SPL) |
| `vlan`, `vlan_id` | `flow.vlan-id` | 802.1Q VLAN ID |
| `vni` | `flow.vxlan-id` | VXLAN Network Identifier (coalesced from `vxlan_id` in SPL) |

## 2. Cisco Nexus Dashboard Endpoints (`nd_endpoints_mobility.ndjson`, `sourcetype="cisco:dc:nd:endpoints"`)

Grounded in `fixtures/raw/FIELDS.md` and `fixtures/raw/nd_endpoints.ndjson`:

| Field | Grounding | Meaning in `endpoint_mobility` |
| --- | --- | --- |
| `_time` | epoch seconds | Collection / observation timestamp |
| `host`, `nd_host`, `fabricName` | `cisco_dc_nd_collector.py` | Collector host, ND controller host, fabric name |
| `endpointId`, `mac`, `ip` | ND endpoint payload (`ip` may be string or array) | Endpoint ID, MAC address, and associated IP(s) |
| `nodeName`, `displayInterface` | ND attachment (`displayInterface` may be string or array) | Leaf/switch node and attached interface |
| `modType`, `createTime`, `anomalyScore` | ND endpoint change record | Change type (`creation`, `deletion`, `modification`, `move`), creation time, anomaly score |
| `tenant`, `displayBd`, `displayEpg`, `encap` | ND tenant/BD/EPG context | Tenant, Bridge Domain, EPG, and encapsulation (`vlan-1040`, `vxlan-...`) |

## 3. Cisco ACI `fvCEp`, Nexus 9K DME & Syslog (`aci_nxos_mobility.ndjson`)

- **ACI `fvCEp`** (`cisco:dc:aci:stats`, `cisco:dc:aci:class`): `component="fvCEp"` filtered before `| head`, projecting `dn`, `mac`, `ip`, `addr`, `encap`, `tDn` (`topology/pod-1/paths-201/pathep-[eth1/5]`), `modTs`, `status`, `lcC`, `apic_host`.
- **Nexus 9K DME** (`cisco:dc:nexus9k:dme`): `(component="epmMacEp" OR component="l2MacAddressEntry" OR dn="sys/eps/*" OR dn="sys/bd/*")` filtered before `| head`, projecting `dn`, `mac`, `ip`, `addr`, `interface`, `vlan`, `vni`, `encap`, `switch`, `leaf`, `port`, `move_count`, `status`, `modTs`.
- **NX-OS / ACI Syslog**: `cisco:ios`, `cisco:dc:nexus9k:syslog`, `cisco:aci`, `cisco:dc:aci:syslog` via `buildSyslogStateSearch` (`MOBILITY_SYSLOG_CATEGORIES` in `adapter.ts`).

### Excluded Sensitive Fields

`_raw`, `src_content`, `dest_content`, `cookie`, `form_data`, `uri_query`, `login`, `password`, and AAA/auth syslog categories (`AUTH`, `AUTHPRIV`, `AAA`, `VSHD`, `SEC_LOGIN`, `SSH`) are excluded by `FORBIDDEN_SENSITIVE_FIELDS`, `buildAllowedFieldsClause("endpoint_mobility", ...)`, and `nxosSyslog.ts`.
