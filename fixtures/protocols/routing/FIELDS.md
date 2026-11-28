# `routing` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/routing/` are grounded in Cisco DC Networking 2.0.10 (`research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/props.conf`, `default/transforms.conf`, `bin/cisco_nexus_9k.py`, `bin/cisco_dc_n9k_custom.py`) and the shared SC4S / NX-OS operational syslog contract in `frontend/src/protocols/shared/adapters/nxosSyslog.ts`.

## `nxos_routing_syslog.ndjson` (SC4S `cisco:ios` / `cisco:aci` & DCN TA `cisco:dc:nexus9k:syslog`)

| Field | Grounding | Meaning in `routing` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | `props.conf` (`EVAL-dest`, `EVAL-dvc`) | Reporting switch hostname or management IP |
| `sourcetype` | SC4S (`cisco:ios`, `cisco:aci`) or DCN TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`) | Syslog source type |
| `category` | `props.conf` `EXTRACT-fields` (`cisco:dc:nexus9k:syslog`) / `nxosSyslog.ts` `| rex` (`cisco:ios`) | Cisco facility (`BGP`, `OSPF`, `OSPFV3`, `BFD`, `ISIS`, `HSRP`, `VRRP`) |
| `severity_id` | `props.conf` `EXTRACT-fields` / `nxosSyslog.ts` `| rex` | Syslog severity `0`–`7` |
| `mnemonics` | `props.conf` `EXTRACT-fields` / `nxosSyslog.ts` `| rex` | Operational mnemonic (`ADJCHANGE`, `ADJCHG`, `SESSION_STATE_DOWN`, `SESSION_STATE_UP`, `NBR_RESET`) |
| `syslog_msg` | `props.conf` `EXTRACT-fields` / SC4S message body | Message body parsed for peer IP, VRF, local ASN, interface, and transition state |
| `interface` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional egress interface (`Ethernet1/1`, `eth1/49`) |
| `neighbor_ip` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional neighbor IP when extracted at search time |
| `vrf` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional routing VRF (`default` when omitted) |

### Excluded Syslog Categories & Mnemonics

Authentication/AAA categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) and configuration-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CONFIG_I`, `USER_CONFIG`, `SYSTEM_CONFIG`, `COPY_RUNNING_STARTUP`, `CFGLOG_LOGGEDCMD`) are excluded both in SPL (`buildSyslogStateSearch`) and client-side (`normalizeSyslogRow`).

## `dcn_bgp_dme.ndjson` (Cisco DC Networking `cisco:dc:nexus9k:dme`)

Verified against `cisco_nexus_9k.py` (`cisco:dc:nexus9k:dme`, `Row_info` DME attributes for `bgpPeerEntry` / `bgpPeer`, `ospfAdjEp`, and `bfdSess` listed in `cisco_dc_n9k_custom.py:71-72`), projected into `LENS_FIELD_ALLOWLISTS.routing` by `buildRoutingDmeSearch`:

| Projected Field | DME / ND Source | Meaning in `routing` |
| --- | --- | --- |
| `_time` | epoch seconds | Poll timestamp |
| `host` | `device` / `host` (`props.conf:1020-1022`) | Switch hostname or management address |
| `sourcetype` | `cisco:dc:nexus9k:dme` (or `cisco:dc:nd:*`) | DME/ND state sourcetype |
| `dn` | `Row_info.dn` | DME distinguished name (e.g. `sys/bgp/inst/dom-default/peer-[10.255.0.2]/ent-[10.255.0.2]`) |
| `vrf`, `vrf_name` | `Row_info.vrfName` / `dom-<vrf>` in `dn` | VRF name |
| `peer_ip` | `Row_info.addr` / `Row_info.peerIp` / `Row_info.destAddr` | BGP/OSPF/BFD neighbor IP |
| `peer_asn`, `local_asn` | `Row_info.asn`, `Row_info.localAsn` | Remote and local BGP AS numbers |
| `operSt`, `oper_state`, `state` | `Row_info.operSt` / `operStatus` | Operational session state (`established`, `active`, `idle`, `full`, `up`, `down`) |
| `prefixes_received` | `Row_info.rcvPfx` / `Row_info.pfxRcvd` | Received BGP prefixes (explicitly `Not covered` when syslog-only) |
| `flap_count` | `Row_info.flapCnt` / `Row_info.flapCount` | Cumulative peer flap counter |
| `uptime` | `Row_info.upTs` / `Row_info.uptime` | Session uptime or last-flap timestamp |
| `protocol` | `component` (`bgpPeerEntry`, `ospfAdjEp`, `bfdSess`) / `protocol` | Routing protocol |
| `area` | `Row_info.area` | OSPF area ID |
| `interface` | `Row_info.ifId` / `Row_info.ifName` | Interface associated with adjacency |

### Excluded Sensitive Fields

BGP peer `password` fields, `_raw`, and all global `FORBIDDEN_SENSITIVE_FIELDS` are never projected by `buildRoutingDmeSearch` (`| head ... | eval ... | table ...`) and are stripped client-side by `projectRowToLensAllowlist("routing", ...)`.
