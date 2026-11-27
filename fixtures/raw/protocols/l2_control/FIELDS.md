# `l2_control` Synthetic Fixture Field Grounding

All fields in `fixtures/raw/protocols/l2_control/` are grounded in the extracted Splunk Stream 8.1.6 stream definitions (`research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/dhcp` and `streams/arp`) and Cisco DC Networking 2.0.10 / SC4S syslog contracts (`research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/props.conf` and `frontend/src/protocols/shared/adapters/nxosSyslog.ts`).

## `stream:dhcp` (`stream_dhcp.ndjson`)

Verified directly against `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/dhcp` (where Stream ships with `enabled: true`, `statsOnly: true` / Estimate mode by default):

| Field | TA Type / Term | Meaning in `l2_control` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Stream forwarder or sensor host |
| `sourcetype` | string (`stream:dhcp`) | Splunk Stream DHCP sourcetype |
| `src_ip`, `dest_ip` | string (`flow.c-ip`, `flow.s-ip`) | Client / relay / DHCP server IP addresses |
| `src_mac`, `dest_mac` | string (`flow.c-mac`, `flow.s-mac`) | Ethernet frame MAC addresses |
| `chaddr` | string (`dhcp.client-mac`) | Client hardware MAC address (coalesced into allowlisted `client_mac` in SPL) |
| `opcode` | string (`dhcp.message-type`) | DHCP message type (`DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `NAK`; coalesced into allowlisted `dhcp_message_type` in SPL) |
| `yiaddr` | string (`dhcp.new-client-ip`) | IP address offered or assigned to the client |
| `ip_lease_time` | integer (`dhcp.lease-time`) | Lease duration in seconds (coalesced into allowlisted `lease_time` in SPL) |
| `vlan_id` | integer (`flow.vlan-id`) | Optional 802.1Q VLAN ID (disabled by default in Stream `streams/dhcp`) |
| `vxlan_id` | integer (`flow.vxlan-id`) | Optional VXLAN VNI (coalesced into allowlisted `vni` in SPL) |
| `transaction_id` | string (`dhcp.transaction-id`) | DHCP transaction identifier (retained only as context in raw events, not projected in `| table`) |

### `stream:arp` (`streams/arp`) Compatibility

When `sourceKind` is `"auto"`, `buildL2StreamSearch` also queries `sourcetype="stream:arp"`, coalescing `arp_src_mac` / `src_mac` -> `client_mac`, `opcode` (`1`=Request, `2`=Response) -> `dhcp_message_type` (`message_type`), and `vxlan_id` -> `vni` so Stream `arp` rows stay within `LENS_FIELD_ALLOWLISTS.l2_control`.

## NX-OS / ACI Syslog (`nxos_l2_syslog.ndjson`)

Grounded in `frontend/src/protocols/shared/adapters/nxosSyslog.ts` and `cisco-dc-networking_2010/default/props.conf`:

| Sourcetype | Collector | Fields |
| --- | --- | --- |
| `cisco:ios`, `cisco:aci` | SC4S (primary recommended) | `_time`, `host`, `sourcetype`, `syslog_msg` containing `%FACILITY-SEV-MNEMONIC: message` (parsed via `rex` in `buildSyslogStateSearch` and `normalizeSyslogRow`) |
| `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Cisco DC Networking 2.0.10 TA (UDP fallback) | `_time`, `host`, `sourcetype`, `category`, `severity_id`, `mnemonics`, `syslog_msg`, `interface`, `dn`, `descr` |

### Excluded Sensitive Fields

`src_content`, `dest_content`, `option_value`, `login`, `password`, and `_raw` are strictly excluded by `FORBIDDEN_SENSITIVE_FIELDS` and `buildAllowedFieldsClause("l2_control", ...)` (`| table ...`). Authentication categories (`AUTH`, `AUTHPRIV`, `AAA`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CFGLOG_LOGGEDCMD`, etc.) are filtered out both in SPL and by `nxosSyslog.ts`.
