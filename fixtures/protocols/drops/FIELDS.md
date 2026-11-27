# `drops` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/drops/` are grounded in `fixtures/raw/FIELDS.md`, `fixtures/raw-aci/FIELDS.md`, `LENS_FIELD_ALLOWLISTS.drops` (`frontend/src/protocols/shared/fields.ts`), and the extracted vendor TAs (`cisco-dc-networking_2010`, Cisco Security Cloud `3.7.2`, Cilium `flow.proto`).

## `ftd_drops.ndjson` (`cisco:sfw:estreamer`)

Grounded in `fixtures/raw/FIELDS.md` (`cisco:sfw:estreamer`) and Cisco FMC ConnectionEvent field definitions (`HeaderFieldSet`, `ConnectionKeySet`, `DetailFieldSet`, `Device`, `DeviceIP`, `AccessControlRuleName`):

| Field | Grounding | Meaning in `drops` |
| --- | --- | --- |
| `_time` | `FirstPacketSecond` (epoch seconds) | Event timestamp |
| `host`, `Device`, `DeviceIP` | `cisco:sfw:estreamer` `props.conf` | Reporting FMC / FTD device identity |
| `sourcetype` | `cisco:sfw:estreamer` | Cisco Secure Firewall eStreamer sourcetype |
| `InitiatorIP`, `InitiatorPort` | `ConnectionKeySet` | Client/initiator source IP and port |
| `ResponderIP`, `ResponderPort` | `ConnectionKeySet` | Server/responder destination IP and port |
| `Protocol` | `ConnectionKeySet` | IP transport (`TCP`, `UDP`) |
| `AC_RuleAction` | `DetailFieldSet` | Native FTD verdict (`Block`, `Block with reset`, `Drop`, `Reset`; `Allow` excluded) |
| `AccessControlRuleName` | `DetailFieldSet` | Native FTD access control policy rule name |
| `IngressZone`, `EgressZone` | `DetailFieldSet` | Security zone pair |
| `Application` | `DetailFieldSet` | Detected application protocol |
| `InitiatorBytes`, `ResponderBytes`, `InitiatorPackets`, `ResponderPackets` | `DetailFieldSet` | Byte and packet counters |

## `hubble_drops.ndjson` (`cilium:hubble:flow`)

Grounded in `fixtures/raw-aci/FIELDS.md` (`cilium:hubble:flow`, Cilium `flow.proto` protojson `UseProtoNames: true`) and `tests/splunk/test_live_scenario_gaps.py`:

| Field | Grounding | Meaning in `drops` |
| --- | --- | --- |
| `_time` | `flow.time` / envelope `time` | Observation timestamp |
| `host`, `node_name`, `flow.node_name` | `<cluster>/<node>` | Observing Kubernetes / Cilium node |
| `sourcetype` | `cilium:hubble:flow` | Hubble flow export sourcetype |
| `flow.verdict` | `"DROPPED"` (`"FORWARDED"` ignored) | Native Cilium verdict; `buildDropsHubbleSearch` filters `flow.verdict="DROPPED"` (unquoted dotted field) before `\| head` and `\| spath` |
| `flow.drop_reason`, `flow.drop_reason_desc` | Cilium drop reason enum (e.g. `133`, `POLICY_DENIED`) | Projected via `\| spath` into allowlisted `drop_reason` and `drop_reason_desc` |
| `flow.IP.source`, `flow.IP.destination` | `flow.IP` | Projected into `src_ip` and `dest_ip` |
| `flow.l4.TCP` / `flow.l4.UDP` | `source_port`, `destination_port` | Projected into `src_port`, `dest_port`, and `transport` |
| `flow.source`, `flow.destination` | `namespace`, `pod_name` | Projected into `src_namespace`, `src_pod`, `dest_namespace`, `dest_pod` |

## `nd_aci_drops.ndjson` (`cisco:dc:nd:flows`, `cisco:dc:aci:class`, `cisco:dc:aci:syslog`)

- **Nexus Dashboard (`cisco:dc:nd:flows`)**: Grounded in `research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/data/ui/views/nd_flow_overview.xml` and `fixtures/raw/nd_flows.ndjson`. Extracts `srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocolName`, `fabricName`, `nd_host`, `stats{}.dropPktCount`, `stats{}.dropReasons{}`, and `stats{}.nodeNames{}` via `| spath` after `| head`. Flows with `dropPktCount > 0` and empty `dropReasons` surface as unattributed drops.
- **ACI (`cisco:dc:aci:class` `acllogDropL3Pkt` and `cisco:dc:aci:syslog`)**: Grounded in `fixtures/raw-aci/aci_class.ndjson` and `splunk_app/splunk_adm/default/macros.conf` (`adm_flows_acllog`). Normalizes `srcIp`/`src_ip`, `dstIp`/`dest_ip`, `srcPort`/`src_port`, `dstPort`/`dest_port`, `protocol`, `dn`, `drop_reason`, `contract_name`, `tenant`, `vrf`, `node`, `device`, `descr`, and `pktLen` (`bytes`). Duplicate `acllogDropL3Pkt` DNs re-reported across 5-minute APIC polls are deduplicated client-side so a single logged drop is counted once.

### Excluded Fields

`_raw`, `src_content`, `dest_content`, `cookie`, `form_data`, `uri_query`, `sql_statement`, `bind_variable_value`, `content`, `community`, `value_raw`, `varbind_list`, `login`, `password`, and row-expansion user identifiers are never projected (`buildAllowedFieldsClause("drops", ...)` and `projectRowToLensAllowlist("drops", ...)`).
