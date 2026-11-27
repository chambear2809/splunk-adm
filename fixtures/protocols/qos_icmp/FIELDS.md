# `qos_icmp` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/qos_icmp/` are grounded in:
- `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/netflow`
- `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/icmp`
- `research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/props.conf` (`[cisco:dc:nd:flows]`) and `default/data/models/Cisco_DCN_nexus_dashboard.json`
- `fixtures/raw/FIELDS.md`

## `stream_netflow_dscp.ndjson` (`stream:netflow`)

| Field | Grounding | Meaning in `qos_icmp` |
| --- | --- | --- |
| `_time` | epoch seconds | Flow end timestamp |
| `host` | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `stream:netflow` | Splunk Stream NetFlow sourcetype |
| `exporter_ip` | `streams/netflow:41` (`netflow.exporterIPAddress`) | Exporting router/switch management IP |
| `src_ip`, `dest_ip` | `streams/netflow:91,98` | Flow source and destination IP addresses |
| `src_port`, `dest_port` | `streams/netflow:105,112` | Flow source and destination L4 ports |
| `protoid` | `streams/netflow:133` (`ip.protoid`) | IP protocol number (`6`=TCP, `17`=UDP, `1`=ICMP) |
| `tos` | `streams/netflow:140` (`ip.tos`, uint8) | IP Type of Service byte: `DSCP = (tos >> 2) & 0x3f`, `ECN = tos & 3` |
| `min_ttl` | `streams/netflow:326` (`netflow-min-ttl`) | Minimum TTL observed in the flow |
| `bytes`, `packets` | `streams/netflow:147,154` | L3 byte and packet counters |

The adapter also accepts explicit `transport`, `dscp`, `ip_dscp`, and `ecn` fields when `tos` is absent, while always prioritizing `(tos >> 2) & 0x3f` and `tos & 3` when `tos` is present.

## `stream_icmp.ndjson` (`stream:icmp`)

Verified against `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/icmp` (where default is `enabled: true`, `statsOnly: true` / Estimate mode):

| Field | Grounding | Meaning in `qos_icmp` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Stream sensor host |
| `sourcetype` | `stream:icmp` | Splunk Stream ICMP sourcetype |
| `src_ip`, `dest_ip` | `streams/icmp:20,62` | ICMP sender and target IP addresses |
| `type` | `streams/icmp:117` (`icmp.type`) | Numeric ICMP type (`3`=Destination Unreachable, `11`=Time Exceeded, `8`/`0`=Echo; IPv6 `2`=Packet Too Big) |
| `code` | `streams/icmp:101` (`icmp.code`) | Numeric ICMP code (`3/4`=Fragmentation Needed -> PMTUD candidate) |
| `bytes`, `bytes_in`, `bytes_out` | `streams/icmp:14,34,74` | Byte counters |
| `time_taken` | `streams/icmp:80` (`flow.time-taken`, µs) | Flow completion duration in microseconds |

The adapter also tolerates CIM aliases `icmp_type`, `icmp_code`, `packets`, `packets_in`, `packets_out`. `icmp.data` and `type_string`/`code_string` are not selected; classifications are derived strictly from numeric `type` and `code`.

## `nd_drops.ndjson` (`cisco:dc:nd:flows`)

Grounded in `cisco-dc-networking_2010` `default/props.conf:311-350`, `Cisco_DCN_nexus_dashboard.json`, and `fixtures/raw/nd_flows.ndjson`:

| Field | Grounding | Meaning in `qos_icmp` |
| --- | --- | --- |
| `_time` | epoch seconds | Collection / flow timestamp |
| `host` | string | Collector host (`splunk-hf-01`) |
| `sourcetype` | `cisco:dc:nd:flows` | Nexus Dashboard flow telemetry sourcetype |
| `srcIp`, `dstIp` | `props.conf:328,337` | Flow source and destination IP |
| `srcPort`, `dstPort` | `props.conf:329,338` | Flow source and destination port |
| `protocolName` | `props.conf:339` (`FIELDALIAS-transport`) | Upper-case transport protocol name (`TCP`, `UDP`, `ICMP`) |
| `dropPktCount` | `Cisco_DCN_nexus_dashboard.json` (`stats{}.dropPktCount` projected via `| spath` + `| eval`) | Fabric dropped packet count |
| `dropReasons` | `Cisco_DCN_nexus_dashboard.json` (`stats{}.dropReasons{}` projected via `| spath` + `| eval`) | Fabric drop reason codes (e.g. `QOS_WRED_DROP`, `BUFFER_OVERFLOW`) |
| `nodeName` | `props.conf:379` (`stats{}.nodeNames{}` projected via `| spath` + `| eval`) | Leaf/spine switch reporting the flow |
| `fabricName` | `nd_flow_traffic.xml:191` | Nexus Dashboard fabric name |
| `nd_host` | `props.conf:346` | Nexus Dashboard controller host |

Nested paths (`stats{}.dropPktCount`, `stats{}.dropReasons{}`, `stats{}.nodeNames{}`) are extracted via `| spath` AFTER `| head` and projected into flat allowlisted fields before `| table ...`, never queried with dotted quotes in base `search`.
