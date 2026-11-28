# `mgmt_plane` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/mgmt_plane/` are grounded in:
- Splunk App for Stream 8.1.6 (`splunk_app_stream/default/streams/snmp`, `streams/ftp`, `streams/netflow`)
- SC4S (`cisco:ios`, `cisco:aci`) and Cisco DC Networking 2.0.10 TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`)
- `frontend/src/protocols/shared/fields.ts` (`LENS_FIELD_ALLOWLISTS.mgmt_plane`, `FORBIDDEN_SENSITIVE_FIELDS`)
- `fixtures/raw/FIELDS.md`

## `stream_snmp_ftp.ndjson` (`stream:snmp`, `stream:ftp`)

### `stream:snmp`

| Field | Grounding | Meaning in `mgmt_plane` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `stream:snmp` | Splunk Stream SNMP sourcetype |
| `src_ip`, `dest_ip` | Stream SNMP flow tuple | NMS / manager source IP and managed target IP |
| `src_port`, `dest_port` | L4 UDP ports (`161`, `162`) | Source and destination ports |
| `snmp_version`, `version` | SNMP protocol version | `"1"`, `"2c"`, `"3"` (`v1`/`v2c` flagged as cleartext community-based SNMP) |
| `pdu_type`, `method` | SNMP PDU operation | `"GetRequest"`, `"GetBulkRequest"`, `"SetRequest"` (`set`/`set-request` flagged as SNMP SET write) |
| `status` | SNMP response status | `"noError"` or error string |
| `bytes_in`, `bytes_out` | Byte counters | Request/response byte counts |
| `time_taken` | `flow.time-taken` (µs) | Transaction duration in microseconds |

**Excluded sensitive fields (never selected or present in fixtures):** `community`, `value_raw`, `varbind_list`, `payload`, `_raw`.

### `stream:ftp`

| Field | Grounding | Meaning in `mgmt_plane` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `stream:ftp` | Splunk Stream FTP sourcetype |
| `src_ip`, `dest_ip` | Stream FTP flow tuple | Client source IP and FTP server/device IP |
| `src_port`, `dest_port` | L4 TCP ports (`21`) | Source and destination ports |
| `command`, `method` | FTP command verb | `"RETR"`, `"STOR"`, `"LIST"` (never credential arguments) |
| `status`, `reply_code` | FTP response status & numeric code | e.g. `226`, `"226 Transfer complete"` |
| `bytes_in`, `bytes_out` | Byte counters | Session byte counts |
| `time_taken` | `flow.time-taken` (µs) | Transaction duration in microseconds |

**Excluded sensitive fields (never selected or present in fixtures):** `login`, `password`, `passwd`, `authorization`, `content`, `src_content`, `dest_content`, `_raw`.

## `netflow_cleartext_mgmt.ndjson` (`stream:netflow`)

| Field | Grounding | Meaning in `mgmt_plane` |
| --- | --- | --- |
| `_time` | epoch seconds | Flow end timestamp |
| `host` | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `stream:netflow` | Splunk Stream NetFlow sourcetype |
| `exporter_ip` | `streams/netflow:41` (`netflow.exporterIPAddress`) | Exporting switch/router management IP |
| `src_ip`, `dest_ip` | `streams/netflow:91,98` | Manager/client source IP and target device IP |
| `src_port`, `dest_port` | `streams/netflow:105,112` | L4 ports filtered on cleartext management ports (`21` FTP, `23` Telnet, `69` TFTP, `161`/`162` SNMP, `80` HTTP) |
| `protoid`, `transport` | `streams/netflow:133` | IP protocol (`6`/`tcp`, `17`/`udp`) |
| `bytes`, `packets` | `streams/netflow:147,154` | Flow volume counters |

## `syslog_receipt_gap.ndjson` (`cisco:ios`, `cisco:dc:nexus9k:syslog`, `cisco:aci`)

| Field | Grounding | Meaning in `mgmt_plane` |
| --- | --- | --- |
| `_time` | epoch seconds | Syslog event arrival timestamp |
| `host` | string | Reporting switch/controller hostname or management IP |
| `sourcetype` | `cisco:ios`, `cisco:dc:nexus9k:syslog`, `cisco:aci`, `cisco:dc:aci:syslog` | SC4S or Cisco DC Networking TA syslog sourcetype |
| `category`, `facility` | Syslog facility/category | Non-auth operational facility (`ETHPORT`, `BGP`, `OSPF`, `ACI`); AAA/auth categories excluded |

**Excluded sensitive fields (never selected or present in fixtures):** `_raw`, `syslog_msg`, AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`).
