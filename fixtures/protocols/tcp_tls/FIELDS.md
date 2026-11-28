# `tcp_tls` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/tcp_tls/` are grounded in the extracted Splunk Stream 8.1.6 stream definition at `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/tcp` and the existing repository NetFlow grounding in `fixtures/raw/FIELDS.md`.

## `stream:tcp` (`stream_tcp_tls.ndjson`)

Verified directly against `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/tcp` (Splunk App for Stream 8.1.6, where default is `enabled: true`, `statsOnly: true` / Estimate mode):

| Field | TA Type / Units | Meaning in `tcp_tls` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Forwarder or sensor host |
| `sourcetype` | string (`stream:tcp`) | Splunk Stream TCP sourcetype |
| `src_ip`, `dest_ip` | string (IPv4/IPv6) | Client and server addresses |
| `src_port`, `dest_port` | integer | Ephemeral client port and service port |
| `bytes_in`, `bytes_out` | bytes | Directional byte counts |
| `packets_in`, `packets_out` | packets | Directional packet counts |
| `client_rtt`, `server_rtt` | microseconds (µs) | Average client/server RTT; converted to ms (`/ 1000`) by `adapter.ts` |
| `client_rtt_packets`, `server_rtt_packets` | packets | Sample count backing `client_rtt`/`server_rtt` (`0` + `0` = unmeasured) |
| `duplicate_packets_in`, `duplicate_packets_out` | packets | Duplicate/retransmitted TCP packets |
| `missing_packets_in`, `missing_packets_out` | packets | Missing packet gaps detected by Stream (contributes to loss/retransmit ratio; note sensor capture drops can also increment this counter) |
| `canceled`, `refused` | boolean (`true`/`false`) | Connection canceled or refused |
| `tcp_status` | integer (`0`, `1`, `2`) | Stream 8.1.6 enum: `0=OK`, `1=RESET`, `2=IGNORED` |
| `time_taken` | microseconds (µs) | Connection duration |
| `ssl_version` | string | Negotiated SSL/TLS version (e.g. `TLSv1.3`, `TLSv1.2`, `TLSv1.0`, `TLSv1`) |
| `ssl_cipher_name` | string | Negotiated TLS cipher suite |
| `ssl_subject` | string | Leaf X.509 certificate subject DN |
| `ssl_issuer` | string | Certificate issuer DN |
| `ssl_validity_end` | string / epoch | Certificate expiration timestamp (parsed via `Date.parse` or epoch seconds to compute remaining days relative to query `latest`) |
| `ssl_cert_self_signed` | integer (`1`/`0`) or boolean | Whether the server certificate is self-signed (`streams/tcp` documents `1`/`0`; adapter accepts both `1`/`0` and boolean) |
| `vxlan_id` | string/integer | Optional VXLAN VNI when encapsulated |

### Adapter Compatibility Aliases (Not Emitted by Default Stream 8.1.6)

The adapter also tolerates normalized/CIM alias fields if an external knowledge object or newer TA emits them (`tls_version`, `ssl_cipher`, `cipher_suite`, `ssl_cert_subject`, `ssl_subject_common_name`, `ssl_cert_not_after`, `ssl_end_time`, `ssl_cert_days_remaining`, `sni`, `ssl_error`), and falls back to `retransmits` / `resets` if pre-aggregated. Synthetic fixtures in this directory emit only verified Stream 8.1.6 `streams/tcp` fields.

### Excluded Sensitive Fields

`src_content`, `dest_content`, `ssl_session_id`, and all raw packet/payload fields are strictly excluded by `FORBIDDEN_SENSITIVE_FIELDS` and `buildAllowedFieldsClause` (`| table ...`, which drops `_raw` server-side). Any other unallowlisted fields are dropped both by `| table` and by client-side `projectRowToLensAllowlist`.

## `stream:netflow` (`stream_netflow_fallback.ndjson`)

Grounded in `fixtures/raw/FIELDS.md` (`stream:netflow`):

| Field | Type / Units | Meaning in `tcp_tls` Fallback |
| --- | --- | --- |
| `_time` | epoch seconds | Flow export timestamp |
| `host`, `exporter_ip` | string | Exporter switch or NetFlow collector |
| `sourcetype` | string (`stream:netflow`) | NetFlow fallback sourcetype |
| `src_ip`, `dest_ip` | string | Flow endpoints |
| `src_port`, `dest_port` | integer | Flow ports |
| `bytes`, `packets` | bytes / packets | Projected via `eval total_bytes=...` / `eval total_packets=...` into allowlisted `total_bytes`/`total_packets` |

NetFlow fallback rows NEVER emit synthetic RTT, retransmits, resets, or TLS posture — they always render as `Not covered`.
