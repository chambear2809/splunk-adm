# `dns_ops` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/dns_ops/` are grounded in the extracted Splunk Stream 8.1.6 DNS stream definition at `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/dns` and the `cilium:hubble:flow` DNS L7 schema documented in `fixtures/raw-aci/FIELDS.md` and `tests/splunk/test_dns_evidence.py`.

## `stream:dns` (`stream_dns.ndjson`)

Verified directly against `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/dns` (Splunk App for Stream 8.1.6, where default is `enabled: true`, `statsOnly: true` / Estimate mode):

| Field | TA Type / Units | Meaning in `dns_ops` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | Forwarder or sensor host |
| `sourcetype` | string (`stream:dns`) | Splunk Stream DNS sourcetype |
| `src_ip`, `dest_ip` | string (IPv4/IPv6) | Client IP (`flow.c-ip`) and DNS resolver IP (`flow.s-ip`) |
| `query` | string or string[] (`isList: true`) | Queried DNS domain name (`dns.query`) |
| `query_type` | string or string[] (`isList: true`) | DNS record type (`A`, `AAAA`, `SRV`, etc.; `dns.query-type`) |
| `message_type` | string or string[] (`isList: true`) | `QUERY`, `RESPONSE` (`dns.message-type`) |
| `reply_code` | string | Return message (`NoError`, `NXDomain`, `ServFail`, `Refused`; `dns.reply-code`) |
| `reply_code_id` | integer | Numeric DNS rcode (`0=NOERROR`, `2=SERVFAIL`, `3=NXDOMAIN`, `5=REFUSED`; `dns.reply-code-id`) |
| `response_time` | microseconds (µs) | Request-to-response elapsed time (`dns.response-time`), converted to ms (`/ 1000`) |
| `time_taken` | microseconds (µs) | Flow event duration (`flow.time-taken`), fallback latency in µs when `response_time` is absent |
| `host_addr` | string[] (`isList: true`) | Returned IP addresses (`dns.host-addr`), used for answer-churn detection |
| `ttl` | integer[] (`isList: true`, seconds) | Answer TTL (`dns.ttl`) |
| `transaction_id` | integer | DNS transaction identifier (`dns.transaction-id`) |

### Excluded Fields Not Projected by `dns_ops`

`LENS_FIELD_ALLOWLISTS.dns_ops` intentionally excludes `src_content`, `dest_content`, `txt_vals`, and `_raw`. `buildDnsOpsSearch` projects only allowlisted fields via `| head <maxRows + 1> | table <allowlisted fields>`, dropping `_raw` server-side before results leave Splunk.

## `cilium:hubble:flow` (`hubble_dns.ndjson`)

Grounded in `fixtures/raw-aci/FIELDS.md` (`cilium:hubble:flow` `ExportEvent` / `flow.proto`) and `tests/splunk/test_dns_evidence.py`:

| Field | Schema / Notes | Meaning in `dns_ops` Fallback |
| --- | --- | --- |
| `_time` | epoch seconds | Flow observation timestamp |
| `host` | string | Kubernetes node name |
| `sourcetype` | string (`cilium:hubble:flow`) | Hubble flow export sourcetype |
| `node_name` | string (`<cluster>/<node>`) | Hubble cluster/node observer |
| `flow.IP.source`, `flow.IP.destination` | string | Source and destination IP; on `RESPONSE` flows `flow.IP.source` is the resolver and `flow.IP.destination` is the client (inverted vs `REQUEST`). `buildDnsOpsSearch` projects into allowlisted `src_ip` / `dest_ip`. |
| `flow.l7.type` | `"REQUEST"` \| `"RESPONSE"` | L7 DNS message direction, projected into allowlisted `message_type` |
| `flow.l7.dns.query` | string | Queried domain name |
| `flow.l7.dns.qtypes` | string[] | Requested DNS RR types |
| `flow.l7.dns.rcode` | integer | Numeric DNS rcode (`0=NOERROR`, `2=SERVFAIL`, `3=NXDOMAIN`, `5=REFUSED`; proto3 may omit `0` on `RESPONSE` events) |
| `flow.l7.dns.ips` | string[] | Returned answer IPs |
| `flow.l7.dns.ttl` | integer (seconds) | Reported RRset TTL |

Hubble DNS L7 export does **not** carry resolver latency (`response_time` / `time_taken`). `dns_ops` always surfaces latency as `Not covered` in Hubble-only mode and never marks a Hubble-only row green `OK`.
