# `lb_health` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/lb_health/` are grounded in:
- `fixtures/raw/FIELDS.md` ("Ecosystem load balancer and cloud flow logs")
- `frontend/src/ecosystem/loadBalancerEvidence.ts` (`F5_LTM_HTTP`, `AWS_ELB_ACCESS`)
- `frontend/src/protocols/shared/fields.ts` (`LENS_FIELD_ALLOWLISTS.lb_health`, `FORBIDDEN_SENSITIVE_FIELDS`)
- Splunk Add-on for F5 BIG-IP (`f5:bigip:ltm:http:irule`, `f5:bigip:ltm:lb:failed:irule`) and SC4S (`f5:bigip:ltm:failed:irule`)
- AWS ALB Access Logs (`aws:elb:accesslogs`, `aws:alb:accesslogs`) and AWS NLB TLS Access Logs (`aws:elb:accesslogs`, `aws:nlb:accesslogs`)

## `f5_ltm_irule.ndjson` (`f5:bigip:ltm:http:irule`, `f5:bigip:ltm:lb:failed:irule`, `f5:bigip:ltm:failed:irule`)

| Field | Grounding | Meaning in `lb_health` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | string | BIG-IP / syslog collector host (`bigip-01`) |
| `sourcetype` | `f5:bigip:ltm:http:irule` / `lb:failed:irule` / `failed:irule` | F5 BIG-IP TA or SC4S iRule HSL sourcetype |
| `f5_irule` | `Splunk-iRule-HTTP` / `Splunk-iRule-LB_FAILED` | Distinguishes forwarded HTTP transactions from `LB_FAILED` balancer failures |
| `vip` | `IP::local_addr` (optional `%rd` route domain) | Virtual server IP owned by the balancer |
| `virtual_server` | `LB::server` | Virtual server / pool string |
| `pool` | `pool` / `pool_name` / first token of `virtual_server` | Selected LTM pool |
| `node`, `node_port` | `LB::server addr` / `port` | Selected pool member IP (optional `%rd`) and port; omitted on `LB_FAILED` |
| `src_ip` | `IP::client_addr` | Client IP (optional `%rd`) |
| `http_method` | `HTTP::method` | HTTP request method |
| `http_status` | `HTTP::status` | Backend HTTP status (`>= 500` with member = target error) |
| `req_elapsed_time` | `req_elapsed_time` (ms; fallback `response_time` / `time_taken`) | Elapsed request-to-response time in milliseconds |
| `bytes_in`, `bytes_out` | Content-Length headers | Request and response byte counters |

## `aws_alb_nlb.ndjson` (`aws:elb:accesslogs`, `aws:alb:accesslogs`, `aws:nlb:accesslogs`)

### AWS Application Load Balancer (`app/...`)

| Field | Grounding | Meaning in `lb_health` |
| --- | --- | --- |
| `_time` | epoch seconds | Request completion timestamp |
| `host` | string | AWS TA collector host (`aws-ta-hf`) |
| `sourcetype` | `aws:elb:accesslogs` / `aws:alb:accesslogs` | AWS ELB/ALB access log sourcetype |
| `elb` | ALB resource ID (`app/<name>/<id>`) | Load balancer identifier |
| `target_group` | ARN (`targetgroup/<name>/<id>`) | Target group / pool identifier |
| `target_ip`, `target_port` | field 5 (`target:port`, `-` when not forwarded) | Selected backend target IP and port |
| `src_ip` | field 4 (`client:port` IP) | Client IP |
| `dest_ip` | field 34 (`ip_address`) | Load balancer node IP |
| `elb_status_code` | field 9 | Status code returned by ALB (`>= 500` without target 5xx or with `error_reason` = balancer error) |
| `target_status_code` | field 10 (`-` when no target contacted) | Status code returned by target (`>= 500` = target error) |
| `error_reason` | field 25 | ALB error reason (`NoHealthyTargets`, `TargetTimeout`, `LambdaUnhandled`, etc.) |
| `actions_executed` | field 23 | ALB rule actions (`forward`, `authenticate`, `waf`, etc.) |
| `request_processing_time`, `target_processing_time`, `response_processing_time` | fields 6–8 (seconds, `-1` when unset) | Summed and converted to ms for request latency |
| `bytes_in`, `bytes_out` | fields 11–12 | Received and sent bytes |
| `ssl_protocol`, `tls_version` | fields 15–16 | TLS cipher suite and protocol version |

### AWS Network Load Balancer TLS (`net/...`)

| Field | Grounding | Meaning in `lb_health` |
| --- | --- | --- |
| `sourcetype` | `aws:elb:accesslogs` / `aws:nlb:accesslogs` | AWS NLB TLS access log sourcetype |
| `elb` | NLB resource ID (`net/<name>/<id>`) | Load balancer identifier |
| `listener` | NLB field 5 | TLS listener ID |
| `src_ip`, `dest_ip` | NLB fields 6–7 | Client IP and listener endpoint IP (NLB does not log backend target IP) |
| `connection_time_ms`, `handshake_time_ms` | NLB fields 8–9 (ms) | Total connection duration and TLS handshake latency (`handshake_time_ms` used for latency p95) |
| `bytes_in`, `bytes_out` | NLB fields 10–11 | Decrypted client bytes in/out |
| `ssl_protocol`, `tls_version` | NLB fields 14–15 | TLS cipher and protocol |
| `tls_alert` | NLB field 12 | TLS alert sent/received (`-`/`none` when absent) |
| `verify_status` | NLB field 21 | `Success` or `Failed:<reason>` |

### Excluded Sensitive Fields

`_raw`, `cookie`, `form_data`, `uri_query`, `user_id`, `authorization`, `http_user_agent`, `http_uri`, `http_url`, and `ssl_session_id` are never projected (`buildAllowedFieldsClause("lb_health", ...)` and `projectRowToLensAllowlist("lb_health", ...)`).
