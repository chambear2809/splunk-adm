# Operator Guide: Load Balancer Pool Health (`lb_health`)

**Status:** Staged (synthetic fixture-verified; not yet qualified against a live deployed feed)

The **Load Balancer Pool Health** lens inspects VIP, pool/target-group, and member health across **F5 BIG-IP LTM** (iRule HSL / SC4S), **AWS Application Load Balancer (ALB)** access logs, and **AWS Network Load Balancer (NLB)** TLS access logs over a bounded UTC window.

## 1. Supported Data Sources

| Source | Sourcetypes | Collector / TA | Error Split & Coverage |
| --- | --- | --- | --- |
| F5 BIG-IP LTM | `f5:bigip:ltm:http:irule`, `f5:bigip:ltm:lb:failed:irule`, `f5:bigip:ltm:failed:irule` | Splunk Add-on for F5 BIG-IP (iRule HSL) or SC4S | `Splunk-iRule-LB_FAILED` / `*failed:irule` → **Balancer error** (pool selection or member connect failed). `http_status >= 500` with a selected `node`/`member_ip` → **Target error**. |
| AWS ALB | `aws:elb:accesslogs`, `aws:alb:accesslogs` | Splunk Add-on for AWS (ELB access logs) | `elb_status_code >= 500` when `target_status_code` is `-`/absent, `< 500`, or differs with `error_reason` → **Balancer error**. `target_status_code >= 500` → **Target error**. |
| AWS NLB (TLS) | `aws:elb:accesslogs`, `aws:nlb:accesslogs` | Splunk Add-on for AWS (ELB access logs) | Non-empty `tls_alert` (other than `-`/`none`) or `verify_status` starting with `Failed` → **Balancer/TLS error**. Backend targets are not logged by NLB (`Target Errs` renders **Not covered**). |

> Reference contract: `frontend/src/ecosystem/loadBalancerEvidence.ts` (`F5_LTM_HTTP`, `AWS_ELB_ACCESS`).

## 2. F5 BIG-IP TA iRule HSL & SC4S Setup

1. Attach the Splunk Add-on for F5 BIG-IP LTM iRules (`Splunk-iRule-HTTP` and `Splunk-iRule-LB_FAILED`) to your virtual servers and route HSL traffic to your Splunk syslog / SC4S collector.
2. **Sourcetype mapping:**
   - The Splunk Add-on for F5 BIG-IP assigns `f5:bigip:ltm:http:irule` and `f5:bigip:ltm:lb:failed:irule`.
   - **SC4S (Splunk Connect for Syslog)** assigns `f5:bigip:ltm:failed:irule` for `LB_FAILED` events. The `lb_health` lens accepts both `f5:bigip:ltm:lb:failed:irule` and `f5:bigip:ltm:failed:irule`.
3. Ensure extracted/aliased fields (`f5_irule`, `vip`, `virtual_server`, `pool`/`pool_name`, `node`/`member_ip`, `node_port`/`member_port`, `src_ip`, `http_method`, `http_status`, `req_elapsed_time`/`response_time`/`time_taken`, `bytes_in`, `bytes_out`) are available in the target index. The lens also runs an anchored `rex` extraction before `| head` to prevent unquoted `http_uri`/`http_url` delimiter injection from forging `node` or `http_status` values.

## 3. AWS ALB & NLB Access Logs Setup

1. Enable S3 access logging on your ALB and TLS-enabled NLB listeners in AWS.
2. In Splunk Add-on for AWS, configure an SQS-based S3 or Incremental S3 input using `aws:elb:accesslogs` (or explicit `aws:alb:accesslogs` / `aws:nlb:accesslogs` sourcetypes) pointing to the target index.
3. For ALB, ensure `elb_status_code`, `target_status_code`, `error_reason`, `target_group`, `target_ip`, `target_port`, and processing-time fields (`request_processing_time`, `target_processing_time`, `response_processing_time`) are extracted.
4. For NLB TLS, ensure `elb`, `listener`, `connection_time_ms`, `handshake_time_ms`, `tls_alert`, `verify_status`, `ssl_protocol`, and `tls_version` are extracted.

## 4. Interpreting Balancer vs. Target Errors

- **Balancer error (F5 `LB_FAILED`, ALB pre-target 5xx, NLB TLS failures):** The load balancer itself failed to select/reach a healthy pool member (`LB_FAILED`, `NoHealthyTargets`, `TargetTimeout`), rejected authentication/Lambda (`AuthInvalidToken`, `LambdaUnhandled`), or failed TLS negotiation at the NLB listener (`tls_alert`, `Failed:*`). Inspect pool health checks, target group capacity, SG/NACL rules, and listener certificates.
- **Target error (F5 member 5xx, ALB `target_status_code >= 500`):** A specific backend member/target received the request and returned HTTP 5xx (for example `502`/`503`/`500`). Inspect application logs and resource saturation on the flagged member IP.
- **Latency (`p95`):** F5 uses `req_elapsed_time` (falling back to `response_time`/`time_taken`, in ms); ALB sums non-negative `request_processing_time`, `target_processing_time`, and `response_processing_time` (converted from seconds to ms); NLB uses `handshake_time_ms` (not total idle `connection_time_ms`).

## 5. Profile Configuration (`adm_protocol_profiles`)

Configure one `auto` profile (when F5 and AWS logs share an index, or to auto-detect) or source-scoped profiles (`f5_ltm`, `aws_alb`, `aws_nlb`) under the same `scope`:

```json
{
  "id": "lb-health-prod",
  "source": "protocol_lb_health",
  "lens": "lb_health",
  "scope": "prod:us-east",
  "index": "lb_logs",
  "observer": "bigip-01",
  "validFrom": 1764243000,
  "validUntil": 1764250200,
  "extra": {
    "sourceKind": "auto",
    "errorRateWarnPct": 2,
    "latencyWarnMs": 500,
    "lbFailedWarnCount": 1
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"auto" \| "f5_ltm" \| "aws_alb" \| "aws_nlb"` | `"auto"` | Exact enum only |
| `errorRateWarnPct` | number | `2` | `(0, 100]` |
| `latencyWarnMs` | number | `500` | `(0, 60000]` |
| `lbFailedWarnCount` | integer | `1` | `[1, 1000]` |

Unknown keys or out-of-range values fail closed during profile parsing.

## 6. Evidence Semantics & Security Boundaries

- **Sensitive fields excluded:** Searches strictly project allowlisted `lb_health` fields via `buildAllowedFieldsClause("lb_health", ...)` and never select `_raw`, `cookie`, `form_data`, `uri_query`, `user_id`, `authorization`, `http_user_agent`, or `ssl_session_id`.
- **Bounded search:** Every search emits `| head <maxRows + 1>` before `| table ...`, capping rows at the indexers and dropping `_raw` server-side.
- **Not covered vs. None observed:** NLB TLS rows without backend target telemetry render **Not covered** in the `Target Errs` column and KPI tile when no F5/ALB target telemetry is present. Capped, blocked, or unavailable searches never display `None observed`.

## 7. Verification Checklist

1. Confirm F5 and AWS ELB/ALB/NLB fields in Splunk:
   - `index=<lb_index> (sourcetype="f5:bigip:ltm:http:irule" OR sourcetype="f5:bigip:ltm:lb:failed:irule" OR sourcetype="f5:bigip:ltm:failed:irule") | head 5 | table _time f5_irule vip pool node node_port http_status req_elapsed_time`
   - `index=<aws_index> (sourcetype="aws:elb:accesslogs" OR sourcetype="aws:alb:accesslogs" OR sourcetype="aws:nlb:accesslogs") | head 5 | table _time elb target_group target_ip elb_status_code target_status_code error_reason tls_alert verify_status`
2. Open **Application Atlas → Protocols → Load Balancer Pool Health**, select the scope and UTC window, and click **Investigate**.
3. Confirm `LB_FAILED`, ALB balancer-vs-target 5xx splits, and NLB TLS failures sort first in Overview, highlight in the VIP × Pool Member Matrix, and open with `literal()`-quoted raw-event links in the Detail drawer.
