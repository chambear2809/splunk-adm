# Operator Guide: DNS Operations (`dns_ops`)

The **DNS Operations** lens inspects per `client → resolver` DNS query health, `NXDOMAIN` / `SERVFAIL` / `REFUSED` rates, resolver latency (`response_time` / `time_taken` p50/p95 in ms), answer churn (multiple distinct answer sets observed for a domain), and search-suffix amplification hints across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary | `stream:dns` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Full coverage: `query`, `query_type`, `reply_code` / `reply_code_id`, `message_type`, `response_time` / `time_taken` (µs), `host_addr`, `answer`, `answers`, `ttl`, `transaction_id`. |
| Fallback | `cilium:hubble:flow` | Cilium / Hubble L7 DNS flow export via OTel Collector | Query names, `qtypes`, `rcode`, answer `ips`, and `ttl` (`flow.l7.dns.*`). Resolver latency is not exported by Hubble and explicitly reports **Not covered** (unflagged Hubble-only pairs never report green `OK`). |

## 2. Enabling `stream:dns` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6, `streams/dns` ships with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream reports volume estimates into `_internal` (`sourcetype="stream:stats"`) but does **not** index `stream:dns` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or universal forwarder.
2. In Splunk App for Stream (**Configuration → Configure Streams → dns**), switch `dns` from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`), disable aggregation so individual transactions are retained, and select the target index (for example `netflow` or `stream_dns`).
3. Keep raw packet/payload fields (`src_content`, `dest_content`, `txt_vals`) disabled where not needed. Application Atlas blocks payload fields in both SPL construction (`| table ...`) and client-side row projection (`FORBIDDEN_SENSITIVE_FIELDS`).
4. Monitor daily Splunk license volume before enabling `stream:dns` on busy recursive resolvers.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:dns` completes with 0 rows, or clicks **Check Stream mode** in the banner, Atlas inspects `index=_internal sourcetype="stream:stats"` (parsing `senders{}.streams{}.id` and `senders{}.streams{}.stats_only`) and reports directly whether `dns` is still in Estimate mode.

## 3. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "dns_ops"` under a scope (for example `dc-east`):

```json
{
  "id": "dns-ops-primary",
  "lens": "dns_ops",
  "scope": "dc-east",
  "index": "stream_dns",
  "label": "Stream DNS (dc-east)",
  "extra": {
    "sourcetype": "stream:dns",
    "latencyWarnMs": 50,
    "nxdomainWarnPct": 10,
    "servfailWarnPct": 2
  }
}
```

Add an optional fallback profile with `"sourcetype": "cilium:hubble:flow"` under the same scope; it runs only when the primary `stream:dns` profile returns zero events.

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourcetype` | `"stream:dns" \| "cilium:hubble:flow"` | `"stream:dns"` | Exact enum only |
| `latencyWarnMs` | number (ms) | `50` | `(0, 60000]` |
| `nxdomainWarnPct` | number (%) | `10` | `[0, 100]` |
| `servfailWarnPct` | number (%) | `2` | `[0, 100]` |

Unknown keys or out-of-range values fail closed at profile validation time.

## 4. Field Grounding & Security Boundaries

- **TA source:** `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/dns` and `fixtures/protocols/dns_ops/FIELDS.md`.
- **Units:** `response_time` (request-to-response) and `time_taken` (flow completion) are in microseconds (µs); Atlas divides by `1000` to render milliseconds and omits latency on request-only records.
- **Response codes:** `reply_code` and `reply_code_id` (`0=NOERROR`, `2=SERVFAIL`, `3=NXDOMAIN`, `5=REFUSED`) normalize consistently across Stream and Hubble `flow.l7.dns.rcode` (treating omitted proto3 `rcode` on Hubble `RESPONSE` events as `NOERROR`).
- **Directionality in Hubble:** On `cilium:hubble:flow` `RESPONSE` events, `flow.IP.source` is the resolver and `flow.IP.destination` is the client; `buildDnsOpsSearch` and `normalizeDnsOpsRow` invert `REQUEST` vs `RESPONSE` endpoints accurately.
- **Server-side projection:** All searches emit `| head <maxRows + 1> | table <allowlisted fields>`, bounding rows at the indexers and dropping `_raw` before results leave Splunk. `query` is allowlisted on `dns_ops` (domain name) while remaining blocked on SQL lenses.
- **Role scoping:** Per `splunk_app/splunk_adm/metadata/default.meta`, the `adm_protocol_profiles` KV Store collection is readable by `adm_investigate`, `adm_viewer`, `admin`, and `sc_admin`, and writable only by `admin` and `sc_admin`.

## 5. Verification Checklist

1. Verify `stream:dns` events are landing in the configured index:
   `index=<index> sourcetype="stream:dns" | head 5 | table _time src_ip dest_ip query query_type reply_code reply_code_id response_time host_addr`
2. Open **Application Atlas → Protocols → DNS Operations**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - Flagged `client → resolver` pairs sort to the top of Overview and highlight in Matrix.
   - Selecting any pair opens the Detail drawer with Status first, copyable client/resolver IPs, top failing query domains, answer churn count, Exceptions, and a bounded **Open raw events in Splunk** link.
   - If only `cilium:hubble:flow` is present, resolver latency reports **Not covered** and unflagged pairs never report green `OK`.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (`stream:dns`)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** Scoped `streamfwd` capture (`atlas-streamfwd-wire.service`) feeds live `stream:dns` into `index=netflow` (~`0.08 MiB/hr`): `7` client → resolver pairs observed (`Resolver Latency p95: 40 ms`, `0.0%` SERVFAIL/NXDOMAIN, `1` high-latency pair `69 ms` flagged with `Resolver latency p50 / p95` bar chart). Production Hubble DNS SPL (`flow.l7.dns.*`) is also verified in the Docker Splunk lab (`tests/splunk/test_protocol_lenses.py::test_dns_ops_hubble_search_returns_l7_dns_fields`).

