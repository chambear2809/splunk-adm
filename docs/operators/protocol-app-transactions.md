# Operator Guide: HTTP & DB Transactions (`app_transactions`)

**Status:** Staged (synthetic fixture-verified; not yet qualified against a live deployed feed)

The **HTTP & DB Transactions** lens tracks golden signals (transaction rate, error rate, and p50/p95 latency) per HTTP service and SQL database endpoint across **Splunk Stream** wire telemetry without collecting SQL query text, bind variable values, HTTP query strings, form payloads, or cookies.

## 1. Supported Data Sources

| Kind | Sourcetype(s) | Collector | Coverage |
| --- | --- | --- | --- |
| HTTP | `stream:http` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Request rate, HTTP status (`4xx`/`5xx`), sanitized `uri_path` (query strings stripped), `site`, `time_taken` / `response_time` (µs), `bytes_in` / `bytes_out`. |
| SQL Databases | `stream:mysql`, `stream:postgres`, `stream:tds`, `stream:tns` | Splunk Stream 8.1.6+ | Transaction rate, SQL error rate (strict code tokens from `sql_error_code` / `sql_result_codes`, or `"SQL_ERROR"` boolean fallback), `dbname`, `result_row_count`, `time_taken` / `response_time` (µs), `bytes_in` / `bytes_out`. |

## 2. Enabling Splunk Stream (`http`, `mysql`, `postgres`, `tds`, `tns`)

In Splunk App for Stream 8.1.6, `streams/http`, `streams/mysql`, `streams/postgres`, `streams/tds`, and `streams/tns` ship with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream writes volume estimates into `_internal` (`sourcetype="stream:stats"`) without indexing protocol transaction events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or universal forwarder.
2. In Splunk App for Stream (**Configuration → Configure Streams**), switch the streams you want to monitor (`http`, `mysql`, `postgres`, `tds`, `tns`) from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and assign the target index (for example `stream_app`).
3. **Disable sensitive fields in Stream configuration (recommended):** Uncheck `query`, `sql_statement`, `affected_tables`, `bind_variable_value`, `login`, `password`, `cookie`, `form_data`, `uri_query`, `uri`, `request`, `src_headers`, `dest_headers`, `src_content`, and `dest_content` in your Stream definitions so sensitive credentials and payloads are not indexed at all.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and a queried Stream source completes with 0 rows, or clicks **Check Stream mode** in the banner, Atlas inspects `index=_internal sourcetype="stream:stats"` (`senders{}.streams{}.id` and `senders{}.streams{}.stats_only`) to report whether any of `http`, `mysql`, `postgres`, `tds`, or `tns` remain in Estimate mode.

## 3. Strict Privacy Boundary

- **Blocked at SPL & projection layers:** `assertNoForbiddenFieldsInSpl("app_transactions", spl)`, `buildAllowedFieldsClause("app_transactions", ...)`, and `projectRowToLensAllowlist` forbid `query`, `sql_statement`, `bind_variable_value`, `uri_query`, `form_data`, `cookie`, `authorization`, `content`, `payload`, `src_content`, `dest_content`, `login`, `password`, `passwd`, and `_raw`. Raw free-text SQL `error` messages are never projected across the wire (`| eval` maps non-empty `error` to `"SQL_ERROR"` before `| table`, and client normalization maps any non-code-token string to `"SQL_ERROR"`).
- **Client-side defensive sanitization:** `uri_path` is stripped of any `?…` query string or `#…` fragment client-side before aggregation or display.
- **Server-side row bounding:** Every SPL search emits `| head <maxRows + 1>` before `| table <allowlisted fields>` so indexers bound rows and drop `_raw` before results reach the search head.

## 4. Profile Configuration (`adm_protocol_profiles`)

Configure a unified `"auto"` profile (when HTTP and DB streams share an index) or separate `"http"` and `"db"` profiles under the same `scope`:

```json
{
  "id": "app-txns-dc1",
  "source": "protocol_app_transactions",
  "lens": "app_transactions",
  "scope": "prod:dc1",
  "index": "stream_app",
  "observer": "stream-fwd-01",
  "validFrom": 1764243000,
  "validUntil": 1764250200,
  "extra": {
    "sourceKind": "auto",
    "errorRateWarnPct": 5,
    "latencyWarnMs": 500
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"auto" \| "http" \| "db"` | `"auto"` | Exact enum only |
| `errorRateWarnPct` | number (%) | `5` | `(0, 100]` |
| `latencyWarnMs` | number (ms) | `500` | `(0, 60000]` |

Unknown keys or out-of-range thresholds fail closed during profile validation.

## 5. Verification Checklist

1. Confirm Stream events are indexed with non-sensitive fields:
   - `index=<index> sourcetype="stream:http" | head 5 | table _time src_ip dest_ip dest_port http_method status uri_path site time_taken`
   - `index=<index> (sourcetype="stream:mysql" OR sourcetype="stream:postgres" OR sourcetype="stream:tds" OR sourcetype="stream:tns") | head 5 | table _time sourcetype src_ip dest_ip dest_port dbname sql_error_code time_taken`
2. Open **Application Atlas → Protocols → HTTP & DB Transactions**, select the scope and UTC window, and click **Investigate**.
3. Confirm:
   - Flagged services sort first in Overview; healthy services sit behind **Show all (n)**.
   - Client × Server Matrix marks unobserved pairs as **None observed** when complete and **Unknown** when capped/partial.
   - Detail Drawer displays **Status** first, sanitized `uri_path` / `dbname` breakdowns, privacy boundary notice, and a `literal()`-quoted **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Lab only**
- **Notes:** Splunk Stream HTTP/DB wire streams (`http`, `mysql`, `postgres`, `tds`, `tns`) remain in Estimate mode on PseudoCo (no capture NIC / 80% daily license cap). Verified via unit and Playwright fixture tests.

