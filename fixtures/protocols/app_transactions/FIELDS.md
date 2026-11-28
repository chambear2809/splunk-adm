# `app_transactions` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/app_transactions/` are grounded in the extracted Splunk App for Stream 8.1.6 definitions under `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/`:

- `streams/http` (`stream:http`, `statsOnly: true` default)
- `streams/mysql` (`stream:mysql`, `statsOnly: true` default)
- `streams/postgres` (`stream:postgres`, `statsOnly: true` default)
- `streams/tds` (`stream:tds`, `statsOnly: true` default)
- `streams/tns` (`stream:tns`, `statsOnly: true` default)
- `vocabularies/flow.xml`, `vocabularies/http.xml`, `vocabularies/database.xml`, `vocabularies/mysql.xml`, `vocabularies/postgres.xml`, `vocabularies/tds.xml`, `vocabularies/tns.xml`

## 1. `stream_http.ndjson` (`stream:http`)

| Field | Grounding | TA Units / Type | Meaning in `app_transactions` |
| --- | --- | --- | --- |
| `_time` | epoch seconds | epoch s | Event completion timestamp |
| `host` | string | string | Stream forwarder host (`stream-fwd-01`) |
| `sourcetype` | `streams/http:799` | `stream:http` | Splunk Stream HTTP sourcetype |
| `src_ip`, `dest_ip` | `streams/http:331,181` (`http.c-ip`, `flow.s-ip`) | IPv4/IPv6 | Client and HTTP server IP |
| `src_port`, `dest_port` | `streams/http:32,193` (`flow.c-port`, `flow.s-port`) | uint16 | Client and server TCP ports |
| `http_method` | `streams/http:487` (`http.method`) | shortstring | HTTP request verb (`GET`, `POST`, etc.) |
| `status` | `streams/http:603` (`http.status`) | uint16 | HTTP status code (`200`, `401`, `502`, `503`) |
| `uri_path` | `streams/http:639` (`http.uri-stem`) | string | Request path excluding query string (adapter also strips any `?…`/`#…` defensively) |
| `site` | `streams/http:473` (`http.host`) | shortstring | HTTP `Host` header |
| `time_taken` | `streams/http:283` (`flow.time-taken`) | microseconds (µs) | End-to-end transaction duration (`/ 1000` → ms) |
| `bytes_in`, `bytes_out` | `streams/http:89,213` (`flow.cs-bytes`, `flow.sc-bytes`) | uint64 bytes | Client-to-server and server-to-client byte counts |

The adapter also tolerates CIM aliases `method`, `status_code`, `protocol`, `app`, and `response_time` (`flow.sc-send-time`, µs).

## 2. `stream_db.ndjson` (`stream:mysql`, `stream:postgres`, `stream:tds`, `stream:tns`)

| Stream(s) | Field | Grounding | TA Units / Type | Meaning in `app_transactions` |
| --- | --- | --- | --- | --- |
| All DB | `_time`, `host`, `sourcetype` | `streams/{mysql,postgres,tds,tns}` | epoch s, string | Timestamp, forwarder host, Stream DB sourcetype |
| All DB | `src_ip`, `dest_ip`, `src_port`, `dest_port` | `flow.c-ip`, `flow.s-ip`, `flow.c-port`, `flow.s-port` | IP, uint16 | Client and database server tuple |
| All DB | `dbname` | `{mysql,postgres,tds,tns}.dbname` | string | Accessed database / catalog name |
| `mysql`, `postgres`, `tns` | `sql_error_code` | `database.sql-error-code` | shortstring | SQL error code (`0`/`00000` when OK; e.g. `40001` deadlock) |
| `tds` | `sql_error_code` (aliased from `sql_result_codes`) | `streams/tds:371` (`database.sql-error-code-int`, `isList: true`) | uint32[] → string | Projected into `sql_error_code` via `\| eval` after `\| head` |
| `postgres` | `sql_error_code` (boolean-derived from `error` when `sql_error_code` is empty/`00000`) | `streams/postgres:320` (`postgres.error`) | shortstring → `"SQL_ERROR"` | Raw `error` free-text is **never** projected across the wire; converted server-side before `\| table` to `"SQL_ERROR"` |
| All DB | `time_taken`, `response_time` | `flow.time-taken`, `flow.sc-send-time` | microseconds (µs) | Transaction duration and server send time (`/ 1000` → ms) |
| All DB | `result_row_count` | `database.result-row-count` | uint32 | Result set row count (count only, no row values) |
| All DB | `bytes_in`, `bytes_out` | `flow.cs-bytes`, `flow.sc-bytes` | uint64 bytes | Client/server byte counts |

The adapter also tolerates normalized aliases `database`, `db_type`, `protocol`, `app`, `status`, `error_code`, and `rows_returned`. Client-side normalization accepts only strict code tokens matching `/^[A-Za-z0-9_.:-]{1,32}$/` and maps any free-text string to `"SQL_ERROR"`.

## 3. Fields Not Verified Against a Live Deployed Feed

- **`stream:tds` `sql_result_codes` list coercion:** `streams/tds` defines `sql_result_codes` (`isList: true`) rather than `sql_error_code`. Search-time `| eval sql_error_code=coalesce(..., if(sourcetype=="stream:tds", sql_result_codes, null()), ...)` and client array handling have not yet been verified against a live Splunk Stream TDS feed.
- **Non-Stream normalized latency units:** Splunk Stream 8.1.6 defines `time_taken` and `response_time` in microseconds (`µs`). If an alternative non-Stream pipeline writes `response_time` in milliseconds (`ms`), `/ 1000` normalization has not been verified against that feed.
- **`postgres.error` fallback in production:** `streams/postgres` documents `postgres.error` as `shortstring` ("Error message"), which can quote SQL fragments or user input; the adapter never projects `error` across the wire and instead converts non-empty `error` server-side to `"SQL_ERROR"`. Live behavior when `sql_error_code` is `"00000"` alongside a populated `error` has not been verified in a deployed feed.
- **`stream:mysql` / `stream:tns` error population:** Whether live `stream:mysql` and `stream:tns` emit `"0"` vs omit `sql_error_code` on successful queries has not been verified in a live feed; the adapter treats both empty and `"0"`/`"00000"` as healthy on Stream DB sourcetypes.

## 4. Strict Privacy & Security Exclusions

The following fields are **never** projected in SPL, **never** parsed or rendered by `app_transactions`, and **never** included in fixtures:

- `SQL_FORBIDDEN_FIELDS`: `query` (blocked anywhere in `app_transactions` SPL by `assertNoForbiddenFieldsInSpl`)
- `FORBIDDEN_SENSITIVE_FIELDS`: `sql_statement`, `bind_variable_value`, `uri_query`, `form_data`, `cookie`, `authorization`, `content`, `payload`, `src_content`, `dest_content`, `login`, `password`, `passwd`, `_raw`
- Wire-excluded free-text fields: `error` (`postgres.error` is converted server-side to boolean `"SQL_ERROR"` before `| table` and is not in `LENS_FIELD_ALLOWLISTS.app_transactions`)
- Stream fields intentionally omitted: `affected_tables`, `http.uri`, `http.request`, `http.cs-headers`, `http.sc-headers`, `http.referer`, `user`, `ntlm_user`, `proxy_login`
