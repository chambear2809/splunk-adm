# Change verification

**Verify change** lives at the bottom of the Impact page. In the demo, the CAB pre-flight under Depends on also links to it. You save dependency assertions, pick a before and an after window around a change, and Atlas reports **pass**, **fail** or **unknown** for each assertion. The result pack exports as JSON, CSV or Markdown. Exports are drafts: Atlas writes nothing back to ServiceNow, devices or any other system.

Status: the evaluation reads the existing scoped Trace reader. **It has not been qualified against a live deployment.** ServiceNow change-number lookup is unqualified as well: no live `snow:change_request` input has been checked.

## Assertions

| Kind | Statement | Fields |
| --- | --- | --- |
| Reaches | A reaches B on `tcp/5432` | scope, source IP, destination IP, transport (tcp, udp, sctp), port |
| Redundant paths | A reaches B on `tcp/5432` through at least N observers | as above, plus N from 2 to 8 |
| No new blocked flows | No blocked or dropped flows between A and B that were not already there before the change | scope, source IP, destination IP |

Assertions need a mapped routing scope (not `unmapped:`) and canonical IP literals. Use the IPv4 form for IPv4-mapped addresses and lower-case, compressed IPv6. The Impact selection can draft up to five "Reaches" assertions from the conversations it found. Drafts run without being saved.

### Storage and permissions

Saved assertions are shared rows in the KV collection `adm_change_assertions`. They go through the same insert-only, hash-chained collaboration ledger as shared saved views (`adm/collaboration?kind=assertions`).

- Reading needs `adm_investigate`, like every collaboration read.
- Saving needs `adm_investigate` **and** write access to the collection. `metadata/default.meta` grants write to `admin` and `sc_admin` only. Other investigators can read and run the shared assertions, and they can run their own unsaved drafts. When they try to save, the UI tells them it did not happen.
- Each saved assertion records its owner. Nobody can change or delete an assertion that another user owns, administrators included, in the same way as shared views. The check runs against the current ledger head, inside the compare-and-swap write.
- Bounds: at most 100 assertions, 24 KiB per document, names up to 80 characters, notes up to 280 characters on one line. The server rejects anything else.
- Compacting the ledger needs `admin_all_objects`, the same as for views and ownership.
- An assertion is never an authorization source. Evaluation always runs as the reader, so a user without index access sees unknown, not pass.

## Windows

- **Manual:** enter the change start and end in UTC and choose a comparison span of 15 minutes, 1 hour or 4 hours. The before window is `[start − span, start)` and the after window is `[end, end + span)`.
- **ServiceNow change number:** live only. This needs the Splunk Add-on for ServiceNow ([Splunkbase 1928](https://splunkbase.splunk.com/app/1928)) collecting the `change_request` table, which gives sourcetype `snow:change_request` ([data types](https://splunk.github.io/splunk-add-on-for-servicenow/Datatypes/)). Point the `adm_index_snow` macro at that index. `adm_change_request_window(<number>)` reads at most 500 events from the last 90 days and keeps the latest record per `sys_id`, ordered by `sys_updated_on`, the add-on's time field for `change_request` ([inputs](https://splunk.github.io/splunk-add-on-for-servicenow/Configureinputs/)).
  - If `work_start` and `work_end` are both set, they define the window, labelled *actual*.
  - If no work start is recorded, `start_date` and `end_date` define it, labelled *planned*.
  - Work started with no valid work end, more than one `sys_id` for the number, more than 500 events, or a missing record all stop the lookup. Enter the window manually instead.
  - Dates must be in the ServiceNow API `value` form, UTC `YYYY-MM-DD hh:mm:ss` ([Change Management API](https://www.servicenow.com/docs/r/api-reference/rest-apis/change-management-api.html)). Display values and other formats are rejected. Do not configure the input to replace the base fields with display values; `dv_state` is only shown as a label.
  - The change state is shown but never interpreted. A cancelled change still yields its recorded times.

Window limits: each window is at most 24 hours long, and the before window must end before the after window starts. A window that closes less than 10 minutes before now makes its result unknown, because late events may still arrive.

## Evaluation

Each window runs `` | `adm_path_trace(<src>,<dst>,<scope>)` | where row_type="observation" `` as the reader, over absolute epoch bounds. Results are capped at 240 rows, and overflow is an error. The sources are those of scoped Trace:

- ACI ACL log and Hubble report a forwarding verdict (permit or forwarded, drop).
- Nexus Dashboard flows, FTD eStreamer and qualified Nexus NetFlow show only that traffic was present.

A run covers at most 10 assertions. Searches run one at a time, and identical pair/window searches are reused.

| Kind | Pass | Fail | Unknown |
| --- | --- | --- | --- |
| Reaches | An observer showed the service forwarded after the change. A presence-only source counts only when it saw both the request and the reply. | The service was only dropped after the change (*observed*). Or nothing was seen after the change, while every baseline observer (at most 4) had carried the service before and was proven to report other traffic in the after window (*inferred*). | Any incomplete after window. Traffic whose outcome these sources cannot establish. A row that mixes dropped and other services. No baseline, or baseline observers not proven live. |
| Redundant paths | At least N distinct observer devices showed forwarding. | Fewer than N after the change, where a complete before window had at least N, and the missing observers now drop the service (*observed*) or were proven live (*inferred*). | Every other case, including a baseline that never showed N. |
| No new blocked | Every drop after the change already existed before it, keyed by direction and service. Or ACI ACL log or Hubble saw the pair after the change and reported no drops. | Drops after the change that did not occur before it (*observed*). | Drops after the change with an incomplete before window. No drop-reporting source saw the pair. |

A window is **incomplete** if any of these happen:

- a search error, warning, truncation or failure, or the row limit is exceeded;
- `observers_capped` or `records_capped`;
- a malformed observation row;
- the window has not settled.

An incomplete after window always gives unknown. Missing evidence is never read as healthy, absent or removed.

The liveness probe is `` | `adm_device_flows(<observer device>)` | head 1 `` over the after window. It proves that the device exported records of any kind. The probe cannot match a Nexus Dashboard fabric name to a leaf, so liveness stays unproven for ND and those cases stay unknown.

## Result pack

The table lists every assertion with its result. The basis says *observed* or *inferred*. A short reason and a summary of the before window let you spot regressions such as pass → fail. Each row links to Trace for the before window and for the after window.

- **JSON** has the windows and their basis, the change number and `sys_id`, the exact SPL, per-window issues, forwarding, dropped and unresolved observers, drop keys, up to 32 event references, the liveness probes, and the Trace links.
- **CSV** has one row per assertion. Formula-leading cells are neutralized.
- **Markdown** is a CAB-ready table.

## Limits and follow-ups

- Unqualified. This has not been run against live ACI ACL log, Hubble, ND, FTD or NetFlow data, or against a live ServiceNow input. The fixture `fixtures/raw-snow/change_request.ndjson` covers parsing only.
- Liveness is device-level and source-agnostic. A device that reports only unrelated sources can make an *inferred* fail possible. Treat inferred fails as prompts to investigate, not proof.
- Without ACI ACL logging or Hubble, "No new blocked" cannot pass. Presence-only sources need both directions to show reachability.
- Evaluation runs in the browser. There is no scheduled verification, alerting or write-back.
