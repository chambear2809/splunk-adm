# Bounded source observations

These observations were made on 2026-11-16 using the explicitly selected local
Cloud profile and the existing search-tier REST endpoint. The selected profile
passed static validation, its HTTPS endpoint matched its configured Cloud stack,
and certificate verification was enabled. The server reported version
`10.6.0.5` and the installed `splunk_adm` app reported `0.8.6`; the server
metadata did not provide an affirmative Cloud identity marker. These are
observations of the existing installation, not qualification of this checkout.

The earlier profile check failed on `SPLUNK_HOME` in the HF and Enterprise
profiles and the flat auxiliary `SB_USER` and `SB_PASS` keys. The checker was
updated to recognize those documented fields with strict scope and validation;
the canonical file then passed. No credential values or raw events were
recorded. The earlier statement that no Cloud query followed that failure
remains true for that earlier increment; it is superseded as a statement about
the current task.

## Aggregate receipt check

One `tools/discover_feature_sources.py` run used the explicitly selected
profile, fixed current index-selector macros and one bounded `tstats` count
search over the most recent 24 hours, ending around 2026-11-16 20:30 UTC.
The query completed and its temporary search job was deleted. The timestamps
below are the earliest and latest returned **event times**, not the exact
requested window bounds, ingestion times, or proof of continuous collection.

| Source family |     Count | First event, UTC    | Last event, UTC     |
| ------------- | --------: | ------------------- | ------------------- |
| ACI           |   868,478 | 2026-11-15 20:31:11 | 2026-11-16 20:29:22 |
| Hubble        | 2,181,086 | 2026-11-15 20:30:31 | 2026-11-16 20:30:27 |
| OTel          | 2,672,065 | 2026-11-15 20:30:31 | 2026-11-16 20:30:28 |
| Stream        | 5,401,083 | 2026-11-15 20:30:31 | 2026-11-16 20:30:24 |
| Inventory     |     4,352 | 2026-11-15 20:31:47 | 2026-11-16 20:30:26 |
| FTD           |         0 | —                   | —                   |
| Envoy         |         0 | —                   | —                   |

Six returned index/source-type groups were not mapped to a fixed family. Zero
counts do not establish source absence, especially with unmapped groups or
unknown permissions and routing. Counts are indexed events, not distinct
entities, a complete topology, or proof of correctness or retention.

## Sampled field presence

One `tools/discover_field_presence.py` run made two fixed aggregate-only
probes over the absolute UTC interval **2026-11-16 20:23:36–20:38:36**. Each
used at most 16 sampled input events, returned only predefined numeric
indicators, completed successfully, and deleted its temporary search job.

- Hubble: source and destination pod, namespace, IP and port, plus flow time,
  verdict and node name, appeared in 16 of 16 sampled events. Source and
  destination workload name and kind each appeared in 8 of 16.
- Kubernetes pods: pod UID, owner kind/name/UID, condition type and status,
  pod IPs and node name appeared in 16 of 16 sampled events. A condition type
  equal to `Ready` appeared in all 16.

The checks used fixed source types and paths grounded in the app macros and
fixtures. The Splunk post-extraction predicates identified all present sampled
fields as strings and none as numeric, including ports; this does not prove
their original JSON types or port usability. The Ready-type and condition-status
counts are independent and do not establish a paired Ready status or workload
readiness. A 16-event sample does not establish representative coverage,
ownership, historical validity, source entitlement, end-to-end paths, or an
eligible baseline. No raw capture was retained, and no collector, schedule,
notification, application installation, or source configuration was changed.
