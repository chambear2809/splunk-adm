# Data quality and pipeline health

Application Atlas exposes two related diagnostics: flow-record quality in the
data layer and app-wide pipeline health in the installed UI. Both run as
read-only searches in the caller's Splunk context.

## Flow quality

The generating macro `adm_flow_quality` is shared by `adm_flow_enrich` and the
conversation rollup. It annotates every normalized flow candidate with a
status:

- `excluded` when identity, addresses, observer/scope, time, transport, ports,
  supplied counters, or sampling values are invalid;
- `accepted_with_warning` when counters are missing, sampling is unknown, or
  the observer has no explicit scope mapping;
- `accepted` when neither class applies.

The rollup consumes rows whose status is not `excluded`. Missing byte/packet
measurements remain unmeasured. Missing NetFlow sampling keeps the existing
1:1 assumption and is reported as a warning. An unmapped observer uses the
`default` scope, which can affect identity joins.

The `adm_health_quality` macro applies the same enrichment to eligible flow
sources indexed in the last 24 hours and returns counts by source, status, and
reason. Its `evaluated` row counts each candidate once; reason counts can
overlap when one record has multiple problems. Source-specific eligibility
filters run before validation, so this is not a raw-ingestion audit.

## Pipeline health panel

In live mode, **Splunk → Pipeline health** runs three independent searches:

- `adm_health_sources` returns all eight configured source names, including
  sources with no visible records. It reports event count, latest event time,
  latest index time, and maximum nonnegative ingestion delay.
- `adm_health_jobs` combines app-local saved-search configuration with visible
  `_internal` scheduler events for `ADM - *` searches. It reports disabled
  state, latest run/success, outcome, failures, and skips.
- `adm_health_quality` provides the flow-quality counts described above.

Source probes use a fixed 24-hour index-time window and broad event-time bounds
from epoch through ten years ahead so delayed events can be included. The UI
flags no source data within 20 minutes, and uses shipped cadence thresholds
for jobs: 20 minutes for five-minute builders, two hours for interface
inventory, and 26 hours for maintenance prune searches. A disabled prune is
expected in the normal operating model. **Check again** reruns the snapshot.

Missing results, restricted indexes, missing REST access, or absent scheduler
history are shown as unavailable or unconfirmed. They do not prove an outage
and the app does not grant permissions. Health is app-wide and independent of
the map's service, namespace, and time-range filters; demo fixtures never claim
to establish live health.

## Limits and interpretation

Quality counts are bounded by the health search's result limits and the
configured source macros. They describe records visible to the current user,
after source eligibility and normalization, rather than every event sent by an
exporter. Reason totals are unsuitable for summing into a total number of bad
records. Accepted warnings can still affect bytes, scope, or identity
resolution. The diagnostics do not validate collector configuration, sampling
accuracy, network delivery, clock correctness beyond the configured bounds, or
the completeness of data hidden by index permissions.
