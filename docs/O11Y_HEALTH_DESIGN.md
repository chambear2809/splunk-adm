# Observability Cloud health evidence design

Application Atlas can inspect a bounded historical capture of selected service
and runtime metrics already available in Splunk Observability Cloud. It does
not connect to Cloud from the browser. A separately operated exporter reads a
SignalFlow computation with a server-side access token, and publishes an
atomic JSON Lines file of HEC event envelopes for a separately configured HEC
ingestion job. A plain file monitor cannot unwrap these envelopes into the
searchable event fields and is unsupported. Atlas searches only the configured
Splunk index as the current user.

## Producer contract

`tools/export_o11y_health.py` pins the standalone Splunk package
`signalflow-client-python==1.3.9` in `tools/requirements-o11y.txt`. The
producer uses `SignalFlowClient(token=..., endpoint=..., timeout=...)`,
`execute(program, start=<epoch ms>, stop=<epoch ms>, resolution=<ms>,
immediate=True)`, then consumes `computation.stream()`. The SDK consumes
`EndOfChannelMessage` internally and marks the computation complete; the
exporter wraps the SDK message channel to independently observe exactly one
normal end-of-channel. `ErrorMessage`, channel abort, missing EOC, SDK timeout,
SDK result caps, missing identity properties and partial streams prevent
publication. Timeout closes the computation and client. The wrapper around
private SDK channel members is tied to the pinned 1.3.9 source and is covered
by fake-SDK tests; update those tests and verify the new SDK before changing
the pin.

The client factory uses the SDK's SSE transport through
`tools/o11y_transport.py`, not its default WebSocket transport. The adapter
checks the installed package version, bounds the SignalFlow program and
response, and limits the whole request and one-shot stream. It verifies the
TLS certificate and hostname, uses the fixed realm endpoint, disables
redirects and ambient proxies, and does not reconnect a capture. `--ca-bundle`
or `ATLAS_O11Y_CA_BUNDLE` can add an operator-managed CA without disabling
verification. A transport error or incomplete stream never publishes a
capture.

Only `SPLUNK_OBSERVABILITY_TOKEN` is read for authentication. It must be
injected by the operator's secret manager or protected process environment;
do not pass it as a command argument, place it in Splunk config, or commit it.
The exporter never sends data to Splunk. It writes a mode-0600 temporary file,
fsyncs it, and atomically links the completed capture to a new output path. It
refuses overwrite. Incomplete work leaves no destination file. Standard error
is generic and does not print SDK messages or source payloads.

The pinned computation emits five allowlisted streams:

| Label                       | Source stream and operation                                                              | Value unit                                       |
| --------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------ |
| `request_count`             | `histogram('service.request').count(by=apm_service_dimensions)`                          | count in one resolution bucket                   |
| `request_errors`            | Same histogram filtered by `sf_error='true'`, then count grouped by APM service identity | count in one resolution bucket                   |
| `request_latency_p90`       | `histogram('service.request').percentile(pct=90, by=apm_service_dimensions)`             | ns for the qualified OTel APM histogram contract |
| `container_cpu_utilization` | `data('container.cpu.utilization').mean(by=service_identity_dimensions)`                 | unit ratio (`1`)                                 |
| `jvm_memory_used`           | `data('jvm.memory.used').mean(by=service_identity_dimensions)`                           | bytes (`By`)                                     |

The requested resolution is `max(10s, ceil(window_seconds / 300))`, with a
maximum 24-hour history and an output cap of 63 metric series plus one
completion event. For each signal and exact service identity, the exported
value is its latest logical sample in the requested interval. In particular,
request and error counts are per-resolution-bucket values, not totals for the
selected time window. The exporter records the actual resolution reported by
SignalFlow, which may be coarser than requested; a metric stream with no
reported resolution is rejected. The event keeps logical timestamp, capture
window, actual resolution, statistic, unit, aggregation, source dimensions and
authority.

The exporter requires the graph identity dimensions
`service.name`, `deployment.environment.name`, `k8s.cluster.name` and
`k8s.namespace.name`, plus OTel `service.namespace`. `service.namespace` is a
distinct source property; it is not Kubernetes namespace. If the operator did
not select an OTel service namespace, the capture is accepted only when one
source namespace appears. Missing or multiple values fail closed. No display
name lookup is performed. Pod UID and container names are retained if future
qualified producers supply them; current service association does not claim a
particular pod or network cause.

RED is queried only from the operator-selected custom APM MMS: the SignalFlow
filter requires `sf_dimensionalized=true` and exact `sf_mms_id` equal to the
required `--apm-mms-id`. RED output grouping adds `sf_dimensionalized` and
`sf_mms_id` to the graph service dimensions, preserving both values in the
aggregated output metadata for exporter validation. The exporter places the
same `apm_mms_id`, `sf_mms_id` and `sf_dimensionalized` values on RED metric
rows and the completion row. Runtime streams are grouped independently by
service dimensions and carry no APM MMS identity. A missing or mismatched MMS
dimension prevents complete capture publication; the browser also rejects
cross-MMS or default-MMS rows.

Splunk APM's default `service.request` MMS dimensions do not include cluster,
Kubernetes namespace or OTel service namespace. The operator must create and
qualify a custom service-level MMS containing the dimensions needed by this
contract, and runtime streams must carry the same exact identity properties.
Custom dimensions must be indexed in APM before they can be filtered or
grouped. If the observed MMS schema, service namespace, metric unit or runtime
dimensions differ, keep the source staged and schema qualification disabled.
The exporter does not synthesize workload identity by joining on service
display names.

## Indexed envelope and admission

Each JSONL row uses a standard HEC event envelope with `time`, `host`,
`source`, `sourcetype` and a schema-versioned `event`. `host` and `observer_id`
identify the configured ingestion authority; they are not the Observability
Cloud organization ID. Each event carries the exact `organization_id`,
`realm`, routing scope, service identity, capture ID and capture interval.
The final source event is `event_type=export_completion` with the expected
metric record count and number of signals that returned data. Zero available
signals still produce a complete empty capture; they do not indicate healthy
telemetry.

New producers include a SHA-256 `record_id` for every metric and completion
event. The v1 reader remains compatible with captures produced before that
additive field existed: it uses Splunk's indexed `event_fingerprint`
(`sha256(index, _bkt, _cd)`) as the legacy record identity, and accepts a replay
only when the canonical event, event time and host agree. A present but
malformed `record_id` is rejected; it does not fall back to the legacy rule.

The browser projection is an allowlisted JSON field set, capped at 64 input
rows and one selected capture. Normalization requires the completion event,
matching capture ID/times/window and expected metric count, one unique
verified `o11y_export` mapping, and exact equality for observer, organization,
realm, environment, service, cluster and Kubernetes namespace. A selected
APM MMS identity is required on the completion event and every RED row, while
runtime rows must not claim an APM MMS. OTel service namespace is checked
independently. If no namespace is selected,
multiple namespaces suppress the entire result. Multiple verified authorities
for the same scope and cluster also suppress the result; the UI does not pick
one silently. Detector and alert state is not queried.

The SPL projection converts Splunk's internal `_time` and `_indextime` values
to numeric `event_time_epoch` and `indexed_time_epoch` fields before returning
rows. The normalizer requires both values and checks that event time matches
the capture timestamp within one second; it does not parse ambiguous display
time strings.

## Evidence limits

This is historical measured context. It does not report detector state,
collector health, topology causality, or whether a network event caused a
metric change. A missing metric sample is missing telemetry, never zero or
healthy. A synthetic fixture proves only the exporter, schema, search and
normalizer implementation. Production qualification additionally requires an
operator to verify the Cloud organization and realm, the custom MMS ID and
dimension set, the exact units and timestamps, the collector's runtime
dimensions, the index and retention, and a known service against source UI
evidence.

## Detector-event source

The separate `o11y_detector_events` source calls the official v2
`GET /detector/{id}/events` route on
`https://api.<realm>.observability.splunkcloud.com` with `X-SF-TOKEN`. The
current API reference specifies inclusive `from` and `to` values in Unix
milliseconds, nonnegative `offset`, and `limit` (default 50). Its retrieve
guide describes offset/limit pagination; the detector API reference caps one
response at 10,000 events. Atlas requests at most 1,000 events per page,
accepts at most 16 configured detector IDs, one interval of at most 24 hours,
and 9,999 source events per capture plus one completion row. If one detector
reaches the API's 10,000-event ceiling, the exporter fails closed because the
route cannot prove whether older or additional events were truncated. The
exporter limits individual responses to 16 MiB, a full multi-page run to five
minutes, the final capture to 64 MiB, and each record to 65,535 bytes plus
newline. The Atlas browser projection separately caps inspection at 64 rows
including completion; larger captures can still be searched directly in
Splunk but are not partially rendered in the panel.

The event API returns observations, while incidents are retrieved separately
and represent collections of events. Detector events include trigger and
clear observations; anomaly states such as `ANOMALOUS`, `OK`,
`MANUALLY_RESOLVED`, and `STOPPED` are preserved as returned, along with
unknown future source values and the canonical raw event. The source stores
each event, the explicitly configured detector list, and an exact observed-row
count in its completion row. It does not fetch current incident state or
reconstruct lifecycle intervals.
Organization, realm, routing scope, cluster and selected detector IDs are
configuration context only. This source makes no service or MMS association.
The API reference permits the `read_only` role for event retrieval; use an
organization API access token assigned that role and store it in
`SPLUNK_OBSERVABILITY_TOKEN`. Do not use an ingest token.

Splunk documents 12-month retention for Observability Cloud events. The
operator configures retention for the destination Splunk index separately.
See [`o11y-detector-events.md`](operators/o11y-detector-events.md) for the
operator procedure and source references.

## Durable HEC delivery

Both exporters produce structured HEC event envelopes, but neither sets an
index or sends the event. A separate scheduled process can enqueue the
finalized JSONL capture through `tools.hec_delivery` and deliver from its
private spool. Source IDs namespace capture IDs and snapshot IDs, allowing the
sender to serve multiple Atlas producers without changing their event data.
Queueing is at-least-once; exhausted capacity, endpoint drift, transport
failure and corrupt progress preserve queued source rows.

The spool defaults to 1 GiB, 10,000 pending captures, and 1,000,000 pending
records. A capture can contain at most 10,000 rows and 64 MiB; a JSONL row is
at most 65,535 bytes plus newline and a POST batch at most 256 KiB. Each send
invocation handles at most 100 captures or 300 seconds. Spool paths must be
owner-private and outside every Git checkout. The sender verifies TLS, refuses
redirects and ambient proxies, bounds DNS and full request time, and binds
partial progress to the configured endpoint. A corrupt checkpoint checksum
replays conservatively from the first row. `status` reports queue counts, HTTP
acceptance and indexer acknowledgment separately; only a search confirms
indexed readback.

The standard Enterprise route is `/services/collector/event`. An explicitly
configured structured `/services/collector` path is preserved for Splunk Edge
Ingest, with HEC acknowledgment disabled. If an exporter omits the HEC `index`
property, route events through the token's dedicated default index or explicit
index routing.

## Source references and version basis

- The official [`signalflow-client-python` repository](https://github.com/signalfx/signalflow-client-python) documents the standalone client import, endpoint, token and stream API. The implementation pin is version `1.3.9`; that exact package source was inspected for the historical `execute` arguments, message end state, and metadata behavior. The old [`signalfx-python` repository](https://github.com/signalfx/signalfx-python) says its SignalFlow code migrated and is deprecated.
- Splunk's [Monitoring MetricSets reference](https://help.splunk.com/en/splunk-observability-cloud/monitor-application-performance/analyze-services-with-span-tags-and-metricsets/learn-about-monitoring-metricsets) documents `service.request`, histogram count and percentile operations, available default dimensions, and custom MMS dimensions.
- Splunk's [histogram reference](https://help.splunk.com/en/splunk-observability-cloud/manage-data/metrics-metadata-and-events/metrics-events-and-metadata/histogram-metrics) documents histogram statistics. The prior non-histogram `service.request.duration.ns.p90` name is the basis for the `ns` unit in this versioned OTel APM contract; qualify the tenant's produced MMS before enabling it.
- Splunk's [SignalFlow functions reference](https://dev.splunk.com/observability/docs/signalflow/functions/) documents the SignalFlow expression model; aggregation methods group by named dimensions. The exact tenancy-specific dimensions and units still require external qualification.
- Splunk's [detector events API reference](https://dev.splunk.com/observability/reference/api/detectors/latest), [retrieve data guide](https://dev.splunk.com/observability/docs/apibasics/retrieve_data_basics/), [event retention guide](https://help.splunk.com/en/splunk-observability-cloud/manage-data/metrics-metadata-and-events/metrics-events-and-metadata/events), and [custom role capabilities](https://help.splunk.com/en/splunk-observability-cloud/administer/user-and-team-management/manage-roles/custom-roles) ground the detector route, pagination, event semantics, retention and read access.
