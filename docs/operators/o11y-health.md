# Qualify Splunk Observability Cloud health evidence

This optional path exports a bounded historical SignalFlow capture to the
Splunk Enterprise index read by Application Atlas. It does not make a browser
request to Splunk Observability Cloud and does not need an Observability Cloud
token in Atlas or in the Splunk app. Keep the source unselected until the
organization, dimensions, units and one known service have been qualified.

## Prerequisites

1. Identify the correct Observability Cloud organization and realm from its
   organization settings. Create or use a server-side API access token with
   permission to execute historical SignalFlow queries for the required
   metrics. Inject it into the scheduled exporter's environment as
   `SPLUNK_OBSERVABILITY_TOKEN` using your secret manager. Never use an ingest
   token, command-line token argument, repo file or shared Splunk setting.
2. Confirm that APM exposes a custom service-level Monitoring MetricSet for
   `service.request` with exact indexed dimensions `service.name`,
   `deployment.environment.name`, `service.namespace`,
   `k8s.cluster.name` and `k8s.namespace.name`. Splunk's default service MMS
   does not include the Kubernetes and OTel namespace dimensions required by
   Atlas. The service environment field is the OTel `deployment.environment.name`
   attribute and must remain separate from Splunk's built-in `sf_environment`.
   Record its exact `sf_mms_id`; this value must be the same in the exporter
   argument, indexed events and verified Atlas observer mapping. The exporter
   filters RED streams to `sf_dimensionalized=true` and this exact `sf_mms_id`
   so a default MMS cannot be counted alongside the custom MMS.
3. Confirm the exact duration unit and timestamp behavior in the realm's
   service metric. This version's qualified APM schema expects histogram p90
   in nanoseconds (`ns`), based on the existing `service.request.duration.ns.p90`
   metric contract. If the tenant emits another unit, do not enable this
   schema; update and requalify the versioned metric contract first.
4. If runtime series are wanted, ensure `container.cpu.utilization` and
   `jvm.memory.used` are reported with the same service, environment, cluster,
   Kubernetes namespace and OTel service namespace properties. These streams
   are optional in Observability Cloud, but a matched output missing any
   required dimension causes the complete export to fail closed. Values use
   ratio (`1`) and bytes (`By`) units respectively.
5. Configure a dedicated HEC input and Splunk index for the export. Submit
   each JSON Lines record as a complete structured HEC event envelope with
   sourcetype `atlas:o11y_health`; the ingestion job must preserve the outer
   `event` payload. Route through the HEC token's default index or explicit
   HEC routing because the exporter does not include an `index` field. A plain
   file monitor is unsupported: it indexes the HEC envelope instead of
   unwrapping `event`. The exporter creates an atomic local file and never
   submits it to Splunk.

## Run and verify the exporter

Install the pinned client in a controlled virtual environment:

```sh
python3 -m venv .venv-o11y
.venv-o11y/bin/pip install -r tools/requirements-o11y.txt
```

Run the exporter on an approved secured host. Use explicit UTC offsets and a
window no longer than 24 hours. Keep `--observer` equal to the stable HEC host
that Splunk will index; it identifies the configured ingestion authority, not
the Observability Cloud organization.

```sh
.venv-o11y/bin/python tools/export_o11y_health.py \
  --observer o11y-prod-exporter \
  --organization-id org-example \
  --realm us0 \
  --scope prod-east \
  --service-name checkout-api \
  --environment production \
  --cluster eks-prod-east \
  --kubernetes-namespace commerce \
  --apm-mms-id checkout_service_mms_v1 \
  --start 2026-10-23T15:00:00Z \
  --end 2026-10-23T15:15:00Z \
  --output /var/spool/splunk/o11y/checkout-20261023T151500Z.ndjson
```

The token is read from the process environment and omitted from this command.
Optionally pass `--service-namespace` only when that exact OTel service
namespace is intentionally selected. Without it, the exporter refuses a
capture if multiple OTel service namespaces match. Each capture publishes at
most 63 metric rows plus a completion row. The output path is new-only and
created mode 0600; schedule cleanup and retention for the spool directory.

## Schedule capture and delivery

For recurring captures, use the stateful wrapper. It stores its identity config
and state in operator-owned paths outside Git checkouts and enqueues finalized
captures through the shared durable sender:

```sh
python -m tools.capture_o11y_health \
  --config /etc/atlas/o11y-health.json \
  --state-dir /var/lib/atlas/o11y-capture \
  --window-seconds 300 \
  --lag-seconds 120
```

Provide `SPLUNK_OBSERVABILITY_TOKEN` from the secret manager and set
`ATLAS_HEC_SPOOL_DIR` in the protected process environment. The config is
version 1 and contains source identity fields only; it holds no endpoint or
credential. Schedule this command once per minute. Each invocation handles at
most one contiguous, settled interval; the first run starts at the latest
settled interval and later runs catch up in order. State is bound to the
identity config, spool and cadence. If capture or queueing is interrupted, the
wrapper reuses the finalized pending file and idempotently checks queue
acceptance before removing it. Spool exhaustion pauses new captures and keeps
the pending file for recovery.

The wrapper's default 300-second capture interval is matched only when the
Atlas service map uses that exact UTC start and end. The health search requires
`capture_window_start` and `capture_window_end` to equal the selected graph
interval; it does not combine adjacent captures or add their bucket counts.
To inspect a scheduled capture, set the map's custom time range to the exact
start and end recorded in its completion event. An arbitrary rolling 15-minute
window, or a differently aligned five-minute window, will not match. To inspect
another interval, make a bounded one-shot export with explicit `--start` and
`--end` values for that interval (maximum 24 hours), then search using the same
interval in the service map.

The capture wrapper only produces and queues captures. Run the common HEC
sender separately with `ATLAS_HEC_URL`, `ATLAS_HEC_TOKEN`, and
`ATLAS_HEC_SPOOL_DIR` supplied through a protected environment:

```sh
python -m tools.hec_delivery send
python -m tools.hec_delivery status
```

Keep `ATLAS_HEC_TOKEN` out of scripts, configs, command arguments and logs.
Place the spool outside all Git checkouts; its defaults cap it at 1 GiB,
10,000 pending captures and 1,000,000 pending records. One send invocation
handles at most 100 captures or five minutes. A capture is capped at 10,000
rows and 64 MiB; each JSONL record is at most 65,535 bytes plus newline and
batches are at most 256 KiB. Delivery uses verified HTTPS, refuses redirects,
and is at-least-once across a crash after HEC accepts a batch.

The first delivery attempt binds each pending capture to the canonical HEC URL
and acknowledgment mode. Keep both unchanged while that capture is pending.
If either must change after partial delivery, the sender fails closed and
preserves its checkpoint and queued file. To recover, retain the original
spool, copy the exact queued JSONL capture to a separate private recovery path,
configure the intended URL and `--ack-mode` with a new spool, then enqueue that
copy under the same source ID. The new spool replays from the beginning, so
previously accepted batches can be delivered again; keep capture and record
IDs for downstream deduplication and verify indexed readback. Do not edit a
checkpoint or delete the original queued capture to force a destination or
mode change. Keep the original spool until the recovered capture is verified.

Use an Enterprise `/services/collector/event` input for the normal HEC route.
An explicitly configured structured `/services/collector` route is preserved
for Splunk Edge Ingest; leave indexer acknowledgments off for that route. HEC
HTTP acceptance and Enterprise indexer acknowledgment do not prove that a
search can read the event. Verify the dedicated index with a search after
delivery. A final file is not discarded when queueing or HEC delivery fails.

Validate that one indexed file has the exact number of source metric rows and
one final `export_completion` event. A completed capture can be empty. It
records `expected_record_count=0` and `signals_with_data=0` rather than
inventing zero-valued health metrics. Missing metrics and detector state are
not inferred.

## Configure Atlas

In deployment settings, select the `o11y_health` supplemental source and
configure its dedicated index, recentness window, and a verified observer
mapping. The mapping must use observer kind `o11y_export` and include:

- exact indexer-visible `observer` value, matching the event's `host` and
  `observer_id`;
- routing `scope` and Kubernetes `cluster`;
- `organization_id` and short lowercase `realm`;
- exact `apm_mms_id` equal to the custom APM MMS `sf_mms_id` used by the
  exporter;
- `mapping_status=verified`, attested by the service owner.

In the `adm_observer_scope` observer mapping KV row for
`observer_kind=o11y_export`, store this as `apm_mms_id`; its value must match
`--apm-mms-id` and is validated as a bounded literal. The source
normalizer also requires every RED event and completion event to carry that
exact `apm_mms_id`, `sf_mms_id` and `sf_dimensionalized="true"`. Runtime
metrics carry no APM MMS identity and are kept separate.

Set `adm_index_o11y_health` to the dedicated index and enable
`adm_o11y_health_schema_qualified` only after the checks below. Multiple
verified organizations/realms for one scope and cluster fail closed. Configure
one unambiguous authority for the selected service scope; Atlas does not
offer an authority picker in this version.

If `observability_origin` is configured on the verified observer mapping, it
must be an HTTPS origin without user information, path, query or fragment.
Atlas uses it only for source navigation. Otherwise the UI links to the realm's
Observability Cloud application root; it does not construct a metric, chart or
detector deep link from event content.

The service map joins against the graph boundary's exact service name,
environment, cluster and Kubernetes namespace. `service.namespace` is a
separate OTel source dimension; it is never treated as Kubernetes namespace.
If the capture carries multiple OTel namespaces and no explicit service
namespace was selected, no health record is shown. A service display name
alone cannot associate a record.

## Qualification checklist

- Compare one export against the same bounded service in Observability Cloud
  and confirm the organization, realm, `service.request` values, unit, latest
  logical time and selected SignalFlow resolution.
- Verify the exact `sf_mms_id` and confirm the RED queries select only
  `sf_dimensionalized=true` with that ID. The SignalFlow output groups RED by
  the service identity plus both MMS dimensions so they remain verifiable
  after aggregation. Record the MMS ID and exact dimension list alongside
  qualification notes.
- Verify that request and error counts are one-resolution-bucket counts, not
  sums over the selected window. p90 uses the histogram's percentile 90
  operation.
- Verify Kubernetes cluster, Kubernetes namespace, OTel service namespace,
  environment and service dimensions on each reported runtime stream. Missing
  dimensions must remain absent; do not repair them by display-name joins.
- Test a complete output, a missing completion event, an altered organization
  or realm, an alternate OTel service namespace, missing identity dimensions,
  delayed/stale export, timeout and file/index permission failure. The
  exporter must not leave a destination on timeout or partial stream.
- Confirm a viewer can read the configured index and observe the complete
  event envelope. Confirm other organizations, realms, observers, clusters,
  namespaces, service environments and display-name collisions are excluded.
- Keep detector state marked `not queried`; this source only reports measured
  metrics. Missing metric samples mean telemetry is unavailable for that
  signal. They do not mean zero or healthy.

Synthetic tests verify only code behavior. Keep schema qualification disabled
until these tenant-specific checks pass. See
[`O11Y_HEALTH_DESIGN.md`](../O11Y_HEALTH_DESIGN.md) for the bounded data
contract and external source references.
