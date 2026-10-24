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
   each JSON Lines record as a complete HEC event envelope with sourcetype
   `atlas:o11y_health`; the ingestion job must preserve the outer `event`
   payload and report failures. A plain file monitor on this output is
   unsupported: it indexes the HEC envelope itself rather than unwrapping
   `event` into the searchable source fields. Set HEC/index routing outside
   the exporter. The exporter only creates a local, atomic file and never
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
