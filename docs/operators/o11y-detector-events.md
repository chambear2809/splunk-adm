# Qualify Observability Cloud detector events

This optional source copies bounded historical detector events from Splunk
Observability Cloud into a dedicated Splunk index for Atlas. It is a read-only
event export. It does not inspect detector definitions, current detector state,
or the separate latest-incidents endpoint. It does not associate a detector
with an APM service or Monitoring MetricSet.

## API scope and limits

The exporter calls the documented v2 operation
`GET https://api.<realm>.observability.splunkcloud.com/v2/detector/<id>/events`
with `X-SF-TOKEN`. The detector ID is configured literally; the exporter does
not enumerate all detectors. The API reference documents inclusive `from` and
`to` Unix timestamps in milliseconds, nonnegative `offset`, and `limit` (50 by
default). This exporter requests pages of at most 1,000 events and pages by
offset until the selected detector returns a short page. Splunk documents a
maximum of 10,000 events from this operation even if more are present. Atlas
also caps one capture at 10,000 events across all configured detectors, so a
larger result is rejected rather than represented as complete.

One capture accepts 1–16 unique detector IDs and one closed interval no longer
than 24 hours. The request timeout is configurable from 1–300 seconds; the
whole multi-page capture is limited to five minutes. Responses are limited to
16 MiB, captures to 64 MiB, and one JSONL event row to 65,535 bytes plus its
newline. Requests that exceed a cap fail without publishing a partial file.
Observability Cloud retains its events for 12 months; the exporter does not
extend that retention. Plan the local Splunk index retention separately.

The event route and the incident routes are different. Splunk describes a
detector incident as a collection of events and separately exposes an
incidents operation. This integration retrieves the event history only. It
preserves each event as observed, including its detector, incident and event
IDs, timestamp, anomaly state, severity, label, and the canonical source JSON.
Optional identifiers are empty when the API does not return them. A trigger and
a later clear are two observations; Atlas does not infer an active interval,
fill a missing clear, or carry an event forward as current state. A selection's
service is graph-boundary context only. Configured organization, realm, scope,
cluster and detector IDs pin the source. No service or MMS attribution is
claimed.

## Access and source configuration

Use a server-side organization access token with the API permission and the
Observability Cloud `read_only` role. The detector API reference allows the
read-only role for event retrieval; the role's documented read capabilities
include `READ_DETECTOR`, `READ_EVENT`, and `READ_INCIDENT`. A custom role can
grant those read capabilities without detector mutation capabilities. Do not
use an ingest token or a power/admin token for this export. Keep
`SPLUNK_OBSERVABILITY_TOKEN` in the process environment supplied by the secret
manager. Never place it in the command, config, HEC envelope, browser, or app
settings.

Create a dedicated Splunk index and HEC input for this source. Set the token's
default index or configure explicit HEC routing to that dedicated index; the
exporter does not put an `index` field in its events. The HEC input must accept
structured event envelopes and retain the `event` object as the indexed source
fields. A file monitor of the JSONL file is unsupported because it indexes the
outer HEC envelope rather than unwrapping `event`.

Example read-only export:

```sh
python tools/export_o11y_detector_events.py \
  --observer o11y-detector-prod \
  --organization-id org-example \
  --realm us0 \
  --scope prod-east \
  --cluster eks-prod-east \
  --detector-id detector-id-from-the-authorized-inventory \
  --start 2026-10-23T15:00:00Z \
  --end 2026-10-23T15:15:00Z \
  --output /var/spool/atlas/o11y-detectors/capture.ndjson
```

Supply the token through the protected process environment, and optionally use
`--ca-bundle` for an operator-managed private CA. TLS certificate and hostname
verification stay enabled. Redirects and ambient proxies are not used. The
output is created atomically with mode 0600 and is never overwritten.

## Durable HEC delivery

The exporter-only file workflow is available for qualification. For recurring
delivery, enqueue the finalized file into the common private spool and let a
separate scheduled sender deliver it:

```sh
ATLAS_HEC_SPOOL_DIR=/var/lib/atlas/hec-spool \
  python -m tools.hec_delivery enqueue \
  --input /var/spool/atlas/o11y-detectors/capture.ndjson \
  --source-id o11y_detector_events

python -m tools.hec_delivery send
```

Before running `send`, configure `ATLAS_HEC_URL`, `ATLAS_HEC_TOKEN`, and
`ATLAS_HEC_SPOOL_DIR` in the protected process environment. `ATLAS_HEC_TOKEN`
must come from the secret manager; do not put its value in a script or shell
history. Store the spool outside every Git
checkout with owner-only permissions. Queueing never deletes the finalized
source file. If the spool is full, a checkpoint is corrupt, or a sender run is
interrupted, the undelivered capture remains pending for replay or operator
recovery. The sender is at-least-once: a crash after HEC acceptance but before
the durable receipt may replay the last batch. Keep record IDs and capture IDs
for downstream deduplication.

Sender defaults cap the spool at 1 GiB, 10,000 pending captures, and 1,000,000
pending records. A capture is limited to 10,000 rows and 64 MiB; each JSONL row
is limited to 65,535 bytes plus newline, and batches to 256 KiB. One send run
processes at most 100 captures or 300 seconds. The endpoint is fixed in the
environment and is bound to a partially delivered capture; changing it leaves
the capture pending for operator review. `python -m tools.hec_delivery status`
reports counts and delivery stages without printing payloads or credentials.

HTTP acceptance, indexer acknowledgment, and successful search readback are
separate facts. Enterprise HEC indexer acknowledgments can be enabled only
when the configured input supports them. For Splunk Edge Ingest's explicitly
configured structured `/services/collector` endpoint, leave acknowledgments
off; its configured path is preserved. A bare HEC origin defaults to
Enterprise `/services/collector/event`. Verify the dedicated index with a
Splunk search before enabling the Atlas source.

## Atlas admission and limitations

Configure the `o11y_detector_events` supplemental index, verified observer
mapping, organization, realm, scope, cluster and the same unique detector ID
list used by the exporter. Mark the source qualified only after the operator
has checked the identity and one capture against the Observability Cloud UI.
The mapping is `o11y_detector`; it does not require an APM MMS ID.

The UI link opens the configured HTTPS Observability Cloud origin (or the
configured realm's application origin). It does not encode an unsupported
detector/event deep link or carry the current time filter. Use the copied
detector ID to navigate in the source UI. Splunk documents that a detector's ID
appears in the URL when viewing that detector.

Test an empty range, trigger and clear observations, missing completion,
incomplete configured detector list, duplicate IDs, conflicting duplicate
event content, stale/partial capture, wrong organization or realm, denied
read-only access, timeout, and unavailable index. A missing detector event
means no event was observed in this export; it does not mean healthy, clear, or
inactive. Keep schema qualification disabled until these source-specific
checks pass.

## Official references

- [Retrieve Events for a Single Detector API reference](https://dev.splunk.com/observability/reference/api/detectors/latest) documents the v2 event route, timestamp filters, pagination, response shape, 10,000-event cap, and read-only access requirements.
- [Retrieve data basics](https://dev.splunk.com/observability/docs/apibasics/retrieve_data_basics/) describes detector events and incidents as separate retrieval paths and explains the general retrieve limits and pagination fields.
- [Events in Observability Cloud](https://help.splunk.com/en/splunk-observability-cloud/manage-data/metrics-metadata-and-events/metrics-events-and-metadata/events) documents trigger and clear events and 12-month event retention.
- [Custom roles](https://help.splunk.com/en/splunk-observability-cloud/administer/user-and-team-management/manage-roles/custom-roles) documents the `READ_DETECTOR`, `READ_EVENT`, and `READ_INCIDENT` capabilities.
- [Manage roles](https://help.splunk.com/en/splunk-observability-cloud/administer/user-and-team-management/manage-roles) describes API token role inheritance and the read-only role.
- [Incidents and alerts API reference](https://dev.splunk.com/observability/reference/api/incidents/latest) describes incident status values; this exporter preserves event values but does not query or reconstruct incident state.
