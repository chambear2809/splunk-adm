# Application Atlas processor profiles v1

These files are optional SPL2 templates for two narrow data partitions:

- `stream:netflow` from Splunk Stream, routed to `netflow`.
- `atlas:o11y_health` v1 capture events, routed to `atlas_o11y`.

Observability detector-event sourcetypes and AppDynamics sourcetypes are
outside these v1 partitions. Route those sources directly to their existing
destination, or qualify their product-specific unmatched/default route
separately before sending them through the same processor input. The v1
profiles do not establish their coverage or fallback behavior.

Edge Processor and Ingest Processor have separate deployment profiles and
templates. Each template is a one-destination pass-through that changes only
the destination `index` metadata. It does not extract, rename, aggregate,
filter, mask, enrich, or branch events. The pipeline builder partition selects
one exact sourcetype; it is not implemented as a SPL2 `where` filter. This
keeps unrelated input eligible for the product's unmatched-data fallback.

## Product and deployment matrix

| Product/profile | Availability and version | Selected input | Destination and unmatched input |
| --- | --- | --- | --- |
| Edge Processor, `edgeProcessor` SPL2 profile | Edge Processor on Splunk Cloud Platform is documented for Cloud 9.0.2209+ in supported regions after tenant activation. Edge Processor on Splunk Enterprise requires Enterprise 10.0+. The repository lab is Enterprise 10.6.0.5 and does not include the Edge Processor runtime. | Structured HEC event envelopes at `/services/collector`. `/services/collector/raw` is a separate raw-payload endpoint and is not used for these JSON envelopes. | One Splunk index destination per pipeline. A connected platform uses S2S; a non-connected platform can use S2S or HEC. Unmatched data goes to the Edge Processor's configured default destination, or is dropped if none is configured. |
| Ingest Processor, `ingestProcessor` SPL2 profile | Splunk Cloud Platform only; product release notes list Cloud 9.1.2308+ availability. It is not available on Splunk Enterprise. | Structured HEC event envelopes using the input endpoint advertised by the tenant, or Splunk forwarders on the configured receiver port. The docs identify HEC port 8088 and forwarder port 9997; this profile does not claim an Ingest `/services/collector/raw` contract. | One connected Splunk Cloud index destination per pipeline. A partition that matches no applied pipeline is sent to the non-configurable `splunk_indexer` destination. |

For each product, apply two disjoint pipeline partitions in the product UI:

1. `sourcetype` equals `stream:netflow`.
2. `sourcetype` equals `atlas:o11y_health`.

Check that neither partition has extra `host` or `source` restrictions. Confirm
each source type is available in the tenant and has the intended event breaking
configuration. Select exactly one destination for each applied pipeline. The
profiles are not enabled by default and must remain staged until the runtime
qualification in [the operator guide](../operators/ingest-processors.md) passes.

## Input and data fidelity

The selected sources send structured HEC envelopes. The HEC layer interprets
envelope metadata (`time`, `host`, `source`, `sourcetype`, optional `index`, and
optional top-level `fields`) separately from the `event` body. HEC `time` is
Unix epoch seconds. The event body is retained as the JSON event for the
destination indexer to parse. The templates preserve `time`, `host`, `source`,
`sourcetype`, the full event body, and any top-level HEC `fields`; only output
index routing changes.

The Stream TA performs its search-time field extraction after indexing.
`adm_flows_netflow` reads the original `timestamp`, `endtime`, exporter,
endpoints, ports, protocol, counters, sampling interval, and interface indexes.
The template does not replace the RFC3339 event times or adjust the counters.
The selected Stream corpus includes TCP, UDP, ICMP without ports, both
directions, and late-export records.

The health exporter emits six HEC events for the current v1 fixture: five
metrics and one final completion event. The HEC event time remains
`captured_at`; metric `logical_timestamp`, resolution in seconds, value, units,
authority, dimensions, and completion count remain event fields. The producer
does not set an input index. The template selects `atlas_o11y`; set the app's
`adm_index_o11y_health` macro to that index, or edit the template target and
macro together before enabling the source.

`fixtures/processors/v1/inputs/otel_trace_with_hec_fields.ndjson` has resource
identity in top-level HEC `fields`, outside `event`. The contract checks that
boundary and its provenance. OTel is not a selected v1 processor partition.

Every health metric fixture event contains the four optional dimension keys
`pod_uid`, `container_name`, `host_name`, and `jvm_memory_pool_name` as explicit
JSON `null`, matching the current `tools/export_o11y_health.py` producer. The
offline validator requires those keys to exist with null values and hashes the
event including them; a regression removes or coerces them and must fail.
This verifies the fixture and golden semantic contract. It does not qualify
Edge/Ingest runtime serialization or prove indexed processor output retains
the nulls; preview and indexed readback still need to verify that behavior.
JSON byte order and whitespace also remain runtime checks. Input fixtures with
duplicate JSON keys are rejected by the offline validator as ambiguous; the
behavior of a real HEC/processor version is not inferred from that rejection.
Templates do not deduplicate retries. One route prevents pipeline fan-out, but
sender retries can still create duplicate indexed events; no exactly-once
delivery claim is made.

The checked-in golden file fingerprints semantic JSON values using sorted-key
canonical JSON. It does not test serialized key order or execute SPL2.
`python3 tools/validate_processor_contract.py` checks fixtures, required facts,
health completion semantics, metadata boundaries, profile manifests, and the
reviewed identity templates. Its output explicitly reports
`processors_executed: false` and both profiles as `unqualified`.

## Product differences that matter

**HEC input.** Edge Processor documents both `/services/collector` and
`/services/collector/raw`; the structured endpoint is selected here because
the producer sends HEC event envelopes. Raw payload input has different
event-breaking behavior and request metadata. Splunk warns that JSON sent to
the raw endpoint might not be transformed as expected. Ingest Processor docs
document HEC as an input and its default port, but do not establish the same
raw endpoint contract. Use the endpoint shown for the actual Ingest tenant.

**Acknowledgements.** Turn off HEC indexer acknowledgement on tokens feeding
Edge or Ingest Processor. For forwarders feeding Ingest Processor, set
`useACK=false`. If an Edge pipeline uses an HEC destination, disable
acknowledgements on that HEC receiver token too.

**Unmatched input and filtered events.** Edge routes data outside applied
partitions to its configured default destination; without one, it drops the
data. Ingest routes unmatched partitions to `splunk_indexer`. Both products
drop data filtered by a pipeline. These templates contain no filtering
command. Malformed HEC requests fail at the receiver; they do not enter an
unmatched partition, and the actual receiver error/counter behavior must be
checked on the selected version.

**Index selection.** Both templates explicitly assign one target index. For
Edge S2S, review platform data-routing rules, which can take precedence over a
pipeline `eval index`; for Edge HEC output, the pipeline index takes precedence
over input event metadata and destination defaults. For Ingest, verify the
connected destination exposes the target index and that it exists. Do not
configure an additional branch, output destination, or overlapping partition.

## Qualification state

| Evidence | Edge Processor | Ingest Processor |
| --- | --- | --- |
| Templates and manifests | Implemented; offline semantic contract checked. | Implemented; offline semantic contract checked. |
| Installed Splunk direct-ingestion search comparison | Runs against Enterprise 10.6.0.5 plus installed Stream TA and Atlas app. It validates direct-source fields only. | Runs against Enterprise 10.6.0.5 plus installed Stream TA and Atlas app. It validates direct-source fields only. |
| Product preview, processed ingress/egress, destination readback | Not available in the local lab; unqualified. | Cloud-only service is not available in the local lab; unqualified. |

Do not describe these profiles as runtime-tested or enable them in production
until the exact Edge/Ingest tenant version, HEC input behavior, destination,
fallback, and installed-search comparison have passed. See
[runtime qualification and rollback](../operators/ingest-processors.md).

## Official Splunk references

Checked 2026-10-25. Recheck them against the tenant and target version before
deployment.

- [Data Management Solutions and supported deployment choices](https://help.splunk.com/en/data-management/onboard-data-to-splunk-cloud-platform/explore-data-management-solutions/data-management-solutions)
- [Edge Processor HEC endpoint usage](https://help.splunk.com/en/data-management/collect-http-event-data/send-hec-data-to-and-from-edge-processor/send-data-to-edge-processor-with-hec/usage-information-and-examples-for-supported-hec-endpoints)
- [Edge Processor pipeline syntax](https://help.splunk.com/en/splunk-cloud-platform/process-data-at-the-edge/use-edge-processors-for-splunk-cloud-platform/working-with-pipelines/edge-processor-pipeline-syntax)
- [Edge Processor data flow and default destination behavior](https://help.splunk.com/en/data-management/process-data-at-the-edge/use-edge-processors-for-splunk-cloud-platform/how-the-edge-processor-solution-works/how-data-moves-through-the-edge-processor-solution)
- [Ingest Processor release notes and minimum availability](https://help.splunk.com/en/data-management/process-data-at-ingest-time/use-ingest-processor/introduction/release-notes-for-ingest-processor)
- [Ingest Processor input, partition, and fallback behavior](https://help.splunk.com/en/splunk-cloud-platform/process-data-at-ingest-time/use-ingest-processors/how-the-ingest-processor-solution-works/how-data-moves-through-the-ingest-processor-solution)
- [Create Ingest Processor pipelines and partitions](https://help.splunk.com/en/data-management/process-data-at-ingest-time/use-ingest-processor/working-with-pipelines/create-pipelines-for-ingest-processor)
- [Ingest Processor pipeline syntax and `ingestProcessor` profile](https://help.splunk.com/en/data-management/process-data-at-ingest-time/use-ingest-processor/working-with-pipelines/ingest-processor-pipeline-syntax)
- [SPL2 compatibility profiles](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/spl2-compatibility-profiles-and-quick-references/spl2-compatibility-profiles)
- [Ingest Processor requirements and default input ports](https://help.splunk.com/en/splunk-cloud-platform/process-data-at-ingest-time/use-ingest-processors/getting-started/system-requirements-for-ingest-processor)
- [HEC indexer acknowledgements](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.0/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment)
