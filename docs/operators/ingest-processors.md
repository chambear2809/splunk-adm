# Qualifying an Atlas Edge or Ingest Processor profile

This guide stages the optional v1 templates in
[`integrations/processors/v1`](../../integrations/processors/v1/). The profiles
route only `stream:netflow` to `netflow` and `atlas:o11y_health` to
`atlas_o11y`. They are unqualified until a real processor preview and indexed
readback pass on the target tenant.

## Before you create a pipeline

1. Confirm whether the target is Edge Processor on Splunk Enterprise/Cloud or
   the Cloud-only Ingest Processor. Record the processor build, Splunk Cloud
   tenant version/region, destination deployment, and target index versions.
   Edge Processor on Splunk Enterprise requires Enterprise 10.0+; Edge on
   Splunk Cloud requires Cloud 9.0.2209+ in a supported region and tenant
   activation. Ingest Processor is documented for Cloud 9.1.2308+.
2. Configure a separate processor HEC token/input. For these JSON event
   envelopes, Edge uses structured `/services/collector`; do not redirect this
   JSON producer to `/services/collector/raw`. Ingest uses the structured
   endpoint advertised by the tenant; the current docs establish HEC port 8088
   but not an Ingest raw-endpoint contract. HEC envelope `time`, `host`,
   `source`, `sourcetype`, optional `index`, `fields`, and `event` must be
   passed as metadata and event body as shown by the fixtures.
3. Turn off HEC indexer acknowledgement on tokens feeding either processor.
   Set forwarder `useACK=false` for forwarders feeding Ingest Processor. If
   Edge sends to an HEC destination, disable acknowledgements on that receiver
   token as well.
4. Confirm both source types exist in the tenant and that their event breaking
   settings match the HEC envelopes. Ingest requires the source type to be
   registered; verify the same on the Edge Processor source type page.
5. Confirm the `netflow` and `atlas_o11y` indexes exist and are available from
   the connected destination. The health exporter omits an input index; set
   the Atlas `adm_index_o11y_health` macro to `index=atlas_o11y` before enabling
   health searches. Change the profile target and app macro together if using
   another index.
6. Review routing and existing ingest pipelines. Apply disjoint exact
   sourcetype partitions and one destination per pipeline. Do not apply a
   second matching pipeline or add a `branch`/`thru` output. A pipeline
   `where` is filtering: filtered data drops instead of reaching the unmatched
   fallback.

## Preview and runtime qualification

Keep the profile disabled while previewing. Use the product pipeline preview
with the exact contents of each `.spl2` file and confirm the UI partition is
the exact source type in the deployment descriptor. Check that preview contains
one input and one output per sample, and that only the target `index` changes.
Include these cases:

- Stream TCP and UDP records with ports.
- An ICMP record with ports absent.
- A late NetFlow record, with `timestamp`, `endtime`, counters, sampling, and
  interface indexes unchanged.
- All five health metrics and the final `export_completion` record. Confirm
  the event time still equals `captured_at`, metric values and units are
  unchanged, and the completion count remains five.
- One structured HEC event with top-level `fields` outside `event`, such as the
  OTel boundary fixture. OTel is not a selected production pipeline; this case
  only verifies the envelope boundary on the receiver/runtime.
- An event containing an explicit JSON null and a request with duplicate JSON
  keys. These are not covered by the selected source fixtures. Record receiver
  responses and output behavior; do not infer it from the offline validator.
- An unknown sourcetype, a malformed JSON request, and a destination outage.
  Check the documented unmatched route, request errors, drop/fallback
  counters, queue/backpressure metrics, and sender retry behavior.

Use a non-production HEC token and destination or an isolated index for this
preview. Do not point both the direct sender and processed output at the same
production index during the comparison. Keep processor metrics for accepted,
processed, sent, unprocessed, and dropped events with the qualification record.

Then send a bounded capture through the processor and verify indexed readback:

1. Compare output count with submitted count: 42 NetFlow fixture events and
   six health fixture events for one input pass. Inspect index, host, source,
   sourcetype, and `_time` on every result.
2. Run the installed Stream TA search:

   ```spl
   search `adm_flows_netflow`
   | table host source sourcetype index exporter_ip src_ip src_port dest_ip dest_port protoid bytes packets exporter_sampling_interval timestamp endtime input_snmpidx output_snmpidx adm_transport adm_sampling adm_bytes_fwd adm_packets adm_start adm_end
   ```

   Compare the required facts with `fixtures/processors/v1/golden_outputs.json`
   and with direct-ingestion results from the same fixture set. The offline
   golden comparison and local Splunk search do not execute SPL2.
3. Run Atlas's existing v1 Observability health search for the exact configured
   authority, service dimensions, capture window, and `atlas_o11y` index. Check
   that all five signals and one final completion record are returned, with no
   rejected rows. Compare labels, values, units, time fields, authority, and
   completion count to the golden health fixture. The existing app search uses
   `latest=now`; use a fresh capture whose `captured_at` is current.
4. Compare direct and processed results with a single submitted pass. Confirm
   exactly one destination receives each processed event; check the unmatched
   default separately. Check for duplicate records after any sender retry.
   HEC acceptance, processor counters, and HEC ACK do not prove that Atlas can
   search all output records.
5. For Edge, verify the default destination handles non-matching sourcetypes;
   if no default is configured, those events drop. For Ingest, verify an
   unmatched source reaches the non-configurable `splunk_indexer` destination.
   Confirm filtered and malformed behavior separately; neither is evidence of
   the unmatched path.
6. Record exact processor/SPL2 profile versions, input URL form (never the
   token), source type partition, destination type, index, query results,
   event counts, counters, errors, and known gaps. Keep the profile
   `unqualified` until all required cases pass.

Do not claim exactly-once delivery. A sender retry can duplicate an event, and
Ingest Processor explicitly provides no data delivery guarantee during high
backpressure or prolonged destination outages. The templates add no branch,
filter, deduplication, masking, or aggregation.

## Rollback

1. Pause/remove only the two v1 partitions from the processor and save the
   profile revision used for rollback evidence.
2. Restore the sender's previously qualified direct destination and token.
   Do not leave the sender pointed at a processor after its partition is
   removed.
3. Preserve any configured Edge default destination. Confirm the Ingest
   `splunk_indexer` unmatched route and the direct source index before
   resuming full traffic.
4. Run bounded HEC and installed-search readback for both source types. Confirm
   counts resume in the original indexes and Atlas search configuration points
   at the intended indexes.

See [profile details and references](../processors/README.md) for exact product
differences. These steps are a qualification checklist, not a report that a
processor runtime was available in the local lab.
