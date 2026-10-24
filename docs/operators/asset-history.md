# Importing asset history

Asset history is an optional evidence source for endpoint and application
investigations. Application Atlas does not connect to a CMDB or IPAM service.
An operator exports a versioned CSV or JSON file, validates it locally, and
ingests the generated NDJSON through the organization's existing Splunk
receiving path.

## Prepare and validate an export

Include a stable lowercase authority name, a unique snapshot ID, snapshot time,
and one row per address assignment or current-only observation. Use stable
asset IDs and, where applicable, stable service IDs. Optional environment and
network IDs retain network context; owner display names require stable owner
IDs. Keep records for separate routing domains in the correct scope. Source intervals use inclusive
valid_from and exclusive valid_to; source timestamps must include a UTC
offset or Z, or be numeric Unix seconds.

Run the importer with an output path outside the repository:

```sh
python3 tools/import_asset_history.py export.json \
  --output /tmp/asset-history.hec.ndjson \
  --report /tmp/asset-history.report.json
```

The output is deterministic newline-delimited HEC event JSON with
sourcetype=adm:asset_history, source=asset_history, and time=valid_from (or
snapshot_at for point snapshots). The selected Splunk receiving path
determines the destination index; the importer does not send the data or carry
credentials. Review accepted/rejected counts and every reported overlap before
ingestion. Use --fail-on-conflict to require zero overlapping owners before
the tool writes NDJSON. Conflicts are evaluated on the latest revision of
each record while all historical revisions remain in NDJSON. Different
contents for the same record_id and revision in one export fail validation;
conflicting copies from separate ingests are retained as ambiguous evidence.
Re-running an unchanged export produces the same records; the default protects
existing output files, including concurrent creation, and --overwrite is
required to replace one.

For example, the JSON file in
[fixtures/inventory/history.json](../../fixtures/inventory/history.json)
contains two non-overlapping owners that reuse one address. The conflict
fixture retains concurrent claims and shows that identical addresses in
different scopes are independent:
[fixtures/inventory/owner-conflict.json](../../fixtures/inventory/owner-conflict.json).

The importer treats snapshot_complete as descriptive metadata. Missing rows
never retire old assignments. Export explicit valid_to or retired_at values
to close assignments. Current-only snapshots are point context and do not own
earlier traffic.

## Configure the optional source

After the source format, timestamp extraction, search permissions, and
retention are qualified in the target deployment:

1. In the shared adm_observer_scope collection, add a verified
   observer_kind=asset_authority mapping. Set observer to the lowercase
   authority string in the export and scope to its routing scope. Keep each
   authority literal unique; if one CMDB serves separate scopes, use a distinct
   export authority per scope.
2. Configure the app-merged macro adm_index_asset_history with the literal
   destination index (or approved list of indexes).
3. Set adm_asset_history_schema_qualified=1 only after checking that indexed
   events retain every documented field and _time follows valid_from (or
   snapshot_at for current snapshots).
4. Mark asset_history active in deployment expectations and choose a
   staleAfterSeconds value appropriate for the export cadence. This is a
   freshness indicator, not an assignment end time.

The default index is unconfigured_optional and schema qualification defaults
to 0, so the panel remains unavailable until an administrator configures and
qualifies the source. Selectors and authority mappings are attribution inputs;
the search runs with the viewer's existing Splunk permissions.

## Read the panel

The Asset history panel is loaded only after an explicit request and is
independent from the traffic table. A historical record shows the source
interval and whether it covers all or part of the selected window. Open
intervals are only observed through their snapshot time. Current snapshots are
shown as point-in-time context and never attributed to earlier traffic.

Overlapping different asset IDs for the same scoped IP are marked ambiguous.
Concurrent records for one asset ID are also marked ambiguous when stable
owner, service, environment, or network IDs disagree.
A 10,001-row authority-wide history scan cap, 10,001 eligible-input cap,
64-row display cap, rejected source rows, timeout, changed source
configuration, malformed revision/interval fields, or unqualified schema
prevents a unique-owner claim. History
is scanned across scopes and addresses through capture time; latest revisions
are resolved before selected scope, IP, and time-window filters are applied.
Empty results do not prove no asset existed or complete source coverage.
Disabling the optional source removes it from later reads; previously indexed
events remain subject to the organization's normal index retention and access
controls.
