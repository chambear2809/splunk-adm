# Asset history supplemental evidence

## Purpose

Asset history supplies optional, scoped inventory context beside an endpoint or
application investigation. The repository has no established CMDB or IPAM
service integration, so v1 accepts operator-provided CSV or JSON history files.
The importer validates local files and renders deterministic Splunk HEC NDJSON;
it does not call a vendor or Splunk API.

Asset records remain supplemental evidence. They do not create traffic records,
application graph edges, connections, or counters. Traffic and inventory keep
independent event times and provenance.

## Import record contract

The JSON format is a versioned manifest with one authority and snapshot:

```json
{
  "schema_version": 1,
  "authority": "cmdb-prod-east",
  "snapshot_id": "export-2026-10-23T120000Z",
  "snapshot_at": "2026-10-23T12:00:00Z",
  "snapshot_complete": true,
  "records": [
    {
      "record_id": "assignment-web-17",
      "revision": 1,
      "asset_id": "asset-17",
      "asset_name": "web-17",
      "service_id": "checkout",
      "service_name": "Checkout",
      "environment": "production",
      "owner_id": "team-commerce",
      "owner_name": "Commerce Platform",
      "network_id": "vpc-prod-east",
      "scope": "prod-east",
      "ip": "10.20.0.17",
      "validity_basis": "source_interval",
      "valid_from": "2026-10-20T08:00:00Z",
      "valid_to": null
    }
  ]
}
```

The equivalent CSV repeats the manifest columns on each row. See
[fixtures/inventory/current-snapshot.csv](../fixtures/inventory/current-snapshot.csv)
for the flat header and a current-only record.

Each record requires a source-stable record_id, a nonnegative revision, a
stable asset_id, a mapped routing scope, and one literal IP. A service
label requires a stable service_id. Display names never serve as identity.
Optional environment and network_id values retain source context. owner_name
requires a stable owner_id; the panel presents both without using display names
as identity. Asset, service, owner, environment, network, authority, scope, and
IP values remain source observations and do not derive traffic relationships.
authority is normalized to lowercase and must match a verified
asset_authority scope mapping.

validity_basis=source_interval requires an inclusive valid_from; optional
valid_to is exclusive, so intervals are [valid_from, valid_to). A missing
valid_to means the source has no recorded end. It does not prove future
continuity: an open interval is only observed through its manifest's
snapshot_at, and an observed interval cannot begin after that snapshot.
retired_at is optional and, when present, must equal the
explicit exclusive valid_to. An assignment ending does not by itself mean the
asset was retired.

validity_basis=snapshot_current is a point-in-time inventory observation. It
cannot contain valid_from, valid_to, or retired_at; the importer uses
snapshot_at as its event time. The UI labels it as context only and never
attributes earlier traffic to it. Snapshot freshness is computed separately
from validity using the configured staleAfterSeconds; freshness does not
extend an interval or imply retirement.

snapshot_complete describes the source export. It does not close old
assignments when a row is absent. Only explicit interval ends or retirement
records change validity. revision is monotonic per authority and record_id:
a higher source revision supersedes an older copy of that same record;
disagreement at the same revision remains ambiguous. Conflict reporting first
chooses the highest revision of each source record while retaining all
revisions in the generated history stream. Different asset IDs with
overlapping intervals for the same scope and IP are retained and reported as
conflicts. Concurrent records for the same asset ID are also ambiguous when
they disagree on stable owner, service, environment, or network IDs; missing
optional context remains unknown rather than contradicting a populated value.

## Search and attribution limits

The source-specific search uses only the configured asset-history indexes and
verified authorities. It dispatches from epoch zero through the later of the
selected window end and capture time, scans each authority across scopes and
addresses, resolves the highest revision, then filters to the selected scope,
addresses, and validity window. This ordering prevents an old assignment from
being admitted after a later correction closes it or moves it. The query has a
30-second server/client budget, reads at most 10,001 matching source rows to
detect overflow, counts malformed revision identities and interval fields
before filtering, and returns at most 64 eligible records. A timeout, source
or eligible-row cap, malformed source row, rejected projected row, changed
configuration, or unqualified schema means the panel cannot establish a
unique owner. These limits bound returned work; an all-history time-range
dispatch can still be expensive, so keep index and authority selectors narrow
and size Splunk retention and search capacity accordingly.

Only caller-visible search results are considered. A zero-row result does not
prove that the caller can search the configured index, that the source retained
all history, or that an asset did not exist. Scope is attribution context, not
an authorization boundary. Conflicts remain visible; the feature does not
choose a last-written owner or infer ownership from a flow alone.

## Validation

tools/import_asset_history.py validates JSON and CSV, normalizes IP literals
and timestamps, checks interval and retirement semantics, detects overlapping
owner claims, and emits deterministic HEC event envelopes. Invalid rows fail
the batch and produce a report without a partial NDJSON file. Conflicts are
reported while preserving valid candidate rows; --fail-on-conflict prevents
NDJSON output when the report contains overlaps. Existing output files are
protected unless --overwrite is supplied.

Synthetic coverage is in
[tests/test_import_asset_history.py](../tests/test_import_asset_history.py)
and frontend/src/data/inventoryEvidence.test.ts. No real CMDB/IPAM feed,
vendor schema, ingest route, or production index is qualified by these tests.
