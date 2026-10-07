# Pilot graph contract (v1)

A snapshot is one JSON object, stored as one Splunk event (`sourcetype=adm:graph`).
The frontend reads the latest complete event for a selected boundary. Never join
nodes from different snapshots. Required top-level fields:

```json
{
  "schema_version": 1,
  "snapshot_id": "unique-id",
  "generated_at": "2026-10-07T12:00:00Z",
  "window": {"start": "2026-10-07T11:45:00Z", "end": "2026-10-07T12:00:00Z"},
  "demo": true,
  "boundary": {"id": "shop-demo", "service": "frontend", "environment": "demo", "cluster": "demo-cluster", "namespace": "shop", "root_node_id": "service:frontend"},
  "nodes": [],
  "edges": [],
  "coverage": {"spans": 0, "flows": 0, "matched_flows": 0, "unresolved_flows": 0, "warnings": []}
}
```

Node: `id`, `label`, `kind` (`service`, `workload`, `endpoint`), optional `namespace`,
`cluster`, `addresses` (string array), `reason`.
Edge: `id`, `source`, `target`, `relationship` (`calls`, `communicates_with`,
`runs_on`), `evidence` (string array), `confidence` (`observed`, `correlated`,
`unresolved`), `count` (number), optional `bytes`, `reason`, `observers` (string array).
No health, latency or routed-path claims without direct supporting telemetry.

## Projection rules

Scope frontend by service/environment/cluster/namespace. Traverse span parent IDs
within each trace starting at matching frontend spans; exclude upstream and sibling
branches. `calls` means observed cross-service parent/child spans. Root absence
produces a valid empty graph and a warning. Missing parents reduce coverage.
Resource attributes bind services to pod UIDs. Pod objects require explicit
`cluster`, `valid_from`, `valid_to` metadata in their normalized wrapper. A single
current inventory cannot retroactively resolve historical IP ownership.

Flow input is explicit source/destination IP + start/end + bytes + exporter.
Resolve only uniquely owned pod addresses in the same cluster across the full
flow interval. Include communication attached to a traced workload; preserve
unknown external endpoints. Never infer call direction from exporter `flow_dir`.
No NAT/VIP translation without separate evidence. Do not merge communication with
calls. Deduplicate trace/span IDs; ambiguous duplicates must not create false edges.
Limit input and output sizes, fail clearly rather than silently truncate graphs.

## Local CLI interface

`python3 tools/adm_pipeline.py --spans fixtures/spans.json --inventory fixtures/inventory.json --flows fixtures/flows.json --boundary-id shop-demo --service frontend --environment demo --cluster demo-cluster --namespace shop --start 2026-10-07T11:45:00Z --end 2026-10-07T12:00:00Z --demo --output fixtures/demo-graph.json --hec-output fixtures/demo-hec.ndjson`

OTLP JSON input: `resourceSpans[].resource.attributes`, `scopeSpans[].spans[]`.
Inventory normalized input: `{ "pods": [{ "cluster": "...", "valid_from": "...", "valid_to": "...", "object": { "metadata": {"uid": "...", "name": "...", "namespace": "..."}, "status": {"podIP": "...", "podIPs": [{"ip": "..."}]} } }] }`.
Flow input: array of `{ "src_ip", "dest_ip", "timestamp", "endtime", "bytes", "exporter_ip", "cluster" }`.

HEC output is local NDJSON only: `{ "time": <window end epoch>, "sourcetype": "adm:graph", "event": <snapshot> }`.
No credentials or automatic network transmission. Real deployment must schedule
projection and deliver complete snapshots to an explicitly provisioned index.
