# Process interruption rehearsal

`tools/fault_pipeline.py` is a bounded, local-only rehearsal for an abrupt
Splunk process failure. Run it only against the disposable lab:

```sh
python3 tools/fault_pipeline.py --reset-lab --output dist/fault/latest.json
```

The harness requires the same localhost Docker/image and installed-app
fingerprint checks as the benchmark harness. It submits deterministic fixture
events through HEC, waits until every accepted event is searchable, dispatches
the closed conversation rollup, and polls until a genuinely incomplete/running
job is observed. It then uses `docker kill` (SIGKILL), records the stopped
state, starts the container, waits for management, KV, and container startup completion, and retains the
raw indexes.

An interrupted aggregate is not replayed in place. The harness clears only the
lab's `adm_summary` index while raw records remain, then reruns the identical
closed index-time slice and compares raw searchable records with the expected
deduplicated summary count. The JSON report retains the interrupted and replay
job IDs, submitted/searchable counts, kill evidence, and any restore failure.

This demonstrates recovery for a clean rebuild from retained raw data. It does
not claim transactional exactly-once writes, arbitrary partial-aggregate
replay safety, or protection against duplicate HEC submissions. If a running
state cannot be observed before the bounded deadline, the test fails rather
than recording a skipped or simulated fault. After a successful local preflight, the `finally` path starts the
container and waits for readiness after any failure. A rejected preflight
does not attempt recovery or modify a container. Raw event identities are
hashed before and after restart, in addition to checking their count.
