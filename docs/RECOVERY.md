# Recovery and replay

Recovery runs are administrator operations. Keep the original raw data and record the saved-search job ID, absolute event-time bounds, absolute index-time bounds, app version, and observer-scope configuration before making changes. Do not use relative times such as `-10m` when retrying a historical job: those select different data on every retry.

## Interrupted conversation rollups

New summary rows include `rollup_id`, a SHA-256 identity of the sorted set of original indexed-event identities contributing to that row. The graph removes duplicate `rollup_id` values before adding counters. Each source event is identified by its index, bucket ID and within-bucket event address; ACI ACL records use their APIC-qualified object identity and timestamp. The summary remains compact, with one row per conversation, five-minute event-time bucket and observer.

For a rollup whose source search and aggregation completed successfully but whose summary write failed or was interrupted:

1. Pause the conversation rollup schedule and wait for active instances to finish or cancel them. Inspect the scheduler and job messages to establish the affected input slice.
2. Check that the raw source buckets remain available and that index macros, normalization, observer scopes and app version are unchanged. Capture the original job's **absolute event-time and index-time bounds**. Include the complete original slice; do not select only the rows missing from the summary.
3. Re-dispatch **ADM - Conversation rollup** with those same absolute bounds. It is safe to repeat a closed, immutable slice: already-written summary rows are deduplicated by the graph and missing rows are added. Physical duplicate summary events remain stored until index retention expires; replay protection makes reads idempotent, not writes transactional.
4. Wait for ingestion to finish. Check the job for errors or truncation, compare raw and deduplicated summary totals for that slice, and confirm the map's warnings and pipeline health. Resume the schedule after verifying the affected slice.

If the source search was truncated, auto-finalized, or returned partial results before aggregation, an existing row may describe only part of the original input set. Use a separate-index rebuild in that case; an identical retry cannot repair overlapping partial aggregates.

Do not overlap differently bounded slices, combine failed slices into a larger replay, or retry a slice that was still receiving data. A different input-event set produces a different row identity and may overlap an existing aggregate. If original bounds cannot be established, if normalization changed, or if ingestion/bucket reconstruction changed event identities, rebuild the affected history into a **separate summary index** using a recorded, disjoint partition of closed index-time slices. Validate it before switching both `adm_index_summary` and `adm_summary_index_name`. Keep the old index available for rollback. This procedure does not claim general exactly-once delivery or detect every ingestion-side duplicate.

Rows written before replay identities were introduced remain readable, with a graph warning. They cannot be safely deduplicated retrospectively from aggregate counts. Do not replay legacy history into the same summary index. A clean rebuild is required for that history.

## Duplicate ingestion and event identity

Two independently indexed NetFlow records can have identical payloads and timestamps while representing separate legitimate observations. They have distinct indexed-event identities and remain separate. Replaying the *same indexed records* is protected; sending the same payload to HEC again creates new indexed records and is not a replay. Fix ingestion-side retries at the collector or ingestion boundary using a verified source-specific event ID. Never deduplicate solely by IP tuple, port, timestamp or payload hash: this can erase legitimate observations. Restore/reindex operations also require the clean rebuild procedure above.

## Builder recovery

Builders upsert deterministic KV keys. Replay their original closed slices in chronological order while their schedules are paused, then verify interval boundaries and the latest attributes before resuming. Do not run two manual instances of the same builder concurrently. A saved search's single-instance limit does not serialize different saved searches or manual macro calls. The existing interval regressions cover same-batch gaps and out-of-order replays; arbitrary overlapping concurrent updates are not transactional.

## Pruning and maintenance

All five prune searches ship with scheduling disabled, and `adm_prune_maintenance=0` makes them read-only reports. Enabling a prune saved search alone cannot authorize its collection rewrite. The gate is an explicit operator assertion of a maintenance window, **not a lock**. Scheduling prunes between normal builder start times cannot prevent a long or delayed builder from overlapping.

1. Pause **all** ADM builder and prune schedules and prevent manual dispatches. Drain or cancel every active builder/prune job. This includes service binding, service backends/routes, identity and ACI policy writers.
2. Back up each affected collection and record row counts. Confirm the backup is complete and recoverable before pruning.
3. Temporarily set the local `adm_prune_maintenance` macro to `1`. Run one prune at a time and inspect `complete`, `rows_expired`, `rows_pruned`, and `warnings`. Incomplete reads never rewrite the collection. The empty-write safeguard also retains an entirely expired collection for separate administrator cleanup.
4. Verify surviving rows and counts. Restore `adm_prune_maintenance=0` **before** resuming builders. Keep prune schedules disabled.

If a maintenance prune fails or is interrupted, leave writers paused and compare the collection with its backup; restore the verified backup if necessary. Do not assume a partial collection rewrite is safe to retry. Never restore a backup while builders are running, because that can overwrite newer updates.

## Verification

`tests/splunk/test_recovery.py` exercises replay identities and summary deduplication. `tests/splunk/test_prune_recovery.py` injects a builder-style upsert after a prune's snapshot and verifies that the default maintenance gate preserves it for all five collections. Existing maintenance tests explicitly enable the gate with builders idle and continue to cover incomplete reads and empty-write safeguards.

Splunk documents the underlying bucket and event-address fields in [Use default fields](https://help.splunk.com/en?resourceId=Splunk_Knowledge_Usedefaultfields&version=splunk-9_3). These are identities of indexed records, not source-system transaction IDs.

## Clean restore rehearsal

The [backup/restore rehearsal](BACKUP_RESTORE.md) recreates the disposable lab, restores all six app collections and deployment-local files, rebuilds summaries from retained synthetic fixtures, and compares the resulting map. It does not substitute for a production raw-index or platform backup.
