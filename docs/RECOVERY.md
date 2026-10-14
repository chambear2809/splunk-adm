# Recovery and replay

Recovery runs are administrator operations. Keep the original raw data and record the saved-search job ID, absolute event-time bounds, absolute index-time bounds, app version, and observer-scope configuration before making changes. Do not use relative times such as `-10m` when retrying a historical job: those select different data on every retry.

## Missed runs during an outage

Do not assume that continuous scheduling automatically replays an outage. The
[exclusive local scheduler rehearsal](benchmarks/2026-10-13-pipeline.md) resumed
future jobs but did not recover a missed slice, despite a 24-hour lookback.
Compare expected scheduled slots with successful executions after restart and
verify raw-versus-summary counts. Recover each affected closed slice using the
absolute-bound procedure below; do not merge multiple slices into one replay.
Follow-up probes on this Splunk 10.6.0.5 standalone lab observed the scheduler
advance its next runtime while KV Store was starting, then decline to replace
that later runtime when persisted history loaded. This is observed startup
behavior in the tested environment, not a qualification of other deployments.
The lab now waits for both KV Store readiness and a successful collection data
read after restart; that readiness check alone does not restore missed slots.

The [assisted lab rehearsal](SCHEDULER_TESTS.md#assisted-recovery-rehearsal)
exercises the absolute-slice procedure and records replay jobs separately from
native scheduler activity. It is not an unattended production recovery tool.

`adm_health_jobs` cannot surface the exact failure above: it reports the
*latest* scheduler.log status per saved search, so a missed slot followed by
a successful later slot still reads `status="ok"`. `ADM - Scheduler
missed-slot alert` (search `adm_health_missed_slots`) closes that gap by
diffing expected five-minute cron slots against `scheduler.log` successes
whose SID starts with `scheduler__`, with a 10-minute grace period before a
slot counts as missed. Only slots strictly after a target's earliest visible
scheduler success are expected: gaps have `reason=missed_slot`, while slots
before that checkpoint are not reported. An enabled, scheduled target with
no successful checkpoint produces exactly one `reason=no_successful_checkpoint`
row without `scheduled_time`; investigate its configuration and scheduler
history instead of treating the row as a replayable slice. Disabled and
explicitly unscheduled targets are excluded. A successful run after a pause
does not reset an earlier checkpoint or clear the intervening gaps.
The saved alert searches from `-1445m@m` (24 hours plus the preceding
five-minute checkpoint); if `adm_missed_slot_lookback` is increased, extend
the alert's `dispatch.earliest_time` accordingly. It ships
**disabled**, like every other saved search in this app. Enabling it requires
three separate steps: (1) enable the saved search itself; (2) configure
`alert_actions.conf` or the Alerts UI with an actual notification (email,
webhook, etc.) — this repo ships no paging integration, since that is
site-specific; and (3) treat a firing alert purely as a trigger to run the
absolute-slice recovery procedure above, not as something that resolves on
its own. The alert does not replay anything and does not clear itself; the
missed slot remains unrecovered until an administrator replays it. A manual
replay does not supply scheduler success evidence, so the detector continues
to report that slot until it leaves the lookback window. Durable recovery
acknowledgments are not part of this detector-only implementation.

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
5. After resuming writers, review the missed-slot alert. With a pre-pause successful checkpoint in the window, it reports unsatisfied slots from the paused period as `reason=missed_slot`. Replay those original absolute slices using the recovery procedures above: pause the affected target's schedule, drain its active jobs, and replay builders chronologically, one at a time. Recover any additional slots passed during replay before the final resume. A resumed builder reads only its rolling ten-minute index-time window, and the rollup reads one closed five-minute slice; data indexed during the pause outside those resumed windows otherwise stays unprocessed. Keep maintenance windows shorter than the 24-hour detection lookback and retain the pause times for reconciliation. If the checkpoint has aged out, `no_successful_checkpoint` or a new post-resume checkpoint does not prove that the paused period was processed; reconstruct its slices from retained operational history.

Maintenance gaps are not suppressed. Future Phase 2 recovery-service pauses
must remain tracked through the durable pause record and included in recovery
planning even while their schedules are off or their checkpoint has aged out.
Any future maintenance label must reuse that state and keep the gaps visible;
it must never silently exclude them.

If a maintenance prune fails or is interrupted, leave writers paused and compare the collection with its backup; restore the verified backup if necessary. Do not assume a partial collection rewrite is safe to retry. Never restore a backup while builders are running, because that can overwrite newer updates.

## Verification

`tests/splunk/test_recovery.py` exercises replay identities and summary deduplication. `tests/splunk/test_prune_recovery.py` injects a builder-style upsert after a prune's snapshot and verifies that the default maintenance gate preserves it for all five collections. Existing maintenance tests explicitly enable the gate with builders idle and continue to cover incomplete reads and empty-write safeguards.

Splunk documents the underlying bucket and event-address fields in [Use default fields](https://help.splunk.com/en?resourceId=Splunk_Knowledge_Usedefaultfields&version=splunk-9_3). These are identities of indexed records, not source-system transaction IDs.

## Clean restore rehearsal

The [backup/restore rehearsal](BACKUP_RESTORE.md) recreates the disposable lab, restores all six app collections and deployment-local files, rebuilds summaries from retained synthetic fixtures, and compares the resulting map. It does not substitute for a production raw-index or platform backup.
