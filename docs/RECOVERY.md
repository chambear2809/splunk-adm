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
native scheduler activity. The shipped action is **automated assisted
recovery**: it is administrator-only and separately opt-in. The accepted KV
claim gate covers standalone Splunk only. The [core milestone live tests](benchmarks/2026-10-14-recovery-core.md)
passed on standalone Splunk 10.6.0.5. The separate abandoned-lease supervisor
adds detection; it never takes over a recovery. SHC and failover behavior are not qualified. The action
refuses other versions, Cloud, SHC, remote search peers, indexer clustering, and unknown deployment evidence. It requires the qualified standalone Enterprise roles (indexer, KV Store, and local licensing) before changing any writer, and remains disabled until local
overrides explicitly enable both the saved-search action and
`local/adm_recovery.conf`. Native scheduler catch-up remains a failed
qualification; the manual absolute-slice fallback remains required when the
action refuses or becomes uncertain.

`adm_health_jobs` cannot surface the exact failure above: it reports the
*latest* scheduler.log status per saved search, so a missed slot followed by
a successful later slot still reads `status="ok"`. `ADM - Scheduler
missed-slot alert` (search `adm_health_missed_slots`) closes that gap by
diffing expected five-minute writer slots and hourly V2 catalog slots against `scheduler.log` successes
whose SID starts with `scheduler__`, with a 10-minute grace period before a
slot counts as missed. Only slots strictly after a target's earliest visible
scheduler success are expected: gaps have `reason=missed_slot`, while slots
before that checkpoint are not reported. An enabled, scheduled target with
no successful checkpoint produces exactly one `reason=no_successful_checkpoint`
row without `scheduled_time`; investigate its configuration and scheduler
history instead of treating the row as a replayable slice. Disabled and
explicitly unscheduled targets are excluded. A successful run after a pause
does not reset an earlier checkpoint or clear the intervening gaps.
The saved alert searches from `-1500m@m` (24 hours plus the preceding
hourly checkpoint); if `adm_missed_slot_lookback` is increased, extend
the alert's `dispatch.earliest_time` accordingly. It ships
**disabled**, like every other saved search in this app. Enabling it requires
three separate steps: (1) enable the saved search itself; (2) configure
`alert_actions.conf` or the Alerts UI with an actual notification (email,
webhook, etc.) — this repo ships no paging integration, since that is
site-specific; and (3) treat a firing alert as notification only unless the
separate recovery action is explicitly enabled. The notification action does
not replay anything or clear a slot. With recovery disabled, the missed slot
remains unrecovered until an administrator replays it. A manual
replay does not supply scheduler success evidence, so it does not clear a slot
unless the recovery action verifies it. Verified records in the
administrator-only `adm_recovery_state` collection suppress only the matching
recovered slots. Claims in progress remain visible as `in_progress`; failed or
expired nonterminal claims remain visible as `uncertain` and are never
automatically re-dispatched or taken over.

A recovered record is evidence that its original slice completed under the
recorded configuration. Changing normalization or index macros does not reopen
historical scheduler successes or recovered slots. The action refuses further
recovery for a target when its recorded recovery configuration differs from the
current macro configuration; reconcile that change manually using the rebuild
guidance below. Do not delete claims simply to bypass this refusal.

The opt-in configuration is local and must be reviewed by an administrator:

```ini
# local/savedsearches.conf
[ADM - Scheduler missed-slot alert]
action.adm_recovery = 1
disabled = 0

# local/adm_recovery.conf
[recovery]
enabled = 1
management_uri = https://localhost:8089
ca_file = /path/to/trusted/splunk-ca.pem
```

Keep notification configuration separate from `action.adm_recovery`.
`ca_file` must identify a trusted certificate chain and hostname verification
remains enabled; do not disable TLS verification or use a bypass value.

This adds Python under `bin/`, a custom alert action, a pinned bundled Splunk
SDK, and administrator-only KV state/audit collections. The action uses the
alert owner's session and local HTTPS management API. It does not install
dependencies at runtime. These additions require renewed AppInspect and
Splunk Cloud review; this milestone does not qualify recovery for Cloud.

## Automated assisted recovery core action

The action's allowlist covers the existing V1 identity, service-binding,
service-backend and conversation writers. The Cisco client-history builder,
V2 conversation and traffic writers, and V2 catalog are monitored by missed-slot
detection but are outside that allowlist. A detected V2 gap requires an
administrator's bounded replay and readback evidence; it is not automatically
recovered by enabling the action. V2 outage recovery on distributed Enterprise,
SHC and Cloud remains an open [qualification gate](CISCO_NETWORKING_QUALIFICATION.md).

The core action handles one target at a time. Before pausing, it reads and
durably records the target's saved-search state, configuration fingerprint and
owner claim. The record is written before the REST pause, so a process failure
does not leave the original state only in memory. It changes only
`is_scheduled`, drains active jobs, and restores that field from the recorded
value after verification. Restoration currently leaves a local
`savedsearches.conf` `is_scheduled` override; retain that override in the
recovery audit and remove it only through the normal configuration workflow.

The qualified invocation admits at most four initial missing slots and eight
total slots, with a 120-second per-slot budget, an 18-minute pause cap and a
25-minute alert-action `maxtime` (the internal action deadline is 21 minutes).
Larger backlogs are refused before pausing. Builders replay chronological
closed slices one at a time; their intentional overlapping ten-minute index
windows are allowed because deterministic KV merges are idempotent. The
conversation rollup accepts only closed, disjoint five-minute slices and
rejects overlap or altered bounds. Recovery history retains all scheduler
outcomes: a candidate rollup slot with a prior job SID, failure or unknown
outcome is refused before pausing, and checked again before replay. Only an
absent execution or an explicit skip without a SID is eligible automatically.
A failed native aggregate might already have written partial rows with
different identities; a new full-slice manifest cannot prove those rows absent.
Use manual reconciliation or the separate-index rebuild for that case.
While a builder is paused, its indexed data
can therefore be about 18 minutes stale until recovery completes.

Each target and slot claim uses an insert-only deterministic KV key. A duplicate
claim refuses the run. A lease expiry never permits takeover: the claim stays
uncertain and requires manual reconciliation. `dispatch_pending` is persisted
before dispatch; an unknown dispatch response is uncertain and is not retried.
The core action records audit events and performs ordinary known-failure
cleanup, and the separate supervisor reports expired claims for manual reconciliation.
Neither component reclaims a paused target.

For rollups, the pre-replay manifest compares the raw accepted count with the
expected rollup identities and counts for the exact slice. This is a
**slice-stability check**, not proof that the replay wrote its summary. After
dispatch, the action compares the replay output and queries the summary index
for every expected `rollup_id`; that post-replay summary check is the actual
verification. Empty slices are verified as no-ops. If either check is
inconclusive, the slot remains uncertain and the manual fallback applies.

## Abandoned recovery claims

`ADM - Recovery abandoned-lease alert` ships disabled. On qualified standalone
Splunk 10.6.0.5, an administrator can enable it independently of the recovery
action. It pages through the recovery-state lookup every five minutes,
including targets that are paused and claims older than the missed-slot
history window. It reuses `adm_kv_read_all` (20 pages of 10,000 rows) and
raises `incomplete_recovery_state_read` if completeness cannot be proved,
including at its page ceiling. Investigate that alert even if no specific
abandoned claim was returned. It creates a tracked Splunk Triggered Alert when expired
claims remain. Results include the claim key, target, state, owner, expiry,
slot time and SID when available. No email, webhook or paging integration is
shipped; configure notifications separately in the Alerts UI. Without that
configuration, an administrator must inspect Triggered Alerts. Unresolved
claims can produce another alert on each run; alert tracking has finite
retention, while claims remain available until manually reconciled.

Every existing target claim whose `expires_at <= now()` is reported, regardless
of its state. In particular, `restored` only means the schedule was restored;
normal completion must also delete the target claim. A crash between those
steps leaves a record that blocks future recovery. For slot records, only
`recovered` is terminal. An expired `verified` slot remains unresolved because
it has not completed the invocation's handback. Unknown states and record
types with a valid expired lease are reported conservatively.

The supervisor reads claims and writes only Splunk's ordinary search/alert
artifacts. It never extends or deletes a claim, changes a schedule, cancels a
job, or dispatches a replay. The recovery action remains separately disabled.
An interrupted recovery normally leaves its schedule paused; a process killed
after restoration leaves the schedule restored. Neither fact resolves an
orphaned target claim. A replay deadline with an active SID leaves the schedule
paused because the writer may still be running. An administrator's concurrent
saved-search or macro change prevents automatic restoration over that change.

For an alert, inspect the original target snapshot, slot bounds, audit events,
SID and live job status. Establish whether any writer remains and reconcile
its actual outputs before considering a manual replay or restoring a schedule.
Preserve the evidence. Claim removal is an explicit administrator operation
after reconciliation, never a way to bypass a refusal. Recovered slot records
remain recovery evidence and must not be deleted merely to clear an alert.
There is no automatic retry, lease takeover, or new SHC qualification.

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

Builders upsert deterministic KV keys. Replay their original closed slices in chronological order while their schedules are paused, then verify interval boundaries and the latest attributes before resuming. Do not run two manual instances of the same builder concurrently. A saved search's single-instance limit does not serialize different saved searches or manual macro calls. The existing interval regressions cover same-batch gaps and out-of-order replays; arbitrary overlapping concurrent updates are not transactional. The automated assisted recovery action enforces this one-at-a-time rule and permits the builders' intentional overlapping ten-minute windows. It refuses rollup slices that overlap or are not closed.

## Pruning and maintenance

All prune searches, including the additional Cisco client-history prune, ship with scheduling disabled, and `adm_prune_maintenance=0` makes them read-only reports. Enabling a prune saved search alone cannot authorize its collection rewrite. The gate is an explicit operator assertion of a maintenance window, **not a lock**. Scheduling prunes between normal builder start times cannot prevent a long or delayed builder from overlapping.

1. Pause **all** ADM builder and prune schedules and prevent manual dispatches. Drain or cancel every active builder/prune job. This includes service binding, service backends/routes, identity, Cisco client history and ACI policy writers.
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
