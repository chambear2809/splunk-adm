# Actual scheduler and downtime rehearsal

`tools/scheduler_pipeline.py` runs the shipped five-minute schedules in the
isolated localhost Splunk lab. Its default `native` mode does not manually
dispatch target saved searches or shorten their cron expressions.

```sh
python3 tools/scheduler_pipeline.py --reset-lab
```

Allow roughly 25–30 minutes, depending on the starting minute and container
startup time. The bounded default deadline is 30 minutes after lab reset.
The default downtime is 330 seconds. A failing result returns nonzero and
writes diagnostic evidence to `dist/scheduler/latest.json`.

The rehearsal enables Identity builder, Service binding, Service backends,
and Conversation rollup. Interface inventory and ACI policy scheduling are
outside this fixture's scope; all maintenance prunes remain disabled.
It supplies current-time pod, span and NetFlow events, observes real
`scheduler.log` successes and checks initial summary convergence. The backend
builder is scheduled with no EndpointSlice objects in this fixture; this
checks its scheduling, not backend population (covered by functional tests).

It then submits another batch of independent observations, records the batch's
actual index-time slice, and stops the container before that slice's rollup is
due. The outage crosses a complete scheduling period. After restart, every
target must have a successful missed-slot run dispatched after the restart
request, including the exact rollup slot holding the second batch. The final
summary must have exactly twice the flow records, and the graph must retain
correct identities, traffic totals and connection counts. The same payload
indexed twice represents separate observations; this is not HEC retry dedupe.

Scheduler skips/failures and their reasons are retained and fail the rehearsal.
Startup deferrals (`status=continued`) are retained but do not count as
successful runs. The bounded wait still requires every missed target to
complete and the summary to converge; a deferral cannot certify recovery.
The health macro must expose recent successful runs with no failed/skipped
runs. This does not intentionally force resource contention or prove that
an overloaded scheduler never skips; synthetic health regressions separately
cover how skipped/failed outcomes are displayed.

## Assisted recovery rehearsal

```sh
python3 tools/scheduler_pipeline.py --reset-lab --recovery replay --timeout 2400
```

This explicit mode keeps the real baseline schedules and outage, then pauses
schedules, drains active jobs, and replays missing slots in chronological order.
Every dispatch uses the original absolute event-time and index-time bounds.
The planner requires a recent successful checkpoint for all four targets and
rejects gaps before the outage, misaligned slots, and recovery ranges over
24 hours. Already successful slots are excluded. It repeats planning for slots
that elapse during recovery before resuming schedules.

A passing result requires all 12 flow records before resumption, fresh real
scheduled successes from all four targets afterward, and exact final graph
and summary totals. `recovery.jobs` records manual replay SIDs and bounds;
`catchup_rows` contains only actual native scheduler successes. Manual jobs also
appear in `scheduler.log`, so successes require a `scheduler__` job ID;
sid-less deferrals and skips remain diagnostic evidence. Empty binding or rollup
windows may emit a known no-results warning. The harness accepts only the exact
no-op output with zero scanned/matched events and no other warning, retaining
`accepted_empty_window` on the original job record. Other warnings still fail.
Assisted success
does **not** qualify native catch-up or install an automatic production recovery
service. This command only supports the disposable lab. Production recovery
remains the administrator procedure in [Recovery and replay](RECOVERY.md).

## Ordering and limits

The shipped rollup runs at minute 0 modulo 5, identity at 1, service binding at
2, and service backends at 3. Cron offsets express intended staggering, not a
transactional dependency chain. The rollup consumes an older closed index-time
slice; graph enrichment is checked only after builders and rollup converge.
The rollup uses `-10m@m` through `-5m@m`: minute rounding is valid Splunk
syntax, and the five-minute cron aligns those bounds to adjacent closed slices.
`@5m` is not a valid snap unit; the live rehearsal exposed premature collection
with that previous setting. A parser regression checks the shipped bounds
and their adjacency using Splunk itself.
The harness verifies configured offsets and the actual dispatch order of a
complete cycle before the outage. Scheduled, dispatched and completion times
distinguish that baseline from delayed catch-up. It records catch-up order
without assuming those queued jobs run in cron order.

The exclusive October 13 rehearsal failed downtime recovery: future jobs resumed,
but the second batch remained absent and no missed-slot successes appeared.
See [the evidence](benchmarks/2026-10-13-pipeline.md). Automatic catch-up is
not qualified by the current test results.

Continuous scheduling (`realtime_schedule=0`) requests catch-up of missed periods;
recovery also depends on the platform's continuous-search lookback setting and
retained raw history. See Splunk's [saved-search configuration reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.8-configuration-file-reference/savedsearches.conf)
and [scheduler limits](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.2/configuration-file-reference/10.2.4-configuration-file-reference/limits.conf).
The app's accepted event-time range remains the shipped `-24h` through `+15m`;
fixture envelope and embedded clocks are shifted together to respect it.

Only the pinned disposable localhost lab is supported. The harness verifies
local Docker, loopback ports, image and installed app fingerprints before any
mutation. Cleanup disables app schedules after owning the lab. Remove the lab
with `tests/splunk/lab.sh purge` when finished. Do not run another lab test at
the same time: reset and downtime deliberately affect the entire container.
Separate Git worktrees do not isolate Docker containers or localhost ports.
Reserve exclusive use of `adm-splunk-lab` for the entire rehearsal.
The rehearsal entry points and `lab.sh` now share a cooperative ownership lock
across checkouts run by the same OS user. A second independent invocation
fails before it can mutate the lab; child setup/reset calls inherit their parent's ownership. Direct
Docker commands and older checkouts without the lock can still interfere.
During downtime the scheduler rehearsal checks that the container remains
stopped, and reports unexpected state changes without cleaning up another
process's lab state.

Wrap direct integration-test runs in the same lock:

```sh
ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk -v
```
