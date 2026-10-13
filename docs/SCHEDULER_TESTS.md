# Actual scheduler and downtime rehearsal

`tools/scheduler_pipeline.py` runs the shipped five-minute schedules in the
isolated localhost Splunk lab. It does not manually dispatch the target saved
searches or shorten their cron expressions.

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

Continuous scheduling (`realtime_schedule=0`) can catch up missed periods;
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
