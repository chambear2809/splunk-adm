# Automated assisted recovery — supervisor and failure windows

Date: 2026-10-14. Base commit: `4e571bd`; changes remain uncommitted.

**Result:** 43 distinct live tests and 59 unit tests passed. All live work ran
in the disposable standalone Splunk 10.6.0.5 lab with `tools/lab_lock.py` held
across startup, installation, tests and purge. The container, volumes, image and
generated lab secrets were removed. Independent read-only review finished with
no actionable findings. The five recovery entrypoint/library source files
still match their Milestone 1 recorded hashes.

## Shipped behavior

`ADM - Recovery abandoned-lease alert` ships disabled and administrator-only.
It reads recovery claims in pages and creates a tracked Splunk Triggered Alert
for expired unresolved claims. It never changes claims or schedules, extends
leases, retries a replay, or takes over recovery. No notification or paging
integration is shipped; administrators must configure that separately or
inspect Triggered Alerts. The operator procedure is in `docs/RECOVERY.md`,
which is now included in the application package.

Every expired target record is reported, including `restored`. Successful
recovery deletes its target claim; a persisted state value cannot make an
existing target record safe to ignore. Only slot records in `recovered` are
excluded. Expired `verified` slots are unresolved. Unknown record types/states
with valid expired timestamps are reported conservatively.

The existing `adm_kv_read_all` reader covers 20 pages of 10,000 rows. If it
cannot establish completeness, the supervisor emits an
`incomplete_recovery_state_read` incident even when the returned records are
all terminal. This prevents retained recovered slots from silently hiding
abandoned claims behind the KV query cap.

## Exact coverage

| Suite | Live tests | Coverage |
| --- | ---: | --- |
| `tests/splunk/test_recovery_supervisor.py` | 3 | Expired/unexpired target and slot state matrix, including target/restored and slot/verified; unknown types/states; unchanged claims and schedule configuration; tracked alert matched to the current dispatch SID; expired target behind 50,001 recovered slots; incident on an injected incomplete-read signal. |
| `tests/splunk/test_recovery_failures.py` | 8 | Three actual SIGKILL windows; second-invocation refusals; administrator cron and re-enable conflicts; real stalled replay exceeding the default 120-second slot timeout; reduced five-second pause-cap and overall-action deadlines. |
| `tests/splunk/test_recovery_action.py` | 11 | Milestone 1 core live regression suite, including known dispatch failure cleanup, serial replay, rollup verification and detector integration. |
| `tests/splunk/test_recovery_permissions.py` | 2 | Administrator ACL reads; restricted-user configuration/KV writes and saved-search dispatch denied, including the supervisor. |
| `tests/splunk/test_health.py` | 14 | Existing health and missed-slot detector regression suite. |
| `tests/splunk/test_recovery_entrypoint.py` | 4 | Deployed runtime/SDK, single-slot replay, disabled refusal, verified localhost TLS and actual sendalert execution. |
| `tests/splunk/test_upgrade.py` | 1 | Actual package upgrade preserving local state and administrator ACLs for all shipped saved searches, including the supervisor. |

The 59 unit tests comprise 15 planner, 21 scheduler-pipeline, 15 recovery-core
and 8 upgrade tests. The added upgrade unit check covers the supervisor's
shipped disabled state, recovery action off, tracked alerts and inherited
administrator-only saved-search permissions. These unit tests do not count as
live tests. [Machine-readable evidence](2026-10-14-recovery-supervisor.json)
records every final test identity, runner duration and relevant source hashes.

## Failure injection and observed behavior

The crash tests run production `Recovery.run()` in a separate Python process
using real Splunk REST operations. They inject scheduler history and a fixed
wall-clock boundary, as in Milestone 1; production planning remains intact.
A test hook blocks after a durable state write and its audit, then the parent
sends SIGKILL and checks the process exit code is `-9`:

- After `paused`: no slot was dispatched, and the schedule remains paused.
- After slot `running`: one real SID is persisted, no slot is verified, and
  the schedule remains paused.
- After target `restored`, before the final DELETE: the schedule is restored,
  but the target claim persists and the slot is still `verified`.

After each kill, test setup changes only that owner's persisted lease expiry
to the past, avoiding a 30-minute wait without changing `Settings.lease_seconds`.
The installed supervisor SPL reports every expected unresolved claim. A normal
second invocation refuses the paused target during preflight. To additionally
prove the target-existence guard itself, a separate test-only subclass supplies
the genuine persisted pre-pause snapshot/configuration as its preflight result;
it then executes the real `run()` guard. The restored-target case reaches that
guard without substitution. Every case checks that these invocations do not
mutate claims or schedules or dispatch a replay; refusal audit writes are
allowed. Paused targets are never re-enabled to reach the guard.

Deadline tests replace the builder macro before preflight with an isolated
synthetic workload, then use Splunk's real job-control API to pause the real
replay SID after it reaches RUNNING. The captured configuration digest includes
that fixture. Production job polling, REST timeouts and monotonic clocks remain
real. The default slot test actually runs at least 120 seconds, returns
`uncertain` with `invocation deadline reached`, keeps target and slot uncertain,
keeps the schedule paused and dispatches exactly once. Separate tests reduce
only the pause cap or overall action deadline to five seconds. The pause cap
allows uncertain-state cleanup; the overall deadline leaves the earlier durable
`paused`/`running` states because cleanup has no remaining time. Both remain
visible to the supervisor after expiry. Test cleanup cancels the actual jobs
before removing fixture claims and restoring configuration.

These tests qualify deliberately stalled real jobs, not naturally slow
production datasets. They do not wait out the full 18-minute pause cap,
21-minute action deadline or external 25-minute alert-action maxtime. The
reduced-budget cases exercise the internal deadline precedence; external
maxtime termination is not newly qualified.

Administrator-conflict tests edit cron or manually re-enable the target through
a separate REST client after pause. Both return
`Uncertain("conflicting administrator changes")`, dispatch no replay and
preserve the administrator's edit. With a cron conflict, cleanup also refuses
restoration, leaving the persisted target `paused`; with re-enablement, the
target is saved `uncertain`. A nonterminal record need not literally say
`uncertain` to require manual reconciliation.

The incomplete-read test injects `adm_complete=0` after actual live KV reads;
it does not change the server's query limit. The separate 50,001-row regression
exercises real paging beyond the ordinary 50,000-row cap.

## Execution

The lifecycle was held under:

```sh
ADM_LAB=1 python3 tools/lab_lock.py --root . -- bash
```

Inside that lock, the final successful runs were:

```sh
tests/splunk/lab.sh up
tests/splunk/lab.sh install
python3 -m unittest tests.test_scheduler_recovery tests.test_scheduler_pipeline tests.test_recovery_core tests.splunk.test_upgrade.UpgradeUnitTest -v
python3 -m unittest tests.splunk.test_recovery_action tests.splunk.test_health tests.splunk.test_recovery_permissions tests.splunk.test_recovery_entrypoint -v
ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0-upgrade.tar.gz python3 -m unittest tests.splunk.test_upgrade.UpgradeIntegrationTest -v
python3 -m unittest tests.splunk.test_recovery_supervisor tests.splunk.test_recovery_failures -v
tests/splunk/lab.sh purge
```

The package was built with `node tools/package-app.mjs`. The four changed/new
Python test files passed Ruff lint and formatting checks, the package helper
passed Prettier, and the diff passed whitespace checks.

Preliminary runs found test setup issues: disabled saved-search dispatch,
invalid encoding of a permission probe, an overstrict expectation that every
conflict persists the literal state `uncertain`, and a stalled-search fixture
whose generating command placement and subsearch completion did not guarantee
a stalled parent job. These were corrected before the final successful runs.
An initial unit invocation outside the held lock was refused by the lock;
the full unit suite passed when rerun inside it. Review also caught the
unpaged-read risk and a tracking assertion that could accept an old alert;
both have regression coverage now.

SHC, failover, Splunk Cloud approval, automatic takeover and automatic retries
remain outside qualification. The existing standalone claim-gate evidence was
not rerun. No commit was made.
