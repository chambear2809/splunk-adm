# Automated assisted recovery — core milestone

Date: 2026-10-14. Base commit: `4e571bd`; changes remain uncommitted.

**Result:** 32 distinct live tests and 58 unit tests passed. All
live work ran in the disposable standalone Splunk 10.6.0.5 lab under
`tools/lab_lock.py`. The container, image and generated lab secrets were purged.
This qualifies the exercised Milestone 1 core paths only. SHC, failover and
Splunk Cloud approval are not qualified.

## Exact test coverage

| Suite | Live tests | Coverage |
| --- | ---: | --- |
| `tests/splunk/test_recovery_action.py` | 11 | All three builders; chronological overlapping two-slot replay with the first SID done and schedule paused before the second dispatch; empty backlog; empty and nonempty rollup; malformed/unclosed rollup refusal; prior native rollup failure refusal with zero pauses/dispatches; dispatch failure/no retry; recovered and uncertain detector integration; slots created during a pause; durable bounds, SID and restoration audit. |
| `tests/splunk/test_recovery_permissions.py` | 2 | Explicit administrator ACLs and denied restricted-user configuration writes, KV data inserts and saved-search dispatch. |
| `tests/splunk/test_health.py` | 14 | Full health regression suite, including checkpoint, manual SID, unscheduled/disabled, maintenance gap and saved-alert history-range cases. |
| `tests/splunk/test_recovery_entrypoint.py` | 4 | Deployed SDK single-slot recovery; disabled refusal; verified-TLS no-op; actual `sendalert adm_recovery` with owner session. |
| `tests/splunk/test_upgrade.py` | 1 | Actual package upgrade preserves local state and administrator recovery ACLs. Seven additional tests in this module are unit tests. |

The unit total comprises 15 planner, 21 scheduler-pipeline, 15 recovery-core
and 7 upgrade tests. It includes missing/changed summary rejection, inconsistent
budget rejection, prior rollup execution refusal and real SDK URL-encoding
transport coverage. [Machine-readable evidence](2026-10-14-recovery-core.json)
lists every test identity, final runner durations and source-file hashes.

## Execution

The lock was held across one lab lifecycle using:

```sh
ADM_LAB=1 python3 tools/lab_lock.py --root . -- bash
```

Inside that lock, the final successful suites were:

```sh
tests/splunk/lab.sh up
tests/splunk/lab.sh install
ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0-upgrade.tar.gz python3 -m unittest tests.splunk.test_upgrade -v
python3 -m unittest tests.splunk.test_recovery_action tests.splunk.test_recovery_permissions tests.splunk.test_health -v
python3 -m unittest tests.splunk.test_recovery_entrypoint -v
python3 -m unittest tests.test_scheduler_recovery tests.test_scheduler_pipeline tests.test_recovery_core tests.splunk.test_upgrade.UpgradeUnitTest -v
tests/splunk/lab.sh purge
```

The package was built with `node tools/package-app.mjs`. Changed Python files
passed Ruff lint/format checks; the package helper passed Prettier, and the
diff passed whitespace checks. The SDK's pinned archive hash and Apache
license are shipped; packaged Python bytecode is excluded.

## Test scope and resolved findings

Core tests inject scheduler history and selected clock boundaries to create
specific missing slots. Saved-search replay, KV state, raw input and summary
verification use live Splunk. Entrypoint tests additionally use the actual
packaged Python runtime and SDK with a temporary trusted localhost certificate;
credentials stay in memory and are supplied through standard input. The
single-slot entrypoint test uses the real clock and real pause/replay/restore.
These tests do not requalify native scheduler catch-up, which remains a failed
qualification.

Preliminary runs exposed and corrected the history-bound mismatch, inconsistent
budget admission, REST `_time` formatting, SDK double encoding, and failed-native
rollup ambiguity. Test setup fixes covered empty DELETE responses, fixture SPL
and temporary lab file ownership. Final results above supersede those failures.
Independent read-only review accompanied the corrections.

The accepted [claim gate](2026-10-14-recovery-claim-gate.md) is preserved unchanged:
25 trials, one winner/dispatch and zero losing dispatches per trial, standalone
only. It was not rerun during this milestone.

## Review boundary

Everything ships disabled with separate administrator opt-in. Recovery preserves
original windows, serializes each target, refuses expired/uncertain claims and
records pause intent before mutation. Rollup prechecks measure slice stability;
post-replay summary reconciliation is the write verification. A prior failed
native rollup requires manual reconciliation because partial aggregates may
already exist. Restoration is audited and leaves a local `is_scheduled` override.

Supervisor/abandoned-lease detection, process-kill cases, forced-slow deadline
paths and conflicting-admin live tests remain deferred to Milestone 2. No commit
was made. See [RECOVERY.md](../RECOVERY.md) for opt-in and manual fallback.
