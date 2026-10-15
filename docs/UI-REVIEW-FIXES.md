# Atlas UI review fixes and release verification

Phase 9 was completed and committed as `39c0b0e` before creating
`codex/atlas-review-fixes`. The earlier integration results are recorded in
[UI-PHASE-9.md](UI-PHASE-9.md). This report covers the subsequent review fixes
and their final verification. Delivery is tracked in
[PR #3](https://github.com/chambear2809/splunk-adm/pull/3).

## Finding ledger

| Item | Status | Commit | Result |
| --- | --- | --- | --- |
| 1 | Fixed | `87cda49` | Unscoped live Map waits for a scope; only a single available scope is preselected. Native live regression confirms no demo-valued graph search. Demo defaults remain available. |
| 2 | Fixed | `53f075f` | Navigation follows URL writes and browser history changes, retaining the edited scope. |
| 3 | Fixed | `2c5335d` | Copy link and Save view use the loaded snapshot's scope and window; both are disabled without a snapshot. |
| 4 | Fixed | `bf8661a` | Selecting a grouped Service includes every member's incident connections, including VIP and NodePort entry points. |
| 5 | Not reproduced | `abf1d57` | The original macro returned all 50,001 services under both the default 50,000-row KV query limit and a lowered 10,000-row limit on Splunk 10.6.0.5. Production scope code is unchanged; a permanent live regression records this behavior. |
| 6 | Fixed | `14b4592` | Complete catalog snapshots prune expired rows using identity retention, preserve recent rows, and refuse replacement after incomplete/failed reads. Large catalogs show an explicit limit message and support an exact service filter. Metrics identify their last completed hour and are independent of the Find/map time picker. |
| 7 | Fixed | `f3d09ef`, `17a7f92` | Polling pauses while hidden and does not run globally on Help or Setup. Broad event-time bounds are retained for ingestion-freshness semantics; see below. |
| 8 | Fixed | `1b4bd56` | Setup accepts validated parenthesized OR index groups, marks non-pilot sources optional, and detects administrator access from capabilities. Server-side permission checks remain. |
| 9 | Fixed | `8ab4055` | Invalid deep-link parameters are dropped; valid values survive and a dismissible notice explains recovery. |
| 10 | Fixed | `e1d2ff0` | Denied browser-storage access is caught and reported as unavailable. |
| 11 | Fixed | `bf8661a` | MapView uses the exported emphasis-count function. |
| 12 | Fixed | `d935f9d` | Query-string construction no longer depends on `URLSearchParams.size`. |
| 13 | Fixed | `a30611c` | Pods without owner/service metadata use exact identity, without name parsing; Changes explains replacement behavior. |
| 14 | Fixed | `223f2ab`, `bf907ac` | Phase 7/8 reports identify their completed commits. A permanent documentation regression fails against the old text. |
| Bundle guard | Fixed | `89bab37` | Release validation enforces 650 KiB / 665,600 gzip bytes for `pages/atlas.js`, with passing and failing test cases. The spike and Phase 9 documents record the replacement limit. |

`14b4592` also reconciles existing browser tests with the requested live-map,
deep-link and fixed catalog-window behavior. MapPage was not split. No bundle
reduction, dependency upgrade, archive-model change, or unrelated data-layer
change was introduced by this review pass.

## Regression and review evidence

New behavior regressions were exercised against prior behavior and then against
the fixes. The catalog retention regression failed against the original writer
because the expired row remained; the revised live catalog suite passed all
16 tests in 154.786 seconds. Its safeguards cover complete empty snapshots,
incomplete prior-catalog reads, lookup failure, identity caps, expansion loss,
recent-row retention, and viewer permissions. The internal empty marker and
writer contract are documented in [DATA_LAYER.md](DATA_LAYER.md#application-catalog-and-exact-find).

For item 5, `python3 /tmp/atlas-scope-verify.py` restored the original macro and
ran `tests.splunk.test_scope_options`: 3 tests passed in 4.323 seconds. The
permanent regression seeds 50,001 grounded service-binding records using REST
batches of 1,000, lowers `max_rows_per_query` to 10,000, verifies every service,
and restores the setting and deletes only its own namespace. The unchanged
macro also passed the same bulk check at the default 50,000 limit. Earlier
exploratory setup failures are not used as evidence of truncation.

Health source searches already restrict ingestion to the last 24 hours through
`_index_earliest=-24h`. Narrowing event time would hide newly ingested historical
events and distort lag diagnostics. The live test
`test_source_window_uses_ingestion_time_for_old_events` passed, supporting the
retained event-time bounds.

The independent read-only reviewer found two actionable issues during this
pass: warning-only lookup failures could resemble an empty catalog, and a
marker-only catalog could skip configured-scope fallback. Both were fixed,
covered by regressions, and verified by the reviewer. The reviewer reported no
remaining actionable findings. A terminal-newline validation finding was
withdrawn after the existing test and runtime check confirmed rejection.

The catalog, Find and preceding-window demo fixtures were recaptured from live
Splunk queries (`python3 /tmp/atlas-review-captures.py`), not reconstructed by
editing provenance hashes. Their grounded application/graph data stayed the
same apart from refresh timestamps.

## Final verification

All commands ran from the review worktree. The parent lifecycle driver held
`tools.lab_lock.LabLock` from startup through purge; its subprocesses inherited
that ownership and `ADM_LAB=1`. The full suite also received
`ADM_UPGRADE_PACKAGE` pointing to the exact archive below. This provides the
same locked execution as the documented `tools/lab_lock.py --root . -- ...`
wrapper, while keeping ownership across the entire lifecycle.

| Command | Final outcome |
| --- | --- |
| `npm run lint` | Passed |
| `npm test` | 363 tests passed in 37 files |
| `npm run test:browser` | 59 passed |
| `npm run typecheck:browser` | Passed |
| `ruff check tools tests` | Passed |
| `ruff format --check tools tests` | Passed; 66 files |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | 171 passed in 7.790 seconds |
| `python3 -m unittest tests.test_ui_phase_docs -v` | 1 passed; both old reports failed the before-fix subtests |
| `npm run package` | Passed |
| `python3 tools/check_release.py --dist dist` | Passed |
| `tests/splunk/lab.sh up` | Passed in the owned disposable lab |
| `tests/splunk/lab.sh install` | Passed with current source and built assets |
| `ADM_LAB=1 python3 -m unittest tests.splunk.test_catalog -v` | 16 passed in 154.786 seconds |
| `ADM_LAB=1 ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0.tar.gz python3 -m unittest discover -s tests/splunk -v` | 196 passed in 1,407.955 seconds; no skips |
| `tests/splunk/lab.sh purge` | Passed; container, volumes, image and generated secrets removed |
| `/tmp/atlas-phase2-appinspect311/bin/splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz --mode precert --included-tags cloud --output-file dist/appinspect-cloud.json` | Passed: 0 errors, 0 failures, 5 warnings |
| `python3 tools/check_appinspect.py dist/appinspect-cloud.json` | Passed |

The full lab run includes native admin and restricted-viewer browser flows,
Setup write protections, both live upgrades, and the 50,001-service scope
regression. The temporary research symlink was removed, the cooperative lock
was released, and all three pre-existing collector containers were preserved.
Offline tests ran only after that cleanup.

The first full browser iteration exposed five outdated assertions around the
new behavior; those were reconciled before the 59-test passing run. A live
empty-catalog test initially used a temporary lookup filename without `.csv`;
that test setup was corrected before the passing catalog and full-suite runs.

## Artifact and delivery

- Archive: `dist/splunk_adm-0.2.0.tar.gz`, **850,798 bytes**.
- SHA256: `926a3caaa5d13845acd8a7146e4f0e8106ee6550524600d9b7bbd5bf3cf705bb`.
- Shared `atlas.js`: **2,335,815 bytes raw / 587,273 bytes gzip**.
- Enforced gzip limit: **665,600 bytes**.

PR #3 uses frontend, browser, Python and security checks as merge gates.
The PR workflow intentionally skips the trusted self-hosted lab job; the full owned local lab result above supplies this pass's live integration
evidence. No production deployment or release publication was performed.
