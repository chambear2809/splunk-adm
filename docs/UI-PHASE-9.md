# Phase 9 — Final integration and release readiness

Phase 8 is committed as `bfda974` (following Phase 7, `74d8a4a`). This
report supersedes the historical commit-status statement in the Phase 8 report.
Phase 9 was completed on `codex/atlas-phase-9` before the separately requested
review-fix branch. No release or production deployment was performed.
The subsequent review findings are tracked as follow-up work; this pass does
not claim that those findings have already been resolved.

## Scope and corrections

This pass qualifies the integrated Applications, Map, Data health, Setup and
Help experience, including comparisons, exports and per-user saved views.
The standard Splunk dashboard panel boundary remains in place.

- Applications now attempts its configured-scope fallback once when the catalog
  is empty or fails. A failed fallback previously caused a duplicate request
  after an empty catalog. Two browser regressions cover both failure paths.
- Native Splunk configuration validation found unsupported `alert_type` keys
  on the scheduler missed-slot and abandoned-lease alerts. Removed those keys;
  the supported `counttype`, `relation` and `quantity` conditions remain intact.
  Both alerts still ship disabled, with administrator-only access.
- The CI lab job now installs frontend/browser prerequisites, builds and checks
  the single release archive, and supplies it to the live upgrade test. It
  refuses an existing lab container before registering its cleanup trap.
  Three offline contract tests cover this wiring and the AppInspect gate.
- Pilot, upgrade and historical spike documentation now describe current
  navigation, packaging, lab ownership and Cloud qualification accurately.

## Verification

Validation is against the local Splunk Enterprise 10.6.0.5 disposable lab and
TA-shaped synthetic fixtures. GitHub Actions itself has not been run for this
uncommitted patch.

| Check | Result |
| --- | --- |
| `npm run lint` | Passed |
| `npm test` | 349 tests passed in 37 files |
| `npm run test:browser` | 48 passed |
| `npm run typecheck:browser` | Passed |
| `npm run package` | Passed |
| `python3 tools/check_release.py --dist dist` | Passed |
| `ruff check tools tests` | Passed |
| `ruff format --check tools tests` | Passed, 65 files |
| CI lifecycle shell syntax | Passed |
| Native install and `tests/splunk/lab.sh btool` | Passed after invalid alert keys were removed |
| `ADM_LAB=1 ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0.tar.gz python3 -m unittest discover -s tests/splunk -v` under the parent-owned LabLock | 191 passed in 1,443.466 seconds; no skips |
| `python3 -m unittest discover -s tests -p 'test_*.py'` after lab cleanup | 168 passed |
| Python 3.11 AppInspect Cloud precertification and JSON report gate | Passed: 0 failures, 0 errors, 5 warnings |

The AppInspect warnings concern Python script existence, custom-conf replication,
collections configuration, Python SDK version and synthetic/documentation
hostnames/IPs. The report gate treats any error or failure as blocking.

The configured independent reviewer inspected the complete patch, CI contract
tests and surrounding code. It reported no actionable correctness or security
findings; its missing-report finding is resolved by this document. It also
passed 11 focused Python tests, browser typecheck and three catalog fallback
browser tests. Earlier review attempts encountered capacity limits; the final
review completed successfully.

Final archive: `dist/splunk_adm-0.2.0.tar.gz`, 847,672 bytes.
SHA256: `ae4377fa909e084e2c478ac3933223068aac7a369dce4f300cf550ad963c048c`.
Shared `atlas.js`: 2,330,177 bytes raw / 585,033 bytes gzip.

## Qualification limits and rollout

Local validation and AppInspect are not formal Splunk Cloud approval. Cloud
runtime testing and actual Cloud vetting remain required, as does a customer
pilot with real data. Search-head cluster behavior is not qualified by this
standalone lab. The shared bundle remains above the original size budget.
The separate mixed/scheduled pipeline rehearsals are outside this UI integration
pass. No dependency upgrades or operator/cloud infrastructure changes were made.

Use the [pilot procedure](PILOT.md) for environment preparation and the
[upgrade procedure](UPGRADES.md) for backup, local override review, scope
migration and post-install verification. Follow [recovery guidance](RECOVERY.md)
for data recovery; a frontend rollback does not reverse KV or summary writes.
Saved searches remain disabled by default and require explicit operator setup.

The cooperative lock protected the entire owned lab lifecycle. Native admin
and restricted-viewer browser flows and both live upgrade tests passed. The
container, volumes, image and generated secrets were purged successfully; the
temporary research symlink and ephemeral test identities were removed. Foreign
containers were preserved. No production system was used.
