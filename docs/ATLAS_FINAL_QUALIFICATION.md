# Application Atlas final engineering qualification

This is the evidence record for the work following accepted main
`64473e54d1fca4311ac592bc34c4a96a022efd48`. Qualification is still in progress.
Splunk Cloud remains unverified because no authorized test stack is available;
the user explicitly deferred that environment until access exists.

## Source, package and ownership

- Isolated branch: `codex/atlas-final-qualification`.
- Exact current candidate: `dist/final-qualification/packages/candidate-07.tar.gz`.
- SHA-256: `cb37e69e0eb6670a85d11f176346aac750b08e937acbdcc7855306817ffb3005`.
- Accepted-baseline archive SHA-256:
  `e691df2369712f21fc55442064fda8d52e1c0de00aab8ee8f77780a3f7a9bb41`.
- Source and test hashes, commands, timestamps, outcomes and package bindings
  are retained under `dist/final-qualification/`. Results executed before a
  commit record the accepted HEAD plus the actual diff and relevant file
  hashes; a HEAD alone is not claimed to identify uncommitted code.
- The primary checkout, its user edits, other worktrees and prior qualification
  artifacts remain separate. Copied research material has explicit origin and
  checksum manifests. Four unavailable original Cisco archive links are not
  claimed as newly verified downloads; the copied extracted configuration/data
  bytes are recorded independently.

Actual session metadata verified the requested coordinator and independent
reviewer as `gpt-6-astra` / `max`, and all four implementation workers as
`gpt-6.1-sol` / `high`. No persistent agent configuration was changed. See
`dist/final-qualification/agent-assignments.json` for the session assignments.
The coordinator alone operates the lab, holding the repository lifecycle lock
and an exclusive remote-host lock.

The disposable target is EC2 `i-0b186b390ea7ff8dc`, `us-east-1`, using the
existing approved authentication workflow. Splunk Enterprise is **10.6.0.5**,
from pinned image
`splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`.
Independent readiness, migration and SHC clients use the task's private CA with
hostname verification. The inherited local lab client uses its existing
loopback-only test connection. Secrets and migration journals remain in protected external directories. The host is
ephemeral; cleanup is limited to identified task resources.

## A — Selection performance

The avoidable Catalyst delay was a compositor wait on raster work from the
preceding map frame. Native Chromium traces measured baseline commit waits of
227.6–256.4 ms and candidate waits of 125.2–180.0 ms. Retaining the transformed
map content layer with `will-change: transform` permits raster overlap; this
does not claim that raster CPU work disappeared. The product change is four
CSS lines. Event handlers, selection evidence and workload limits are retained.

Matched near-limit Catalyst results use 500 nodes / 2,000 edges, 20 repetitions
per cache condition, and capture input → intended DOM → stable rendered frames.
Automation completion is recorded separately.

| Selection | Accepted baseline median / p95 | Candidate median / p95 |
| --------- | ------------------------------ | ---------------------- |
| Cold      | 367.6 / 384.8 ms               | 275.0 / 301.0 ms       |
| Warm      | 367.9 / 384.7 ms               | 285.1 / 300.1 ms       |

Warm median improved 22.5%, and warm observed p95 improved 22.0%. Both complete
matrices passed **14 cases / 140 samples**. Matched native diagnostics contain
six measured samples per build plus separately discarded warmup traces.
The ordinary browser suite passed **94 tests**, and readiness tests passed
**nine**. Source, imported fixture, served-asset and harness fingerprints agree
across the final runs. Package 07's static assets match package 05; profiling
bundle bytes are not misrepresented as package bytes.

This is not a universal speedup: dense Meraki selection/filtering and Catalyst
filtering had slower medians, and several individual/p95 samples exceeded
investigation thresholds. These thresholds are not production SLOs. Earlier
incomplete or provenance-invalid runs remain retained but excluded from the
acceptance comparison. See [full distributions and limitations](benchmarks/atlas-final-selection-results.md),
[methodology](BROWSER_PERFORMANCE.md), and the
[139-artifact index](benchmarks/atlas-final-browser-evidence-index.json).

## B — Late Catalyst receipts

The accepted package reproduced the failure: the raw observation and history
existed, but topology omitted an otherwise eligible attachment because its
older source timestamp was outside the selected event-time window.

Catalyst eligibility now begins at the earliest retained indexed receipt and
ends at the earlier of its one-hour bound or the next distinct receipt for the
same authority and native identity. Disconnects, moves, incomplete identities
and conflicting observations terminate prior attachments conservatively.
Source time stays separate; collection time is never fabricated. Receipts at
or after the selected interval's exclusive end cannot leak into that interval.
Source observations beyond the qualified history horizon, malformed/ahead
clocks, caps and missing coverage remain explicit uncertainty.

History is read once through a bounded complete-history strategy (at most
20 pages of 10,000 rows). Receipt/source age and coverage survive graph
aggregation and remain available in Inspector, Find, comparison and exports.
Authority, routing scope and cluster dimensions remain part of identity and
replay handling. Meraki retains its event-time/900-second behavior.

Seven focused native regressions passed against the unchanged packaged SPL,
including the complete raw → history → topology path and all five tested
next-receipt termination cases. The final complete installed-suite result is
recorded below when available. See [semantics and acceptance cases](LATE_CATALYST_RECEIPTS.md).

## C — Atomic administrator settings

The accepted package reproduced silent lost updates: two same-revision writes
both succeeded and the latter replaced the former. The replacement endpoint
uses immutable KV documents and atomic unique-key insertion to arbitrate one
successor per expected revision. Initial creation has one root anchored to the
legacy record fingerprint; request IDs and payload fingerprints support
idempotent retries and recovery after response loss. Product writes do not
overwrite or delete existing ledger entries. The ledger is bounded at 1,024
entries, and incomplete/capped reads fail closed.

The server requires the authenticated caller's administrator capability and
collection authorization. Reader access and existing schema-1 settings remain
compatible. A conflict preserves the administrator's unsaved draft and offers
a verified refresh. Defaults keep writes disabled until an operator qualifies
the supported persistence namespace; Cloud and unqualified deployments cannot
silently fall back to best-effort updates.

Native standalone races, initial creation, stale revision, lost-response retry
and viewer refusal passed. A separate real `max_rows_per_query=2` test retained
three ledger rows, observed the native two-row cap, and required the endpoint
to return 503/unavailable. The original limit and settings were restored and
verified. SHC-specific native status and cross-member races remain a separate
execution gate. See [deployment boundary and operator setup](DEPLOYMENT_HEALTH.md).

## D — V2 cutover and pruning

The [operator procedure](V2_FINAL_QUALIFICATION.md) and migration harness cover
controlled interruption after a verified durable mutation, resume, repeated
execution, same-controller concurrent-operation refusal, rollback and a fresh
restoration journal. The target lock is scoped to the same OS user/controller
and authenticated server GUID; it is not distributed fencing. The helper
continues to refuse SHC and Cloud cutover.

The actual final-package cutover/rollback/restoration and active-V2 browser run
are pending. No static or skipped test is presented as this deliverable.

Three native pruning cases have passed: disabled gate causes no deletion;
enabled fixture pruning respects retention/current/replay boundaries and
idempotence; malformed/incomplete evidence and unauthorized writes fail closed.
Original rows, macros and schedules were restored and verified. The complete
installed suite also enables these cases against package 07. Production
pruning defaults remain disabled.

## E — Complete suites and deployment boundaries

| Check                                   | Current recorded outcome                                                                       |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Frontend lint, types and formatting     | Passed                                                                                         |
| Frontend unit tests                     | 45 files / 572 tests passed                                                                    |
| Ordinary browser regression             | 94 passed                                                                                      |
| Python lint and formatting              | Passed                                                                                         |
| Python unit tests                       | 531 passed                                                                                     |
| Distributed tooling tests               | 34 passed; offline only                                                                        |
| Build/package and release validation    | Passed for retained candidate 07                                                               |
| Installed package bytes                 | All 85 archive files matched                                                                   |
| Installed V1 public contract            | All eight selectors coherent; pruning closed                                                   |
| AppInspect 4.3.1 Cloud precertification | 123 success, 117 not applicable, five warnings, one skip; zero failures/errors/future failures |
| Fresh complete installed suite          | First run has networking setup errors; clean complete rerun required                           |
| Actual distributed/SHC                  | Pending fresh execution                                                                        |
| Actual Splunk Cloud                     | Unavailable; explicitly deferred until access exists                                           |

AppInspect warnings remain recorded: Python migration advice, intentional
custom-configuration replication boundary, collection presence, older bundled
SDK and hostname/IP detection in version/fixture text. The endpoint declares
both `python.version=python3` and `python.required=3.13`: the former satisfies
the current checker while Enterprise 10.6 honors the required runtime. Native
execution verified Python 3.13.11. AppInspect is not Cloud deployment evidence.

The planned SHC topology is three search heads, a separate deployer and a
separate indexing/search peer on the same host, RF3, with actual remote-search,
shared-persistence, scheduling and V1/staged-V2 checks. It can establish bounded
synthetic functionality only. It does not establish a supported production
topology with independent machine failure domains, sizing, production TLS,
load-balancer/SSO behavior, multisite, indexer clustering or Cloud. See
[the exact SHC procedure and limits](SHC_FINAL_QUALIFICATION.md).

## Independent review and publication

The first independent Astra/max review found four P2 issues: lost source-time
status during graph aggregation, missing next-receipt attachment termination,
inconsistent generic lab-port overrides, and incomplete SHC collection scans
under a hidden server cap. All four were corrected and received focused
validation. The bounded follow-up found no new actionable source defects.
Final review of the complete final-package execution evidence is pending.

Commit, PR, CI and post-merge identifiers will be recorded after qualification
and the final independent review. No overall Cloud qualification is claimed.
