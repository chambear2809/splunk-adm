# Application Atlas final engineering qualification

This is the evidence record for the work following accepted main
`64473e54d1fca4311ac592bc34c4a96a022efd48`. Qualification is still in progress.
Splunk Cloud remains unverified because no authorized test stack is available;
the user explicitly deferred that environment until access exists.

## Source, package and ownership

- Isolated branch: `codex/atlas-final-qualification`.
- Exact current candidate: `dist/final-qualification/packages/candidate-08.tar.gz`.
- SHA-256: `946ff4806917bda093659328811b05c348251a9197e3b61244b0902254a9b4b6`.
- Package source: `50e098a602a21ef386172015aa2ed888b936efd4`. Qualification
  revision `d8d4ff0a595174cd141e89818decfe6229e1e3ce` changes only the SHC
  installed-file verifier, its tests and documentation; packaged application
  sources and standalone integration tests are unchanged.
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
across the final runs. Package 08's static assets match packages 05 and 07; profiling
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
next-receipt termination cases. All seven also passed in the clean complete
package-08 suite. See [semantics and acceptance cases](LATE_CATALYST_RECEIPTS.md).

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
verified. Cohosted PDL does not return Mongo replica-set/member fields. The
SHC gate therefore checks the actual cluster/member endpoints, current member
GUID, stable cluster GUID and exact management identities. Namespace identity
excludes the elected captain and ephemeral PDL port. All-member KV readiness
and live cross-member races remain separate execution gates. See [deployment boundary and operator setup](DEPLOYMENT_HEALTH.md).

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
Original rows, macros and schedules were restored and verified. The first complete
installed suite enabled and passed these cases against package 07. All three
also passed in the clean complete package-08 run. Production
pruning defaults remain disabled.

## E — Complete suites and deployment boundaries

| Check                                   | Current recorded outcome                                                                       |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Frontend lint, types and formatting     | Passed                                                                                         |
| Frontend unit tests                     | 45 files / 572 tests passed                                                                    |
| Ordinary browser regression             | 94 passed                                                                                      |
| Python lint and formatting              | Passed                                                                                         |
| Python unit tests                       | 557 passed                                                                                     |
| Distributed tooling tests               | 52 passed; offline only                                                                        |
| Build/package and release validation    | Passed for retained candidate 08                                                               |
| Installed package bytes                 | Package 08: all 85 files byte-exact before the suite; 84 exact afterward, with only documented generated install checksum in app.conf |
| Installed V1 public contract            | Package 08: all eight selectors coherent and pruning closed before and after the complete suite |
| AppInspect 4.3.1 Cloud precertification | 123 success, 117 not applicable, five warnings, one skip; zero failures/errors/future failures |
| Fresh complete installed suite          | Package 08: 393 tests, 390 passed, 3 explicit skips, zero failures/errors; 2,168.188 seconds |
| Actual distributed/SHC                  | Pending fresh execution                                                                        |
| Actual Splunk Cloud                     | Unavailable; explicitly deferred until access exists                                           |

AppInspect warnings remain recorded: Python migration advice, intentional
custom-configuration replication boundary, collection presence, older bundled
SDK and hostname/IP detection in version/fixture text. The endpoint declares
both `python.version=python3` and `python.required=3.13`: the former satisfies
the current checker while Enterprise 10.6 honors the required runtime. Native
execution verified Python 3.13.11. AppInspect is not Cloud deployment evidence.

The SHC topology is three search heads, a separate deployer and a
separate indexing/search peer on the same host, RF3. Its required application
phases cover remote search, shared persistence, scheduling and V1/staged-V2
behavior; these phases have not yet passed. It can establish bounded
synthetic functionality only. It does not establish a supported production
topology with independent machine failure domains, sizing, production TLS,
load-balancer/SSO behavior, multisite, indexer clustering or Cloud. See
[the exact SHC procedure and limits](SHC_FINAL_QUALIFICATION.md).

The first complete run retained byte-exact installed package files throughout,
but used an SSH Docker endpoint. Four networking setup classes correctly refused
that endpoint, causing two additional missing-manifest errors. Downstream
missing-control/vendor fixture failures were consistent with absent initialization;
that attribution remains an inference requiring native rerun confirmation.
Two recovery tests exceeded their
five-second polling-count expectation over SSH; that assertion is unchanged
for the native rerun. A viewer metadata response race was reproduced offline
and fixed. The clean rerun uses the host's local Unix Docker socket, complete
reviewed fixtures, and the exact retained package. Focused successes do not
replace the required complete pass. The fresh native run subsequently passed
all 393 discovered tests except the three explicit environment/opt-in skips:
the standalone cutover rehearsal and the two distributed interface cases.
Those three require their separate actual qualification and are not considered
passed by the complete-suite result.

The clean run used source `d8d4ff0a595174cd141e89818decfe6229e1e3ce`, the
exact candidate-08 archive, Python 3.12.3, Node 22.13.0, and the local Docker
socket. It ran from 18:53:55 to 19:30:04 UTC on 2026-10-18, with no source/test
file changes during execution. The retained log SHA-256 is
`a41af4d41a7254114207076ead63a9614bf946a5bf650571efb41aafeac929a5`.
Evidence is under `dist/final-qualification/native-08/`.

The original post-suite byte-check helper ran as the container's default OS
user and failed to read files after the upgrade test's REST reinstall changed
permissions. A separate read-only check as the Splunk service owner verified
all 85 files: 84 byte-exact, and `default/app.conf` with only the documented
generated `[install] install_source_checksum` added. Every declared setting
remained exact; both hashes and the generated field are retained. The failed
helper result is preserved separately from the passing complete suite and the
successful corrected verification. V2 rehearsal starts with the same archive
reinstalled through the normal lab procedure, followed by fresh owned fixtures.

SHC startup attempts are retained individually. They exposed shared-parent
permissions required by the image bootstrap user, CLI terminal/login behavior,
the supported double-hyphen `--answer-yes` flag, and the native cohosted status
schema. A diagnostic cluster also demonstrated paced PostgreSQL checkpoint and
replica initialization followed by automatic sidecar recovery: all three
members eventually passed strict readiness without a reset or forced restart.
Attempt05 passed bootstrap and subsequent three-member readiness, then failed
the bundle's installed-file verifier: all 85 package files were checked on all
three members, and only Splunk's documented generated
`[install] install_source_checksum` differed. The verifier had allowed the
wrong field name. The narrow correction validates the generated field's
observed shape, records both file hashes, and still rejects changes to declared
settings or unrelated files. Attempt05 remains failed, with cleanup and 24
exported JSON records retained; a fresh corrected lifecycle is required.
Default internal sidecar TLS behavior is not represented as production
transport qualification.

## Independent review and publication

The first independent Astra/max review found four P2 issues: lost source-time
status during graph aggregation, missing next-receipt attachment termination,
inconsistent generic lab-port overrides, and incomplete SHC collection scans
under a hidden server cap. All four were corrected and received focused
validation. The bounded follow-up found no new actionable source defects.
Subsequent independent reviews covered package fingerprints, viewer response
matching, private HEC staging, CLI terminal draining and environment isolation,
the native SHC/PDL gates, and generated installation-checksum verification. The terminal-drain finding was corrected; later
source reviews found no actionable defects. Final review of the complete
final-package execution evidence is pending.

Commit, PR, CI and post-merge identifiers will be recorded after qualification
and the final independent review. No overall Cloud qualification is claimed.
