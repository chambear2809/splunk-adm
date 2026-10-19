# Application Atlas final engineering qualification

This is the evidence record for the work following accepted main
`64473e54d1fca4311ac592bc34c4a96a022efd48`. Engineering and the available
standalone/SHC runtime qualification are complete.
Splunk Cloud remains unverified because no authorized test stack is available;
the user explicitly deferred that environment until access exists.

## Source, package and ownership

- Isolated branch: `codex/atlas-final-qualification`.
- Exact current candidate: `dist/final-qualification/packages/candidate-09.tar.gz`.
- SHA-256: `024d11c83ae9cb21a19259b57038d0e4a68414d1b2d3dde82cad527d789a0097`.
- Package source: `6ebbf0dae3bd9ff0a2d982fe9f3b561687764eca`. This candidate
  fixes the final-review settings-read race described below. Relative to
  candidate 08, only `appserver/static/pages/atlas.js` and the generated
  `default/app.conf` build value changed. All other 83 package files remain
  byte-exact, including CSS, SPL, backend code and installation defaults.
- Retained candidate 08 SHA-256:
  `946ff4806917bda093659328811b05c348251a9197e3b61244b0902254a9b4b6`;
  its package source is `50e098a602a21ef386172015aa2ed888b936efd4`.
  Subsequent SHC verifier/convergence and opt-in terminal-success corrections
  are separately identified by each run's source revision and test hashes.
  Candidate-08 execution results do not become candidate-09 qualification.
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

Historical session metadata verified the original coordinator and independent
reviewer as `gpt-6-astra` / `max`, and all four implementation workers as
`gpt-6.1-sol` / `high`. No persistent agent configuration was changed. See
`dist/final-qualification/agent-assignments.json` for the session assignments.
On resumption, the user explicitly selected `gpt-6.1-sol` / `high` for the
coordinator; both resumed workers use the same model/effort. The separate final
reviewer is verified as `gpt-6-astra` / `max`; independent review and exact-head
CI are required publication gates. Resumed assignments are recorded separately from the
historical record in `dist/final-qualification/resumed-agent-assignments-02.json`
and `dist/final-qualification/resumed-reviewer-assignment-02.json`.
The coordinator alone operates the lab, holding the repository lifecycle lock
and an exclusive remote-host lock.

The historical disposable target was EC2 `i-0b186b390ea7ff8dc`, `us-east-1`.
It was terminated externally during Attempt12; no live lab remains there.
Read-only inventory and SSH checks found no ready host of the required size;
the reachable alternatives run existing demo workloads. After declining reuse
of `smartagentctl-base`, the user authorized a new disposable host. Attempt13
uses EC2 `i-029223a47cbb06aee` (`us-east-1`, `m6i.2xlarge`, encrypted 100-GiB
root disk), with SSH restricted to the controller address. Its fresh locked
lifecycle passed platform preparation and both original distributed cases,
then failed the exact base-classification oracle described below. Host creation
and the passing prefix do not establish SHC application acceptance.
Attempt14 subsequently passed unassisted bootstrap, exact package distribution,
963-event ingestion, the independent ACI graph and topology oracles, and
all-member V1 parity. Its staged V2 graph passed, but the qualifier rejected
a topology warning set. Investigation identified an oracle imported from a
differently mapped standalone fixture: the unclustered APIC fixture correctly
filters adjacency rows before the unsupported-row diagnostic. This attempt
remains failed; its original records are preserved, and fresh qualification
after the reviewed oracle correction ran as Attempt15 from
`7659d84339b9ea3901c00fba9eec5c9287e8d876` (source27). Independent
review73 verified the correction, 118 offline cases and actual source bindings;
review74 verified the failed Attempt14 exports and exact cleanup. Attempt15
passed V1/V2/member/viewer parity and actual scheduling, then failed settings
preparation before bundle application or settings writes. Diagnosis and
independent review identified the harness's runtime `docker cp -a` ownership
override: the image's configured Ansible UID999 replaced the intended Splunk
UID41812, making the login-state parent unwritable. The reviewed fix at
`5391d93d7fe4ca63aab63080fc833979d09173bb` removes that override; 122 offline
distributed checks passed. Failed Attempt15 is preserved, and corrected source28
is pinned for Attempt16. Its first bootstrap and all gates through settings
passed, including both actual cross-member `[200,409]` races, third-member
idempotent retries, stale 409 and viewer 403. Native ownership/authentication
evidence closed the copy defect. Its next refusal gate failed before API calls
because the host import path omitted the exact packaged SDK. After independent
review, the same controller installed only those 27 pinned SDK files as a host
prerequisite, then passed refusal and reapplication. Both verified exports retain
the original failure and exact cleanup; the temporary SDK copy was removed.
The permanent import/origin correction at
`5b305648aa465ebdaec74ff0074673fbf26d1729` passed 125 offline tests and a
separate actual native GET-only check. Full execution details and the explicit
intervention are recorded in `SHC_FINAL_QUALIFICATION.md`.
Authentication retains the approved `duo-sso` workflow. The qualified standalone
Splunk Enterprise version was **10.6.0.5**,
from pinned image
`splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`.
Independent readiness, migration and SHC clients use the task's private CA with
hostname verification. The inherited local lab client uses its existing
loopback-only test connection. Secrets and working migration journals remain
in protected external directories; credential-scanned journal exports are
retained with the ignored local evidence. The old host's disposable-data
authorization does not apply to another machine. Any reused host's existing
services and data require explicit preservation and scoped availability;
cleanup remains limited to identified task resources.

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
| Cold      | 352.2 / 370.0 ms               | 274.4 / 301.0 ms       |
| Warm      | 366.85 / 382.8 ms              | 276.35 / 286.9 ms      |

Warm median improved 24.7%, and warm observed p95 improved 25.1%. Both complete
matrices passed **14 cases / 140 samples**. Matched native diagnostics contain
six measured samples per build plus separately discarded warmup traces.
The candidate-09 source's CI browser suite passed **94 tests**; the separate
readiness suite previously passed **nine**. Source, imported fixture,
served-asset and harness fingerprints agree across the final09 runs. The
standalone profiling bundle is byte-identical to the earlier candidate because
the deployment client is outside its import graph. Package 09's JavaScript
changed, and these performance runs do not validate that client's race repair.
Earlier native traces support attribution of the unchanged CSS fix. A brief
19-test Python run (0.048 seconds) and Ruff overlapped the final candidate
matrix before pausing; this timing limitation is retained without attributing
or excluding individual samples.

This is not a universal speedup: dense Meraki selection/filtering and Catalyst
filtering had slower medians, and several individual/p95 samples exceeded
investigation thresholds. These thresholds are not production SLOs. Earlier
incomplete or provenance-invalid runs remain retained but excluded from the
acceptance comparison. See [full distributions and limitations](benchmarks/atlas-final-selection-results.md),
[methodology](BROWSER_PERFORMANCE.md), and the
[172-artifact index](benchmarks/atlas-final-browser-evidence-index.json).

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
package-09 suite. See [semantics and acceptance cases](LATE_CATALYST_RECEIPTS.md).

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

Final integrated review reproduced a browser-side stale-read race: an older
settings read could wait for source-index macros, be overtaken by a newer read
or verified save, then publish the old revision. Candidate 09 checks the
revision watermark and namespace again after every awaited source read and
immediately before publishing configured settings. Two deterministic delayed
read/save regressions pass; the independent follow-up closed the finding.

## D — V2 cutover and pruning

The [operator procedure](V2_FINAL_QUALIFICATION.md) and migration harness cover
controlled interruption after a verified durable mutation, resume, repeated
execution, same-controller concurrent-operation refusal, rollback and a fresh
restoration journal. The target lock is scoped to the same OS user/controller
and authenticated server GUID; it is not distributed fencing. The helper
continues to refuse SHC and Cloud cutover.

The final candidate-09 disabled-origin rehearsal passed with source
`c314cc89f7ea6e14f317371fd5c2d19e5b74cc6b`: two tests in 380.464 seconds,
23:10:00–23:16:20 UTC on 2026-10-18. It verified a controlled interruption,
resumed activation of all eight public selectors, actual scheduled
summary/history cycles and rollback to the original disabled state. Repeated
terminal execution passed in 0.275 seconds without replaying the migration.

The enabled-origin rehearsal passed separately on the same source and exact
archive: two tests in 1,901.969 seconds, 23:20:58–23:52:40 UTC. It activated V2,
recovered the deliberately aged V1 receipt gap, rolled back, and restored V2
from a fresh journal. Recovery verified one exact expected rollup; rollback
completed at 23:40:34. The harness automatically captured the actual 23:45 V1
scheduler checkpoint, later than the recovery and rollback boundary, before
restoring V2. Actual V2 summary/history schedules and all eight public selectors
passed. Repeated terminal execution passed in 0.980 seconds. The final browser
qualification is recorded separately below.

An earlier candidate-08 attempt correctly refused activation because the first required
history schedule had no successful dispatch. Scheduler evidence recorded
"Could not get next runtime" and a later successful cycle; the cause of that
miss is not established. Supported rollback restored the exact original
configuration before the fresh passing attempt. The guard was not weakened.
A competing real CLI operation was refused while the first operation held its
lock; it neither created a competing journal nor changed live configuration.

Independent review identified a separate test-harness defect: a failed and
rolled-back journal could retain staging eligibility and be accepted as a
completed rehearsal. Revision `d4b781e574b7747191b71294e161c41cb11dff36`
requires durable completed activation, the exact verified mutation plan,
scheduled-cycle bounds and all public-selector proofs. A live negative check
rejected the retained failed journal without changing it or the live
configuration; the genuine completed journal passed the same pure guard.

The candidate-08 enabled-origin rehearsal also passed, after preserved attempts
with an expired one-hour session and a correctly refused restoration audit
containing the preceding manual recovery write. A fresh approved session and a
separately proven later actual V1 checkpoint allowed the unchanged product
guards to complete. The automatic checkpoint behavior described above replaces
that manual qualification step and has pure regressions and independent review.
The candidate-08 active-V2 browser check failed its selected-client conversation-edge
assertion. Investigation identified an incorrect qualifier assumption: the
export contains the MAC node's traffic observations and a separate scoped IP
conversation with its own Hubble handoff. The qualifier must check both paths
without inventing MAC/IP continuity or substituting aggregate service backends.
The correction verifies original tuple payloads, time-qualified Service backend
socket mappings, exact CSV/Inspector attribution and the two distinct evidence
paths in comparisons. Its 44 targeted cases and independent review pass;
the first candidate-09 native browser attempt then exposed a separate qualifier
error: raw numeric identifiers and string flags were compared directly with the
frontend's canonical strings/booleans and omitted empty optional fields.
That failed attempt retained unchanged configuration and zero configuration
writes. Its four-file evidence export is
`dist/final-qualification/native-09-browser-failure-01/`; archive SHA-256
`5675616c5531e4874bd7bef65f4eb7d690d15e96bb8861f4536e85ae27086984`.
The normalization correction passed 12 targeted tests and independent review.
The next native attempt passed the data comparison, then failed because the
persistent Inspector intercepted a pointer click on the MAC card. Its four-file
export is `dist/final-qualification/native-09-browser-failure-02/`, archive
SHA-256 `30eb2869d7a9caac76dee2a82ffb3dc622ba0c029c0ad87ad01b344165573267`.
The reviewed driver now uses each exact map card's supported keyboard handler,
with focus, selected-state and prior-card deselection assertions, and verifies
that the export popover has closed. It preserves all evidence checks. This
exercises keyboard selection, not pointer access beneath the Inspector.
The third attempt passed the ACI/Catalyst scenario, then rejected correctly
quoted Meraki CSV authority text with an invalid raw-substring assertion.
Parsed CSV authority columns now must match the exact full JSON record on the
same row; wrong/blank authority and extra opposite-kind attribution fail.
Independent review reproduced and closed that additional assertion gap. The
11-file failed export is `native-09-browser-failure-03/`, archive SHA-256
`3c92dd722103470ff6e4ffcfe46ced504f9fb28c06d95413a6b57a22b9c73ae2`.
The fourth attempt passed both complete networking scenarios, then failed a
Health display-name assertion: the product intentionally omits the `ADM - `
prefix from scheduled-search names. Its 15-file failed export is
`native-09-browser-failure-04/`, archive SHA-256
`dc6e669aa850d6e5e0805b6b1e3e6ca9566bc98cb841a5561d3fdcbf97169fee`.
All four attempts retained unchanged configuration, zero configuration writes
and zero demo requests. The corrected Health assertion selects the exact scheduler table, matches each
required canonical job to its displayed name, and retains status/run/count
evidence. It rejects a required job classified as not required, while allowing
extra inactive diagnostics and unknown/stale run evidence. Fifteen focused
cases, the 584-test pure suite and independent follow-up review pass.
The complete native browser05 run passed at source
`d7d0c61f818018ef9cbf8ee6ad17ca9fd246aa69`, 00:26:59–00:28:16 UTC on
2026-10-19, with no source changes. Both ACI/Catalyst and Meraki/NX-OS scenarios
passed graph, Inspector, path, Find, reload, comparison and exact export checks.
Setup observed all eight active V2 selectors; Health used the actual V2 source,
quality and scheduler dependencies. Configuration remained unchanged, with zero
configuration writes and zero demo requests. Health retained overdue fixture
receipt warnings and four disabled prerequisite builders instead of claiming
uniform health. The post-browser check verified all 85 installed files
byte-exact. The combined migration/browser export contains 474 hash/size-verified files:
`dist/final-qualification/native-09-migration-complete-02/`, archive SHA-256
`58a3167b53ccdd32ffec541f10ef4deb3d565dd8c9c13ba0d1eb5a4bbfd6ccb2`.
Credential scanning found zero matches. All five source snapshots and four
source transitions are recorded; interpreter hashes are checked in memory
without exporting binaries or session values. Independent runtime review verified all 474 files, 2,010 Git-bound source
fingerprints, exact browser attribution and all three 85-file package proofs,
with no actionable findings. The owned native container and volumes were
removed at 00:41:17 UTC on 2026-10-19 after local evidence verification; the
lifecycle lock was then released. No unrelated containers were removed.
Failed attempts remain failed evidence.
Evidence already
exported under `dist/final-qualification/native-08-migration/` contains 53
hash-verified files for the failed first-history attempt and 107 for the
passing disabled-origin attempt. Failed attempts remain failed evidence.
These older exports remain candidate-08 evidence; the candidate-09 rehearsals
above have their own source, command, timestamp and package bindings.

Three native pruning cases have passed: disabled gate causes no deletion;
enabled fixture pruning respects retention/current/replay boundaries and
idempotence; malformed/incomplete evidence and unauthorized writes fail closed.
Original rows, macros and schedules were restored and verified. The first complete
installed suite enabled and passed these cases against package 07. All three
also passed in the clean complete package-09 run. Production
pruning defaults remain disabled.

## E — Complete suites and deployment boundaries

| Check                                   | Current recorded outcome                                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend lint, types and formatting     | Passed                                                                                                                                |
| Frontend unit tests                     | 45 files / 574 tests passed on candidate-09 source                                                                                    |
| Ordinary browser regression             | 94 passed in CI at 79c18ce, with candidate-09 product inputs unchanged                                                                |
| Python lint and formatting              | Passed                                                                                                                                |
| Python unit tests                       | 584 passed after restoration-checkpoint, normalization, CSV authority and Health row regressions                                      |
| Distributed tooling tests               | 125 passed; offline only                                                                                                              |
| Build/package and release validation    | Passed for retained candidate 09                                                                                                      |
| Installed package bytes                 | Package 09: all 85 files byte-exact before the suite; 84 exact afterward, with only documented generated install checksum in app.conf |
| Installed V1 public contract            | Package 09: all eight selectors coherent and pruning closed before and after the complete suite                                       |
| AppInspect 4.3.1 Cloud precertification | Candidate 09: 123 success, 117 not applicable, five warnings, one skip; zero failures/errors/future failures                          |
| Fresh complete installed suite          | Package 09: 393 tests, 390 passed, 3 explicit skips, zero failures/errors; 2,173.773 seconds                                          |
| Actual distributed/SHC                  | Passed Attempt16; same-host RF3 synthetic boundary, with recorded SDK prerequisite repair                                             |
| Actual Splunk Cloud                     | Unavailable; explicitly deferred until access exists                                                                                  |

AppInspect warnings remain recorded: Python migration advice, intentional
custom-configuration replication boundary, collection presence, older bundled
SDK and hostname/IP detection in version/fixture text. The endpoint declares
both `python.version=python3` and `python.required=3.13`: the former satisfies
the current checker while Enterprise 10.6 honors the required runtime. Native
execution verified Python 3.13.11. AppInspect is not Cloud deployment evidence.

The SHC topology is three search heads, a separate deployer and a
separate indexing/search peer on the same host, RF3. Its required application
phases cover remote search, shared persistence, scheduling and V1/staged-V2
behavior. Attempt15 passed those prefix gates before its settings-overlay
preparation failed. Attempt16 then completed the full sequence, including
concurrent administrator settings, refusal and reapplication, followed by
verified exports and cleanup. The exercised layout can establish bounded synthetic
functionality only. It does not establish a supported production
topology with independent machine failure domains, sizing, production TLS,
load-balancer/SSO behavior, multisite, indexer clustering or Cloud. See
[the exact SHC procedure and limits](SHC_FINAL_QUALIFICATION.md).

The first complete run retained byte-exact installed package files throughout,
but used an SSH Docker endpoint. Four networking setup classes correctly refused
that endpoint, causing two additional missing-manifest errors. Downstream
missing-control/vendor fixture failures were consistent with absent initialization;
those failures were absent from the subsequent complete native run. The
attribution to missing initialization remains an inference from those records.
Two recovery tests exceeded their
five-second polling-count expectation over SSH; that assertion is unchanged
for the native rerun. A viewer metadata response race was reproduced offline
and fixed. The clean rerun uses the host's local Unix Docker socket, complete
reviewed fixtures, and the exact retained package. Focused successes do not
replace the required complete pass. The fresh native run subsequently passed
all 393 discovered tests except the three explicit environment/opt-in skips:
the standalone cutover rehearsal and the two distributed interface cases.
Those three require their separate actual qualification and are not considered
passed by the complete-suite result. Disabled- and enabled-origin cutover
scenarios subsequently passed separately on candidate 09, as did the complete
active-V2 browser check. Both original SHC cases and the full application
sequence subsequently passed in Attempt16, within its recorded boundary.

The final-package clean run used source
`c314cc89f7ea6e14f317371fd5c2d19e5b74cc6b`, the exact candidate-09 archive,
Python 3.12.3, Node 22.13.0, and the local Docker socket. It ran from
22:17:58 to 22:54:12 UTC on 2026-10-18, with no source/test file changes during
execution. The retained log SHA-256 is
`05c811139bfd44d458dfca0bf46276333b9ba46b4ad8f076e2d3b2ae62230a86`.
All 41 exported files were hash/size verified locally before fixture reset;
the evidence archive SHA-256 is
`04b239f7cbb548a69973def2bed710223abfb8bc5dee5d0821148a28e37c4f1e`.
Evidence is under `dist/final-qualification/native-09-complete-suite/`.
The subsequent `f3b42485e38119f93e6363bfdeb28a0e99973788` and
`7fc04abbda74b2840174fe4a305220dae7237873` and
`56947e7466851ec2b6584eb2060466551a5314f2` change only SHC
tooling, its offline tests and documentation. Later revisions
`ae3fd812c9f17c90c672237cb5fca0591071c5f5` and
`837095f270fb36c205aff39ffdb3f567a9465983` and
`078008c844dbaa73d09692d3b9e6929a402c3afb` and
`d7d0c61f818018ef9cbf8ee6ad17ca9fd246aa69` change only the separate post-cutover
browser qualifier and its pure tests. Package inputs, migration code and the
complete installed suite's separate browser paths remain identical. The separate
post-cutover browser checks were rerun in full at `d7d0c61f`. Exact source
comparisons and old/new file hashes are recorded in
`candidate-09-source-binding-f3b4248.json` and
`native-09-browser-source-binding{,-02,-03,-04}.json`. The earlier package-08
run remains separately retained under `dist/final-qualification/native-08/`.

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
Attempt09 passed all-member readiness, exact bundle verification, both native
interface cases and collection setup, then failed Service binding dispatch with
HTTP 400/disabled. The saved-search GETs used for the readiness gate were
captain-proxied, so they did not prove each member's local configuration. The
`7fc04abb` qualifier verifies each member through `configs/conf-savedsearches`,
including its exact local HTTPS identity, application/owner and both flags.
Local configuration agreement is not an atomic
promise of dispatch readiness; native dispatch errors still fail qualification.
The failed attempt remains explicitly failed/incomplete, with no ambiguous
builder retry. Its 45-file final failure export includes verified removal of
all five owned containers and the network.

Attempt10 passed the same prefix, and the corrected local configuration gate
allowed Identity and Service binding to finish through different members.
Interface inventory then finished with a native warning because the ACI-only
batch contained no NX-OS inventory events. The base phase failed at
02:22:23 UTC on 2026-10-19. The final 57-file failure export preserves its
50 original records; all files and cleanup of the exact five containers/network
passed independent review. Export SHA-256:
`626217006eb730335acdb09902dffeb75312d2656a6b9f9f8418dd6700c4473e`.
During earlier bundle application the PDL sidecar recovered automatically;
an ordinary restart preflight refused before mutation because KV was already
ready. No manual restart occurred. The next harness revision adds the existing
105-event NX-OS fixture in a disjoint event-time window, requires the complete
963-event classification and exactly two independently specified interface
records on every member, and fails terminal warning jobs promptly without
redispatch. That correction passed all 99 offline cases. Attempt11 used
`56947e7466851ec2b6584eb2060466551a5314f2` with 144 verified source inputs,
but failed its strict 1,200-second all-member KV readiness gate at
02:53:42 UTC on 2026-10-19. One ordinary Splunk restart of sh1 returned exit 0
at 02:52:20; PDL remained unready at the deadline. No application phases ran.
Its 31-file final failure archive preserves all 24 original records and exact
five-container/network cleanup at 03:07:31 UTC. Independent review63 verified
both exports. Final archive SHA-256:
`2c9f7f553544d3beed9b60fe65ce1ba21a25455a0808c540306079f32c1f6cfb`.

The subsequent qualifier journals captain bootstrap before dispatch and records
an acknowledgment only after a successful CLI response. An explicit retry can
then repeat only the unchanged all-member readiness check, after validating the
durable acknowledgment, source and owned resource identities. Unknown CLI
outcomes refuse redispatch. All 106 offline cases and independent review61 pass. Attempt12 used
immutable source `79c18ce8f3b63aee657ab12a6a3a7705504d8086`, but its EC2
host was terminated from the AWS console at `2026-10-19T03:13:15Z`. The
bootstrap CLI acknowledgment at 03:12:54 does not establish full member readiness.
The controller was lost before any application phase. This interrupted attempt
cannot use the same-controller retry contract; a fresh lifecycle is required.
Local owner responses, runtime/acknowledgment records, source/package bindings
and the EC2/CloudTrail event remain retained. The original remote evidence
snapshot was not exported before termination. The authorized new host's fresh
Attempt13 passed unassisted bootstrap (864.031 seconds), bundle distribution
(425.726 seconds), peers, both original interface cases (zero skips) and all
15 collection checks. It then failed exact base classification: all 963 events
were present, but the reviewed CiscoSecurityCloud 3.7.2 add-on had rewritten
four `cisco:isovalent` events to `cisco:isovalent:processConnect`. The qualifier
had expected their submitted sourcetype. No application builder was dispatched.
Its original failed prefix and verified cleanup/export remain retained.
The correction at `74a77e1f28c3d454bdf7bb38257d02f018b26480` derives
indexed classification from the pinned add-on rules and fixture payloads.
Fresh Attempt14 then passed exact 963-event classification, the two NX-OS
interface rows on every member, and independent V1 ACI graph/topology plus
all-member parity. It failed a staged V2 topology warning oracle imported from
a differently mapped standalone fixture. The product correctly filters
unclustered APIC adjacency before unsupported-row counting; the reviewed
`7659d84339b9ea3901c00fba9eec5c9287e8d876` correction requires exactly the
two warranted warning strings and retains strict identity/mapping boundaries.
Its 118 offline cases passed. Attempt14 remains failed/incomplete, with all
96 original records and 100/104-payload-file exports independently verified
against 22 separately retained prefix snapshots, followed by exact cleanup. Attempt15 from source27 then passed V1/V2/viewer
parity and the real scheduler probe, but failed settings preparation because
its live overlay copy changed directory ownership. No settings race or new
bundle apply ran in that failed invocation. The diagnosed harness defect and
reviewed `5391d93` correction are recorded in `SHC_FINAL_QUALIFICATION.md`.
Source28 Attempt16 subsequently passed all application gates, with the
explicit SDK prerequisite repair and original failure preserved as described
in the SHC record. Its 112/117-file exports and exact cleanup are retained.
The candidate archive and native-suite inputs are unchanged.

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
the native SHC/PDL gates, generated installation-checksum verification, explicit
deployer settings overlays and settings convergence. Findings concerning
terminal draining, null settings revisions and false terminal cutover success
were corrected and independently reviewed again. Review verified all 34
complete-suite export hashes, 400 source fingerprints, pruning restoration and
the 53/107-file failed/passing cutover exports. Review36 independently verified
the final package-09 complete-suite export, and review48 verified all 474
migration/browser files and 2,010 Git-bound fingerprints. Final review of SHC
evidence and the reconciled publication record is a required publication gate,
recorded separately in the retained independent-review records.

The final combined-source review found the additional stale settings-read
race described above. It was fixed in candidate 09 and independently reviewed
with no new actionable findings. The fresh complete suite and standalone V2
rehearsals/browser acceptance above use that exact new package.

Review also closed stale preactivation restoration-checkpoint reuse and
verified the renewed performance distributions, 33 new artifacts and unchanged
prior evidence. All 364 enabled-origin export files, their persisted-result
references and 400 source fingerprints were independently checked. Review of
the revised browser qualifier found incomplete Hubble payload validation,
acceptance of extra CSV backend attribution and incomplete backend-port
validation. All were corrected and follow-up review closed them, including
independent wrong-port, valid port-translation and validity-boundary checks.
Final native acceptance subsequently passed and received the separate runtime
review described above. Additional qualifier findings in flattened CSV
authority, required scheduler classification and resolved interpreter evidence
were corrected and independently closed before their passing executions.

PR [#12](https://github.com/chambear2809/splunk-adm/pull/12) publishes this work
against the accepted main above. Historical CI run `39193292006` passed all
enabled checks at `79c18ce8f3b63aee657ab12a6a3a7705504d8086`; it is not
substituted for final-head CI. The native integration CI job is deliberately
skipped, with the separate complete installed suite and distributed execution
recorded above. Publication requires final independent review, all enabled
checks at the exact pushed head, normal merge without policy bypass, and
post-merge verification. Exact final/merge SHAs, CI outcomes, the local patch
and preservation checks are recorded in the retained final publication record
and PR. No overall Cloud qualification is claimed.
