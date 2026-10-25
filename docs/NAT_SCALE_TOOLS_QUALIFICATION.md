# NAT, search measurement and operational tooling qualification

Task date: 2026-10-25. Starting remote main:
`2c1e702d278ce12b5e7342fff6bd73a87ae37eea`.

## Roles and isolated resources

Actual session `turn_context` metadata verified the orchestrator as
`gpt-6.1-sol` / `medium` and each implementation worker as `gpt-6-luna` / `max`.
The independent reviewer uses `gpt-6-astra` / `medium`; its verification and
review disposition are recorded below when complete. No persistent model
configuration was changed.

The task identifier is `nat-scale-20261025`. Every lab uses
`adm-nat-scale-20261025-<owner>` as its container name, `<name>-net` as its
network and `<name>-etc` / `<name>-var` as its volumes. All carry exact task and
lab ownership labels. Resources use `splunk/splunk:10.6.0.5`, image ID
`sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`.

| Owner | Worktree directory under `~/.codex/worktrees/` | Web / management / HEC ports |
| --- | --- | --- |
| NAT | `nat-scale-20261025-nat/splunk-adm` | 28000 / 28089 / 28088 |
| Performance | `nat-scale-20261025-performance/splunk-adm` | 28100 / 28189 / 28188 |
| Refactor | `nat-scale-20261025-refactor/splunk-adm` | 28200 / 28289 / 28288 |
| Integration | `nat-scale-tools/splunk-adm` | 28300 / 28389 / 28388 |
| Reviewer | `nat-scale-20261025-reviewer/splunk-adm` | 28400 / 28489 / 28488 |

All endpoints bind only `127.0.0.1`. The cross-checkout lock for each is
`/tmp/splunk-adm-lab-<uid>-<name>.lock`. Private credentials, environment
configuration, resource manifest, container identities, and retained evidence
live outside disposable resources under
`~/.codex/task-evidence/nat-scale-20261025/<owner>/`. The resource manifest
contains no credential values.

The Docker daemon exposes 12 CPUs and 8,214,585,344 bytes RAM. Only one task
Splunk lab runs at a time. Pre-existing collectors and other resources remain
untouched. This is namespace isolation; host CPU, memory, storage and background
activity are not controlled production measurement conditions.

## Acceptance and ownership

- Orchestrator owns lab infrastructure, integration, shared configuration,
  source/package bindings, final checks and evidence reconciliation.
- NAT worker owns supported translation evidence, regression coverage and NAT
  instructions. Missing, malformed or ambiguous evidence must remain unresolved;
  firewall NAT cannot establish a separate load balancer's selected backend.
- Performance worker owns benchmark tooling, bounded measurements, workload
  correctness tests and methodology. Local results cannot establish production
  capacity or qualify the 20,000-row topology limit.
- Refactor worker owns the migration entrypoint and cohesive extracted modules.
  Fixture-generator ownership transfers only after any NAT/workload baseline
  changes are integrated. CLI, import, journal, safety and deterministic-output
  compatibility must be preserved.
- The reviewer independently inspects the integrated candidate and corrections;
  publication follows review, required CI and repository protection gates.

Isolation checks exercised separate labelled resource creation and cleanup,
showing that removing NAT's resources left performance's resources present.
Unit coverage checks foreign lab/task labels, public/wrong port bindings,
network/volume mismatch, invalid identities, authentication ordering, and Docker
inventory failure. Existing named-lock concurrency and private staging tests
remain in use. See [task lab procedure](TASK_LABS.md).

## Baseline verification

Before workstream integration, frontend lint/type checks, 787 Vitest tests,
111 Playwright tests, package build and release verification passed. Python
lint/format passed; 779 offline tests passed after installing the repository's
pinned `signalflow-client-python==1.3.9` in a task-local virtual environment.
The first run lacked that dependency and was not counted as a passing run.
125 distributed tests and 18 offline upgrade cases (three live cases skipped)
also passed.

The integration lab installed baseline archive SHA-256
`ca5140664818dec913e9355febc5e5939bb588da71a44d70bacbc205d122477e`, restarted,
and returned the expected `makeresults` smoke row. A foreign task label was
refused. The verified lab was stopped before granting performance its slot.
Live refusal checks also exercised `up`, `install`, `reset`, `down`, `purge`,
`btool` and search with a foreign task label: each refused before mutation,
retaining the original container ID/state and credential file. A Docker-free
shell regression covers the same entrypoints. These are baseline/infrastructure
results, not final integrated acceptance.

## Search measurement results

Tooling source `b1b9f083950f70fb5f43fc3e59bccb2ef4054320` measured the retained
baseline app archive identified above. These measurements are not rebound to a
later package. See [methodology and source limits](SPLUNK_SEARCH_PERFORMANCE.md).

| Expected / fetched topology rows | Input events / scan count | Splunk run seconds | Search wall seconds | Result pages | Boundary outcome |
| --- | --- | --- | --- | --- | --- |
| 19,999 | 19,998 | 2.106 | 2.5573 | 2 | Complete within modeled cap |
| 20,000 | 19,999 | 2.052 | 2.5282 | 2 | Complete within modeled cap |
| 20,001 | 20,000 | 1.983 | 2.2606 | 3 | Extra sentinel detected; job result marked incomplete for application use |

All three jobs reached `DONE`; exact device/interface identities and the two
expected metadata warnings matched. The workload has no link-discovery or SNMP
ifIndex input. `dropCount=0` and `eventIsTruncated=false` were present;
`resultIsTruncated` was omitted and is recorded as unavailable. The 20,000-row
application cap was modeled from source, not exercised in a live browser. This
is local response-boundary evidence; it does not measure NAT-enriched flow
aggregation. It is not production capacity or qualification
of the bound under representative load.

Sampled whole-container peaks were 5,873,917,952 / 5,922,373,632 /
5,933,101,056 bytes, including cache and unrelated Splunk processes; these are
not per-search RSS. Other task labs were stopped and heavy worker tests paused.
Three pre-existing collectors remained running; host CPU, I/O and caches were
uncontrolled. Each case reset its data and used one measured search. Reset,
startup, install, HEC submission and index-visibility timing are separate.
HEC code-zero responses establish HTTP acceptance; complete indexed counts and
row identities provide separate visibility/correctness evidence.

The first attempt stopped on an overly narrow expected-warning oracle after
its first completed job. It remains retained separately; the correction
requires both exact known workload warnings and rejects unexpected warnings.
The corrected three-case report is
`performance/topology-boundary-corrected-b1b9f08.json` in retained evidence.

Post-measurement review added bounded reset subprocesses and host process-group
cleanup in `104986f` and `cbd1c6d`; 51 focused benchmark tests passed, including a
real child that ignores TERM after its parent exits. Reset timeouts retain an
uncertain-state report and stop without an automatic retry. Host-group cleanup
cannot prove Docker daemon-side exec completion. These guards do not retag or
extend the earlier measurements. A later bounded `server/info` preflight
records native version/build/product type when available, with explicit
unavailable status otherwise; 56 final benchmark-focused tests passed. Older
immutable reports have only the image tag/digest and are not retroactively
assigned native server metadata.

The separate existing pipeline smoke workload also completed its builders,
rollup, summary and graph searches: 19 events became visible, with 8 graph nodes
and 10 edges. This is a small local functional regression check.

## Same-event FTD NAT evidence

The NAT implementation conditionally retains complete,
changed, single-valued reported and translated FTD tuples on the existing V1
conversation. [The data contract](DATA_LAYER.md) and
[firewall operator guide](operators/firewall-security.md) bind the field
semantics to reviewed Cisco Security Cloud 3.6.5/3.7.2 material, Cisco's FQE 7.4
ConnectionEvent definitions, and Splunk JSON extraction behavior. Raw deployed
emission remains unqualified; the old categorical statement that the TA cannot
expose translated fields was corrected.

Evidence retains mapped routing scope, reporting device IP, indexed-event
fingerprint, event time, receipt time and initiator-to-responder roles.
`OriginalInitiatorIP` remains a separate optional field; the reported tuple is
not assumed to be universally original, particularly for tunnel events.
Missing, malformed, multivalue, unusable, unmapped and unchanged tuples do not
become translation observations. Equivalent IPv6 spellings are compared by
address value. Each observation is filtered to the selected half-open time
window before aggregation. Numeric evidence bounds retain the precision
reported by Splunk in portable validation/exports. On this tested image,
`addinfo` truncates both measured boundaries to milliseconds even when the
job retains the requested sub-millisecond bound. The helper can therefore widen
the effective lower bound or narrow the upper bound. Native indexed-summary
searching also returned the same three rows at a bucket start and that start
plus 0.0005 seconds; the proposed native-earliest protection was disproved and
is not counted as acceptance. The app now rejects absolute graph bounds with
nonzero digits beyond milliseconds before dispatch. It preserves harmless
trailing zeros and relative syntax, whose bounds remain server-resolved.
Direct `adm_graph(4)` callers must supply millisecond-aligned absolute bounds;
finer original-request precision at either end is unsupported and cannot be
recovered from `addinfo`. Numeric export labels identify native bounds, not
exact original-request precision. A
32-observation cap remains explicit
in inspector, portable/CSV evidence and graph comparisons.

The change adds no translated conversation or traffic counter and no endpoint
alias or backend hand-off. Cross-event/native-key lifecycle correlation,
counter deduplication across separate observations, and load-balancer/backend
attribution remain unsupported. This normalizer retains no distinct close time;
actual eStreamer end-time output is unqualified. V2 does not project this field,
and this task does not qualify NAT evidence preservation through V1-to-V2
cutover. V2 activation requires an equivalent schema path.

Worker offline checks passed 196 focused frontend tests, lint/build and focused
Python lint/compilation checks. The first dedicated live run of `f72f3cd` failed
(three errors, one failure across four tests). Native SPL rejected direct
Boolean field assignments; the test also mishandled an OTel fixture object and
assumed `addinfo` retained sub-millisecond bounds. That immutable attempt remains
separate from corrected validation. The precision probe retained the requested
job bounds while measuring `addinfo` outcomes at +0.0005, +0.001, +0.0015 and
+0.5 seconds.

The corrected worker app source `f722633` and archive SHA-256
`d8bdc00fc70b3537e123e527434d9bc78f67185b11844330ea89b95bb4891d0b`
passed all four live tests with test source `dfb34cb`. Real `adm_graph` output
passed frontend `rowsToGraph` validation: each of the three windows had six
nodes and three communication edges; a 33-event case retained 32 observations
with a truncation flag, with the same traffic/counts as its no-NAT counterpart.
Window evidence counts were three for the full bucket, two through `N+0.5`,
and one through exact `N`. No translated-address node or backend edge appeared.
Malformed reported IPs were excluded by quality checks. A multi-value EventType
was present in raw input but excluded by the existing FTD source selector;
the owned unmapped observer remained present with no NAT evidence. Test setup
corrections and their unsuccessful attempts remain separately retained.
The successful report's structured source/archive fields identify `f722633`;
a legacy limit sentence saying `f72` is stale. A responder-only DNAT follow-up
also passed on that archive with test source `9ee64ef`: the initiator tuple was
unchanged, the responder changed from `10.42.0.21:443` to `10.42.0.99:8443`, and
the graph retained three communication edges with no translated-destination
node or backend attribution. Final integrated validation is recorded below.
Historical capture fields remain unchanged; a separate macro compatibility
review records the no-NAT fixture contract without claiming recapture.

## Tool modularization

Implementation commit `754d04c` retains the legacy entrypoints and their CLI
help/import surfaces. Migration responsibilities are in
`tools/cisco_migration/{common,journal,core,evidence,dispatch,history,cutover,recovery,cli}.py`;
fixture responsibilities are in
`tools/raw_fixtures/{common,nxos,aci,networking,cli}.py`.
The facade-defined `Migration` preserves the qualification source-path check,
while compatibility shims retain the observed constant and API-factory test
seams. [Module map and compatibility evidence](TOOL_MODULARIZATION.md) explains
the dependencies and remaining verification boundaries.

All 63 fixture files matched the captured pre-refactor bytes: 11 NX-OS,
20 ACI, 9 prior-window ACI, and 23 explicitly anchored networking files.
Both CLI help outputs matched their baselines. Root independently checked
147/148 migration and 95/96 generator function ASTs unchanged, with only the
forwarding `main` functions differing; all original top-level value expressions
were retained except the necessary `ROOT` parent offset. Structural comparison
does not prove import/global semantics, so it supplements the runtime tests.

Worker checks passed: migration 177, fencing 7, upgrade harness 21, previous
demo 6, networking capture 16, fixture drift 3, offline SHC qualification 126,
and task-lab safety 11. Source closure hashes now include every extracted
implementation file in future capture/qualification records. Root verified the
historical prior-window capture unchanged outside its explicit generator
compatibility review and confirmed prior review history was retained.

The worker's dedicated migration Docker rehearsal passed two tests in 579.684
seconds using source `754d04c` and the retained baseline archive SHA-256 above.
It used a task-local CA/server certificate with loopback SANs, owner-only inputs
and authentic scheduler receipt slices, preserving TLS verification and
readiness gates. It exercised staged validation, interruption after a verified
cutover mutation, resume and rollback. The journal reached `rolled_back`, with
complete rollback and verified V1 recovery. A native V2 history cycle was
accepted for an empty source expectation, and rollback restored that writer's
original disabled state. The V1 pause gap was empty; matching empty fingerprints
do not establish nonempty gap recovery. Initial TLS/scheduler setup attempts and
the completed run remain separately retained, bound to their actual inputs.
Final integrated package acceptance is recorded below.

## Independent review

The independent reviewer runtime was verified as `gpt-6-astra` / `medium`.
Initial source review reproduced one P2 import regression: the fixture facade's
legacy `aci(s)` builder was shadowed by a private CLI module import. Root fixed
it in `be74b61`, added a direct callable/output regression and audited every
original top-level callable import. Twenty-six targeted compatibility checks
passed. The reviewer independently confirmed the fix, all seven current source
hashes, ordered prior reviews and unchanged historical capture data. No further
consequential finding was reported in that correction.

The reviewer independently passed 56 benchmark and 11 task-lab safety checks,
checked source documentation and retained measurements, and requested an
integrated end-to-end NAT graph/cap/bounds/rows-to-graph check. The completed
final-candidate checks are recorded below.
Follow-up test review found missing OTel/summary index-visibility waits and an
insufficient total-edge assertion. Bounded read-only waits and an exact edge
count were added, and the reviewer confirmed the corrected summary base-search
syntax. These test corrections do not turn a failed native run into acceptance.
The reviewer independently verified the successful four-case and responder-only
DNAT evidence, including source/archive hashes, cap and boundary behavior.
A real-summary probe disproved the proposed sub-millisecond native-earliest
protection. Root added a graph-only pre-dispatch precision guard in `54113b7`;
51 focused provider/time-bound/search-client tests passed, including rejected
bounds with zero dispatch and supported bounds passed unchanged. The reviewer
accepted that correction and the reconciled native-bound export labels. Final
evidence and the documentation-only reconciliation return to the reviewer
before publication; approval, CI and merge status belong to the PR record.

## Integrated acceptance

The first frozen integrated source `93bbc4c` passed lint, formatting, packaging,
release verification, 847 frontend tests, 816 Python tests, 126 distributed
contract tests and 111 browser tests. Its retained archive SHA-256 is
`4d103021e05b5f091c8ee7002fe098cabd34a5830ac81ad332f0bd1cb8c8e0d2`.
The dedicated integration lab installed that exact archive; the installed
macro SHA-256 matched source `29197a19727a0ce497b6adb8aadc3fca0706bb820037c9a5d0834c7dc6bba04b`.
Native server metadata reports Splunk Enterprise 10.6.0.5, build `86587d4e3b27`.

Its full Splunk run completed 438 discovered tests in 2601.545 seconds:
428 passed, eight skipped, one import error and one helper failure. This was a
failed command and is retained as such. The external evidence wrapper omitted
the repository root from Python's import path, so AppDynamics could not import
`tools`; the standard module invocation supplies that root. The NAT helper's
stdout failed strict JSON decoding; the exact captured Splunk rows passed three
fresh parser replays. The helper now silences Vite logging while retaining
nonzero/stderr failures; no output-line filtering or assertion weakening was
added. Both affected modules passed their final-package reruns below.

The eight skips were three opt-in pruning cases, the separately controlled
migration rehearsal, two unavailable distributed-SHC cases, verified HEC TLS
without its CA bundle, and a real-release rollback without a distinct-version
baseline archive. The retained baseline app is also version 0.5.0 and cannot
satisfy that distinct-release condition.

Independent review subsequently found that a portable snapshot could supply
NAT bounds unrelated to its displayed window. Correction `5d87855` requires
each native bound's floor to match its displayed epoch bound, including empty
and truncation-only snapshots, while retaining valid fractional carriers and
legacy behavior. The reviewer accepted the correction and its 121 focused
graph/row tests. Earlier records retain their original source/package bindings.

The final implementation source `e1825b8` passed all ten offline gates:
860 frontend tests, 816 Python tests, 126 distributed contract tests,
18 offline upgrade cases (three live cases skipped), and 111 browser tests,
plus lint/type/format, packaging and release checks. The browser run used
`CI=1` to require a fresh owned test server. The retained archive SHA-256 is
`2773e42c0c856ae8b168887c014b654ae77820d874c7cde81ecebda058d63d2d`.
Compared with the earlier tested `93bbc4c` archive, only `atlas.js` and the
`app.conf` build timestamp changed; all backend and SPL files are byte-identical.
The exact final archive passed installation, identity and btool checks, then
four native NAT cases, the complete AppDynamics module and the native V2
browser module. Actual Splunk rows and parsed frontend graphs are retained.

The same final archive passed the controlled migration rehearsal: two tests in
1209.192 seconds, with strict TLS, authentic schedules and owner-only inputs.
It exercised interruption after a verified mutation, resume, completed V2
cutover, and rollback. The final journal is `rolled_back`, rollback is `complete`
and V1 recovery is `verified`. The injected pause-gap row was absent before
rollback and aged beyond the resumed scheduler's lookback; one verified manual
writer recovered exactly the source-derived row, with no scheduler duplicate.
Original selectors and writer states were restored. All 79 nonprivate runtime
artifacts are retained with hashes in
`integration/final-migration-evidence-manifest.json`.
The accepted native V2 conversation/traffic cycles at 21:05 UTC and history
cycle at 21:06 UTC have empty expected and retained results. They establish
scheduler/reconciliation behavior, not nonempty V2 scheduled processing. The
separate pause-gap tuple has one record, 1,540 bytes and five packets, with zero
V1 retained rows before rollback.

The TLS setup's REST restart left Splunk stopped in the exact owned integration
container. Before a migration journal existed, target/container identity and
stopped status were verified, the service was started without reset/reinstall,
and strict task-CA/localhost verification passed. Original diagnostics and
recovery results remain retained separately from migration acceptance.

Evidence remains outside disposable worktrees at
`~/.codex/task-evidence/nat-scale-20261025/`. It includes original failed runs,
per-source offline reports, immutable packages and sidecars, package byte
comparison, final native graph rows, TLS recovery diagnostics, scheduler proofs,
the terminal migration journal and result artifacts. Current retained credential
and session values were checked against 432 text artifacts with no matches;
private inputs are excluded and scheduled for exact-path cleanup. Historical
purged values were unavailable for that scan.

Worker labs have been purged and their absence independently checked. The
integration lab remains owned until final review/publication finishes; the
reviewer lab was reserved but never created. Publication and post-merge cleanup
follow the reviewed manifest, retaining evidence and preserving the primary
checkout, unrelated worktree and pre-existing Docker resources. Production
capacity, Splunk Cloud/distributed deployment, real vendor-emission qualification,
NAT aggregation cost and the explicitly skipped cases remain unverified.
