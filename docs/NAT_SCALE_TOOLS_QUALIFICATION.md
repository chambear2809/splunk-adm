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
is local response-boundary evidence, not production capacity or qualification
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
extend the earlier measurements.

The separate existing pipeline smoke workload also completed its builders,
rollup, summary and graph searches: 19 events became visible, with 8 graph nodes
and 10 edges. This is a small local functional regression check.

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

Dedicated migration Docker validation and integrated acceptance remain pending.
The live rehearsal uses a task-local CA/server certificate with loopback SANs,
owner-only session/scenario/journal files and an authentic V1 scheduler slice;
it preserves TLS verification and readiness gates.

## Integrated acceptance

Pending integration and final package validation. Historical qualification records remain bound to
their original sources and packages; they are not evidence for this candidate.
