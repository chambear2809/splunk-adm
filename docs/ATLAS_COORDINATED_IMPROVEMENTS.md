# Coordinated Atlas improvements

## Accepted base and ownership

Initial accepted base: `510754c17391e548309dd68ddac3f8b99e0b75c6`, the remote
default `main` when selected. PR #6 includes the accepted PR #7/#8 fixes. The
historical local `0a81682` checkout was stale and was not used. PR #9 was closed
without merging. During verification, PR #11 was accepted into `main` at
`d6863dd326099acb892e1eebaa6c43d4f4410947` (2026-10-18 06:18:21 UTC). The
implementation incorporates that accepted commit, including its provenance
isolation, Service history, raw ACI action and distributed lookup corrections.
No uncommitted enterprise-remediation work was imported. Existing primary-checkout
changes and other chats' worktrees were preserved.

Work is isolated in `atlas-coordinated/splunk-adm`; an untouched checkout of the
accepted `d6863dd` revision supplies the final browser baseline. Earlier measurements
against `510754c` are retained as historical evidence only. User authorization was subsequently
expanded to commits, pushes, PRs and merges, plus operations in test environments.
No production collection, vendor API access, contract activation or pruning is
part of this change.

The orchestrator uses GPT-6 Astra/max (user confirmed the active app setting;
the resumed session's `turn_context` metadata confirms it).
Four workers were explicitly instantiated with GPT-6.1 Sol/high, without the
repository's older model-pinned roles: health/Setup, map, performance, Cisco
completeness. Each child session's `turn_context` metadata confirms
`gpt-6.1-sol` / `high`. Each has exclusive file ownership and cannot delegate.
The separate read-only reviewer session likewise confirms `gpt-6-astra` / `max`.
No persistent agent configuration was changed. Validation and review evidence
are recorded below when complete.

## Source-to-feature coverage matrix

Inventory, discovery, association, traffic and candidate routes remain distinct.
Routing scopes bound attribution; they do not implement tenant authorization.
Existing deployment/RBAC guidance continues to govern index and app access.

| Source / evidence | Authority, routing and cluster | Required collection / dependencies | Active contract and product behavior | Health and acceptance coverage |
| --- | --- | --- | --- | --- |
| Stream NetFlow/IPFIX / traffic | Exporter; V2 exact exporter, observation-domain-presence/value, VPN and routing dimensions; explicit scope/cluster | Stream search-time definitions, configured NetFlow index; conversation rollup; V2 profile and traffic-observation rollup | V1 shipped; V2 staged. Graph conversations, raw traffic inspector, selected-client path, Find, comparison and export retain provenance/counters | Receipt, quality, applicable rollup; normalization, graph, Cisco observation-boundary and path suites. Real exporter/template decoding remains unqualified here. |
| DC Networking ACI / endpoints, attachment, ACL traffic and policy | APIC, tenant/EPG and mapped routing scope; cluster only when mapped | DC Networking TA/index; identity and ACI policy builders; conversation rollup for ACL traffic | V1 pilot and V2 compatible sources. Inventory supplies context; observed traffic supplies conversations; policy uncertainty retained | ACI-specific probe, identity/policy jobs, eligible ACL quality; ACI demo, graph/policy/identity tests. Completeness of real collected policy remains operator evidence. |
| Nexus Dashboard / endpoint discovery and flows | Host for identity; fabric for flows; mapped scope/cluster | DC Networking TA/index; identity for endpoints, rollup for flows | V1/V2. Event history and traffic remain separate; no invented unchanged discovery polls | Separate quiet-feed receipt probe and job-specific observer kinds; identity, scope and flow tests. |
| NX-OS / device and interface inventory | Source-qualified serial/device; mapped scope/cluster | DC Networking TA/index; optional interface inventory | V1/V2. NX-OS fabric demo; partial inventory can render without traffic, pods or traces | NX-OS-specific receipt evidence, no nonexistent quality probe or mandatory rollup; topology and partial-source health tests. |
| Cisco FTD / connection traffic | Firewall observer and mapped routing scope/cluster | Security Cloud TA, FTD index, conversation rollup | V1/V2. Initiator/responder evidence remains directional; failures and unmapped scope visible | Source receipt, required fields, quality and rollup; normalization and graph tests. |
| Isovalent / process connection | HEC source authority, pod/process and explicit cluster/scope | Security Cloud TA, Isovalent index; rollup; Kubernetes identity when available | V1/V2. Process setup evidence is not a byte counter or complete network trace | Receipt, normalization quality and rollup; process/identity and graph tests. |
| Hubble / traffic and handoff | Explicit cluster, namespace and pod; source-qualified flow identity | Configured Hubble feed/index; rollup; Kubernetes object history for resolved backend | V1/V2. Exact client/port/transport/time handoff can resolve receiving node/backend; aggregates cannot replace it | Receipt and quality; client-handoff, partial/capped/conflicting backend and cross-cluster tests. |
| Kubernetes objects / identity, backend and route history | Cluster + namespace + stable UID; per-cluster Cilium settings | OTel k8sobjects receiver/index; identity then service-backends; catalog as applicable | V1/V2. Watch/pull validity, deletion and reused IPs determine nodes/attachments. No topology invented from name alone | Quiet receipt, raw required fields, jobs; identity/history/service/frontend and cross-cluster tests. |
| OpenTelemetry traces / calls and workload binding | Trace/span identity, service/environment/cluster/namespace | Trace receiver/index/sourcetype; service binding, catalog | V1/V2. Calls and runs-on can remain useful when network evidence is absent | Receipt, binding/candidate fields, jobs; trace graph and partial-source Setup tests. |
| Catalyst Center / wired client observations | Controller authority + site routing domain; native/MAC identity remains authority-qualified; explicit scope/cluster | Reviewed Catalyst TA/index; source profile; V2 client-history builder; profiled campus IPFIX for client-to-application traffic | Staged under V1. `catalyst-aci` has receipt-eligible attachment, graph/inspector/path/Find/comparison/export context; snapshot alone is not a traffic path | Hourly-aware receipt, per-family profiles, identity/overlap/history diagnostics; new malformed MAC, unidentified record and pre-receipt tests plus Cisco history/path suites. |
| Meraki MR associations via MS390 IPFIX / association + traffic | Organization/network authority + network routing domain; explicit matching flow scope/cluster | Meraki TA/index; association profile; V2 history; compatible MS390 IPFIX profile and traffic builders | Staged under V1. `meraki-nxos` correlates only compatible association, identity and flow interval. Missing AP/IP/SSID never becomes invented identity | Quiet-feed unknown continuity, per-family profiles, optional-field and conflict diagnostics; roam/IP reuse/stale/partial-handoff suites and source authority tests. |
| Optional Catalyst SD-WAN IPFIX / traffic observations | Exporter + exact observation domain/VPN/routing profile | Documented IPFIX template and Stream boundary, explicit `catalyst_sdwan_ipfix` profile, V2 summaries | Staged under V1. Raw observations/provenance available; overlay references never imply TLOC/tunnel paths | Explicit profile-qualified receipt probe and quality; profile/domain isolation tests. Stream/vendor compatibility and real exporter permissions remain qualification gaps. |

## Intentional fixes and regression cases

| Observed failure | Change and acceptance evidence |
| --- | --- |
| Setup consumes job health while its provider is disabled | Jobs-only lifecycle, one load/manual/verified-write refresh, no background polling; restricted access and late response browser tests. |
| Universal freshness and global requirements penalize partial deployments | Shared administrator expectations/registry; hourly Catalyst, quiet Meraki, selected job chains and unknown absent intent; frontend/readiness tests. |
| Unselected or empty index macros entered combined health searches | Selected named probes and validated index configuration before dispatch; restricted NetFlow viewer with an invalid unselected Meraki macro, plus no-default-index regression tests. |
| V2 summaries/dispositions and mixed profile status were lost | Explicit aliases, strict parser, per-family mapping diagnostics, selected quality coverage, coherent selector verification; parser/SPL regressions. |
| Valid client profiles were rejected by Setup and passive refresh erased drafts | Exact reviewed source/profile pairs, dirty-draft preservation and revision conflict/discard behavior; actual networking profile fixtures and visibility-change browser tests. |
| Old healthy-label matching created false map findings | Typed source assessments exclude healthy, staged and unselected sources while retaining unknown and attention findings; partial-deployment tests. |
| Readiness ignored derived evidence and rejected fractional run timestamps | Registry-derived summary/profile checks, guarded raw-field searches and completion-time/fractional timestamp handling; behavioral analyzer/collector tests. |
| Missing/malformed client MAC could accept a flow without source MAC | Valid identity gate; retain unresolved raw evidence and explain missing identity; synthetic Splunk acceptance tests. |
| Catalyst source timestamp could backdate topology attachment | Eligibility begins at indexed receipt; source timestamp remains separate; pre-receipt negative test. |
| Find omitted useful client-history uncertainty | Bounded history diagnostics describe conflicting/expired/capped/missing optional evidence without adding attachments. |
| Refreshed graph/topology or controls could have different provenance | Atomic snapshot hook; topology uses returned absolute graph window; obsolete client responses rejected; browser lifecycle tests. |
| Order-only evidence changes appeared as comparison changes | Canonical order-insensitive evidence comparison preserving all values; unit tests. |

Map structural work is limited to snapshot/query, presentation state and export
orchestration hooks. Existing `useGraphQuery` and `useMatches` seams remain.
Graph/topology publication uses returned normalized rows, selected scope/time and
the last successful request; editing draft controls does not rewrite existing
export or comparison provenance. Data changes, disappearances, conflicts and
client replacement are tested after refresh. Existing keyboard selection, focus,
deep links, saved views, timezone behavior and warnings remain acceptance gates.
Topology dispatch now follows graph completion to use its absolute resolved
window; this trades parallel dispatch for coherent evidence provenance. No new
automatic refresh policy, streaming transport or graph-limit increase is added.

## Performance and qualification

See [browser methodology](BROWSER_PERFORMANCE.md) for captured versus controlled
synthetic workloads, cold/warm conditions, deterministic readiness, actual browser
timings, repetitions and correctness assertions. Measurements do not include live
Splunk dispatch/download and do not establish production capacity or approved SLOs.

The [corrected accepted-main results](benchmarks/atlas-browser-d686-results.md)
compare `d6863dd` with integrated source `8813eb5`: 14 workloads and 140 measured
samples per revision, with matching runtime, harness and workload fingerprints.
All correctness checks passed. On the 500-node/2,000-edge cold workloads, usable-map
medians changed from 377.4 to 310.6 ms for ACI, 363.8 to 313.3 ms for NX-OS,
1,159.2 to 389.4 ms for Catalyst and 1,159.9 to 389.0 ms for Meraki. Integrated
transformation calls fell from sixteen to one; isolated parsing did not improve.
Filtering, React rendering, long tasks and exports are reported separately.

These gains are not universal: Catalyst near-limit warm highlighted-card selection
increased from 260.9 to 367.9 ms median, while observed p95 changed from 359.3 to
368.7 ms. The cause remains unknown; retained long-task entries have no stacks or
attribution. Both statistics remain below provisional investigation thresholds,
which does not erase the regression or establish an SLO. Five repetitions per
cache state make p95 the observed maximum. The workstation runs used a stopped
Splunk lab, but OS, desktop and thermal activity were uncontrolled. The separate
20,000-row topology bound was not capacity-tested.

Catalyst topology still queries the selected source-event window conservatively:
a late receipt whose source timestamp falls outside that window can omit context;
the code does not fabricate earlier attachment history. Collector checkpoint/API
permission evidence, real controller/exporter behavior, distributed indexing,
SHC, Cloud deployment and production scale need separate qualification. Captured
demos are regression data, not a restriction to four application topologies.

## Verification record

Review has closed fifteen P2 findings across the initial review and follow-ups,
including the browser measurement correction. No P0/P1 finding was reported. The reviewer is a separate Astra/max
session and performed no edits, tests, builds, commits or lab operations. Final
overall approval remains pending the completed live suite and installed-package
checks. The corrected performance evidence has been independently approved within
its documented bounds.

Historical evidence before incorporating PR #11: frontend lint/type checks,
551 unit tests, 92 browser tests, package/release checks and AppInspect Cloud
precert passed. These results do not establish a pass for the later integrated
source or package. AppInspect 4.3.1
on Python 3.9 reported zero errors/failures, five warnings, one skipped check and
127 not-applicable checks. Python 3.14 produced fourteen analyzer initialization
errors and was not counted as a successful scan. Existing warnings include the
bundled Python SDK version, custom configuration replication, collection presence,
Python compatibility and documentation address detection; missing app.manifest
caused the skipped package-ID check. This is not Cloud or SHC qualification.

The first broad browser run had dependency-optimizer reload/HTTP 504 failures.
Explicitly scanning all browser entrypoints fixed the test server; the complete
post-fix run passed with assertions unchanged. Initial focused Splunk runs exposed
uninitialized disposable collections and three fixture/dispatch mistakes, followed
by timestamp serialization and moving-clock comparison issues. These were fixed
without weakening evidence assertions; the two final focused cases passed. A
complete final-source live-suite result is still pending and is not inferred from
those focused reruns.

### Accepted-main integration

The original full live run was interrupted when `main` advanced; it was not a
complete suite pass. Two ACI assertions had failed on the old base. PR #11 changes
the affected ACI action handling and acceptance tests; final validation must use
those accepted definitions. The old package and logs are retained under
`dist/pre-main-integration-7999d3a/`. The interruption also ended the lock wrapper;
the coordinator reacquired the exclusive lab lock before any further lab action,
without contention. The owned lab was then stopped while integrating and
remeasuring. The final integrated validation record will be added below.

### Integrated source checkpoint

The integrated runtime source is `8813eb534f907ac9c95d6673ed02fdbdf1008673`,
reviewed independently against accepted main `d6863dd`. The reviewer found no
new actionable source defects. Fifteen prior P2 findings (fourteen source issues
and the browser interaction timer boundary) are closed in implementation;
corrected performance evidence is approved, and live-package evidence remains
pending.

| Check on the integrated source | Actual outcome |
| --- | --- |
| `npm run lint` | Pass, including ESLint, TypeScript and formatting |
| `npm test` | 561 tests in 45 files passed |
| `npm run test:browser` | Initial run: 91 passed, 1 stale fixture-time assertion failed. After deriving test windows from capture metadata, complete rerun: 92 passed |
| `npm run typecheck:browser` | Passed again after the fixture-harness correction |
| `ruff check tools tests` / `ruff format --check tools tests` | Passed; 102 files formatted |
| `python3 -m unittest discover -s tests -v` | 472 passed, no skips |
| `SOURCE_DATE_EPOCH=1792276353 npm run package` | Both frontend builds and packaging passed |
| `python3 tools/check_release.py` | Passed |
| AppInspect 4.3.1 on Python 3.9.6, Cloud precert plus `check_appinspect.py` | Both passed: 0 errors, 0 failures, 5 warnings, 1 skip, 127 not applicable, 113 successes |
| Full corrected browser performance matrix | Baseline and candidate each passed 14 cases / 140 measured samples; 2,520 action postconditions independently verified |
| Live Splunk integration and installed-package checks | Pending at this checkpoint; no pass inferred from historical runs |

Package: `dist/splunk_adm-0.3.0.tar.gz`, SHA-256
`e691df2369712f21fc55442064fda8d52e1c0de00aab8ee8f77780a3f7a9bb41`.
Logs use `dist/atlas-integrated-*`; the full browser rerun is
`dist/atlas-integrated-browser-rerun.log`. The package retains the recorded build
epoch for reproducibility. Current documentation-only follow-ups do not change
its executable assets; final source/package binding must still be checked.

GitHub workflow `39106103577` also passed frontend, browser and Python checks
for `8813eb5`; GitGuardian passed. Its Splunk integration job was skipped.
CI metadata and logs are retained at `dist/atlas-ci-8813eb5.{json,log}`. This
remote result does not replace the pending task-owned installed-app live run.

### Independent review audit

The separate Astra/max reviewer supplied the following disposition record. All
items were P2; no P0/P1 finding was reported. Closure here means source inspection
and the cited regressions, with final live/measurement qualification tracked
separately. The reviewer performed no edits, commits, builds, tests or lab actions.

| # | Affected symbol / area | Concrete failure and accepted correction |
| --- | --- | --- |
| 1 | `selectedHealthProbes`, `loadHealth` | Combined probes searched unselected/invalid indexes. Selected named probes now validate configuration and use a four-request queue. |
| 2 | Catalyst/Meraki quality SPL | Broader event-time windows overstated recent client-quality evidence. Explicit source adapters apply 24-hour indexed-receipt bounds. |
| 3 | Deployment registry | Nonexistent Kubernetes/trace/summary quality aliases created impossible requirements. Unsupported aliases were removed. |
| 4 | `sourceAssessment`, `jobAssessment` | Missing lookback validation and string-label matching misclassified unavailable evidence. Typed assessments validate receipt and retained coverage. |
| 5 | Deployment/Setup contract diagnostics | Inexact V1 selector checks and unconditional V2 jobs rejected valid partial deployments. Coherent selectors are verified exactly; writers follow selected dependencies. |
| 6 | Setup scheduler table | Fetching scheduler data did not expose the target job's outcome. Run status and last-run/success evidence are shown explicitly. |
| 7 | Map findings | Hardcoded healthy labels misclassified cadence, staged and unselected sources. Findings now use typed assessments. |
| 8 | Readiness derived evidence | Summary/profile results were fetched but not assessed. Registry-driven checks assess required derived evidence. |
| 9 | Readiness completion time | Collection-start timestamps made new receipts look future-dated. Assessment uses completion time. |
| 10 | Setup source profiles | Valid Catalyst/Meraki profile pairs were rejected. Exact reviewed pairs are accepted; wrong-family cases remain rejected. |
| 11 | Setup draft revision handling | Passive refresh overwrote unsaved expectations. Dirty drafts survive; newer revisions require explicit conflict resolution/discard. |
| 12 | Quality parsing/presentation | Supported V2 dispositions lost totals; client history was called flows. Dispositions/reasons are retained with candidate-record terminology. |
| 13 | Readiness raw-field probes | Unselected/empty index macros bypassed search guards. Raw dispatch now requires selected, configured probes. |
| 14 | Readiness timestamps | Integer parsing rejected valid fractional scheduler times. Bounded finite parsing preserves precision and rejects malformed/future evidence. |
| 15 | Browser interaction readiness | Sampling after Playwright completion inflated browser latency. Sampling starts at capture, waits for intended DOM state and stable frames, and records automation completion separately. |

The sparse Cisco performance workload and metadata-only refresh checks were
additional acceptance gaps, not additional numbered P2 findings. Evidence-heavy
synthetic workloads and real membership/attachment refresh mutations address
those gaps. The integrated review against `d6863dd` found no new actionable
source defects, including in accepted PR #11 behavior or the contract-conflict
health diagnostic.

The integrated live-suite run also exposed a stale static assertion expecting
`lookup adm_interfaces`; accepted PR #11 deliberately uses
`lookup local=true adm_interfaces` in V1. The test now checks that accepted form
and strengthens the V2 guard to reject every `adm_interfaces` reference. Both
enrichment macro definitions remain byte-identical to `d6863dd`; the live
raw-interface/ifIndex isolation regression passed unchanged. The complete static
contract class passed all 19 tests without `ADM_LAB`, with its log retained at
`dist/atlas-integrated-contract-rerun.log`. Independent Astra follow-up approved
the correction with no weakened evidence. This closes that assertion only; the
original full-run failure is retained and is not relabeled as a clean full pass.
