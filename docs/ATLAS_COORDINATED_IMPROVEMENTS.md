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

Catalyst topology still queries the selected source-event window conservatively:
a late receipt whose source timestamp falls outside that window can omit context;
the code does not fabricate earlier attachment history. Collector checkpoint/API
permission evidence, real controller/exporter behavior, distributed indexing,
SHC, Cloud deployment and production scale need separate qualification. Captured
demos are regression data, not a restriction to four application topologies.

## Verification record

Source review has closed fourteen P2 findings across the initial review and
follow-ups. No P0/P1 finding was reported. The reviewer is a separate Astra/max
session and performed no edits, tests, builds, commits or lab operations. Final
evidence approval remains pending the completed live suite and performance runs.

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
