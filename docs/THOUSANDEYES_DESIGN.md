# ThousandEyes integration design

Baseline: `1e4f2043ffc095ed0d87a090f572178bd204b134` (fetched remote main).
This task is authorized to implement, qualify, open a PR and merge after all
applicable gates and hosting approvals pass. Production deployment, paid tests,
live collector/rule changes and AWS/customer infrastructure mutations are excluded.

## Decision and evidence boundary

Consume evidence already indexed by the latest Cisco-supported ThousandEyes
Splunk integration. The supplied `cisco-thousandeyes-app-for-splunk_090.tar.gz`
is inspected statically; its identity, latest-version status, provenance and hash
are verified in the research record before its schemas become adapter contracts.
Vendor ingestion is preferred. The static inspection identified a necessary
exception: the 0.9.0 CEA path collector serializes individual API results without
the request's test ID/account-group ID, which the public CEA result model omits.
Those rows cannot establish a uniquely qualified test/target path. The coordinator
approves a narrow optional external CEA path exporter, reading only explicitly
selected existing tests through the official v7 API. It adds request identity to
native results and reuses the existing private durable `hec_delivery.py` queue.
It creates no tests, installs no collector runtime/schedule in Splunk and changes
no live collection. Native endpoint path results remain supported directly when
their own aid/test/agent/time fields and configured source are verified.

The exporter emits `application_atlas.thousandeyes_path.v1` HEC events with
`sourcetype=atlas:thousandeyes:path`, `source=atlas:thousandeyes:path`, schema
version 1, immutable `capture_id`, `authority`, `account_group_id`, `test_id`,
`collection_started_at`, `collection_completed_at`, and the native `result`.
It preserves native round/measurement times, fails closed on pagination/limit/
identity/schema failures, bounds requests/bytes/records/retries/deadlines and
atomically writes private capture files outside checkouts. The existing queue
provides at-least-once delivery; HTTP acceptance, optional indexer acknowledgment
and caller-authorized indexed readback remain distinct. A single indexed path
observation cannot prove complete test history or upstream/index continuity.
The exporter API and genuine target readback remain externally unqualified until
their exact deployment is exercised. No live export is authorized by this task.

ThousandEyes is a new optional evidence source. It starts unselected, with an
unconfigured literal index selector and a false schema-qualification flag.
Existing application and scoped-endpoint inspections own its selection and
cancellation lifecycle. It contributes synthetic measurements, measured probe
paths, synthetic traces and vendor event/change context; it creates no passive
traffic, dependency graph edges, ownership, backend calls or traffic counters.

Use the existing caller-owned optional job budget, app-shared configuration,
bounded completion envelope and configuration fingerprint recheck. A query admits
only configured indexes, source families and validated literal native identities.
An empty caller-visible result never proves source coverage, collection success
or health. Denial, stale receipt, caps, malformed data, incomplete producer
history, conflicting identities and changed configuration remain visible.

Every normalized record preserves the producer/schema, authority and account
group, native test/agent identity when applicable, target and supplied protocol/
port, observation interval, source/index timestamps and origin fingerprint.
Measurements retain their unit, aggregation, direction, denominator and time
basis. Authority-qualified IDs and explicit time-qualified application/environment/
routing-scope bindings control attribution. Names and tags remain labels.
Current inventory and present-day DNS cannot establish historical ownership.

Probe paths describe the identified agent's test target and interval. Missing
hops cannot independently establish forwarding loss. Successful tests validate
only their covered target/protocol/location/time. Synthetic spans remain synthetic.
Activity records describe ThousandEyes configuration changes. Event/alert
lifecycle and history completeness are reported as supplied, without inferring
incident state or health from silence.

## Interfaces and ownership

All workers use a separate task-owned worktree from the explicit baseline above.
The coordinator alone integrates shared types/configuration/entry points and
pushes or manages the PR. No worker delegates. Maximum runtime concurrency is
five agents including the coordinator; keep review capacity available and run
the six workstreams in bounded waves.

| Owner | Exclusive mutable files | Interface / acceptance |
| --- | --- | --- |
| Coordinator | `frontend/src/data/thousandEyesTypes.ts`; shared evidence/config/search admission/settings/registry/ACL files; shared UI entry points; packaging/CI; this design and final qualification record | Publish stable typed normalized records, bindings and inspection result; preserve existing optional-source and caller-permission boundaries; inspect integrated diff and run final gates |
| 1 Research | `docs/research/thousandeyes.md`, `docs/research/thousandeyes-capabilities.md`, ThousandEyes-only package manifest entries; ignored vendor artifacts | Verify latest vendor version and exact package fields; cover every relevant input/capability; send schema evidence before parser contracts freeze |
| 2 Normalization | `frontend/src/data/thousandEyesEvidence.ts`, `frontend/src/data/thousandEyesEvidence.test.ts`, `frontend/src/data/thousandEyesAdapters.ts`, `frontend/src/data/thousandEyesAdapters.test.ts`, `fixtures/thousandeyes/`, `tools/export_thousandeyes_paths.py`, `tests/test_export_thousandeyes_paths.py` | Implement literal bounded source search and strict producer-specific normalization against coordinator types; preserve malformed/duplicate/conflicting/partial behavior; implement only the approved narrow CEA path exporter above using existing delivery |
| 3 Attribution | `frontend/src/data/thousandEyesAttribution.ts`, `frontend/src/data/thousandEyesAttribution.test.ts` | Pure attribution and comparison over normalized records/bindings; exact authority, scope and historical validity; retain target/NAT/proxy/CDN ambiguity |
| 4 UX | `frontend/src/ThousandEyesEvidencePanel.tsx`, `frontend/src/ThousandEyesEvidencePanel.test.tsx`, `frontend/src/thousandeyes.css` | Accessible application/endpoint inspection with measurements, agent comparison, measured paths, change/event context and explicit loading/unselected/staged/denied/stale/incomplete/capped/ambiguous/empty/complete states |
| 5 Qualification | `tests/browser/thousandeyes.spec.ts`, `tests/splunk/test_thousandeyes.py`, `tools/thousandeyes_search.mjs`, `tests/test_thousandeyes_contract.py` | Adversarial, permission, cancellation/config-race and installed exact-query checks; never weaken assertions or edit implementation; harness changes only after explicit assignment |
| 6 Operations | `docs/operators/thousandeyes.md`, `docs/THOUSANDEYES_OPERATIONS.md`, `tools/benchmark_thousandeyes.mjs` | Prerequisites/capacity/quotas/costs; rollout/upgrade/rollback/disable/removal; reproducible realistic-cardinality benchmark with evidence-based envelope |
| Independent reviewer | No edits | Read-only integrated candidate and surrounding code; actionable severity/file/line/scenario/fix findings; re-review remediated final candidate |

Exact TypeScript contracts are frozen by the coordinator after static vendor
schema research. They live in `thousandEyesTypes.ts`; workers import them rather
than editing them. Search loading reuses `SupplementalResult<T>` and
`loadSupplementalEvidence`, including caller-session searches, one source lease,
30-second server/35-second client deadlines, at most 10,001 scanned records to
detect the 10,000 input cap, 64 displayed records and one completion row.
Limits remain conservative and are not raised to accommodate the integration.

## Capability and acceptance matrix

The research matrix records exact producer versions/fields and unsupported or
externally unqualified combinations. This matrix records required Atlas behavior.

| Capability / question | Required behavior | Acceptance evidence |
| --- | --- | --- |
| Metrics: network, HTTP, DNS, page/transaction/API, BGP, voice, endpoint as actually supplied | Typed measurements with failures, absent metrics, units and measurement intervals; no fabricated producer coverage | Package-grounded fixtures/version/unit tests, installed readback, real producer qualification tracked separately |
| Paths | Agent/test/target-qualified ordered probe hops and missing-hop uncertainty; distinguish from inventory candidate paths | Malformed/partial/capped path cases, browser inspection and installed exact query |
| Synthetic traces | Preserve synthetic spans and hierarchy without production service-call edges | Schema and failure tests, explicit UI wording, passive graph/counter regression |
| Detected events and alerts | Preserve native lifecycle, identities and history completeness, including absent/partial pages | Replay/conflict/out-of-order/history tests and visible uncertainty |
| Activity | ThousandEyes-only changes, actor/object identity as supplied, event time and completeness | Change-history tests; no general infrastructure-change claim |
| Application/endpoint, SaaS/API and observed dependency prioritization | Explicit valid bindings and compatible target evidence; prioritize the actual selected observed relationship without creating one | Scope/authority/IP reuse/shared address/NAT/proxy/CDN cases and application/endpoint browser workflows |
| Branch/site/agent and before/after comparison | Comparable metric/test/target/version/windows with location/configuration changes disclosed; reject incomparable groups | Agent relocation, renamed/edited tests, boundary intervals, sample coverage and unit/aggregation tests |
| Segmentation validation | Report only selected agent-to-target protocol/port/time observations | Failed DNS/HTTP/network tests and unsupported-path limits |
| Security / operations | Caller index permissions, admin-only settings, literal queries, safe configured navigation, secret-free artifacts, optional absence | Viewer/admin/partial-index lab, injection tests, cancellation/config-race tests, upgrade/rollback/disable/removal checks |

## Qualification and resources

Focused checks precede lint, frontend/browser types and suites, Python style and
unit suites, packaging, release validation, AppInspect/gate and installed Splunk
integration/permission/upgrade checks. Inspect harness interfaces before use.
Hold `tools/lab_lock.py` throughout a shared/named lab lifecycle. Use task-owned
named resources and distinct ports supported by the existing harness; purge only
those resources after preserving exact candidate hashes, commands, reports,
screenshots, benchmark conditions and review evidence.

The ignored `dist/thousandeyes-qualification/resource-ledger.json` records
worktrees, branches, actual model metadata, lab/container/port/volume ownership
and cleanup status. No credentials or unrestricted transcripts are retained.
Requested and observed profiles: coordinator `gpt-6.1-sol / medium`, workers
`gpt-6-luna / max` (user correction), reviewer `gpt-6-astra / medium`.
The retired medium worker contributes no qualification approval.

Synthetic tests establish implementation behavior. Genuine sanitized producer
data, actual vendor-version compatibility, deployed ingestion/indexed readback,
realistic performance and each claimed deployment topology remain independent
production gates. Missing external evidence keeps the affected capability
disabled and unqualified. Neither AppInspect nor merging grants production
qualification. A disabled implementation can merge only after every applicable
merge gate and independent final review passes.
