# Qualification coverage matrix

This is an inventory and execution ledger for the current checkout, not a claim of live or exhaustive qualification. [coverage-matrix.json](coverage-matrix.json) records the independent expected outcome, positive, negative, failure and recovery scenarios, prerequisites, limitations, code and requirement references, and target-specific result fields for each row. Test files and prior qualification records identify useful checks; their presence does not establish a pass for this candidate.

Every result starts **pending** or **blocked**. Execution outcomes distinguish `live_pass`, `live_fail`, `offline_contract_pass`, `blocked`, `unsupported`, `not_applicable` and `pending`; each requires a rationale. Implementation status and target applicability are recorded separately from outcome. Record exact product and source versions, artifact SHA-256, start and end UTC, a sanitized evidence reference, owner and outcome when evaluating a target. Record individual scenario results in the evidence, including skips and failures; a row passes only when all applicable scenarios meet the independently stated expectation. Never place private evidence or credentials in git. Existing historical evidence remains bound to its recorded archive and environment.

| Coverage | Rows |
| --- | ---: |
| feature | 6 |
| route | 8 |
| source | 23 |
| integration | 2 |
| job | 24 |
| persistence | 20 |
| security | 6 |
| deployment | 6 |
| scenario | 13 |
| environment | 2 |

The eight actual routes include Applications, Map, Endpoints, Data Health, Setup, Help, Device and Impact. `explore` and `admin` are aliases; `dependency_map` is a legacy path. The six newer feature families are incident comparisons, maintenance, dependency drift, cases, business ownership and connected journeys. Their live-source and deployment limits are explicitly retained in the matrix. Every saved-search stanza and KV collection found in the app defaults has its own row; each scheduled search ships disabled. Optional processors and source integrations need their own real-runtime qualification.

The matrix does not replace the detailed contracts in [feature delivery](../FEATURE_DELIVERY.md), [data layer](../DATA_LAYER.md), [deployment health](../DEPLOYMENT_HEALTH.md), [security](../SECURITY.md), [upgrades](../UPGRADES.md), [recovery](../RECOVERY.md), [optional integrations](../OPTIONAL_INTEGRATIONS_QUALIFICATION.md), or the standalone, V2 and distributed final qualification records. A source receipt, synthetic test, historical pass or successful package inspection is not proof of complete source coverage, current authorization, safe failover, or deployment readiness.

Inventory worker runtime evidence reported by the coordinator: session metadata `rollout-2026-11-19T12-26-52-01a1f4d8-cf40-7c90-99e3-1fca75864bcc.jsonl`, agent path `/root/coverage_inventory`, first turn context `gpt-6.1-terra` with `medium` effort. This observed runtime matches the user-requested Terra medium profile. The session log itself is not included in git.

The coordinator observed Splunk 9.4.3 (build 237ebbd22314), ES 8.1.0 and one Ready k3s-02 node (v1.37.2+k3s1). These observations do not establish a qualification pass or independent failure domains. The coordinator also reported November 18 vendor advisories identifying 10.6.1 as patched; verify advisory applicability and supported fixes before selecting a target, since historical qualification cited 10.6.0.5. The version/security scenario remains blocked pending that verification and appropriate requalification.

Before enabling derived jobs or exposing the app, test effective shared summary and KV access with both fully entitled and restricted roles across direct lookups, KV REST, summary search, UI and export. Raw-index denial alone does not satisfy this gate. Current shared ACLs require every viewer to be entitled to the complete configured dataset; a restricted role that can read derived records fails the gate. VMware current inventory naming, APIC VMM topology and vDS IPFIX are separate source contracts. Kubernetes qualification requires an actual denied API list/watch test and lifecycle coverage; Hubble OSS and Enterprise each require target-specific per-node rotation, checkpoint and loss/replay verification.

Current execution, environment repair evidence and upgrade gates: [RUN_STATUS.md](RUN_STATUS.md). The environment-only invoice pass is separate from Atlas qualification; the KV backup failure remains a live failure.

Detailed execution vectors are in [UI scenarios](ui-scenario-inventory.json) and [backend contracts](backend-contract-inventory.json). Their test references indicate available evidence to examine, not an installed pass.
