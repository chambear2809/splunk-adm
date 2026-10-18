# Search head cluster qualification

This record tracks the 2026-10-18 functional qualification of Application Atlas 0.3.0 in an isolated three-member Splunk Enterprise 10.6.0.5 search head cluster. The completed checks below provide bounded synthetic functionality evidence, including an unassisted captain-loss/rejoin repeat. This document does not establish production SHC support.

## Candidate and topology

The final archive is `splunk_adm-0.3.0.tar.gz`, SHA-256 `836485080451caf21997608421db9f596b1262075a19949915c0aef69bccec90`, from the remediation worktree based on `origin/main` commit `510754c17391e548309dd68ddac3f8b99e0b75c6`. Most functional checks used code-qualified archive `eb9ac5fa3ffd37e7fc64bdf53775cc795479fcddf5db45b012e794fd797dc294`. A full archive comparison establishes that the final archive changes only `docs/DATA_LAYER.md` and the `app.conf` build number from that candidate; all executable code, configuration definitions and browser assets are identical. The clean unassisted failover and final two interface regressions used archive `2254f6014b55d206ace1d918a8222949b88e873bc23a2592e173859cbf9fa6bf`. The final archive differs from it only in data-layer documentation and build number as well. Final deployer installation, all-file verification and graph checks are recorded separately; earlier tests are not relabeled as executions of the final archive. The original standalone candidate was `911289f000fead11ced30f170771507745028d759a38c0beddaeab21eac2bd15`. Its distributed rollup exposed the interface lookup defect below. A replication-only intermediate candidate also failed peer lookup availability. Archive comparisons confirm that the final correction changes only two SPL lookup placements, their documentation, and the package build number; frontend assets are byte-identical.

The lab contains three search heads, a separate deployer, and a separate search/indexing peer. All five instances use the same pinned AMD64 image, `splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`. The search heads use replication factor 3 and the platform's cohosted PostgreSQL/PDL KV Store. The platform generates the shared SHC ID; the harness does not supply or modify it.

The containers share one existing 8-vCPU/32-GB qualification host. Members have 4-GB/2-CPU limits, the peer has 4-GB/2-CPU limits, and the deployer has a 2-GB/1-CPU limit. These are synthetic functional limits, not supported production sizing. The same-host container lab does not satisfy Splunk's requirement that each member run on its own machine or VM ([SHC system requirements](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/deploy-search-head-clustering/system-requirements-and-other-deployment-considerations-for-search-head-clusters)). It tests app behavior and does not establish a vendor-supported production topology. Independent machine failure domains and customer workload sizing remain separate gates.

Management and HEC requests verify a private lab CA and the expected hostname. Lab traffic stays on an internal Docker network; browser access uses SSH tunnels. Summary forwarding uses plaintext TCP within that isolated network. End-to-end production TLS, load balancers, SSO, multisite deployment, indexer clustering, and Cloud are outside this lab.

## Qualification contract

The deployer stages the exact candidate and curated vendor search-time configuration. Downloaded vendor input scripts are not executed. The checks must establish:

- Three ready KV Stores, one ready captain, and three `Up` members before app checks.
- Exact candidate definitions on every member after deployer installation.
- Create, cross-member update, and delete convergence for every shipped collection.
- Base ACI fixture ingestion on the separate peer; builders dispatched through different search heads; complete summary and KV visibility.
- Exact graph rows from every member against the packaged standalone capture, excluding only `generated_at`: 25 nodes and 33 edges.
- Restricted viewer access to the same graph and denial of stored-data writes, private recovery collections, and owner-dispatched writer searches on every member.
- Real SplunkWeb live-map requests on every member with no demo fallback, complete graph counts, and a fresh Applications demo mount.
- Identical closed-slice concurrent replay without changed graph counters.
- Captain loss, surviving KV quorum and graph reads, an offline-member KV update, member rejoin, and convergence.
- Replicated configuration and preservation of local configuration/KV data during same-version deployer reapplication. This does not substitute for a version upgrade/rollback rehearsal.
- Actual scheduled execution using the shipped five-minute cron and closed index-time boundaries, assessed separately from manual dispatch.

The raw base fixture dates are fixed at 2026-10-07. The disposable peer's retention is explicitly set to 30 days before ingestion so qualification cannot accidentally freeze that data. Historical builder checks use a captured closed index-time slice and explicit event-time bounds; they do not establish behavior of the normal rolling scheduler. A separate current fixture is required for that check. Only the conversation rollup is enabled for actual scheduling in this lab; other builders and maintenance searches are manually dispatched over the recorded fixture slices. Historical oracle preservation does not establish normal retention/pruning behavior over time.

## Verified distributed lookup defect and correction

**P1 — distributed V1 rollup fails at interface enrichment (corrected).** Source: `splunk_app/splunk_adm/default/macros.conf:347–348`, in `adm_flow_enrich`; called by `adm_flows` before rollup aggregation. Affected shapes are SHC or a search head using remote search peers. Trigger: flow candidates are evaluated on a separate peer while the interface KV lookup export is empty or unavailable. Reproduction: install the original archive, keep interface inventory empty, ingest the raw NetFlow fixture on the separate peer and dispatch the conversation rollup over its closed index-time slice. The actual search failed instead of writing complete conversations, leaving the dependency map without the expected flow evidence. A standalone-only test cannot expose that execution placement.

The original V1 flow enrichment ran two `adm_interfaces` lookups on the peer before aggregation, but the KV definition did not supply a usable peer lookup file. The actual rollup failed with a lookup-construction error. Enabling collection replication alone still produced missing/unreadable peer export errors in this lab; it is not the accepted correction.

The smallest sound correction is to keep the live KV lookup on the search head: both lookups now use `local=true`. The actual production normalizer/enrichment path passes empty-inventory fallback and populated-inventory assertions through the separate peer on every member. This avoids a dependency on an empty or unavailable peer KV export. V1 normalized candidates now cross to the search head before aggregation. That cost is explicit and remains a capacity gate; V2 already uses raw interface fields.

Required correction validation is the actual V1 production normalizer plus enrichment through a separate peer, first with an empty inventory and then a populated key, on every member. Require a completed search without partial-result or lookup warnings, exact interface labels and retained ifIndex fallback; then rerun builders and exact graph comparisons. Those bounded checks passed. Production-size cost remains unverified.

`tests/splunk/test_distributed_interfaces.py` is an opt-in regression for an explicitly identified disposable SHC lab. It neither provisions nor resets a lab, requires healthy remote peers, verifies instance identity, and removes only its own probe key.

Independent static review examined lookup call sites and execution placement, KV definitions and ACLs, owner-dispatched saved searches, actual recovery/migration shape guards, deployer/default configuration behavior, and the frontend search contract. No additional verified SHC code defect was found in those examined paths. This is not evidence of correctness for untested versions, scale, failure modes or tenant authorization models.

## Completed checks

| Check | Observed result |
| --- | --- |
| Deployer installation and exact runtime default-file hashes | Passed on all three members |
| Final archive verification | 75 shipped files checked per member: 74 byte-exact; `app.conf` has identical declared settings plus Splunk's generated installation checksum and whitespace |
| Full collection agreement after rejoin and final deployment | All 14 collection contents agree across all three members; counts and hashes retained |
| All 14 KV collections: create, cross-member update, delete | Passed; probes removed |
| Empty and populated interface enrichment | Two live tests passed across all three members |
| Distributed builders and summary collection | Passed, including the correction to add-on indexing setup described below |
| Administrator graph vs packaged standalone oracle | Exact match on every member: 25 nodes, 33 edges; only `generated_at` excluded |
| Restricted viewer graph and access boundaries | Passed on every member: full graph; REST/SPL writes, private recovery reads, and owner-dispatched writers denied |
| Browser live map and fresh Applications demo | Passed on every member; real graph POST, 25 nodes, 33 edges, no live demo fallback, no page/search errors |
| Three simultaneous manual closed-slice replays | Passed; raw summary rows 62 → 236, exact graph unchanged |
| Same-version deployer reapplication | Passed; KV data, a new local macro, and an equivalent local override of shipped `adm_conn_cap` preserved |
| Scheduled execution during abrupt captain loss | Initial 05:15 slot and later outage/post-rejoin slots passed. Clean repeat: real 05:45, 05:50 and 05:55 UTC slots passed before, during and after the outage, one successful SID per slot. |
| Degraded graph reads and KV update | Exact fixture graph on both survivors; unique KV update converged while the former captain was offline |
| Member rejoin | Initial run was assisted and is retained separately. Clean repeat recovered without intervention in 187 seconds; offline KV update visible on return, all three graphs exact. |
| Fresh configuration after clean rejoin | Create and delete propagated to all three members |
| AppInspect 4.3.1 Cloud precertification | Zero errors/failures, five warnings, one skip; not Cloud acceptance |

The five AppInspect warning classes are Python-script migration advice, custom configuration replication, presence of `collections.conf`, bundled Python SDK 2.1.1 (checker recommends 3.0.0+), and hostname/IP detection in version text and synthetic fixtures. They remain report findings; this run does not dismiss the SDK or custom-configuration warning as platform acceptance. Recovery-specific configuration replication is outside SHC support because recovery itself refuses SHC. Any broader custom configuration support and SDK upgrade require their own compatibility review.

The ACI fixture initially differed because the harness copied search-time/index-time add-on configuration to an already-running peer. Four Isovalent records retained their base sourcetype. Restarting only the task peer loaded the vendor indexing rules; the four records were ingested again and summarized in a separate closed slice. The original records and partial summaries were preserved. The exact oracle result therefore covers a base slice plus a corrected Isovalent slice, not one pristine all-source ingestion.

An initial graph request immediately after creation of the restricted account returned an empty graph with an explicit missing-span warning. Later searches from every member matched the administrator oracle, and the full permission suite passed. The transient setup inconsistency is retained as unresolved evidence; immediate consistency of new role/account changes has not been qualified.

## Unsupported operations

Recovery and Cisco V2 migration remain standalone-only. Their actual deployment qualifiers were called against all three SHC members and refused each member before any mutation. No recovery stage, cutover, replay, rollback, or lease takeover is enabled for SHC by this qualification.

## Captain loss and rejoin

The task killed the current captain container at 05:16:40 UTC. The two surviving members elected another captain at 05:18:20, approximately 100 seconds later, and both KV Stores stayed ready. Their fixture-window graphs matched the full oracle. A unique KV probe written while the old member was offline converged between survivors. Actual scheduled rollup jobs completed at 05:20 and 05:25, each with one success SID; the 05:20 run summarized the fresh current-time probe. This was a kill between scheduled jobs, not a proof of exactly-once output for a crash during `collect`.

With RF3 and two participating members, the elected captain reported `min_peers_joined_flag=false`, `initialized_flag=false` and `service_ready_flag=false`. The original harness gate required full service readiness and therefore could not establish success in that state. That wait was explicitly interrupted after recording degraded functionality; its original evidence is retained. Splunk documents the service-readiness check in terms of having enough members for the replication factor ([restart health checks](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/manage-search-head-clustering/restart-the-search-head-cluster)). No replication factor or readiness flag was changed. Scheduled successes do not establish configuration or artifact replication health; the surviving noncaptain repeatedly logged configuration-replication disconnection during this period.

On starting the old captain, SHC service readiness returned after membership was restored, but its cohosted KV/PDL service remained failed: PDL exhausted local PostgreSQL connection retries during startup. One additional state-preserving restart of that task-owned member was performed. The Mongo-only KV restart endpoint was also attempted and rejected without applying a restart. All three KV Stores subsequently reached ready, the returning member received the offline write, and every graph matched the oracle. The run does not establish that intervention was necessary: the intermediate failed status was transient, and the operator intervened before observing an uninterrupted full recovery window. The assisted run therefore cannot establish unassisted rejoin or production availability. A separate clean repeat is recorded independently.

## Clean unassisted repeat

The second run used a new, unique current NetFlow probe, with its recorded index time outside the pre-loss job's closed upper boundary. A separate check confirmed that its summary was absent after the kill and before the eligible outage slot. This prevents an earlier scheduled result from satisfying the outage assertion.

The 05:45 UTC slot completed before the task killed the current captain at 05:45:08. A replacement was observed after 65 seconds. Both surviving KV Stores remained ready, both fixture-window graphs were exact, and a new KV write converged between survivors. The actual 05:50 job completed while the old captain was still offline, with no search warnings. Its returned `rollup_id` exactly matches the one expected summary for the new probe (`records=1`, `bytes_c2s=900`).

The old member was started exactly once at 05:50:05. No subsequent member restart, KV reset, resync, replication-factor change, readiness override, or other repair was issued. The observation window allowed twenty monotonic minutes, with API request timeouts capped by the remaining budget. All three member and cohosted KV statuses reached ready at 05:53:12: 187 seconds after start. The returning member received the offline write, cleanup converged, and every graph matched the oracle. The actual 05:55 slot then succeeded. A fresh macro creation and deletion subsequently propagated to all three members, separately confirming configuration replication after return.

The first controller observed the new summary before its forwarded scheduler-success log arrived and asserted prematurely. Its `finally` performed the one planned start; no extra lifecycle action occurred. A read-only continuation used the original restart deadline, correlated the completed outage job with the unique summary, and finished the rejoin/post-scheduler assertions. The original exception and checkpoint are retained alongside the passing reconciled evidence. This is a harness/logging-order issue, not an app failure; it is not hidden as a first-attempt harness pass.

This repeat establishes the recorded behavior for a crash between scheduled jobs and one returning member in the synthetic lab. It does not prove exactly-once writes for a crash during `collect`, KV-primary failure under every leader placement, host/site failure, or production recovery-time objectives.

## Platform bootstrap observations

Before the app was installed, two KV members became ready while the third cloned the PostgreSQL database. The clone initially showed an established connection with no data growth, then completed. The third member's PDL service remained failed following the startup deadline; a state-preserving restart of that task-owned member restored startup progress. The cluster elected another captain and the two surviving KV members remained ready. This is platform bootstrap evidence, not app failover qualification. No app defect is inferred from it.

The qualification harness uses `apply shcluster-bundle` on the deployer. The installed CLI does not expose `validate shcluster-bundle`; the harness does not claim a separate successful CLI validation command.

## Evidence and remaining gates

Detailed evidence is retained under the remediation worktree's `dist/shc/`, with SHA-256 hashes in `evidence-manifest.json`. The independent review checked archive lineage and challenged the readiness claims. The final archive was installed through the deployer and its graph checks passed on every member. Earlier full runtime checks remain tied to their original archive hashes; byte-level code/configuration continuity is recorded separately. A same-host functional result cannot establish production availability, platform version range, capacity, disaster recovery, upgrade compatibility, or Splunk Cloud acceptance.

### Support boundary

| Deployment or operation | Status and evidence |
| --- | --- |
| Enterprise 10.6.0.5, three-member SHC plus one remote peer, synthetic same-host lab | Enumerated synthetic checks passed; supported production topology, capacity and operational qualification remain unverified |
| Automated recovery or Cisco V2 migration on SHC | Explicitly unsupported; actual qualifiers refuse all three members before writes |
| Production SHC availability and scale | Unverified; a same-host functional pass, including unassisted rejoin, cannot establish supported failure-domain behavior or sizing |
| Version upgrade/rollback, rolling restart, member replacement, KV backup/restore | Unverified; same-version deployer reapplication establishes only its recorded preservation checks |
| Other Splunk patches, operating systems and architectures | Unverified by this run |
| Splunk Cloud | Runtime and platform acceptance unverified; local AppInspect is not acceptance |

### Release blockers and ordered follow-up

1. Repeat qualification on a supported topology with a separate machine/VM per member and representative sizing, networking, TLS and load-balancer/SSO setup. Include repeated captain/member loss and unassisted return, KV-primary loss, active writer interruption and host failure. Require full member/KV readiness, stored-data agreement, exact graphs, configuration replication and real scheduled-slot evidence. The same-host result is not a substitute; the initial assisted observation does not establish a persistent platform or app defect.
2. Qualify V1 centralization cost with deployment-scale raw candidates, late and duplicate data, large identity/scope sets, concurrent graph readers and overlapping schedules. Require bounded memory/network usage and no partial-result warnings, skipped schedules or changed graph counters.
3. Run a clean all-source ingestion with vendor index-time configuration active before the first event. Require exact source classification, complete builder outputs, and exact graph/oracle results without corrective reingestion.
4. Rehearse an actual app version upgrade, interrupted deployment and rollback, then member replacement and KV backup/restore on the target platform. Require preservation of local overrides, scope/identity state and journal data with documented recovery times.
5. Run release regressions against the final archive on standalone and supported distributed targets; the earlier standalone suite does not automatically establish a clean full-suite result for this final archive. Retain version-specific logs and package hashes.

Nonblocking improvements for a limited synthetic evaluation are to automate the disposable harness and sanitized evidence export, measure propagation latency explicitly, and explain the temporary missing-span warning after a new account/role is created. These do not replace the production gates.

**Readiness verdict:** the verified interface-placement defect is corrected and covered by a production-path distributed regression. The app passed the enumerated bounded SHC functionality and unassisted rejoin checks, but production SHC support remains unverified. Recovery and V2 migration remain disabled for SHC. No commit, push, merge or release is implied by this record.

## Cleanup and preservation

Cleanup passed after export and hash verification of 54 sanitized evidence records. Only the five stored, ID/name/label-verified task containers, their anonymous volumes, task Docker network and private task directory were removed. No task containers remain. The two pre-existing stopped containers retained their exact IDs, names and states; the native Splunk process state matched the preflight snapshot. Existing source changes, SSH keys and credentials were preserved. The pinned Docker image cache was left intact.

The generated browser credentials, browser SSH forwards, management control connection and its private temporary directory were removed. The task-created dependency symlink in the managed worktree was unlinked without removing its target. The remediation worktree, final archive, screenshots and sanitized evidence remain available for review. At qualification cleanup, no commit, push, merge or publication had been performed; subsequent source integration is tracked separately in GitHub.

## Pre-merge provenance follow-up

The previous-window demo capture retains its original captured macro-file hash and rows. A later static-review compatibility record covers only the two `local=true` interface lookup placements; it does not claim a recapture. CI builds containing that provenance-only metadata update remain distinct from the archived qualification packages above. The exact full final-release regression gate remains open. Mocked pipeline unit tests also use private temporary lab-lock files so an unrelated running lab cannot block or be affected by their preflight/error-path assertions.
