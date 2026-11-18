# Application Atlas investigation foundations

This record defines shared evidence and authorization rules for incident
analysis, maintenance planning, dependency monitoring, investigation records,
business services, and connected transport legs. It is a local implementation
contract, not a claim that the candidate has been installed or qualified on
Splunk Cloud.

## Evidence envelope

Every derived finding or saved capture must keep the following facts together:

| Fact         | Contract                                                                                                                                                                          |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source       | Source type, authority, observer, routing scope, and source configuration fingerprint.                                                                                            |
| Identity     | Stable source-native record identity where available; otherwise a documented fingerprint and ambiguity status. Never substitute an address or display name for a stable identity. |
| Time         | Native event or measurement time, indexed time, and capture time are distinct fields. Never rewrite one as another.                                                               |
| Window       | Absolute UTC `[start, end)` bounds requested and the actual returned bounds. A response that cannot prove its bounds is not comparable.                                           |
| Schema       | Input and normalization contract versions accompany each capture. Comparisons require compatible versions or an explicit migration.                                               |
| Completeness | Record counts, caps, truncation, search completion, warnings, stale sources, and denied sources remain visible. Unknown completeness is incomplete.                               |
| Entitlement  | The authenticated caller and source-data authorization used for collection are recorded as provenance, not treated as a future grant. Re-check access on every read/export.       |

Captured facts are immutable. A refresh creates a new capture linked to its
parent. Notes, hypotheses, resolutions, and attachments are separate
revisioned records. Live links are labeled as live references and never
silently replace captured evidence.

## Time comparison and baseline eligibility

Windows are half-open and absolute. Comparisons retain the requested and actual
windows and flag late arrivals separately. A configuration or normalization
revision change makes a baseline comparison ineligible unless an explicit,
reviewed compatibility rule exists. A partial, capped, stale, denied, sampled,
or progressive/top-N result cannot establish absence or a complete baseline.

Dependency identity uses a versioned signature over the normalized endpoints,
transport, listener port, scope, and source evidence needed by that feature.
Traffic-volume changes and routine workload identity churn are separate from
structural dependency drift. “Not observed” is the default when coverage is
insufficient; “removed” requires comparable complete coverage.

## Cases and authorization

Case records and dependency baselines use dedicated persistence contracts;
settings collections, derived graph KV stores, and browser-local saved views
are not case stores. A server handler must authorize list, read, update,
attachment, and export operations independently. Owner access is private by
default; sharing names explicit principals and is revocable. A privileged
capture does not make its source data readable to other users.

Reads and exports re-check both case permission and current source-data
entitlement. Revocation blocks access to protected source material while
retaining non-sensitive case metadata and an audit record. Writes use revision
preconditions, idempotency keys, explicit uncertain-outcome handling, bounded
pagination and quotas, retention/deletion policy, and audit events. If the
backend is unavailable, the UI offers a versioned portable export and clearly
states that durable save did not complete.

## Business services

A business service has a stable catalog ID, time-versioned membership,
accountable team, criticality, source/provenance, and optional runbook and
escalation references. Conflicting claims are retained and displayed as
conflicts. Kubernetes controller ownership remains separate from business
accountability. A current-only import is labeled current-only and cannot be
used to rewrite historical ownership.

The version 2 import separates business claim authority from native identity
provenance. A binding references an exact claim revision and a technical service
four-tuple, source authority/scope and configuration revision. Native references
come only from a qualified reader, never from imported assertions. Exact matches
retain temporal coverage and conflicting claims; they do not verify the business
feed. Browser-local storage is separate from case/baseline sharing. Catalog,
Map, investigation and Impact/maintenance context share this renderer; no owner
is inferred from a name, address, Kubernetes controller or concatenated graph ID.

## Maintenance and failover

Exposure, observed health, readiness, capacity, and functional substitutability
are separate dimensions. A safe maintenance conclusion requires fresh and
complete topology, independent failure-domain evidence, operational readiness,
and capacity with explicit units, interval, direction, deduplication, source,
and assumptions. Unknown, stale, capped, denied, or unauthorized evidence
prevents a safe assessment. Average observed traffic is not peak headroom.

## Connected transport legs

Each leg retains its source, scope, native and indexed times, evidence identity,
and confidence basis. Same-event translation evidence is distinct from
cross-event correlation, compatible candidates, and unknown association.
Address, approximate-time, proxy identity, stream ID, or name alone never
establishes a join. Retries, ambiguity, missing legs, and scope conflicts are
preserved. A path is not rendered as packet order unless its source contract
proves packet order.

## Current evidence and qualification

| Feature               | Evidence available locally                                                                                                 | Current implementation limit                                                                                                                                                                                                                                                                                                   |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Incident timeline     | Historical Cloud scenario documentation records a policy deny, endpoint movement, and collector gap with absolute windows. | Current bounded source receipts are observed; retention and rendered live comparison remain unqualified. Graph differences provide an interval, not an exact change time or cause.                                                                                                                                             |
| Maintenance           | Existing impact analysis and historical topology/failover scenarios.                                                       | No qualified measured failover capacity or alternate functional readiness.                                                                                                                                                                                                                                                     |
| Dependency drift      | Existing adjacent-window graph comparison and lab search outputs based on synthetic raw scenarios.                         | A dedicated authenticated host/client and local version/watch engine exist, disabled and unqualified by default. No production complete source provider or real-source baseline is available. Top-N display is not complete coverage.                                                                                          |
| Investigation records | Dedicated private SQLite cases and caller-revalidated raw comparison captures.                                             | Earlier direct Enterprise capture qualification used the former SDK transport. Installed 0.9.8 notes-only Web and rendered Cases tests passed. Both modes ship disabled. Current capture, real sources, strict bounds, uploads, cleanup and production restore remain unqualified; Cloud/SHC unsupported. See the separate cold case/ledger rehearsal in BACKUP_RESTORE.md.                            |
| Business services     | Kubernetes controller ownership and current catalog mechanisms.                                                            | Validated claims and separate exact technical bindings can be saved in this browser and inspected in catalog/Map/incident/Impact. Only explicit qualified native tuples resolve; legacy, summary-only, stale or denied context remains unresolved. No qualified business feed; imports are assertions, not vendor integration. |
| Connected journeys    | Existing FTD same-event NAT model, selected-client Hubble handoff model, and Envoy single-stream leg model.                | The observer-scope mapping is current-only and cannot qualify historical trace scope; the live trace therefore fails closed rather than drawing device/vSwitch hops. FTD real emission, V2 NAT projection, Hubble SNAT/XFF, and deployed Envoy logging are not qualified.                                                      |

The earlier local profile validation reported `invalid_key` and `unknown_field`
before authentication; that blocker is superseded by later bounded read-only
Cloud-profile discovery. See [Feature source observations](FEATURE_SOURCE_OBSERVATIONS.md)
for the 2026-11-16 receipt and sampled-field results, their provenance and
limits. The 2026-11-04 observations in `docs/demos/LIVE_LAB_SCENARIOS.md` are
historical evidence only.

## Rollout and rollback

New persistence endpoints, collections, schedules, and source projections are
disabled until target-specific authorization, migration, and rollback checks
pass. Local implementation does not enable collector schedules, notifications,
or infrastructure operations. Rollback must preserve case/baseline data and
existing source summaries; code rollback and data deletion are separate
operator decisions.
