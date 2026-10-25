# Optional integration implementation contract

Baseline: `b8f05490f3df8352ff88f9b803ca39d7df3a14d5` from fetched remote main.
This task covers Observability Cloud, AppDynamics, and Edge/Ingest Processor
artifacts. ITSI, ES, SOAR, a general CIM rewrite and Cloud certification are excluded.

## Existing behavior and additions

| Path | Existing | Additions |
| --- | --- | --- |
| Observability | Historical five-signal SignalFlow exporter, v1 health inspection | Durable external HEC delivery, repeatable scheduling, separate selected detector-event history, contextual navigation |
| AppDynamics | Generic versioned asset import | Bounded Controller collector, current node-IP import, full hierarchy/backend candidate evidence and inspection |
| Processors | Direct HEC fixtures and installed searches | Versioned product-specific SPL2 artifacts, transport/deployment profiles, golden contract validation and exact runtime qualification procedure |

## Shared admission and identity

New source IDs are `o11y_detector_events` and `appdynamics_inventory`, both in
the optional evidence readiness tier. They ship unselected, with selectors
`index=unconfigured_optional` and qualification flags `0`. Existing optional
job admission, cancellation, caller search permissions, shared app namespace,
configuration fingerprints and 30-second server/35-second client budgets apply.
There are at most two concurrent optional jobs, 10,001 source rows to detect
caps and 64 displayed records. Scope attributes evidence; it is not tenant
isolation. Unselected sources dispatch no source searches.

Detector events use `application_atlas.o11y_detector_event.v1` /
`atlas:o11y_detector_event` and verified `o11y_detector` mappings. Mappings
pin observer, organization, realm, routing scope, cluster and a JSON list of
one to 16 selected detector IDs. The view reports events observed in the
selected interval for those configured detectors. It does not apply health
MMS identity to alerts, infer service ownership from display names, reconstruct
historical incident state from latest incidents, or interpret silence as health.
Event time, capture time and completion remain separate. Unknown lifecycle,
retention, origin coverage, caps, missing identities and partial pages stay unknown.

AppDynamics node-IP context reuses `adm:asset_history` v1 with
`snapshot_current`. Full hierarchy and backend candidates use
`application_atlas.appdynamics_inventory.v1` / `adm:appdynamics_inventory`,
verified `appd_controller` authority and separate optional selection. IDs are
qualified by Controller authority and application/tier/node/backend IDs;
names are labels. Capture start/end/skew and completion are explicit. No
current snapshot backdates ownership, no missing object synthesizes retirement,
and no backend with zero/missing/unverified association IDs establishes node
ownership. No current DNS lookup fabricates an address or observed call.

Configured navigation accepts HTTPS origins with no userinfo, path, query or
fragment; source-provided URLs are never followed. Source modules add only
documented routes and literal IDs and disclose unsupported contextual filters.

## Delivery, fidelity and rollback

Worker A owns the single reusable external HEC sender. Finalized JSONL HEC
envelopes enter a private spool outside any checkout. Default batches are
bounded to 256 KiB, spool bytes to 1 GiB, pending captures to 10,000, with an
explicit total record cap. Exhaustion refuses new captures and preserves
undelivered data. Durable checkpoints separate remote acceptance from local
progress; uncertain crash outcomes may replay. Identical records deduplicate
semantically; conflicting identities remain incomplete. HTTP acceptance,
Enterprise acknowledgment and caller-authorized indexed readback are distinct
gates. At-least-once delivery may duplicate ingestion; exactly-once is not claimed.
Secrets are injected server-side, TLS stays verified, and redirects cannot
forward credentials. Export-only health CLI compatibility is retained.

Processor profiles preserve event JSON, original times, metadata, nulls,
units/counters, authority, completion/lifecycle and HEC fields outside `event`.
Only explicitly configured destination/index routing changes. Edge and Ingest
have separate input/destination/fallback profiles. Filtering is disabled by
default, and required identity/evidence fields cannot be masked. Offline golden
fixtures do not execute SPL2; real processor qualification remains a separate gate.

Rollback stops external schedules/delivery, leaves the private spool recoverable,
unselects sources and resets qualification flags. No core writer, traffic edge,
permission, counter or application identity depends on these optional sources.
Existing indexed evidence is retained under operator retention policy.

## Ownership and acceptance

| Owner | Mutable paths |
| --- | --- |
| Coordinator | Shared evidence/config types and tests; source registry; macros/props/collections/lookup projection; frontend registration; packaging/CI; lab isolation; integration qualification records |
| Observability worker | Health exporter/normalizer/panel and tests; common HEC delivery; detector exporter/query/panel/fixtures/tests; Observability operator/design docs |
| AppDynamics worker | Controller collector/importer; AppDynamics query/panel/fixtures/tests; AppDynamics operator/design docs |
| Processor worker | `integrations/processors/v1/`, `fixtures/processors/`, processor validator/tests and processor docs |
| Independent reviewer | Review/release records and PR metadata only; no feature/test fixes |

Workers use separate task-owned managed worktrees and containers, unique ports,
external private secret files, and a cooperative lock per named container.
They do not initialize submodules or alter the primary checkout. The ignored
`dist/integrations-qualification/resource-ledger.json` records exact paths,
branches, containers and cleanup disposition. Current root is GPT-6.1 Sol/High
by explicit user correction; workers are GPT-6 Luna/Max; final reviewer is
GPT-6 Astra/Medium by explicit replacement authorization. Sanitized actual
session metadata is retained separately from requested settings. The retired
Astra/Max agent performed release preflight only, not feature approval.

Targeted failure tests precede integrated lint/type/unit/browser/build/package,
release validation and AppInspect Cloud precert. Final installed-Splunk checks
use the exact candidate archive, actual baseline archive for upgrade, and
viewer/admin permission tests. A frozen candidate SHA receives independent
review, fixes and affected rechecks before one PR is created and merged. All
required CI must pass; PR CI's skipped lab job is not installed-app evidence.
External live-source/processor checks may remain pending only for disabled,
explicitly unqualified paths with all locally provable gates passing.
