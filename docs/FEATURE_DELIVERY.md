# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

**Completion status (2026-11-16): the six-feature request is not complete.**
The table records implemented increments and their remaining source, integration
and deployment gaps. Passing local checks does not close those gaps.

| Feature                                     | Local workflow                                                                                                                                                                                                                                       | Evidence and verification                                                                                                                                                                                                                         | Remaining qualification                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` opens a windowed comparison from a live map with findings and coverage notes.                                                                                                                                                          | Local comparison rules and historical scenarios; see the current bounded [source observations](FEATURE_SOURCE_OBSERVATIONS.md).                                                                                                                   | Current source receipt does not qualify rendered live comparisons, audit-event coverage, retention, causation or exact change time.                                                                                                                                                                                                                                                                           |
| Maintenance and failover                    | The optional Impact workflow can capture a before state and compare an after state; assessment separates exposure, readiness, health, capacity, failure domains and substitutability.                                                                | Local conservative model and capture workflow; unknown or incomplete evidence fails closed.                                                                                                                                                       | No qualified live Impact, measured peak-capacity or alternate-readiness feed; do not use the assessment to authorize failover.                                                                                                                                                                                                                                                                                |
| Dependency baselines and drift              | Dedicated authenticated storage, version/history review and manual passive-watch evaluation are connected in the incident Connections section. Source-backed capture remains unavailable without a trusted complete provider.                        | Local domain and frontend coverage; the top-N map is ineligible as a complete baseline.                                                                                                                                                           | The HTTP host ships disabled/unqualified and has no production source provider. Collector loss, sampling and lateness closure are unproven; installed host/Web, real-source baseline, backup/restore and operational scheduling remain unqualified.                                                                                                                                                           |
| Investigation records and evidence packages | Private shared cases now support notes, immutable server-rechecked comparison captures, per-capture read/export, readable handoffs and explicit JSON evidence packages. Source access is revalidated for each current reader and old retry response. | Domain/API/native/host tests and rendered browser workflows pass. Direct REST qualification passed on Enterprise 10.6.0.5 using two non-admin investigators with identical index grants and different search filters, including a second capture. | Persistence and capture mode ship disabled. Raw comparison windows are limited to five minutes each; source retention/configuration changes can withhold evidence while notes remain usable. Installed Web proxy, real-source collection, hard transport bounds, attachment uploads, cleanup scheduling and backup/restore remain unqualified. Cloud/SHC are unsupported; browser retry state is memory-only. |
| Business-service ownership                  | Admin Setup validates versioned claims and separate technical bindings. Catalog, Map, incident and Impact/maintenance entrypoints show imported ownership with explicit native identity references, temporal limits, provenance and conflicts.       | Strict import/binding/mapper tests and synthetic browser checks validate exact tuples, unknown/stale contexts, conflict retention and explicit native-reference exports.                                                                          | Browser-local assertions are not shared, source-authorized or verified business feeds. Native provenance is available only from matching qualified raw reads; legacy/summary-only catalog/maps and IP/name-only Impact evidence remain unresolved. No qualified ownership/criticality vendor adapter.                                                                                                         |
| NAT, proxy, and load-balancer journeys      | Inspector Flows and Proxy evidence render separate FTD, Envoy and selected-client Hubble evidence with gaps and explicit exports.                                                                                                                    | Local model and browser coverage; current bounded Cloud observations are recorded separately.                                                                                                                                                     | No installed candidate qualification or current journey capture. Observer-scope mapping lacks verified historical validity, so live trace fails closed. FTD real emission, V2 NAT projection, Hubble SNAT/XFF and deployed Envoy logging remain unqualified. Per-source cards do not establish an end-to-end route.                                                                                           |

## Current integration increment

The current integration adds capability-gated case controls, the
authenticated but disabled dependency-monitoring host/client, manual watch
evaluation with protected historical evidence checks, and ownership context in
existing catalog/Map/incident/Impact entrypoints. No new top-level navigation,
notification, owner-dispatched search or infrastructure action is enabled.

Native ownership references require explicit service/environment/cluster/namespace
fields plus source authority, scope, configuration SHA-256 and exact observation
window from a qualified raw reader. Full contiguous raw slices propagate matching
provenance; mixed, missing, sampled, summary-only or malformed contexts do not.
This is finite identity provenance, not proof of unsampled dependency coverage or
continuous service lifetime. Names, IPs and concatenated graph IDs are not parsed
to manufacture bindings. Failed/denied refreshes and changed source connections
withhold the retained native ownership context.

Independent review corrected historical occurrence disclosure on fresh duplicate
requests, future cooldown state on historical reads, duplicate JSON metadata
keys, and stale watch status/pagination on selection changes. Strict baseline
source eligibility remains unchanged. See [baseline operations](DEPENDENCY_BASELINES.md)
and [ownership contract](../frontend/src/businessServices/README.md).

The integrated increment passes full lint, 124 Vitest files (1,317 tests),
198 focused baseline/identity/case/release Python checks, and Ruff (234 files).
The package and release verifier pass with the main JavaScript at 685,029 gzip
bytes (1,051 below its unchanged 686,080-byte ceiling) and optional investigation
JavaScript at 30,124 bytes against its unchanged 32 KiB ceiling. The final full browser suite passes: 189 tests, one skipped.

Astra rendered the actual Catalog, Map and Impact pages through an explicitly
synthetic replay at 1,440 and 320 px in light/dark themes. All twelve combinations
fit the viewport. Review verified keyboard opening/closing and focus restoration,
32 px ownership controls, native-only consented exports, and suppression during
source loading, denial and replacement. Corrections added narrow KPI wrapping,
kept Map ownership under More actions to preserve the compact default map, and
added a close action that restores workspace space. This is engineering design
acceptance, not a usability study or real-source/installed qualification.

The preceding installed case qualification remains scoped to its archive.

## Earlier verification performed

The protected case evidence increment passed full lint, 120 Vitest files (1,294
tests), 103 focused case/source/native/host/release Python checks, Ruff and the
full browser suite (177 passed, one skipped). Packaging and release verification
passed. The main bundle report is 683,810 gzip bytes, 2,270 below the unchanged
686,080-byte limit (Python's release measurement is 680,757 bytes). Optional
investigation JavaScript is 20,240 bytes against its unchanged 32 KiB budget.

## Revalidated shared case evidence

The Notes section now opens shared cases through the existing optional asset.
Investigators explicitly consent to a new server-side source read, retain
immutable selected comparison captures, choose a saved capture for rechecking,
and download a fresh authorized JSON projection or readable handoff. Native
coverage warnings and per-window indexing cutoffs remain visible; withheld
captures are counted. Lists do not dispatch searches for every case. Uploading
graphs or arbitrary attachments remains unsupported.

The dedicated installed test `tests/splunk/test_investigation_evidence.py` passed
against archive SHA-256
`42c9603ce4156b26a39be50c578f5825e67a678eb7ecc69d31003af1b19a7a2e`.
It exercised two non-admin investigators with identical four-index grants but
different native search filters, two independent comparison captures, targeted
read and export of the second, public provenance hashes, source revocation,
old retry responses, changed-source configuration and preservation of notes.
That archived increment contained 62 packaged Python files. Subsequent changes
to shared qualified identity output and the new baseline host are locally
validated separately; the current candidate is not byte-identical to that
installed archive and does not inherit its installed qualification. Source inputs were explicitly synthetic protocol/span/Hubble
fixtures processed by installed Splunk; this does not qualify current Cloud data.

Initial installed checks correctly exposed a fixture indexing-horizon mismatch
and a host dependency on configuration-read privileges. The test now observes,
ingests and closes its windows in order; the host reads only fixed app/user
control flags locally, preserving caller-context source searches. Independent
review corrected late-job cleanup, optional-module error-class identity,
authentication-expiry clearing, later-capture starvation and display/export
selection drift. Final rendered review passed at 1,440 and 320 px in light/dark,
including consent, current-reader withholding, retry focus, explicit capture
selection and readable exports. These are engineering checks, not user research.

The task-owned lab was purged. Its container, network, volumes and secrets were
confirmed absent and all three loopback ports were free. No shared Cloud
installation, collector change, schedule, notification or failover occurred.

See [Investigation records](INVESTIGATION_RECORDS.md) for exact supported
contracts and remaining transport, deployment and archival-entitlement limits.

## Maintenance and baseline verification

The latest maintenance/baseline increment passed:

- `npm run lint` and `npm test`: 118 files, 1,285 tests.
- `npm run test:browser`: 173 passed, one skipped, including the actual Impact
  planning wrapper and production optional-asset branches.
- `python3 -m unittest tests.test_baselines tests.test_baselines_api
tests.test_local_access tests.test_feature_source_discovery
tests.test_field_presence tests.test_release`: 106 tests passed.
- `ruff check tools tests splunk_app/splunk_adm/bin/adm_baselines_lib` and the
  corresponding `ruff format --check`: passed.
- `npm run package` and `python3 tools/check_release.py`: passed.

Independent review corrections cover current-source access on reads/retries,
receipt retention, cross-operation retry identity, Unicode signatures, aggregate
evidence quotas, revoked UI state, trusted watch observation timestamps and
wall-clock bounds on discovery and cleanup. No actionable finding remained in
the final review. Rendered review accepted synthetic planning at 1,440 and 320 px
in light/dark, including refresh, unknown, denied, before/after, export consent,
keyboard scrolling and uncertain-write focus. This is engineering verification,
not customer research or real-source qualification.

Maintenance and baseline UI, plus ownership import, now use the explicitly opened
optional investigation asset. The main bundle report measures 684,456 gzip bytes
(1,624 below the unchanged 686,080-byte limit); the release verifier measures
681,436 bytes with Python's gzip implementation. The optional JavaScript report
is 16,123 bytes against its unchanged 32 KiB limit. See
[Dependency baselines and maintenance captures](DEPENDENCY_BASELINES.md) for
interfaces, retention limits and rollout prerequisites. At that earlier increment no baseline HTTP endpoint was registered. The current
increment registers a disabled authenticated host; schedules remain disabled.

Earlier increment verification follows; its counts and access statements are
historical, not the current completion status.

An earlier local increment (prior to the 2026-11-16 source discovery) passed:

- `npm run lint` (ESLint, both TypeScript projects, and Prettier).
- `npm test` (111 files, 1,250 tests).
- `npm run test:browser` (155 passed, 1 skipped).
- Focused Python checks for qualified rollups, identity search, the previous
  demo compatibility record, path-trace macros, and NAT evidence (68 passed,
  5 skipped).
- `ruff check tools tests` and `ruff format --check tools tests`.
- `npm run package` and `python3 tools/check_release.py`.

That increment reported the main JavaScript chunk above Vite's advisory
500 kB threshold and passed the release-archive check. At that time the
Cloud-profile validator returned `invalid_key` and `unknown_field`, and no
authentication or Cloud query followed. This historical blocker was resolved
for the later bounded read-only discovery recorded in
[Feature source observations](FEATURE_SOURCE_OBSERVATIONS.md). No candidate
installation, collector change, schedule, notification or failover was performed.

## Rollout and rollback

The subsequent local case/handoff increment adds a SQLite domain engine and
connects portable records to the incident Notes tab, plus ownership import to
Admin Setup. Validation passed: full lint, 113 unit-test files (1,258 tests before
the final ownership regression), the final 15 focused ownership/portable tests,
nine case-engine tests, 157 browser tests (one skipped), focused Ruff checks, and package/release verification.
Browser verification includes a synthetic comparison replay which downloads
both handoff formats and preserves notes across sections; it does not establish
positive real-source comparison coverage. Independent source review found no
remaining actionable issue in this increment after quota/revocation, coverage
caution, demo labeling and duplicate-claim fixes. Rendered design review accepted the Notes and import screens in a real-Shell synthetic replay at 1,440 px and 320 px in light and dark themes after correcting the import field width and revision label.

The local build does not enable case persistence, privileged schedules,
notifications, or infrastructure actions. Install and qualify source changes
only through the repository's reviewed deployment process. Keep V1 summaries
readable; V2 NAT projection changes require rebuilding older V2 summaries
before expecting the new fields. Rollback code independently of retained
summary data, and do not delete existing evidence as part of code rollback.

## Authenticated notes connection

The shared notes increment adds a strict request adapter, authenticated Splunk
persistent handler, dedicated unassigned `adm_investigate` capability, exact
browser proxy routes, disabled/unqualified deployment defaults and a browser
client with revision preconditions and stable retry IDs. Shared cases now expose
notes/hypotheses/questions, explicit sharing/revocation and server-authorized
export. Portable graph notes are not copied into shared cases.

Validation passed: 20 case domain/API/host tests, 53 release-contract tests,
1,262 frontend tests, 158 browser tests (one skipped), targeted Ruff checks and
rendered design review at 1,440/320 px in light/dark. The installed direct REST
check passed in a distinct task-owned Enterprise 10.6.0.5 lab: disabled state,
private creation/read, same-key retry, note append, sharing, export, revocation,
protected capture rejection and deletion using two non-admin investigators.
The disposable lab and its secrets/volumes were purged afterward.

Installed checks exposed slashless `path_info`, optional Cloud markers absent
from Enterprise server metadata, and administrator-only topology REST access.
The host now normalizes the path, requires exact runtime/license and explicit
platform attestation, rejects positive Cloud markers, and reads only the fixed
local SHC disabled setting without granting users configuration privileges.
Independent review corrected required header forwarding, exact child-resource
proxy exposures and draft loss during unresolved writes. The package verifier
now enforces these registrations without relaxing native CSRF protection.

These results qualify this lab's direct notes API only. No Cloud installation or
query occurred in that increment; the installed Splunk Web proxy/client, protected source capture,
Cloud/SHC deployment, cleanup scheduling and backup/restore remain unqualified.

## Transport journey display

The journey increment adds one-event transport leg cards in existing Inspector
Flows and optional Proxy evidence, with source details, visible missing/retry/cap
states and explicit version 1 evidence downloads. Timing-only Hubble records are
candidates, complete aggregate metadata cannot replace a client-specific handoff,
and cross-cluster clients are allowed without relaxing backend identity checks.
Conflicting source versions remain unknown and are retained for inspection/export.
The export preserves known Hubble scope and raw handoff metadata, and inclusion
consent resets when the selected evidence changes.

Validation passed: `npm run lint`, 1,278 Vitest tests, 165 Playwright tests (one
skipped), 57 release tests, Ruff checks, package/release verification and rendered
review at 1,440/320 px in light/dark. Source review corrected port-zero loss,
discarded conflicting payloads and missing export scope. Production-loader browser
checks exercise real packaged JavaScript/CSS with an AMD stub, no eager request,
failed or mismatched assets, retry, keyboard focus and protected export consent.

The existing 670 KiB main bundle gate remains unchanged. Journey code is an
explicitly opened, fixed same-origin optional asset with shared frozen host
helpers, a source version and JavaScript/CSS hashes. The measured main gzip is
683,796 bytes (2,284 below the 686,080-byte gate); optional journey JavaScript is
5,697 bytes against a 32 KiB gate. Release checks reject partial, mismatched,
tampered or oversized asset sets. Browser CI builds its production loader fixture
before Playwright.

All walkthrough inputs are labeled synthetic. No source query, Cloud install,
collector/schedule change or notification occurred in this increment. Deployed
source qualification and cross-source journey correlation remain outstanding;
these event cards must not be described as reconstructed end-to-end routes.
