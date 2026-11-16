# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

**Completion status (2026-11-16): the six-feature request is not complete.**
The table records implemented increments and their remaining source, integration
and deployment gaps. Passing local checks does not close those gaps.

| Feature                                     | Local workflow                                                                                                                                                                                                                                                                                                                                    | Evidence and verification                                                                                                                                                                                    | Remaining qualification                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` opens a windowed comparison from a live map with findings and coverage notes.                                                                                                                                                                                                                                                       | Local comparison rules and historical scenarios; see the current bounded [source observations](FEATURE_SOURCE_OBSERVATIONS.md).                                                                              | Current source receipt does not qualify rendered live comparisons, audit-event coverage, retention, causation or exact change time.                                                                                                                                                                                                                                                                                                                                        |
| Maintenance and failover                    | The optional Impact workflow can capture a before state and compare an after state; assessment separates exposure, readiness, health, capacity, failure domains and substitutability.                                                                                                                                                             | Local conservative model and capture workflow; unknown or incomplete evidence fails closed.                                                                                                                  | No qualified live Impact, measured peak-capacity or alternate-readiness feed; do not use the assessment to authorize failover.                                                                                                                                                                                                                                                                                                                                             |
| Dependency baselines and drift              | Local durable version and passive-watch domain engine and injectable review UI support baseline capture and comparison contracts.                                                                                                                                                                                                                 | Local domain and frontend coverage; the top-N map is ineligible as a complete baseline.                                                                                                                      | No qualified complete source adapter or authenticated HTTP host for the engine; no real-source baseline or operational watch scheduling is qualified.                                                                                                                                                                                                                                                                                                                      |
| Investigation records and evidence packages | Notes in the incident workspace capture fixed comparisons and export readable handoffs or explicit versioned evidence packages. The incident workspace now connects to an opt-in authenticated notes endpoint backed by private SQLite cases, revisions, ACLs, retries, quotas, retention and audit; the portable graph handoff remains separate. | Nine local store tests cover authorization, revocation, concurrent writes, retries, quotas, export and retention; portable domain and browser export tests pass. Independent review findings were corrected. | The endpoint ships disabled, supports user-authored notes only, and rejects protected graph captures and attachments on both writes and reads. The direct REST notes workflow passed in the task-owned Enterprise 10.6.0.5 lab using two non-admin investigators. Protected-source entitlement binding, installed browser-proxy qualification, scheduled cleanup and backup/restore remain required. Cloud/SHC are unsupported. Retry state in the browser is memory-only. |
| Business-service ownership                  | Admin Setup exposes strict import preview and explicit browser-local save/clear. Qualified-member annotation logic retains temporal limits, provenance and conflicts.                                                                                                                                                                             | Focused import tests, lint, and type checks pass.                                                                                                                                                            | Browser-local imports are not shared or source-authorized. Catalog, Impact, investigation and maintenance still require qualified member identity bindings and annotation integration. No qualified ownership/criticality feed or vendor adapter.                                                                                                                                                                                                                          |
| NAT, proxy, and load-balancer journeys      | Inspector Flows and Proxy evidence render separate FTD, Envoy and selected-client Hubble evidence with gaps and explicit exports.                                                                                                                                                                                                                 | Local model and browser coverage; current bounded Cloud observations are recorded separately.                                                                                                                | No installed candidate qualification or current journey capture. Observer-scope mapping lacks verified historical validity, so live trace fails closed. FTD real emission, V2 NAT projection, Hubble SNAT/XFF and deployed Envoy logging remain unqualified. Per-source cards do not establish an end-to-end route.                                                                                                                                                        |

## Verification performed

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
interfaces, retention limits and rollout prerequisites. No new baseline HTTP
endpoint or schedule is registered.

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
