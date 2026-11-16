# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

| Feature                                     | Local workflow                                                                                                                                                                                                                                                                                                                                    | Evidence and verification                                                                                                                                                                                    | Remaining qualification                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` opens a windowed comparison from a live map; timeline, edge changes, findings, and visible partial-coverage notes are available.                                                                                                                                                                                                    | Graph comparisons are based on the returned windows; rules are deterministic. Focused incident-model tests pass.                                                                                             | No current Cloud observation was made. A graph difference establishes a change interval, not causation or an exact event time. Rendered live comparison and source audit event coverage remain unqualified.                                                                                                                                                                                                                                                                |
| Maintenance and failover                    | A conservative assessment model keeps exposure, readiness, health, capacity, failure domains, and substitutability separate and fails closed on unknowns.                                                                                                                                                                                         | Focused model tests cover unknown and unsafe alternatives.                                                                                                                                                   | Not connected to a qualified live Impact source. No measured peak-capacity or readiness feed is available; do not use it to authorize failover.                                                                                                                                                                                                                                                                                                                            |
| Dependency baselines and drift              | Baseline eligibility and semantic comparison are implemented as a read-only review component.                                                                                                                                                                                                                                                     | Focused model tests cover incompatible or incomplete captures and drift states.                                                                                                                              | No complete source adapter, durable version history, watchlist persistence, or qualified real-source baseline. The top-N map remains ineligible.                                                                                                                                                                                                                                                                                                                           |
| Investigation records and evidence packages | Notes in the incident workspace capture fixed comparisons and export readable handoffs or explicit versioned evidence packages. The incident workspace now connects to an opt-in authenticated notes endpoint backed by private SQLite cases, revisions, ACLs, retries, quotas, retention and audit; the portable graph handoff remains separate. | Nine local store tests cover authorization, revocation, concurrent writes, retries, quotas, export and retention; portable domain and browser export tests pass. Independent review findings were corrected. | The endpoint ships disabled, supports user-authored notes only, and rejects protected graph captures and attachments on both writes and reads. The direct REST notes workflow passed in the task-owned Enterprise 10.6.0.5 lab using two non-admin investigators. Protected-source entitlement binding, installed browser-proxy qualification, scheduled cleanup and backup/restore remain required. Cloud/SHC are unsupported. Retry state in the browser is memory-only. |
| Business-service ownership                  | Admin Setup exposes strict import preview and explicit browser-local save/clear. Qualified-member annotation logic retains temporal limits, provenance and conflicts.                                                                                                                                                                             | Focused import tests, lint, and type checks pass.                                                                                                                                                            | Browser-local imports are not shared or source-authorized. Catalog, Impact, investigation and maintenance still require qualified member identity bindings and annotation integration. No qualified ownership/criticality feed or vendor adapter.                                                                                                                                                                                                                          |
| NAT, proxy, and load-balancer journeys      | FTD V1/V2 same-event NAT fields are preserved in the bounded summary projection; trace requests require a routing scope and preserve exact loaded graph bounds in device links.                                                                                                                                                                   | Static SPL and contract tests cover V1/V2, incomplete tuples, caps, and windows; focused trace tests pass.                                                                                                   | No installed Splunk qualification or current Cloud capture. The existing observer-scope collection has no verified historical validity interval, so scoped live observations fail closed; live trace renders a partial gap, not device/vSwitch hops. FTD live emission, Hubble and Envoy deployed contracts, and end-to-end journey rendering remain unqualified.                                                                                                          |

## Verification performed

The current local increment passed:

- `npm run lint` (ESLint, both TypeScript projects, and Prettier).
- `npm test` (111 files, 1,250 tests).
- `npm run test:browser` (155 passed, 1 skipped).
- Focused Python checks for qualified rollups, identity search, the previous
  demo compatibility record, path-trace macros, and NAT evidence (68 passed,
  5 skipped).
- `ruff check tools tests` and `ruff format --check tools tests`.
- `npm run package` and `python3 tools/check_release.py`.

The package build reports the main JavaScript chunk above Vite's advisory
500 kB threshold; the repository release-archive check passes. No Cloud query,
shared-instance installation, collector change, schedule, notification, or
failover was performed. The configured Cloud-profile validator returned
`invalid_key` and `unknown_field`; no authentication or Cloud query followed.

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
query occurred; the installed Splunk Web proxy/client, protected source capture,
Cloud/SHC deployment, cleanup scheduling and backup/restore remain unqualified.
