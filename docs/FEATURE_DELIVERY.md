# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

| Feature                                     | Local workflow                                                                                                                                                                  | Evidence and verification                                                                                        | Remaining qualification                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` opens a windowed comparison from a live map; timeline, edge changes, findings, and visible partial-coverage notes are available.                                  | Graph comparisons are based on the returned windows; rules are deterministic. Focused incident-model tests pass. | No current Cloud observation was made. A graph difference establishes a change interval, not causation or an exact event time. Rendered live comparison and source audit event coverage remain unqualified.                                                                                                                                                       |
| Maintenance and failover                    | A conservative assessment model keeps exposure, readiness, health, capacity, failure domains, and substitutability separate and fails closed on unknowns.                       | Focused model tests cover unknown and unsafe alternatives.                                                       | Not connected to a qualified live Impact source. No measured peak-capacity or readiness feed is available; do not use it to authorize failover.                                                                                                                                                                                                                   |
| Dependency baselines and drift              | Baseline eligibility and semantic comparison are implemented as a read-only review component.                                                                                   | Focused model tests cover incompatible or incomplete captures and drift states.                                  | No complete source adapter, durable version history, watchlist persistence, or qualified real-source baseline. The top-N map remains ineligible.                                                                                                                                                                                                                  |
| Investigation records and evidence packages | Shared capture, revision, authorization, and export contracts are documented.                                                                                                   | Contract reviewed independently for correctness and security boundaries.                                         | Dedicated server persistence, per-case authorization, entitlement rechecks, revisions, attachments, audit, and export authorization are not implemented. No durable/shareable case claim.                                                                                                                                                                         |
| Business-service ownership                  | Strict import parsing and preview identify row errors and conflicts; current-only claims remain labeled.                                                                        | Focused import tests, lint, and type checks pass.                                                                | Import preview is not persisted or connected to catalog, Impact, or maintenance. No qualified ownership/criticality feed or vendor adapter.                                                                                                                                                                                                                       |
| NAT, proxy, and load-balancer journeys      | FTD V1/V2 same-event NAT fields are preserved in the bounded summary projection; trace requests require a routing scope and preserve exact loaded graph bounds in device links. | Static SPL and contract tests cover V1/V2, incomplete tuples, caps, and windows; focused trace tests pass.       | No installed Splunk qualification or current Cloud capture. The existing observer-scope collection has no verified historical validity interval, so scoped live observations fail closed; live trace renders a partial gap, not device/vSwitch hops. FTD live emission, Hubble and Envoy deployed contracts, and end-to-end journey rendering remain unqualified. |

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

The local build does not enable case persistence, privileged schedules,
notifications, or infrastructure actions. Install and qualify source changes
only through the repository's reviewed deployment process. Keep V1 summaries
readable; V2 NAT projection changes require rebuilding older V2 summaries
before expecting the new fields. Rollback code independently of retained
summary data, and do not delete existing evidence as part of code rollback.
