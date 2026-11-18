# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

**Completion status (2026-11-17): the six-feature request is not complete.**
The table records implemented increments and their remaining source, integration
and deployment gaps. Passing local checks does not close those gaps.

The user subsequently authorized Cloud app updates for development/validation
(2026-11-17 UTC). This extends the initial local-only deployment scope; it does
not authorize collector/schedule activation or infrastructure changes.

| Feature                                     | Local workflow                                                                                                                                                                                                                                       | Evidence and verification                                                                                                                                                                                                                         | Remaining qualification                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` compares baseline, incident and recovery windows, ranks deterministic investigation leads by observed contrasts, and separates support, counterevidence, missing evidence and the next read-only check.                                                                                                                                                          | Local comparison rules and historical scenarios; see the current bounded [source observations](FEATURE_SOURCE_OBSERVATIONS.md).                                                                                                                   | Observed source samples now support bounded native-parser and traffic-evidence replay; they do not qualify rendered incident comparisons, audit-event coverage, retention, causation or exact change time.                                                                                                                                                                                                                                                                           |
| Maintenance and failover                    | The optional Impact workflow can capture a before state and compare an after state; assessment separates exposure, readiness, health, capacity, failure domains and substitutability.                                                                | Local conservative model and capture workflow; unknown or incomplete evidence fails closed.                                                                                                                                                       | No qualified live Impact, measured peak-capacity or alternate-readiness feed; do not use the assessment to authorize failover.                                                                                                                                                                                                                                                                                |
| Dependency baselines and drift              | Dedicated authenticated storage, version/history review and manual passive-watch evaluation are connected in the incident Connections section. Watch observations and status now show readable dependency identities, distinct windows and explicit pagination limits. Source-backed capture remains unavailable without a trusted complete provider.                        | Local domain and frontend coverage; the top-N map is ineligible as a complete baseline.                                                                                                                                                           | The HTTP host ships disabled/unqualified and has no production source provider. Collector loss, sampling and lateness closure are unproven; The installed disabled/source-unavailable host contract passes; positive source-backed capture/version/watch, Web/CSRF and backup/restore remain unqualified. A disabled explicit-window action and durable run journal now have local synthetic tests; automatic scheduling, provider-backed execution, installed action/session ACLs and administrator provisioning remain unavailable or unqualified. A later disable-only HTTP stop command now manages an existing owned binding; it does not provision or enable one.                                                                             |
| Investigation records and evidence packages | Private shared cases support immutable superseding note/hypothesis/question revisions, source-authorized links from entries to saved comparison captures, per-capture read/export, readable handoffs and explicit JSON evidence packages. Source access is revalidated for each current reader and old retry response. | Domain/API/native/host tests and rendered browser workflows pass. The earlier SDK-based direct REST capture path passed on Enterprise 10.6.0.5 using two non-admin investigators with identical index grants and different search filters, including a second capture. Later local Web HTTP checks pass notes, native CSRF and case ACLs; the 0.9.8 rendered Cases notes workflow also passed. Source-backed Web workflows remain unqualified. | Persistence and capture mode ship disabled. Raw comparison windows are limited to five minutes each; source retention/configuration changes can withhold evidence while notes remain usable. Native 0.9.11 synthetic management-REST capture and source-filter/index revocation checks passed with separately reconciled cleanup; Mac Rosetta helper execution remains unsupported. Later native qualification records below separately cover bounded synthetic worker interruption, service restart, selected real-source observations and injected isolated endpoint restore. Protected-capture Web/rendered-client behavior, source completeness, strict whole-endpoint bounds, arbitrary file uploads, cleanup scheduling and operational production restore remain unavailable or unqualified. The separate same-build cold notes/ledger recovery rehearsal passes locally. Cloud/SHC are unsupported; browser retry state is memory-only. |
| Business-service ownership                  | Admin Setup validates versioned claims and separate technical bindings. Catalog, Map, incident and Impact/maintenance entrypoints show imported ownership with explicit native identity references, temporal limits, provenance and conflicts.       | Strict import/binding/mapper tests and synthetic browser checks validate exact tuples, unknown/stale contexts, conflict retention and explicit native-reference exports.                                                                          | Browser-local assertions are not shared, source-authorized or verified business feeds. Native provenance is available only from matching qualified raw reads; legacy/summary-only catalog/maps and IP/name-only Impact evidence remain unresolved. No qualified ownership/criticality vendor adapter.                                                                                                         |
| NAT, proxy, and load-balancer journeys      | Inspector Flows and Proxy evidence render separate FTD, Envoy and selected-client Hubble evidence with gaps and explicit exports.                                                                                                                    | Local model and browser coverage; current bounded Cloud observations are recorded separately.                                                                                                                                                     | A bounded sanitized observed Hubble sample now passes native normalization and existing evidence rendering; it is not a connected journey capture or installed candidate qualification. Observer-scope mapping lacks verified historical validity, so live trace fails closed. FTD real emission, V2 NAT projection, Hubble SNAT/XFF and deployed Envoy logging remain unqualified. Per-source cards do not establish an end-to-end route.                                                                                           |

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

## Final acceptance corrections

Incident leads now use stable, deterministic evidence ordering. An explicit
same-connection permit-to-drop observation ranks ahead of differences needing
corroboration; pre-existing drops supply counterevidence to a new-blocking
explanation. Unknown baseline state is not treated as a permit. Coverage remains
separate, and failed comparisons clear prior results. Supporting observations
are capped and progressively disclosed. These remain investigation leads, not
causal or probability claims.

Manual watches decode the exact versioned dependency identity tuple and show
authorized recurrence status. The later read-derived classification increment
below adds server-derived change kinds from retained captures. Older responses
remain generic; the browser never invents a new/blocked/removed classification
from the current graph. Page counts describe loaded observations, not totals;
no evaluation, schedule or notification is enabled automatically.

Case entries can supersede the latest same-type entry in the same case. Old
text, author and time remain immutable; case revision and idempotency checks
reject stale branches. Explicit saved-comparison attachments contain only an
entry/capture association, with source proof before admission and again on
read/export. Unavailable source evidence withholds the association. Arbitrary
files, URLs and browser-supplied source rows are unsupported. Independent review
found and resolved a receipt-cleanup race that could otherwise skip attachment
admission proof.

The source transport now supervises a short-lived helper with bounded input,
response bytes, deadlines, CPU and address space. Explicit loopback TLS trust
and the hosting instance GUID bind requests and durable cleanup state. Local
intent IDs are distinct from server-assigned job IDs. Unknown creation responses
are never guessed or retried, and remain charged to the three-job global quota.
The helper receives no token in arguments, environment or files. A token-free
runtime preflight runs before capture availability or job-intent allocation.

Two installed attempts against archive
`0b751a5eb9a8bf53297292fb9529cf50d8d18d8d8b55e49c2e4fc23c41e9e92c`
failed qualification: protected capture remained unavailable, and the reordered
runtime check showed that the emulated Linux/amd64 runtime could not apply the
256 MiB address-space contract. Inspection also found the embedded Python needs
its own trusted library directory; the loader-path correction derives that path
from the running installation rather than inheriting loader settings. The
memory limit was preserved. These failed attempts do not qualify the new source
path, and the earlier successful SDK-based capture run below does not qualify
its replacement.

## Current installed notes and runtime boundary

Archive `432647436a63cf598699e4f8a2c4e5be35870b8ed31419b6b3f777c4f4538d57`
passed two installed tests on the task-owned Enterprise 10.6.0.5 lab: notes,
immutable entry revisions, stable retries, stale-branch rejection, sharing,
revocation and deletion; and unsupported-helper preflight with notes still
available and no search-job ledger created. This qualifies the negative runtime
boundary, not successful source capture or installed attachment admission.
The exact container ID, 67 Python-file hashes, three runtime configuration
hashes, test hashes and TLS checks are recorded in
[qualification evidence](FEATURE_QUALIFICATION.json). Those hashes pin that earlier archive's runtime/configuration bytes. The
later baseline read-classification change is separately recorded; that
installed run does not qualify every byte of the current package. The disposable resources and ports were checked
absent after purge, along with generated credentials and TLS material.

Local checks cover entry revision chains, source-authorized reference admission,
revocation and retries, receipt disappearance, cross-case draft recovery,
malformed watch signatures, evidence ranking and cancellation. Independent
review findings were resolved and rechecked. Astra accepted the reviewed
synthetic incident, watch and case states at 1440/320 pixels in light/dark;
screenshots are engineering evidence, not customer research or real-data replay.

Final consolidated checks passed: frontend lint, 125 Vitest files / 1,329 tests,
194 browser tests with one skipped, 93 case Python tests, 58 release tests, Ruff
and packaging. An earlier browser run found an ambiguous text locator introduced
by the attachment entry selector plus two navigation interruptions while source
edits were still occurring; the locator was scoped to the entry list and the
whole suite passed with application files stable. Main bundle gzip is 685,331
of 686,080 bytes; the optional journeys bundle is 31,667 of 32,768 bytes. Neither
limit was raised.

## Observed-source replay and offline restore increment

A bounded read-only source session retained four Hubble records and four pod
records with explicit windows and cleanup checks. The sanitized allowlisted
sample now passes the production native normalizer and observation projection;
the existing traffic-evidence component renders it in the real Shell themes.
Source details, tuples, verdicts, reply/direction, event and receipt times,
non-authoritative counters and unknown coverage remain visible. Long
fingerprints wrap at narrow widths, singular record counts read correctly, and
Inspector evidence timestamps explicitly use UTC. See
[source observations](FEATURE_SOURCE_OBSERVATIONS.md) and the
repository-only transformation manifest at `fixtures/feature-replay/manifest.json`.
Replay records and keys are not bundled into the live app; the archive contains
the qualification record.

Independent sanitizer review corrected cases where canonicalizing an invalid
IP or replacing an invalid identity token could otherwise make rejected input
look valid. Those inputs now fail before pseudonymization. This sample does
not establish complete identity history, readiness, capacity, dependency
coverage or a selected-client handoff; it cannot make the six-feature request
complete by itself.

The separate synthetic offline SQLite rehearsal passes case/history/ACL/audit,
retry and source-redaction checks, baseline watch/version/deduplication checks,
and preservation of unknown creation and cleanup slots after a same-build copy.
It does not establish cross-database atomicity, live backup, downgrade safety,
Splunk deployment recovery or native job reconciliation. Operational restore
remains unqualified; see [backup/restore scope](BACKUP_RESTORE.md).

This increment passed 27 focused Python tests, the full 125-file / 1,329-test
Vitest suite, frontend lint, Ruff and the full browser suite (198 passed, one
skipped). Astra accepted all four sanitized-source replay renders in real Shell
themes; independent review found no remaining issues. Gzip bytes are 685,364 for
the main bundle (limit 686,080) and 31,667 for the optional journeys bundle
(limit 32,768). The qualified scope remains bounded source normalization and
rendering plus synthetic offline SQLite-copy behavior.

## Classified watch observations

Occurrence pages now show server-derived change kinds and the watch's pinned
baseline version. The server compares authorized retained snapshots and applies
the same rules as the existing comparison model; it does not infer a change
from the current graph. Newly observed/related dependencies, explicitly newly
blocked dependencies, fewer observed failure domains and “not observed” remain
distinct. A dependency can have two labels in one window, but recurrence still
counts that window once. The status explains that counts span all qualifying
change types. Missing/incompatible evidence or an impossible classification
fails closed; legacy responses without classification remain generic.

Independent review found and resolved a page-by-baseline memory expansion:
reads now load each distinct capture once, prepare baseline indexes once and
derive only requested signature labels per comparison, including lookahead. Tests exercise a 10,000-dependency
baseline and 100 distinct captures, pinned versions, source denial, concurrent
access/revision changes, classification boundaries and unchanged retry receipts.
No schema, provider, collection, schedule, notification or eligibility gate was
changed. The source-unavailable default and positive installed baseline gaps
remain in force. These labels have local synthetic store/API and browser
qualification; the modified baseline runtime has not received positive
installed source qualification.

This increment passed 32 focused store/API tests, 42 combined baseline/host/
SQLite-restore tests, full frontend lint, 1,331 Vitest tests and the full browser
suite (198 passed, one skipped). Ruff and package/release checks passed. Main
bundle gzip is 685,367 / 686,080 bytes; optional journeys is 31,922 / 32,768.
The earlier installed archive's baseline store fingerprint is superseded by
this locally verified implementation; its installed results are not extended
to these new source-derived labels.

## Earlier installed qualification with verified TLS

The earlier backend passed three installed checks across two sequential fresh,
task-owned Enterprise 10.6.0.5 single-head labs against archive
`21245b2804474d654d504b05a4f98c4db0f1fb3f6a167aec68ce6d8d416302a9`:

- Baseline endpoint: disabled defaults, capability access, source-unavailable
  behavior, empty metadata list, private owner-only SQLite storage, duplicate
  headers/query rejection, media validation and public purge denial.
- Shared notes: creation, idempotent retries, explicit sharing and
  revocation through the installed management endpoint.
- Protected evidence: two non-admin callers with identical index grants and
  different search filters, independent captures, selected read/export,
  revocation, old retries, changed source configuration and retained notes.
  Native output includes the new `attr_service` and `identity_context` fields.

Management and HEC verified their private CA and hostname with TLS 1.3 before
and after installation; wrong-CA and wrong-hostname handshakes were rejected.
The lab tooling now stages private certificates before first startup, pins the
exact container ID/image, disables the image's insecure health command, waits
for bootstrap completion and uses verified, proxy-free, redirect-free clients.
37 focused tooling tests, Ruff, shell syntax and independent review pass.

The initial run exposed premature readiness before bootstrap completion; a
later staging check correctly refused an archive whose companion checksum had
not been copied. The evidence fixture also refused the general host-test task
identity before setup, then passed in its required isolated task. These were
qualification setup failures, not successful feature checks. All attempts were
purged. The two successful endpoint runs' containers, networks, volumes, ports,
credentials and temporary TLS material were independently confirmed absent.

The baseline checks qualify the disabled/unavailable contract, not a complete
source adapter or working source-backed baseline. They do not qualify Splunk
Web/CSRF, Cloud/SHC, backup/restore, hard SDK transport bounds or current real
collection. The full six-feature request remains incomplete. Exact test and
packaged Python hashes are in [qualification evidence](FEATURE_QUALIFICATION.json).

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


## Explicit-window watch execution increment

The private executor now binds one authenticated administrator/owner to one
watch, pinned baseline, exact four-field selection and provider contract. It
uses a separate bounded journal before capture and retains uncertainty, original
binding revision, capture digest, baseline CAS revision and idempotency key.
Retries never automatically recapture, rebase, adopt changed evidence or clear
unknown work. The disabled action accepts only one explicit absolute window and
returns a generic acknowledgment; it supplies no owner-context findings to viewers.

Independent review identified and corrected mutable-reference retries, a
disable/re-enable fence gap and remote authorization under the SQLite writer.
Local host tests exercise real stores with a synthetic injected provider and
verify that authorization callbacks run outside write transactions. No UI was
added; the prior rendered UI acceptance remains scoped to its unchanged build.
Astra accepted the architecture and wire parsing, with explicit qualification
limits. See [execution contract](DEPENDENCY_WATCH_EXECUTION.md) and
[qualification evidence](FEATURE_QUALIFICATION.json) for exact checks.

No production complete provider is shipped. Actual installed Splunk action
invocation, effective action/session ACLs, reviewed administrator provisioning,
source watermark/lateness closure, global transport enforcement and operational
journal recovery remain unqualified. No schedule was created or enabled, no
notification was sent, and no Cloud or infrastructure operation occurred. This
increment does not complete the six-feature request.


## VPN lab native worker check

The newly reachable heavy forwarder runs Linux x86_64 and Splunk Enterprise
10.6.0.5. The exact packaged capture worker passed its token-free preflight under
embedded Python 3.13.11 in 81 ms with the unchanged 256 MiB address-space limit,
10-second CPU limit and disabled core dumps. The expected framed ready response
was verified; its task-owned temporary file and directory were removed. This
supports native interpreter compatibility as the SSH operator, including SSL
initialization and representative bounded allocation, without installing Atlas
or using a Splunk session/token. It did not execute as the Splunk daemon user;
the external three-second driver was separate from the production parent.

The separate standalone Enterprise lab remained unreachable in a bounded SSH/TCP
check. Atlas is absent from the reachable forwarder, and the bounded verified
localhost TLS check did not establish a valid connection. The worker result is
not an installed capture qualification, a production-parent deadline measurement
or evidence of complete source coverage. No existing service, certificate,
collection, Docker resource or source configuration was changed.


## Installed Cloud read-only walkthrough

The user-selected Cloud host matched the canonical Cloud profile and passed
verified HTTPS metadata requests. It reports Splunk 10.6.0.5 and Atlas 0.8.6,
but this does not establish equality with the local candidate. Candidate case
and baseline capability routes and handler-configuration lookups returned 404
in the current API session. No candidate installation or Cloud configuration
change was performed; Cloud persistence remains outside the qualified contract.

In the user-authenticated browser, a fixed five-minute window exercised Explore,
Device and a conversation-to-Map trace. Application discovery and scope options
reported incomplete qualified identity evidence. A device page loaded traffic;
the selected conversation trace displayed 1,889 records with fabric interconnects
explicitly inferred. The recent window retained its incomplete-window warning.
Those observations do not establish complete application identity, readiness,
capacity, NAT/proxy correlation or acceptance of the six new features. Screenshots
remain private outside Git; Astra reviewed the discovery/trace state and noted
the limited 850-pixel viewport.

The installed Explore device form dropped its URL time bounds. The current local
URL-preservation case already has a regression, while this walkthrough exposed
a related local gap after changing the picker: current React bounds were not
used for Device Lookup. That local fix preserves the picker selection and other
navigation context, with a browser regression checking exact destination and
Impact bounds. It does not change the Cloud installation.


## 0.9.0 development candidate

The current picker selection now follows Device Lookup even when the URL contains
an earlier window, and the same absolute bounds reach Impact. Mobile controls
and the table remain within the page; all time-picker panels fit narrow and short
viewports, and their styles apply only to Atlas-owned dialogs. The evidence table
retains its own horizontal scrolling with a descriptive keyboard-focusable region.

Validation passed: 1,331 Vitest tests, 202 browser tests (one skipped), full lint,
69 release/build/report tests, Ruff and package/release checks. One broad browser
run found a test locator ambiguity after the accessible scroll region was added;
an exact outer-region locator fixed it and the whole suite reran cleanly. Astra
accepted 14 synthetic light/dark renders; independent source review found no
remaining issue in this navigation/layout increment. Bundle gzip remains below
the unchanged main and optional asset limits.

Before Cloud installation, a private paginated snapshot reached all 19 requested
metadata sections and all 15 discovered KV collections (99 pages, 5,000 rows).
This live capture is not quiescent, atomic, a raw local-file backup or a verified
restore. No customer rows or credentials are committed. Cloud vetting and install
results remain separate pending evidence; the Enterprise-only persistence and
complete-source gates have not been relaxed to fit the Cloud environment.


The frozen 0.9.0 upload archive SHA-256 is
`b1f8accf9ea53d78fb73fdfd56eca48d833eefef8bb9112dc546160f5bb90ab7`.
A reviewed, target-bound ACS private-app installation attempt returned exit 1;
the prior local ACS context was restored. Subsequent API/ACS reads reported
installed 0.8.6. The user then uploaded the exact package through Cloud Web.
Its private_victoria AppInspect 4.4.0 report returned 139 successes, one failure,
zero errors, six warnings, 100 not-applicable and one skipped check. The blocking
check requires reload declarations for `adm_investigations.conf` and
`adm_baselines.conf`; no install occurred. The report response was bound to the
archive SHA-256. Raw HTML and screenshots remain private outside Git.

The 0.9.1 revision adds the missing reload declarations and release validation;
it does not relax persistence/source gates or bypass inspection. The existing
0.9.0 artifact is preserved separately. The revised archive SHA-256 is
`81b00cb5b02fe52594aee49a45d29517ae967c26138d260bd4ba4b457dc5b2d6`.
All 60 release tests, 10 build/report tests, Ruff, packaging and archive checks
passed. The three frontend assets are byte-identical to the tested 0.9.0
candidate. Cloud validation is pending; this later evidence documentation does
not change the frozen archive.

Read-only vCenter navigation exposed a native VM identifier and its current
relationship to a native distributed-portgroup identifier. This is current
controller evidence only: it does not associate the historical Cloud trace with
that object or prove application ownership, capacity or readiness. The APIC
session expired from inactivity, so no authenticated APIC validation is claimed.
Private identifiers remain outside Git.


## Installed 0.9.1 Cloud validation

Cloud Web approved the exact 0.9.1 archive with AppInspect 4.4.0 private_victoria:
140 successes, zero failures/errors, six warnings, 100 not-applicable and one
skipped check. The report response identifies the frozen archive SHA-256.
Installation succeeded on the logged-in search-head target; the API subsequently
reported version 0.9.1. No whole-stack propagation or platform restart behavior
is claimed. No manual restart or role grant was requested.

The post-update paginated capture reached all 19 metadata sections and 15
collections. All 24 saved searches retain their full semantic configuration and
ACLs; all 15 collection schemas and ACLs match. Two macros were added and three
changed. The affected definitions match the frozen candidate after continuation
and whitespace normalization, but historical layered provenance is unavailable:
the prior definitions cannot be identified as customized overrides or older
shipped defaults. The protected pre-update values remain available outside Git.
There were no missing captured KV keys, eight added rows and 19 changed rows.
These live, paginated observations do not prove atomicity, cause, continuous
consistency or successful restore. New persistence/execution gates remain off.

The serving page's CSS matches the package exactly. Its JavaScript contains a
111-byte Splunk localization preamble followed by the exact packaged payload.
Explore-to-Device navigation preserves the explicit window; changing the picker
preset uses the new absolute bounds despite an older URL and passes those same
bounds to Impact. The known five-minute Device view again displayed 1,160 flows,
39 peers, 154 rows and 42.8 MB. These displayed metrics do not establish source
completeness or capacity. Catalog identity remains incomplete. Case and baseline
capability routes return 403 to the API identity; grants were not expanded, and
Cloud persistence is still unsupported.

Installed testing also found additional UI work: valid Advanced previews cannot
be applied without the toolkit's explicit null success value, the Cloud body's
960px minimum width clips an 850px viewport, and the selected absolute window
needs a visible timezone label. These are follow-up fixes, not behaviors
qualified by the 0.9.1 installation. The Cloud Control header also logs its own
module/navigation errors; those are recorded separately from Atlas's source
identity failure.


## Installed 0.9.2 Cloud validation

The Advanced time picker now accepts validated preview success using the null
value required by the pinned Toolkit. Live previews must contain the exact
requested key and a valid timezone-qualified ISO timestamp; unrelated or malformed
200 responses remain errors. Device shows its resolved selected window in UTC,
including during loading. The app-owned body rule removes Splunk's 960px minimum
only while the Atlas mount exists, keeping the Filter and table shell visible
beside the simulated Cloud sidebar. The table retains horizontal scrolling.

The trusted watch manager can stop an owned binding after source access,
provider or execution configuration becomes unavailable. It authenticates the
current administrator and immutable binding principal, applies revision CAS,
returns no retained definition and never bootstraps/recreates a journal. It
preserves unknown runs and quotas. Existing work in flight may still finish.
Creation, enabling and execution retain full source/owner checks. This exposes no
management HTTP/UI and does not add the missing complete source provider.

Local validation passed 1,334 unit tests, 209 browser tests (one skipped), 161
baseline/release/build/report Python tests, Ruff and the frontend build. Existing
baseline test helpers still emit ResourceWarning under Python 3.15. Two earlier
browser runs each found one assertion issue: a hidden option with the saved
note's text and a pointer click racing an accordion transition. The final full
run passed after semantic targeting and a transition-readiness assertion.
Independent review has no remaining findings; Astra accepted the six corrected
synthetic layouts. Main and optional journey assets retain their unchanged gzip
limits. The frozen 0.9.2 archive passed packaging and release validation with
SHA-256 `820dd27c93d687493b002c21fed4bf395b458dfed7234678cc1142cab52a94d7`.
Package identity and subsequent installed evidence were recorded after the
archive was frozen; these documentation updates do not change its bytes.

Cloud AppInspect 4.4.0 private_victoria approved that exact archive: 140 successes,
zero failures/errors, six warnings, 100 not-applicable and one skipped check.
The Web installer succeeded on the logged-in search head and the API reports
0.9.2. No whole-stack propagation, manual restart or role change is claimed.
The served JavaScript has a 111-byte Splunk localization prefix followed by the
exact packaged payload; served CSS matches the archive exactly.

The installed Advanced picker accepted and applied the absolute window
2026-11-17 02:17:00–02:22:00 UTC. Opening Device preserved those exact bounds and
showed the UTC window. At an actual 850px Cloud viewport, Atlas has 654px available;
the Filter fits and the table scrolls within its own container. At 320px, native
Cloud navigation and gutters leave Atlas only 124px, and the page content
overflows. That host-width boundary remains unsupported in this build and needs
a separate app-owned minimum-width guard; no native Cloud navigation is hidden.
Catalog identity remains incomplete. Case and baseline capability routes still
return 403 to the API identity, and Cloud persistence remains unsupported.

The bounded post-update capture completed 99 pages, all 19 metadata sections and
15 collections. Compared with the 0.9.1 capture, all 24 saved searches, 15 collection
schemas, 263 macros and three REST handler configurations retain their semantic
content and ACLs. Three app.conf stanzas changed; other captured configuration
matches. Captured KV rows increased from 4,662 to 4,677: 15 added, 17 changed and
none missing. Cases, baselines and watch execution remain disabled/unqualified.
These paginated observations are not an atomic backup or restore test and do not
establish the cause of intervening row changes.


## 0.9.3 mount-width follow-up

Atlas now measures its own available width. Below 320px it shows a short request
to widen the window while retaining Atlas navigation and leaving native Cloud
navigation untouched. Page components remain mounted, preserving case and page
drafts. Open Atlas time, scope and glossary popups close; pending time previews
cancel without committing edits. Focus moves from page-owned controls to the
notice, while external controls and Atlas navigation retain focus. Resizing does
not dispatch new source or case requests. At 320px of available app width, normal
content remains supported; a 320px Cloud browser leaves only 124px and receives
the notice. Independent Cloud header overflow remains outside this app guard.

All 1,334 unit tests and 212 browser tests pass (one skipped), as do lint and the
production build. The first full browser run found seven standalone test pages
with default body margins that reduced their app mounts to 304px; their margins
now match the production preview. All 27 affected-suite checks and the final
full run pass. Independent review found no remaining product issues. Astra
accepted the eight rendered layouts and reviewed popup, focus and draft behavior
from source and regression evidence. This is local acceptance; Cloud 0.9.2 remains
the installed, qualified archive until this revision is inspected and installed.

Release/build/report checks passed 71 Python tests. Their runtime-allowlist test
now imports its lab client with the sibling module path and patches that object,
so it runs independently under Python 3.15. Ruff passes for this test-only fix.
Packaging and archive validation passed. The frozen candidate is 1,379,984 bytes,
SHA-256 `cb6252423147875dd6384af1df48505e480105819fa3e3095ca35ee75fcb3440`
(build 1794893171). These final results and package identity were added after
archive freeze and do not alter its bytes.


Cloud approved and installed that exact 0.9.3 archive on the logged-in search
head. AppInspect 4.4.0 reports 140 successes, zero failures/errors, six warnings,
100 not-applicable and one skipped check. The report response is bound to the
archive hash; served CSS matches exactly, and served JavaScript is the exact
packaged payload after the 111-byte localization prefix.

Installed checks at 850px show a 654px Atlas mount, contained Filter and table
scrolling. Shrinking an open time picker to a 320px Cloud viewport leaves a 124px
Atlas mount: the popup disappears, focus moves to the visible width notice and
Atlas navigation remains present. Atlas scroll width equals its 124px mount;
widening restores the Device view with the same UTC bounds. This handles the
unsupported width gracefully; it does not make the full Cloud investigation UI
phone-sized or fix native Cloud header overflow. Draft and scope-popup regressions
are local browser evidence, not Cloud persistence qualification. The complete
preservation capture was not repeated for this frontend-only revision; the
preceding 0.9.1→0.9.2 comparison retains its stated limits.


## Main CI repair and operator stop increment (0.9.4)

Remote main was re-fetched at `577250bf35409ef703e6d0b3c30bd1272c8576ea`.
GitHub run `44024751893` authoritatively failed two 320px ownership browser
checks and Python task-lab fixtures; frontend checks passed and installed Splunk
integration was skipped. The original checkout and its protected `.gitignore`
addition and presentation remain outside this clean continuation worktree.

The retained Linux Chromium trace reports 327px at a 320px viewport. A disposable
local Linux/amd64 Ubuntu 24.04 Playwright 1.64.0 reproduction with DejaVu Sans
returned exactly the same width. The unopened maintenance evidence button was
302.59375px wide at x=24 inside Impact's 272px content area. Its `nowrap` label
expanded the implicit grid column and the ownership content. The shared optional
evidence trigger now wraps and stays within its container before optional CSS
loads. No document overflow mask, width-assertion relaxation or platform-specific
font substitution ships. The reproduction now measures 320px, with the button
272px wide and right edge 296px. All four light/dark 320/1440 layouts were
rendered and inspected. The two new regressions exercise enlarged font metrics,
actual button/text geometry, keyboard opening and focus in the loaded region.
This is synthetic local browser evidence, not installed Cloud validation.

Python ownership fixtures now create private temporary task TLS and exact recorded
container/image/healthcheck identity. The copied shell workspace includes
`lab_tls.py`; valid synthetic credentials let it reach foreign-label refusal.
Every lifecycle action still refuses before mutation, leaving credentials intact.
The test imports its sibling dependency explicitly even when run alone. No
production TLS, ownership, daemon or mutation guard changed.

A narrow authenticated POST stop command now exposes the previously trusted-only
watch stop manager. It checks the current administrator and immutable binding
principal, uses revision CAS, opens only an existing valid private journal and
returns only binding ID/revision/disabled state. It runs independently of source,
execution and persistence readiness. Local tests retain an uncertain run and
its quota record while stopping. It adds no provisioning, enable, list, search,
notification or schedule operation. A lost successful response can make a retry
conflict; operator reconciliation remains necessary. See
[the exact stop contract](DEPENDENCY_WATCH_EXECUTION.md#operator-stop-command).
This is implemented management software; installed Web/CSRF/effective-ACL
validation remains unperformed. The production complete-source provider and
operator provisioning workflow are still missing software.

Versions are consistently 0.9.4 for the changed candidate bytes. Cloud 0.9.3 is
the last installed qualification from the earlier record; this increment has
not been deployed. GitHub again reports zero self-hosted runners. No native
Linux/amd64 Splunk target, source contract, credential/VPN access or current
Cloud state is newly qualified by the disposable Linux browser run. No shared
forwarder workload or private native-lab draft was executed.

Rollback removes the stop HTTP exposure and restores the prior application
assets together while preserving all case, baseline and watch-run databases.
Disabling a binding never clears uncertainty or retroactively cancels admitted
work. Keep execution and persistence defaults disabled. The six-feature request
remains incomplete: audit/application binding, measured maintenance inputs,
complete-source provider, provisioning, native supervised capture and recovery,
business feed/persistence, and connected real-source journeys remain open.


Local checks passed with Node 22.16.0 and Python 3.13.14: `npm run lint`,
`npm test` (126 files, 1,334 tests), `ADM_BROWSER_PORT=4175 npm run test:browser`
(214 passed, one skipped), and 11 focused ownership browser tests under Linux
Node 22.13.0/Chromium 156 with DejaVu Sans. Python full discovery passed 1,319
tests after final principal-binding corrections; distributed discovery passed 126; upgrade discovery passed 18 with three
skipped. Standalone task-lab tests passed 11. Ruff check/format passed (238 files).
One earlier full Python run during simultaneous browser load hit an existing
100ms SQLite busy timeout in the journal race test; that test passed in isolation
and unloaded full discovery passed. A worker discovery during active release
edits used inconsistent inputs and was superseded. No lock timeout, assertion or
security gate was weakened. Existing SQLite ResourceWarning messages remain.


Independent read-only GPT-6.1 Sol review has no outstanding findings. The
coordinator bound stop management to the original authenticated principal rather
than accepting a newly returned identity. Review then found that its first
regression lacked the investigator capability and rejected before exercising that
change. The corrected test proves multiple context reads and no mutation; a
second test prevents a retained manager from switching to another owner. Both
regressions detect the previous unbound manager in a temporary mutation check.
The final 53 focused host/executor/journal tests passed, including 19 watch-host
tests independently rerun by the reviewer. Pinned Luna workers owned the fixture
repair and bounded stop-route files; integration and final verification remained
with the coordinator. Installed Web/CSRF and source qualification were not tested.


The contribution report uses Node zlib gzip level 9, while the unchanged archive
release gate independently uses Python gzip level 9. For this local final-script
payload, Node 22.16.0 measures 686,533 bytes and Python 3.13.14 measures 683,034
bytes against the gate's 686,080-byte limit. The file is the same 2,672,251 bytes;
the discrepancy is compressor/runtime behavior, not an intermediate build or
changed threshold. The contribution report now identifies its compressor/runtime
and diagnostic-only role explicitly. Its negative Node headroom is retained;
release acceptance remains the separate Python archive check. Neither limit nor
compression level changed.


Final packaging, archive integrity and three packaged-bootstrap/security checks
passed. The frozen local 0.9.4 candidate is 1,387,764 bytes, build `1794930346`,
SHA-256 `3c32906f5442e50acabe9b7135d9a475a66fca8475e84dd564961ccd2ad663b1`.
Local AppInspect 4.3.1 precert Cloud checks passed: 139 successes, no failures or
errors, six warnings, 100 not-applicable and one skipped. This is offline
inspection, not Cloud approval/installation. The final runtime files match the
archive. Package identity and these results were recorded after freeze; the
later record edits do not change its bytes. CI will build a separate timestamped
archive, which must not be confused with this frozen local artifact.


The remaining blockers have different kinds. The complete provider, operator
provisioning, and whole-endpoint supervision covering ordinary authentication
and configuration SDK work are missing software, not merely unrun tests. Exact
historical audit/application bindings, maintenance measurement semantics,
business-feed authority and connected-source mappings need verified source
contracts. Positive supervised capture, installed Web/CSRF/ACL, revocation and
recovery need a supported task-owned native target; none was established here.
A later bounded native-access probe validated the canonical Enterprise profile
locally but its SSH TCP port timed out after five seconds. Authentication was not
attempted, VPN state was not established, and prior image observations remain
historical. No remote command or mutation ran. Cloud/SHC persistence is unsupported by design;
no guard or role boundary was removed to bypass that limitation.


PR [#25](https://github.com/chambear2809/splunk-adm/pull/25) first ran CI against
`cbde1847f8ae9191491d2e71276dccd8efcaed8f` in run `44118432669`. Frontend checks,
packaging/release/AppInspect, Ruff and Python passed (1,319 discovery tests with
two skipped, 126 distributed, and 18 upgrade with three skipped). The original
two ownership width failures passed. Browser results were 213 passed, one failed
and one skipped: another existing strict text assertion matched the revised note
both in its entry and in an attachment option. The follow-up test waits for the
option projection, then targets the visible entry by its exact Edit note action
and checks revised text/author. Draft, history and identical retry assertions
remain. Product runtime bytes did not change. All four affected tests passed on Mac and Linux Node22.13/Chromium, and lint
passed. The Linux harness uses a loopback origin to retain the same secure-context
browser APIs as CI; an initial non-loopback proxy attempt timed out three tests
before that environmental difference was corrected.
Independent review found no issues in this test-only correction. Follow the
[final checked-head status](https://github.com/chambear2809/splunk-adm/pull/25/checks)
for the subsequent complete run; the earlier failed run is not reported as green.

## Enterprise native staged transport follow-up

After the user reported restored VPN/instance access and selected the configured
Enterprise lab, pinned SSH authentication succeeded. Read-only inspection found
Linux/x86_64, installed Splunk files version 10.6.0.5/build 86587d4e3b27, embedded
Python 3.13.11 with OpenSSL 3.5.8, and SHC disabled in btool. Atlas was 0.6.0
at that staged observation; there was no Docker CLI/socket. No ADM saved search was scheduled/enabled in the
app-merged btool view, and the new case/baseline storage directories are absent.
The management certificate has no SAN. These are bounded host observations, not
authenticated Splunk API/license/source qualification or proof of a disposable
lab. The shared HF and Cloud were not modified.

The exact `transport.py` and `transport_worker.py` from CI main archive
`dc9f501c4cb600f65db79ac6f13ea68b0fb10ed5dee97a22511d6512af53e2e4` were staged in a
private temporary directory. The actual token-free supervisor preflight passed
in 0.119291 seconds under the embedded native interpreter. It used the unchanged
256 MiB address-space contract. Its constructor was bypassed for this token-free
probe; no trust file, real session token, peer or search was used. This establishes
native helper startup/resource compatibility, not installed capture.

A subsequent staged suite used that archive's real package initialization,
store and two transport files, plus the current test fixture. All 12 transport
regressions passed with the native memory limit and no platform-limit fallback:
valid local TLS, wrong hostname, unrelated valid CA, large CA snapshots, bounded
bodies/deadlines/IPC, token argument/environment isolation, and child reaping.
The new CA regression first proves the alternate matching-host certificate works
when trusted, then rejects it under unrelated trust. Some unit branches use
explicit mocks as before; actual native TLS workers did not mock resource limits.
No real Splunk session credential or source job was involved. The suite took
2.770 seconds (3.167608 including post-run checks), with zero remaining test
threads/child processes and private staged material removed. Exact source/test
hashes and probe hashes are recorded in the qualification JSON.

Initial native attempts found fixture portability issues rather than a transport
failure. The system OpenSSL 3.0.13 CLI loaded Splunk's 3.5.8 libraries under the
inherited loader path and crashed during certificate generation; a controlled
comparison passed with that path removed. Only the fixture's external OpenSSL
commands now omit it. The SSH process umask 0002 also created mode-0664 CA files,
which the unchanged production guard correctly rejected. Fixture certificates
and keys now use explicit 0600 modes, and cleanup is registered before generation.
The final native run passed without weakening TLS, memory limits or file guards.
A diagnostic probe reporting bug during setup failure was also corrected outside
Git. Later/final probes disabled core dumps; no real credentials were supplied.

The final staged suite took 2.596 seconds. Its receipt is `work/native-tls/result.json` in the private task workspace outside Git:
the comment-only source change was rerun once natively and passed all 12 tests;
the final receipt sequence elapsed 2.987447 seconds. The exact test-source hash
is `c6b17fa9882bd9762617f22d367b7d54d54d36493803149cd3fa0fe091af25f1`.
This final receipt supersedes the earlier staged timing observation.

This advances **staged native transport component qualification**. It does not
qualify installed endpoints, establish current capture through Splunk, or qualify
Web/CSRF, ACLs, source revocation, whole-endpoint bounds, restore or real-source
comparisons. Installed Docker-only test guards remain intact. Full installed
tests require a verified loopback-TLS plan and separately authorized temporary
test identities; no role grants, schedules, jobs or notifications were performed
in this staged observation.

Local follow-up checks passed 12 focused transport tests and full Python discovery
(1,320 tests run, OK with two skipped under the unbuilt-frontend convention), plus Ruff
check/format for 238 files. The desktop's platform fallback remains separate from
the native run, which used no memory-limit bypass. No UI or production runtime
source changed; the tested archive remains frozen. Rollback of this test-only
increment requires no data/configuration change. Full installed qualification
still needs verified TLS and a separately reviewed test-identity plan; do not
remove Docker task-ownership guards or grant roles to make a test run.

## Authorized Enterprise lab update to Atlas 0.9.4

The user explicitly authorized updating the selected Enterprise lab from Atlas
0.6.0 to 0.9.4; no preservation step was required for this disposable lab.
The frozen CI archive was `dc9f501c4cb600f65db79ac6f13ea68b0fb10ed5dee97a22511d6512af53e2e4`,
1,392,502 bytes, build `1794932218`. One API install POST returned HTTP 200 over
pinned SSH with CA- and hostname-verified TLS. An initial attempt was refused
before staging because the multiline PID file could not be parsed as an integer;
readback confirmed Atlas 0.6.0 and no staging. The corrected attempt independently
reviewed the positive first PID, exact `splunkd` executable and current UID before
the successful POST. No retry followed the successful install.

Final readback is `work/enterprise-update/verify-result.json`: Atlas 0.9.4 and
156/157 expected files matched exactly. `app.conf` differs only by the
`install_source_checksum` key plus blank lines; all other nonblank bytes and
semantic configuration matched. This does not claim 157/157 exact or that the
checksum equals the archive SHA. The server is Enterprise 10.6.0.5 with GUID
whose SHA-256 is `8c003a4afae8d1197dd165a6ed76e66090d73f1ea9ddcd1723991a5143de6ca3`; its active
license group was empty and all six returned license groups were inactive, so no
active supported license group was observed and license qualification remains open.

The dedicated `adm_investigate` endpoint routes returned 403 because the
capability is absent; no role grants were made. Therefore positive endpoint,
Web/CSRF, source-capture and protected-case qualification remain unqualified.
No additional local operating configuration, TLS, roles or schedules were changed,
and no restart was performed. This work did not modify Cloud or the heavy
forwarder; Cloud’s last recorded version is 0.9.3.

Final guard observations found persistence `capture_mode=disabled`,
`mode=disabled`, `platform=unqualified`; watch execution was disabled and no
schedules were enabled. Existing local `adm_identity.conf`, `transforms.conf`,
`savedsearches.conf` and `macros.conf` were retained; no additional operating
configuration edits were made beyond the packaged app update.

The final web-payload receipt is `work/enterprise-update/web-payload-result.json`.
All three CSS files matched exactly. All three JavaScript files matched the
complete archive payload after accounting only for the identical 111-byte
Splunk `en_US` translation preamble calling `i18n_register` with an empty
catalog and empty suffix. Original raw hashes failed because of that wrapper, not because an asset was stale.
The focused 12-test local run under umask 0002 passed, and Ruff passed for 238
files.


## Enterprise license activation and post-restart checks

After VPN access returned, pinned SSH and the existing CA/hostname-verified API
connection succeeded. The supplied license stayed outside Git and logs. The
first live request returned HTTP 400 because it omitted the documented required
`name` parameter. The corrected request returned HTTP 201 and `VALID` for the
Enterprise group; activating that group returned HTTP 200. No second license
installation followed the successful response.

This first Enterprise activation required a restart. The initial restart
preflight refused before starting a command because the pending-activation API
license list was empty. Read-only disk checks then established exactly one saved
file matching the supplied license, secure ownership/permissions, configured
`active_group=Enterprise`, and a local (`self`) license manager. No existing
license files were deleted. The vendored restart planner selected the matched
`Splunkd.service` and `systemd-cli` path. Independently reviewed guards checked
the instance GUID, version, administrator, Atlas 0.9.4, disabled SHC, exact service
executable, primary daemon ownership, and noninteractive restart permission.

Exactly one `sudo -n /opt/splunk/bin/splunk restart` completed with exit 0. The
service was active, the daemon PID changed, and verified TLS API checks reported
Enterprise active. Port 8000 was not ready at the first check; a separate
read-only wait succeeded after 9.006 seconds. No second restart, forced kill, or
REST restart fallback occurred. The subsequent license API listed three entries,
including one valid Enterprise license.

Post-restart Atlas still reports 0.9.4. All three CSS assets match the installed
archive; each JavaScript response contains the exact archive payload following
only the previously recorded 111-byte empty translation preamble. Persistence
and capture remain disabled/unqualified, watch execution is false, and no ADM
schedule is enabled. The administrator still lacks `adm_investigate`; no roles,
users, source jobs, collectors, notifications or TLS settings were changed. The
public management certificate still lacks a matching local capture name. Cloud
and the shared HF were not modified. These checks qualify the license activation
and app/service recovery after this restart, not installed case/capture, Web/CSRF,
source revocation, restore, or real-source behavior.

Private sanitized receipts are retained in the task workspace under
`outputs/enterprise-0.9.4-update/`, including `license-summary.json`,
`license-install-response.json`, `license-restart-response.json`,
`license-final-status.json`, and the post-restart asset/guard receipts. No license
identifiers, contents or private keys are committed. This increment changes no
app runtime bytes or version and deploys no newly generated archive. Removing
this documentation does not undo the installed license; license removal/group
changes are separate operations and were not performed.

The preceding native test/documentation increment was independently reviewed and
merged in [PR #26](https://github.com/chambear2809/splunk-adm/pull/26). Its
[PR CI](https://github.com/chambear2809/splunk-adm/actions/runs/44145304574) and
[main CI](https://github.com/chambear2809/splunk-adm/actions/runs/44146711977) passed
frontend, browser and Python checks; the installed Splunk suite was skipped.
Browser regression results were 214 passed and one skipped.


## Native installed notes and membership-ACL qualification

The user explicitly approved two restricted temporary accounts and a brief
notes-only persistence test on the selected Enterprise lab. A reviewed one-off
native REST procedure used the approved credential helper, pinned SSH, and the
existing CA/hostname-verified management connection. It bound the exact server
GUID hash, Enterprise 10.6.0.5 and active license, disabled SHC, Atlas 0.9.4 and
13 frozen archive source/default files before and after the exercise. No Docker
task-ownership guard was bypassed or repointed.

The first attempt stopped at role verification, before creating any test account,
case or local persistence configuration. It removed the temporary role and
confirmed disabled storage. A subsequent controlled create/update/read observed
that role creation initially retained six capabilities despite the requested
capability list. Explicitly updating the role reduced this to exactly
`adm_investigate`, matching the existing installed evidence fixture's setup
pattern. Both index lists and imported permissions remained empty. The strict
permission assertions were preserved; both users' effective contexts were
verified before enabling notes. The first attempt's known sanitized receipt was
archived, then only its verified empty task directory was removed under the
same private lock. No application data/storage was removed.

The corrected native exercise passed ten checks: disabled default; notes-only
availability; identical create retry; private-case denial; immutable note
revision; stale-revision rejection; sharing/export; revoked export denial;
capture-disabled rejection; and owner deletion. This is positive current-build
**native management-REST notes and case-membership ACL evidence**. It is not a
Web-proxy/CSRF test, protected-source authorization test, positive supervised
capture, whole-endpoint deadline test, or backup/restore qualification.

Cleanup was part of the acceptance result. The owned synthetic case was deleted
through its normal API, the original disabled/unqualified persistence flags
were restored, and both accounts and their role were deleted. A separate
read-only postcheck confirmed all three identities absent and persistence
`mode=disabled`, `platform=unqualified`, `capture_mode=disabled`. The generated
password recovery state was absent; only a sanitized receipt remained in the
private mode-0700 task directory. The case database remains service-owned,
mode 0600 under a mode-0700 directory. Normal deletion may retain private audit,
retry or history records; this is not an erasure claim. The newly written local
persistence configuration retains disabled flags. No source-job ledger was
created, TLS settings changed, source/index access granted, or watch/schedule
enabled.

Before execution, independent review identified uncertainty being overwritten by
cleanup, ownership-checkpoint ordering, a stale pre-enable configuration check,
cleanup depending on the assertion under test, and missing directory fsync. All
five findings were resolved. Six local safety checks passed for preserved
uncertainty, response/adoption failure recovery, separate ownership checks,
refusing changed-identity deletion, private atomic checkpoints and exact shell
payload fidelity. The operation/checkpoint/cleanup receipt stayed under one
private flock; unknown mutations would retain private recovery state and could
not report a pass. These safeguards belong to the one-off validation procedure,
not a new shipped operator-provisioning feature.

Private sanitized receipts and procedure/wrapper hashes are retained in the task
workspace at `outputs/native-notes-validation/`. The frozen installed archive is
still `dc9f501c4cb600f65db79ac6f13ea68b0fb10ed5dee97a22511d6512af53e2e4`. No app
runtime bytes/version changed and no newly generated archive was deployed. This
increment leaves the feature disabled and preserves the private database; there
is no software rollout or database rollback. Current supervised source capture
still needs a qualified local TLS peer and separately scoped source validation.
Web/CSRF, source revocation, whole-endpoint bounds, restore and real-source
comparisons remain open.

The preceding license record was merged in
[PR #27](https://github.com/chambear2809/splunk-adm/pull/27); its
[PR CI](https://github.com/chambear2809/splunk-adm/actions/runs/44163315644) and
[main CI](https://github.com/chambear2809/splunk-adm/actions/runs/44164936635)
passed, with the installed Splunk suite skipped. The native exercise above was
separate from that skipped suite.


## 0.9.5 request admission and bounded local task labs

Oversized investigation requests previously constructed the case store before
the API checked the body limit. With source capture configured, even an invalid
oversized request could read configuration and probe the source helper. The host
now authenticates and rejects more than 128,000 UTF-8 bytes before those steps,
with the same limit enforced inside the API. Exact-boundary, multibyte and
unauthenticated requests have focused regression coverage. This fixes admission
work; whole-endpoint supervision remains incomplete.

Disposable task containers now enforce 4 CPUs, 8 GiB RAM with no additional swap,
1,024 processes and bounded json-file logs. Resuming work verifies the effective
limits. Legacy cleanup waives only these new limits, preserving every existing
image/ID/label/mount/network/TLS/port ownership guard. Disk and lifetime remain
explicit task-level budgets, not newly claimed Docker volume quotas. The installed
notes fixture now uses an explicitly updated, verified least-authority role,
checks each effective identity, and restores configuration/removes acknowledged
owned identities even after setup/test failure. Uncertain identity creation is
not treated as proof of ownership.

The user clarified that development Docker belongs on the Mac, while
10.237.100.70 remains the existing Splunk host. Native Linux resource qualification
is deferred. No Docker packages, host services, networking or storage were changed
on Enterprise, the shared HF or AWS. The speculative native-host provisioning
proposal was retired outside Git. All permanent persistence/capture/watch/schedule
settings remain as previously observed; no permanent app update occurred.

Local checks pass: `npm run lint`; `npm test` (1,334 tests); `npm run package`
(includes build); `ruff check tools tests`; `ruff format --check tools tests`;
full Python discovery (1,327 tests), distributed discovery (126 tests), and
upgrade discovery (15 passed, 3 installed checks skipped). Browser checks cover
214 passes and one skip: the first invocation omitted the generated asset fixture
and failed eight asset tests, then the required fixture was built and those eight
passed. The other 206 successful checks were not rerun. Archive integrity,
release security/bundle checks, three build tests and AppInspect pass. AppInspect
has zero errors/failures/manual checks and six reviewed existing warnings
(Python compatibility, custom-conf replication, collections, bundled SDK version,
supervised subprocess use and hostname/IP heuristics).

The frozen local 0.9.5 candidate has SHA-256
`b54ea91c3c6a4eb2e0345b17dd7eec6100868cc7d19feed38ef15d12c5c198c4`,
1,401,545 bytes, build 1794956430. It is separate from the frozen installed
Enterprise 0.9.4 archive. Later documentation/CI packaging can produce different
archive bytes; retain this exact candidate for the installed test receipt and
compare runtime-file fingerprints before relating subsequent packages to it.

Independent review cleared the source, fixture and resource-guard changes after
correcting transitive lockfile metadata, optional current-context response fields
and ineffective negative-test setup. A private local lab driver also passed
review and a cancellation probe after fixing descendant process-group retirement.
The first local run was cancelled at the user's stop request, before installation
or tests; its primary cancellation receipt was preserved and container, network,
volumes, credential/TLS files and ports were verified cleaned up under the same
lock. Fresh identities/output directories are used for resumed attempts. One setup
attempt then stopped on a disk measurement performed as the image's unprivileged
account; the measurement now uses container root for sizes only. The next stopped
because the copied archive lacked its required checksum sidecar; the sidecar is
now retained and verified before container creation. Both attempts were fully
purged without installing the candidate. No ownership, TLS or integrity guard was
relaxed.

The exact frozen candidate passed two installed management-REST checks on the
Mac's ARM64-host emulated container: oversized requests return HTTP 413 while
persistence is disabled; and private notes/revisions/retries/CAS/sharing/export/
revocation/disabled capture/owner deletion work with two strictly scoped fixture
identities. The unsupported-runtime preflight test was deliberately skipped
because it requires its separate opt-in. This was `ADM_LAB=1 python -m unittest
discover -s tests/splunk -p test_cases_endpoint.py -v`, run through the reviewed
private lifecycle driver. The installed suite took 24.097 seconds; the lifecycle
took 164.59 seconds. Management and HEC each passed the task-CA/hostname handshake
and rejected the wrong CA and hostname both before and after installation.

The successful task `notes-bounds-v4-20261117` retained its exact container/image,
labels, mounts, loopback bindings and configured resource limits outside Git.
Its largest measured named-volume usage was 2,546,466,816 bytes, under a 10 GiB
cooperative phase-check budget; this excludes cached image/writable-layer/log
space and is not a filesystem quota. The lifecycle allowance was 45 minutes.
All configuration/identity cleanup ran before lab purge; the container, network,
volumes, credential/TLS files and loopback ports were independently confirmed
absent/free afterward. Receipts for each attempt remain separate; a later pass
does not rewrite the earlier cancellation/failure results. No current source
capture was performed. Detailed metadata is in `FEATURE_QUALIFICATION.json`;
private reports are under `local-notes-run-4/outputs/` in the external task
workspace. No native capture, real-source, Web/CSRF, operational restore
or production-readiness qualification is implied by the checks above. Source
capture remains disabled by default; the six-feature request remains incomplete.


## Installed Splunk Web notes, CSRF and case ACLs

A dedicated disposable Mac Docker lab now passes the cases workflow through
**real Splunk Web login cookies and its `/splunkd/__raw` proxy**. The final
frozen-source scenario passes anonymous/incorrect-password denial; two verified
restricted Web identities; private list/read/JSON-export isolation; idempotent
create retry and immutable note revision; sharing/read/member append/export;
revocation blocking read/export/old retry/new writes while the member remains
logged in with unchanged role/capability; owner export/deletion; and stale-session
rejection after logout. A cloned session is first proven valid before that final
logout check. This is native Web HTTP behavior, not rendered-browser interaction
or a qualification of the bundled JavaScript download/handoff flow.

Twelve negative CSRF requests cover missing, invalid and other-session tokens
on create, entry writes, share and DELETE. Each native rejection must identify
CSRF, and subsequent reads prove no case/membership change; valid actions then
succeed. Splunk Web returned 401 for these denials. The first harness expected
403 and stopped before valid case creation; its failed/uncertain receipt remains
separate. The corrected assertion accepts 401/403 only with the CSRF error and
unchanged-state proof. No CSRF flag, route pattern, capability, source grant or
TLS check was weakened.

`ADM_LAB_WEB_TLS=1` opts a new lab into task-bound Web HTTPS without changing
legacy lab defaults. Management, HEC and Web separately passed task-CA/hostname
verification and wrong-CA/wrong-hostname rejection before and after installation.
The private key remains in the protected host runtime and owned container until
purge; no global trust store or browser TLS exception is used. The HTTP client
follows no redirects and ignores proxy environment variables. A mode-0600 private
journal checkpoints exact synthetic case bodies and idempotency keys before
sending and retains response status/hashes or uncertainty. Login bodies, cookies
and CSRF values are excluded; raw journals remain outside Git.

The exact installed archive is 0.9.5, build 1794957921, 1,409,564 bytes,
SHA-256 `6b7e33ac54c745d7f06593108165c69d71130f8e02f9b2cb5b169950a0c9a57b`.
It is the retained PR29 CI artifact, distinct from the earlier local 0.9.5 test
archive and the frozen permanent Enterprise 0.9.4 installation. This increment
changes test tooling and records, not packaged application runtime code, so it
does not bump the app version. Newly rebuilt/CI archives remain separate artifacts.

The final scenario passed in 27.431 seconds; the whole lifecycle took 193.91
seconds. All five exercise/guard source hashes were checked before and after the
run. The journal has 22 mutation requests, all with responses, including the 12
CSRF refusals. Effective fixture permissions were exactly `adm_investigate`, with
no imported roles or source-index grants/defaults/filter. A postcheck confirmed
both users and their role absent and persistence flags restored before purge.
The exact container/image, labels, mounts, ports, configured limits, TLS results,
source/driver hashes and cleanup are retained in qualification evidence. Container,
network, volumes, credentials, TLS files and ports were independently confirmed
absent/free after purge. A bounded port-release retry stays under the same lock;
the earlier immediate-bind uncertainty was preserved rather than overwritten.

Limits remain 4 CPUs, 8 GiB RAM/memory-plus-swap, 1,024 processes, rotated logs,
a 10 GiB cooperative named-volume budget and a 45-minute lifecycle allowance.
The largest final volume sample was 2,547,752,960 bytes. Three unrelated collector
containers kept running; these elapsed observations are not performance isolation,
a filesystem quota or native Linux resource qualification. Native resource
qualification remains deferred as requested. No permanent Enterprise, Cloud,
shared-HF, AWS, collector, watch or schedule operation occurred. Capture stayed
disabled throughout; source-backed reads/exports/revocation, endpoint supervision,
restore and production readiness remain unqualified.

Local checks pass: 35 focused Web/lab checks, full Python discovery (1,333 tests),
Ruff check/format (242 files), build/package and release archive/security/bundle
gates. Independent review added destructive-method CSRF coverage, stronger
revocation/logout proofs and the cleanup/key-residence clarifications. Final independent review found no actionable issues. Repository CI results are attached to the corresponding PR and main commit;
those jobs do not replace the explicitly opted-in installed Web scenario. Private receipts are under `attempt-3/outputs/` in the external
`atlas-cases-web-validation` task directory.

## Direct Cases access and rendered Splunk Web qualification (0.9.8)

Users with only `adm_investigate` can now open **Cases** directly, without first
performing a graph comparison or receiving source-search access. The new view
validates an absolute UTC calendar window for new cases, keeps its client/window
stable while working, and loads the existing cases UI lazily. Pipeline-health
searches do not run on this page. Existing Incident workflows remain available.
Installed testing exposed a focus-before-React-commit race after case creation;
focus now follows the committed heading/editor. Visual review also caught a stale
export-success message after denied access; failures now clear that old message.

The final installed Firefox scenario passes all 12 workflow checkpoints: exact
restricted logins/direct entry; invalid-window keyboard handling; missing/invalid
native CSRF-token denial with unchanged empty lists; case creation/draft retention;
a real committed note response deliberately dropped before the UI receives it,
followed by same-key/body retry with one immutable entry; note revision/history;
private isolation and sharing/member append; consent-gated JSON and Markdown
downloads; narrow-width draft/focus behavior; stale-revision rejection preserving
the draft; revocation clearing visible case data/old success status; and anonymous
navigation returning to login. After revocation, the member remains authenticated
with the same exact role/capability while direct case read and export both return
403. No source search jobs were dispatched. These are notes/membership checks,
not protected-source authorization or capture qualification.

The test uses real installed responses. Its private journal checkpoints exact
synthetic requests/keys before sending, response outcomes and the deliberate
post-commit drop. All 11 mutations have responses, including two native CSRF 401s
and one stale-revision 409. It retains no login bodies, cookies, CSRF values,
authentication traces or HAR. Each browser profile imports only the task's public
CA; certificate/hostname checks stay enabled. Management, HEC and Web separately
passed positive TLS and wrong-CA/wrong-hostname checks before and after install.
A separate local browser trust fixture rejects unknown CA/wrong hostname; that
negative fixture is not an installed-Splunk browser test.

The final frozen installed artifact is **0.9.8**, build **1794966952**,
**1,417,735 bytes**, SHA-256
`8c2f61206fad88faa3a62d6689b826a4a34e2b42b3c3488ca05a8ccd4341802b`.
It is retained under `atlas-cases-ui-validation/attempt-4/outputs/` outside Git,
with its sidecar and receipts. Earlier failed/partial 0.9.6 and 0.9.7 attempts,
and the passing 0.9.7 run that exposed the stale message in visual review, remain
separate. Versions were advanced before deploying changed runtime bytes. Later
CI archives containing updated records/build metadata are separate artifacts;
they must not be silently substituted for this installed archive.

The final scenario took **38.062 seconds**, with **193.61 seconds** for the full
locked lifecycle. Both fixture users and their exact single-capability role were
confirmed absent and persistence restored before purge. The parent retained the
same direct lab lock through exact container/network/volume cleanup, detached
Firefox group retirement, profile/credential/TLS removal, port release and durable
final receipts. A no-authentication cancellation probe separately stopped an
owned Firefox, killed its Node parent and proved exact group retirement before
profile deletion. Incomplete browser ownership refuses a cleanup-success claim.
All three unrelated collector containers stayed untouched. Shared image/browser
caches and private synthetic evidence remain; the permanent SQLite database and
its possible audit/retry/history records were not touched or erased.

Screenshots and exports were inspected. App content fits at actual widths 572,
364 and **320 pixels**, without internal horizontal overflow. At tested phone
viewports the default Splunk shell leaves Atlas less than 320 pixels and its own
header overflows; the app correctly focuses its width notice, hides the editor
and preserves the draft without new investigation requests. **Phone viewport fit
is not qualified.** Existing width assertions and the 320px app minimum remain
unchanged.

Local validation passes: lint/type/format, 1,337 frontend tests, 1,333 Python
tests, Ruff (243 files), build/package, archive/security gates and AppInspect
4.3.1 Cloud precert (zero errors/failures/future failures; six warnings and one
skipped check). Python level-9 gzip measurements are 683,735/686,080 bytes for the
main asset and 31,924/32,768 for optional journeys. The full browser run passed
214 tests with one skip; an initial parallel time-picker timeout passed focused
recheck and the full two-worker rerun. Case-focused checks were rerun after the
focus/error fixes. Repository CI is recorded on the PR/main runs; its gated
Splunk suite is separate from this explicitly opted-in installed scenario.

Independent review covered source, test/fixture contracts, journal durability,
browser cancellation ownership, width interpretation and final evidence. Source
capture, whole-endpoint bounds/cancellation, source-backed stored reads/exports,
backup/restore, native Linux resource limits, real sources and production
readiness remain unqualified. Native resources remain deferred as requested.
No permanent-host, Cloud, AWS, shared-HF, watch, schedule or failover operation
occurred. Shipped persistence/capture/watch/schedule gates remain disabled, and
the six-feature request remains incomplete. Rollback is a reviewed repository
revert; no case schema migration or erasure is part of this increment.


## Installed cold notes and capture-ledger recovery (0.9.8, local Docker)

The customer outcome is retaining private/shared notes, immutable revisions,
access rules, exports, original retries and audit history through a restart and
cold restore into a fresh Splunk container, without discarding unresolved job
slots. This increment adds test tooling and qualification; application runtime
bytes and shipped disabled defaults are unchanged. The six-feature request
remains incomplete.

The successful third rehearsal used the previously frozen **0.9.8** archive,
build **1794966952**, **1,417,735 bytes**, SHA-256
`8c2f61206fad88faa3a62d6689b826a4a34e2b42b3c3488ca05a8ccd4341802b`
for every installation. Newly generated local/CI archives are separate artifacts
and were not substituted for this installed package. No version bump or permanent
Enterprise/Cloud deployment was needed for these test/tooling changes.

`tools/rehearse_case_recovery.py` holds three direct parent locks through the
source, occupied negative target and fresh positive target, running one heavy
container at a time through the existing lab framework. Both case and capture-job
databases come from the same fully stopped verified container. Independently
created installed schemas, integrity/foreign keys, physical bounds, retained
provenance, an external manifest digest and logical table digests gate restore.
Only sealed validated files enter an absent directory on the stopped target;
cold ownership, permissions and bytes are checked before startup. See the
[rehearsal contract and command](BACKUP_RESTORE.md#installed-cold-case-recovery-rehearsal).

The source and target installed fixtures each passed one scenario with zero
skips. Source restart and fresh restore preserved three cases, four ACL rows,
nine retry records, seventeen audit records, immutable note revisions, private
and revoked-member denials, shared reads/exports, and exact old retry responses.
A new shared question worked after restore and preserved prior entries. Every
logical table and all three deliberately unresolved synthetic ledger records
matched before target case API access. Advancing the fixture clock left slots
charged and a fourth reservation was denied. No source search jobs were dispatched.
The installed cold source had only the two main database files; retained-WAL
inclusion is separate positive unit evidence, not an exercised installed sidecar.

Live copy was refused. An occupied target was refused with its sentinel unchanged.
Corrupt and future-schema backups were rejected before destination creation,
with the installed target directory still absent. Two earlier attempts exposed
verified tooling faults: native checksum staging used the image's default user,
and `docker cp -a` replaced tar service ownership with that image user. Explicit
service staging and a tar-stdin copy without that override fixed the causes.
Ownership, mode and byte assertions stayed intact. All resources from both
failed attempts were independently verified removed; their evidence is retained.

The engine was Docker Desktop 29.9.3, Linux/aarch64, 12 CPUs and 15,527,374,848 bytes
memory, using the reviewed pinned Linux/amd64 Splunk 10.6.0.5 image through
emulation. Installed Python 3.13.11/SQLite 3.44.2 ran as UID/GID 41812. Containers had
4 CPU/8 GiB/no-extra-swap/1,024-process limits and bounded logs. A 45-minute execution
deadline, 12 GiB host reserve and cooperative 8 GiB aggregate named-volume budget
were declared; the peak phase sample was 5,150,539,776 bytes. These are functional
installed results, **not native Linux AMD64 resource qualification**.
Management, HEC and Web each passed trusted TLS plus wrong-CA and wrong-hostname
rejection before/after installation and again after target restore startup.

Fixture users/role were absent and disabled flags restored on source and target
before purge. All three task containers, networks, both volumes each, credentials
and TLS material were removed and ports released under their original locks.
The three unrelated collector container IDs and older unrelated labeled resources
were preserved. Private raw/sealed backups, journals and receipts remain outside
Git under `atlas-case-recovery/attempt-3`; this is not an erasure claim. The final
receipt SHA-256 is
`0b9e58a47d5406ab1878795f53fa28411d7698166088986ef23f4281064fbe92`;
the external snapshot manifest SHA-256 is
`88d486524422b676488e7a012f768ede3ec3d951da8136c7386f589f04b9cb4b`.

Local verification passed: 25 focused recovery tests; 1,358 full Python tests;
126 distributed tests; 15 upgrade tests with 3 installed opt-in skips; Ruff check
and formatting; frontend lint; 1,337 Vitest tests; build/package; 214 browser tests
with 1 optional scale skip; archive integrity; 3 bundle checks; AppInspect 4.3.1
Cloud precert plus its report gate (zero errors/failures/future failures,
six warnings). Local Node 22.16/Mac ARM64 and Python 3.13.14 differ from CI's
Ubuntu 24.04/Node 22.13 and Python 3.13 unit/Python 3.11 package jobs. Existing SQLite
ResourceWarnings remain outside this qualification of endpoint resource bounds.
The CI-generated packages do not extend the installed artifact's scope; a skipped
gated Splunk integration job is never counted as passed. Independent review
resolved physical/manifest bounds, complete-mount checks, artifact drift and
cleanup-on-evidence-failure findings, followed by both installed tooling fixes.
Process tests include actual signal cancellation, descendant retirement and
all-lock cleanup despite receipt/log write failures.

This is same-build, synthetic, notes-only case/ledger cold recovery. It does not
qualify current source capture or source-backed authorization, native resource or
whole-endpoint bounds, job reconciliation, live writers, large-scale/RPO/RTO,
upgrade/downgrade, baseline/watch/KV/platform/index recovery, Cloud/SHC or production
readiness. No failover, source grants, watch, schedule or notification was enabled.
Rollback removes test tooling/docs while preserving retained backups and ownership
receipts; no production data deletion or older database writer is authorized.
Exact IDs, hashes, commands and limits are in the
[qualification record](FEATURE_QUALIFICATION.json).

## Case request supervision — 2026-11-18 (0.9.10 candidate)

The customer outcome is a Cases workflow that becomes unavailable in bounded
operational time when authentication, configuration or notes work stalls, while
preserving an interrupted write's exact retry identity. This increment adds a
fresh supervised Linux request worker around the existing host adapter, plus
byte-based list pagination so valid large cases remain accessible through a
bounded response frame. SQLite initialization failures close their connection;
test fixture connections now close explicitly instead of relying on collection.
Schemas, entitlement checks, Web CSRF registration and shipped disabled gates
are preserved. See [the operational contract](CASE_REQUEST_SUPERVISION.md).

The parent admits one worker per persistent-handler process without waiting,
uses a 40-second operational budget and a separate one-second retirement
allowance, and fails closed after uncertain retirement. The Linux child starts
in its own session, receives credentials only on stdin, uses a restricted
environment and keeps its leader/watchdog alive until retirement. TERM/KILL
precede reaping; adopted descendants are reaped only from the owned group.
Raw input is limited to 1 MiB, response frames to 2 MiB, and complete compact ASCII
list pages to 1,500,000 bytes. Clients follow the cursor even after a short page;
the existing Cases UI does so, with a new keyboard/focus regression check.
Synchronous process creation, kernel/filesystem stalls and Splunk Web delivery
are not hard real-time guarantees. This does not qualify complete endpoint
CPU/memory bounds, current source capture or production operation.

Local frontend, browser, Python, release/bundle and AppInspect checks passed.
The final full Python discovery ran 1,396 tests with seven Linux-only skips
and no ResourceWarnings. A loaded full run also reproduced the previously
recorded 100ms SQLite writer-lock race; the timeout and assertions were not
changed. The final request-focused local run ran 50 tests: 39 passed and 11 were skipped.

The frozen 0.9.10 candidate is build `1795016813`, 1,438,212 bytes, SHA-256
`61fe7a81687e6c9aef2a6f1d892e0848de4adcbfed8747a3fd22d6e75049e08d`. Installed
functional qualification passed in attempt-13 on Docker Desktop 29.9.3
(Linux/aarch64, 12 CPUs, 15,527,374,848 bytes RAM) using the cached pinned
Linux/amd64 image under emulation. Web, management and HEC trusted TLS checks
passed before and after install; wrong-CA and wrong-hostname handshakes were
rejected. The installed build and runtime hashes matched the frozen candidate;
all 11 Linux process tests passed. Uninjected positive Web checks passed before
faults and after hook restoration, including pagination of three 762KB cases
over three pages. Four injected stalls returned at about 40 seconds and retired
their groups/descendants within 40.53 seconds. Exact retries produced one case
and receipt for each operation, including a post-commit stall; a client
disconnect after durable commit was likewise reconciled with the exact retry.
The original startup source and cache were restored exactly. Attempt-13 took
449.43 seconds and its receipt SHA-256 is
`54701005db1417a42434c1e46212069719158bef659c54e09f5db859393874cd`.

Independent prelaunch and final integrated-diff reviews found no remaining
actionable findings. The normal repository and pull-request gates remain to run.

Attempts 1–12 remain retained privately. They include the original fixture
assumption that platform startup files were absent; repeated pre-positive 503s
that diagnostics traced to a bare `splunk` lookup in the PATH-free worker; the
fixture's later-discovered 0444 source and generated cache modes; and attempt-12
test-only mismatch accepting only 403 where Splunk Web returned a CSRF-specific
401. Those causes were repaired or aligned with the existing Web contract and
independently reviewed before attempt-13. The first eleven attempts and
attempt-12 did not pass installed positive/fault qualification; their exact
primary outcomes remain marked failed/uncertain in their retained receipts.
Attempt-12's six cleanup checks passed. Attempt-13's six cleanup checks were
independently confirmed true, task resources and credentials/TLS were absent,
and all three ports were released. Failed-attempt receipts and journals remain
outside Git under `atlas-case-request-bounds`.

This is functional evidence for the installed synthetic notes workflow on the
emulated local lab. Synchronous process launch, kernel/filesystem stalls and
Splunk Web delivery are not hard real-time guarantees. It does not establish
strict whole-endpoint CPU/memory bounds, native Linux/amd64 resource
qualification, current source capture, real-source behavior, Cloud/SHC support
or production readiness. Native Linux/amd64 resource qualification is deferred
by the user; Docker Desktop's emulated Linux/amd64 results are functional
container evidence. The permanent Enterprise/Cloud targets, original checkout
and old paused goal remain untouched. Rollback preserves databases,
audit/history and unresolved retry/job state; no deletion or erasure is implied.
Exact performed evidence and remaining gates are tracked in
[the qualification record](FEATURE_QUALIFICATION.json).


## Evidence integration and operator workflow — 2026-11-18 (0.9.11 candidate)

This increment implements the incident audit producer consumer and baseline
operator workflow alongside a runnable source-capture qualification driver.
The incident Timeline consumes exact native authority/scope/object identities
and historically valid application bindings, preserves native action and receipt
times, and displays source coverage, gaps and withheld/ambiguous records. Its
explicit JSON download retains allowlisted detached evidence. Graph comparison
is available independently of optional audit loading; audit requests can be
cancelled and time out after ten seconds. No production audit producer or
authoritative historical binding feed is connected.

The baseline retained-artifact adapter checks selection, immutable digests,
provenance consistency, coverage, revisions, watermark and lateness, then
requires independent producer verification and current source authorization.
A JSON manifest is not completeness proof; a production complete-source provider
is still missing. The bounded-stdin operator command implements create, enable,
disable, inspect and exact-request reconciliation under current administrator
and immutable owner checks. Creation and enablement remain unavailable in the
shipped host without a verified provider. Journal schema 2 adds durable
management receipts, preserving bindings and unresolved runs. Stop capacity is
reserved per enabled binding; older full journals retain unkeyed emergency
stopping. Rollback requires retained databases and a compatible schema-2 writer.

The installed source driver runs exact owned disposable tasks under the shared
lock with frozen archives, runtime hashes, trusted and negative TLS checks,
private exact-operation journals, bounded resources and verified purge. It
includes pre/post-commit capture interruption and current source-revocation
checks, but those positive scenarios have not yet passed installed qualification.
Two 0.9.10 attempts were retained as failed/uncertain: a restart-readiness TLS EOF
and capture-unavailable response before the first capture. Both were purged
with all six cleanup checks verified. Explicit unsupported-helper qualification
is separate and cannot count as a positive capture result.

Independent review found and cleared FIFO-open blocking, stop-receipt quota
exhaustion, uncertain hook-restoration cleanup, optional audit loading blocking
graph results, and mutable/nonallowlisted retained audit projections. Integrated
local checks passed: 1,492 Python tests with seven skips, 1,345 Vitest tests,
215 browser tests with one optional scale skip, distributed and upgrade checks,
release/bundle gates and AppInspect (zero errors/failures, six warnings).
The exact frozen 0.9.11 archive is build `1795023134`, 1,459,090 bytes,
SHA-256 `0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`.
Its installed unsupported-helper test passed: notes remain usable, actual
preflight fails closed and no source-job ledger exists. TLS and runtime hashes
passed, six cleanup checks were independently confirmed, and the lifecycle took
286.8 seconds. Receipt SHA-256 is
`194151a368e16e0309c07032f92356e72c6cef8f6c61f2b2005e1912f26addb8`.
This is negative-path qualification, not successful capture or recovery. A later
host-only journal-directory sync repair has focused tests and review, separate
from the retained installed fixture fingerprints. Native amd64 resources, real-source associations/completeness,
Cloud/SHC and production readiness remain unqualified. Shipped capture,
persistence, watch, schedule and notification defaults stay disabled.

Final independent review found no remaining actionable blocker in the integrated
code or retained evidence. Subsequent repository CI and merge outcomes are
recorded with the corresponding pull request and main commit.

## Native current-transport capture follow-up — 2026-11-18 (0.9.11)

The authorized Enterprise lab at `10.237.100.70` now runs the same frozen
0.9.11/build `1795023134` archive recorded above, upgraded from 0.9.4. All 88
packaged runtime/static hashes match. A management leaf signed by the existing
CA now covers loopback and existing management names; the CA was retained.
Strict positive and wrong-CA/wrong-hostname checks passed, followed by native
helper preflight and an authenticated loopback request. The new leaf expires
2027-02-16 18:46:01 UTC. No Docker was installed or used on this target.

A separately reviewed native fixture exercised two temporary non-admin callers
with exactly `search` and `adm_investigate`, four new synthetic indexes, and a
new HEC input. It preserved the active original identity configuration and
restored it afterward. Eleven functional checks passed: two captures and
provenance digests; selected versus unselected projections; restricted-member
notes access; source-filter and index-grant expansion/revocation; stored reads,
exports and exact retries under current authorization; and redaction after a
source-configuration change. A source-disabled precommit attempt wrote no
receipt and succeeded after restoration using the same operation. For a second
capture the client closed without reading its response after a read-only
SQLite observation established durable commit; retrying the original body and
key retained one receipt, the same revision and capture identities.

The original run remains **failed_or_uncertain**, with a separately passed
functional scenario. Its final unfiltered search-job inventory exceeded the
response budget on a host with 101 unrelated jobs. Cleanup restored original
configuration, deleted its case and HEC input, and preserved temporary owner
credentials/users/roles/indexes for reconciliation. A reviewed bounded inventory
by exact native owner repaired cleanup without repeating successful functional
checks. Subsequent standalone cleanup passed all ten required success flags;
an independent read-only postcheck passed 16/16 checks, verified all 27 capture
ledger jobs terminal and their native SIDs absent, and rechecked all 88 runtime
hashes. The original failed receipt was retained unchanged. Source evidence
came only from task indexes; unrelated jobs were preserved.

The case, test users/roles, HEC input and indexes are API-absent; generated
credentials and known owned temporary files are absent. Both app-local config
files match their original bytes, UID/GID, mode and nanosecond modification
time. Persistence and capture are disabled, and the original identity profile
is restored. Audit/retry/ledger history is retained. API absence does not prove
physical index-data erasure.

Native embedded Python 3.13.11 passed all 11 request-supervisor tests and all
12 transport tests with no skips. An initial transport fixture setup failed:
Splunk prepended its OpenSSL executable to PATH, while fixture code removed the
vendor library path, pairing that executable with incompatible system libraries.
The test-only repair selects host OpenSSL from the Linux default system path;
production transport settings and application bytes are unchanged. The repaired
transport suite also passed 12/12 on Mac Python 3.13.14; nine fixture recovery
regressions and focused Ruff checks passed. Exact source/evidence hashes,
commands, original failures and review are retained in
`cases_current_transport_native_20261118` in `FEATURE_QUALIFICATION.json`.

This establishes installed synthetic management-REST capture and the exercised
source-authorization/retry paths through the current supervised transport.
It does not establish real-source behavior, source-backed Web/CSRF, server-worker
interruption or injected capture commit stalls, unknown job-creation recovery,
cold restore, strict whole-endpoint/resource bounds, Cloud/SHC support, or
production readiness. Verified historical audit and complete-source producers
remain missing. Shipped privileged execution, capture, persistence, watch,
schedule and notification defaults remain disabled.

## Native source, worker interruption and library recovery — 2026-11-18 (0.9.11)

This continuation reuses the frozen 0.9.11/build `1795023134` archive, SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`.
No application runtime bytes changed or new archive was installed. Effective
session records confirmed Sol/high coordination, two Terra/high worker slots
(one rotated into recovery), and independent read-only Astra/high review, with
four threads including the coordinator. The original checkout and dirty peer
worktrees were preserved; work used a new branch from PR #35's merged commit.

The [real-source exercise](CASE_REAL_SOURCE_QUALIFICATION.md) captured the
configured `atlas_identity`/`otel_traces` pair for `coreapi`, `tenant-jobs`,
`lab`, on `k8s-01.uktme.cisco.com`, in adjacent one-minute windows beginning
2026-11-16 15:55 UTC. Existing administrator source authority was supplemented
only with a temporary investigator capability; no real-index grant was added.
Selected reads, exports and the exact original capture retry were visible,
withheld while the source profile was disabled, and visible after exact original
file restoration with the original fingerprint. Four useful graph rows and the
same canonical observation digest were retained in both attempts. The producer
identity/scope/configuration revision agrees with the independent catalog.
Warnings preserve 87 and 90 excluded spans in the respective windows; these
finite ownership/span observations establish neither network traffic/ACI paths
nor source completeness. Collector loss/lateness remains unknown, and the
fixed receipt horizons exclude later arrivals.

The first source attempt remains `failed_or_uncertain`: restoring a setting
through the configuration API rewrote file bytes and correctly caused source
withholding. Its cleanup and independent 11-check postcheck passed. The separate
reviewed second attempt restored exact bytes/UID/GID/mode/mtime before its final
phase and passed, followed by another 11-check postcheck. The 13/17 terminal,
bound, absent SIDs are conservative administrator sequence-range supersets;
no administrator-owner-wide deletion occurred. Original source roles, both
configuration files and disabled gates were restored, the temporary role and
exact task cases were removed, and audit/retry/ledger history was retained.
Owned case deletion clears protected response snapshots while preserving
request identities and digests as tombstones.
Non-admin real-source permission revocation remains unqualified.

The [worker-interruption fixture](CASE_NATIVE_INTERRUPTION.md) uses a task-only
startup extension outside the application archive, exact original operation
journals and authenticated synthetic sources. A failed first attempt stopped
at the root check before hook installation: the Splunk CLI dropped the elevated
interpreter to the service account. A separately reviewed recovery reconciled
its exact temporary resources; 19 independent checks confirmed cleanup and
original platform/configuration state. Its failed primary receipt is unchanged.
The second attempt uses the independently verified direct embedded interpreter
and Linux libc pidfd functions, since the embedded Python exposes neither
Python pidfd API. Its installed primary passed actual worker-only interruption
immediately before and after durable commit, followed by the exact retries,
source permission/configuration changes, process/job retirement, exact startup
source/cache restoration and a successful uninjected capture. The independent
postcheck passed 25 checks, verified all 34 source jobs terminal with bound
native SIDs absent, and rechecked all 88 runtime hashes. Both original worker
groups and descendants were absent. The three exact original write tombstones
and exact owned delete receipts matched; capture identity/cardinality comes
from the precleanup phase journal because deletion clears response snapshots.
The initial read-only checker incorrectly expected projected response fields
and a retained payload after deletion; its failed run and the separately tested
tombstone-aware repair are retained without repeating the fault scenario.
Final integrated review is recorded with the qualification evidence and PR.
A worker kill is separate from the earlier client disconnect; this exercise did
not restart the service or host or create an unknown native search job.

The [isolated recovery exercise](CASE_NATIVE_RECOVERY.md) passed using the
installed native x86_64 `CaseStore`, `ComparisonSource` and `JobLedger` with
synthetic source callbacks in a new private directory. It verified complete
logical case/ledger content, immutable revisions, ACLs, capture attachment
linkage, audit/retry identity, source-redacted projections, unresolved charged
slots, occupied/corrupt target refusal and cleanup of an injected second-copy
failure. All eight independent postchecks passed, including unchanged live
case/ledger and configuration bytes and metadata. This advances same-build
synthetic library recovery; it does not qualify source-backed endpoint or cold
platform restore, live-writer atomicity, native unknown-job reconciliation,
baseline/watch/KV/platform/index recovery or cross-build migration.

Local checks passed 1,516 Python tests (9 skipped), 126 distributed tests and
18 upgrade-gate checks (3 skipped); full Python lint/format checks passed. The
initial broad run lacked the CI-pinned optional SignalFlow client; a new private
environment with the repository's exact requirement passed. Normal PR CI covers
frontend/packaging; no local frontend suite is claimed for this tool/test/docs
change. Exact wrappers, failed attempts, independent evidence, remediation and
remaining limits are recorded under
`native_qualification_continuation_20261118` in `FEATURE_QUALIFICATION.json`.

Shipped privileged execution, capture, persistence, watch, scheduling and
notification defaults stay disabled. Source-backed Web/CSRF, complete-source
and historical audit producers, service/host failure recovery, strict endpoint
resource bounds and production readiness remain unqualified. Cloud/SHC
persistence remains unsupported. This record does not revise any earlier failed
primary outcome or turn cleanup into a successful functional result.


## Native uncertainty and recovery continuation (2026-11-18)

This continuation uses the unchanged, frozen 0.9.11 build `1795023134` archive
(SHA-256 `0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`;
1,459,090 bytes and 88 runtime files). It adds test tooling, regression checks
and qualification records. It does not update the installed application runtime.
The coordinating GPT-6.1 Sol/high session used two GPT-6.1 Terra/high workers,
rotated the durability role into available capacity, and kept a separate
read-only GPT-6 Astra/high reviewer within four total threads.

The [service-restart exercise](CASE_NATIVE_SERVICE_RESTART.md) passed held
precommit and postcommit SQLite boundaries with exact original request retries,
new systemd daemon/invocation identities, retired workers/descendants and new
authenticated handlers. Its independent postcheck passed 29 checks, verified
three exact write tombstones and owned deletion receipts, all 34 source jobs
terminal with native SIDs absent, and all 88 runtime hashes. The workers were
live when the supported restart CLI launched; this does not prove restart rather
than the normal request deadline caused worker death. The initial fingerprint
failure and the second run's post-restart PID-inventory failure remain separate
failed primaries with reconciled cleanup. No host failure is claimed.

The [native job-acknowledgement exercise](CASE_NATIVE_JOB_OUTCOMES.md) observed
actual creation/deletion acknowledgements withheld from the unchanged runtime.
Its original primary remains `failed_or_uncertain`: both scenario checks passed,
but cleanup retained access after encountering an incomplete early `PARSING`
response. A separately reviewed reconciliation passed without repeating the
fault or changing private ledger rows; all 21 independent postchecks passed.
Three exact fault/convergence SIDs and four separately identified setup count
chains were verified. Unbound creation remains charged with no capture receipt;
only the bound task-local deletion uncertainty was cleared by independently
attested administrator proof, after which the exact original local case request
converged to one capture/receipt and stable replay. No live global quota was
stranded or reset, and no shipped automatic reconciliation interface is claimed.

The [injected isolated endpoint restore](CASE_NATIVE_ENDPOINT_RESTORE.md)
passed five installed checks and 29 independent postchecks, including current
ACL/source projections, immutable notes and links, audit/exact receipt identity,
one archived synthetic unknown row, sealed-pair negative cases, both-principal
route/canary attestations and settled workers. All 35 source-job rows were
terminal with bound native SIDs absent. Live main databases and SQLite sidecars,
startup source/cache and app configuration were unchanged during this exercise;
all 88 runtime hashes matched. The first read-only checker failed on a TLS-context
variable collision; a separately reviewed/tested checker-only repair passed.
The restore itself was not repeated. This is an injected private endpoint route,
not an operational fresh-instance or cold-platform restore.

The [non-admin real-source increment](CASE_NATIVE_SOURCE_REVOCATION.md) passed
nine selected read/export/exact-retry operations across allowed, revoked and
restored access. The same stored capture became redacted and then visible again,
with unchanged note content. All 28 independent checks passed, including 17 bound
source jobs terminal with exact native SIDs absent, original configuration and
existing authority restored, and removal of the temporary user, role and secret.
The fixture compares all current-context fields exactly except the validated
login timestamp changed by native Basic authentication; raw contexts remain
retained. The first case-only run remains failed with separately verified cleanup.
The passing case scope omits count controls: raw-count compatibility, broader
index/source/time denial, completeness and loss/lateness remain unqualified.

Earlier pre-account attempts and exact cleanup requirements are retained
separately. The first guard exposed shared write permissions on two unrelated installed app
directories. After explicit user approval, only those exact pinned directories
were permanently narrowed to `0755`. Nine independent checks verified unchanged
configuration content, role membership and runtime hashes against a fresh
pre-hardening baseline. Directory ctime changes are intentional and retained;
shared write access was not automatically reopened. This approved host change
is distinct from temporary fixture cleanup and is not a host-wide security
attestation.

Local validation passed the 1,575-test Python suite (9 skipped), 126 distributed
tests and the 18-check upgrade gate (3 skipped), plus Python lint/format checks.
The eight endpoint tests also passed with resource warnings treated as errors.
No local frontend suite is claimed for this tool/test/docs change; normal PR CI
remains required. Exact wrappers, failed primaries/checkers, separate recovery
receipts, independent evidence and code hashes are recorded in
`native_uncertainty_qualification_20261118` in `FEATURE_QUALIFICATION.json`, under
the private `atlas-uncertain-outcomes` evidence root. Earlier records remain
unchanged.

Shipped privileged execution, capture, persistence, watch, scheduling and
notification defaults remain disabled. Source completeness/loss/lateness,
protected-capture Web/CSRF, strict whole-endpoint resource limits, host failure,
live-writer atomic backup, full operational restore and production readiness
remain unqualified. Cloud/SHC persistence remains unsupported. Each unchanged
live-database result applies to its own exercise interval; later authorized
case operations do not retroactively revise that observation.
