# Application Atlas feature delivery

This is the delivery and qualification record for the six coordinated feature
areas. “Local” means implementation and automated checks in this checkout. It
does not imply a deployed Cloud write path or qualification against current
production data.

**Completion status (2026-11-16): the six-feature request is not complete.**
The table records implemented increments and their remaining source, integration
and deployment gaps. Passing local checks does not close those gaps.

The user subsequently authorized Cloud app updates for development/validation
(2026-11-17 UTC). This extends the initial local-only deployment scope; it does
not authorize collector/schedule activation or infrastructure changes.

| Feature                                     | Local workflow                                                                                                                                                                                                                                       | Evidence and verification                                                                                                                                                                                                                         | Remaining qualification                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident timeline and explanations          | `Investigate` compares baseline, incident and recovery windows, ranks deterministic investigation leads by observed contrasts, and separates support, counterevidence, missing evidence and the next read-only check.                                                                                                                                                          | Local comparison rules and historical scenarios; see the current bounded [source observations](FEATURE_SOURCE_OBSERVATIONS.md).                                                                                                                   | Observed source samples now support bounded native-parser and traffic-evidence replay; they do not qualify rendered incident comparisons, audit-event coverage, retention, causation or exact change time.                                                                                                                                                                                                                                                                           |
| Maintenance and failover                    | The optional Impact workflow can capture a before state and compare an after state; assessment separates exposure, readiness, health, capacity, failure domains and substitutability.                                                                | Local conservative model and capture workflow; unknown or incomplete evidence fails closed.                                                                                                                                                       | No qualified live Impact, measured peak-capacity or alternate-readiness feed; do not use the assessment to authorize failover.                                                                                                                                                                                                                                                                                |
| Dependency baselines and drift              | Dedicated authenticated storage, version/history review and manual passive-watch evaluation are connected in the incident Connections section. Watch observations and status now show readable dependency identities, distinct windows and explicit pagination limits. Source-backed capture remains unavailable without a trusted complete provider.                        | Local domain and frontend coverage; the top-N map is ineligible as a complete baseline.                                                                                                                                                           | The HTTP host ships disabled/unqualified and has no production source provider. Collector loss, sampling and lateness closure are unproven; The installed disabled/source-unavailable host contract passes; positive source-backed capture/version/watch, Web/CSRF and backup/restore remain unqualified. A disabled explicit-window action and durable run journal now have local synthetic tests; automatic scheduling, provider-backed execution, installed action/session ACLs and administrator provisioning remain unavailable or unqualified.                                                                             |
| Investigation records and evidence packages | Private shared cases support immutable superseding note/hypothesis/question revisions, source-authorized links from entries to saved comparison captures, per-capture read/export, readable handoffs and explicit JSON evidence packages. Source access is revalidated for each current reader and old retry response. | Domain/API/native/host tests and rendered browser workflows pass. The earlier SDK-based direct REST capture path passed on Enterprise 10.6.0.5 using two non-admin investigators with identical index grants and different search filters, including a second capture. | Persistence and capture mode ship disabled. Raw comparison windows are limited to five minutes each; source retention/configuration changes can withhold evidence while notes remain usable. The new supervised capture transport has not passed positive installed qualification: this Mac’s Rosetta runtime cannot enforce the unchanged helper address-space contract. Native Linux/amd64 end-to-end capture qualification, Web proxy, real-source collection, whole-endpoint bounds, arbitrary file uploads, cleanup scheduling and backup/restore remain unavailable or unqualified. Cloud/SHC are unsupported; browser retry state is memory-only. |
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


## 0.9.2 follow-up candidate

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
limits. Cloud 0.9.1 remains installed. The frozen 0.9.2 archive passed packaging and
release validation with SHA-256
`820dd27c93d687493b002c21fed4bf395b458dfed7234678cc1142cab52a94d7`;
it still requires its own Cloud inspection/runtime result. Package identity and
completed packaging evidence were recorded after the archive was frozen; these
later documentation updates do not change its bytes.
