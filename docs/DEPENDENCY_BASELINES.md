# Dependency baselines and maintenance captures

## What is connected

Impact offers an explicitly opened maintenance assessment. It retains the
returned absolute window and separates potential exposure, reachability, health,
readiness, substitutability, shared failure domains and measured capacity.
Current Impact alternatives are candidates: the adapter does not qualify them
as healthy or capable. Before/after captures stay in page memory, retain their
original windows and can be explicitly downloaded. Source inputs require a
separate unchecked consent control; assessment details can themselves contain
sensitive names and owners.

The investigation Connections section connects to an authenticated baseline
service at `adm/dependency-monitoring`. The handler and exact Splunk Web routes
are packaged, but storage is disabled and the production source is unavailable
by default. The app reports those limits instead of saving a ranked map. The
injected source/repository workflow has synthetic tests; those tests do not
qualify an installed service or its evidence.

## Persistence and access

`default/adm_baselines.conf` ships with `mode = disabled`,
`platform = unqualified`, and `source_mode = unavailable`. The host requires
an authenticated principal with the dedicated `adm_investigate` capability,
which is shipped without a role assignment. Runtime checks additionally require
Enterprise 10.6.0.5 and a standalone search head. Cloud and search head cluster
storage are unsupported. These runtime checks do not constitute installed
qualification. `source_mode = unavailable` is the only shipped source mode;
there is no production source provider or configuration flag that establishes
source completeness. A trusted Python-injected provider is used in tests only.

Once enabled and runtime-qualified, the host uses the fixed private path
`$SPLUNK_DB/splunk_adm_baselines/baselines.sqlite`. It checks directory and file
ownership and permissions and rejects links. This database is separate from
settings and investigation storage; clients cannot choose its location. It is
local and not replicated. The host derives identity from the current Splunk
session, rejects duplicate raw query and header fields, and uses the registered
Splunk Web CSRF protections. Direct API callers must use an appropriately secure,
authenticated transport.

Baselines are private initially. Owners can grant and revoke principal access,
and source authorization is checked independently of baseline membership.
Baseline, version and watch lists contain metadata and require baseline ACL and
current capability access. Reading or exporting a version also checks current
source access to that selected stored capture. Occurrence pages contain
source-derived facts and require access to the watch's pinned baseline and the
relevant occurrence evidence, including pagination lookahead. Access and
revision are rechecked after source authorization. Owners can revoke sharing or
delete a baseline after losing source access.

Versions are immutable and each watch retains its baseline version. Mutations
use revision preconditions and stable request keys. Captures are deduplicated
within each baseline, with an aggregate 8 MiB default evidence limit, 100
versions, 100 watches and 10,000 occurrences. The store also bounds baseline,
membership, record and request counts. Lists and occurrence results are
paginated.

Manual watch evaluation compares a trusted, complete source capture with the
watch's pinned baseline. The server derives findings and applies distinct-window
recurrence, expected windows and cooldown using the trusted server clock. It
checks current access to the pinned version and all retained evidence that can
contribute to the watch history before returning counts or making a change. The
history proof limit is 100 distinct stored captures per watch evaluation; an
unavailable proof or a history above that limit fails closed without a write.
The status endpoint uses the same history checks. It rejects a requested time
before the latest surfaced finding when the earlier cooldown state cannot be
reconstructed. Evaluations do not schedule searches, deliver notifications or
perform actions.

Authorized occurrence reads also return `changeKinds` and the watch's pinned
`baselineVersion`. The server derives these fields from the retained baseline
and that occurrence's retained comparison, after reauthorizing both; the
browser does not classify the current graph or trust submitted labels. Reads
validate compatibility and the stored window, then recheck current access and
revision after deriving the page, including its pagination lookahead.

The labels distinguish newly observed destinations/ports, related dependency
changes, explicitly unblocked-to-blocked observations, fewer observed failure
domains, and dependencies not observed in the comparison window. Unknown
blocking does not establish a new block. Domain counts must be present on both
sides and decrease; changed members with equal counts do not establish a loss.
Newly observed blocked dependencies are labeled new/changed, not newly blocked.
“Not observed” is not removal or an outage. These are read-time comparisons
under the current app rules, not new immutable source records or proof of cause.

A single occurrence may show both newly blocked and fewer-domain labels.
Recurrence counts distinct recorded windows with any qualifying change for the
dependency, across change types; multiple labels do not add windows. Existing
threshold, expected-window and cooldown rules remain unchanged. The UI shows
the pinned version and absolute UTC window. Older responses without both new
fields retain the generic dependency-change presentation; partial, duplicate,
unknown or impossible kind combinations are rejected. No storage migration or
new source mode is introduced.

Projection loads each distinct retained capture once, prepares the baseline
comparison indexes once per page and retains only requested signature
classifications, including lookahead. It does not
retain every baseline finding for every comparison capture. The bounded-work
regression covers a 10,000-dependency baseline and 100 distinct comparisons.

A successful initial manual evaluation returns inserted and surfaced counts.
A retry using the same request key acknowledges the committed revision with
`resultWithheld: true`, without replaying source-derived counts. Legacy
occurrence-write retries have the same withheld-result behavior. Reconcile the
record and, where authorized, its evidence rather than treating a withheld
result as a new evaluation. Occurrence receipt times come from the trusted
clock and follow the capture's knowledge horizon; clients cannot supply
`observedAt`.

Deleted-baseline request receipts remain available for safe retries for 30 days
by default. An independently authorized maintenance method can purge aged
deleted receipts; it is not exposed through the public host. Live receipts
remain subject to a quota, with reserved capacity for revocation and deletion.
There is no automatic cleanup schedule, live-record age retention or standalone
audit feed.

## Evidence prerequisites

The app has no production collector that can currently establish a complete
baseline. A qualified source must provide and validate a collector manifest for
the exact selection and requested window, including collection coverage,
sampling and caps, and evidence of loss or truncation. It must establish a
watermark and a knowledge horizon that accounts for required event lateness,
and verify exact requested and returned bounds. It also needs stable logical
endpoint identity, including historical workload-to-controller identity where
applicable, reliable port and protocol identity, and source, configuration and
normalization revisions. Current caller access must be independently enforced
both when capturing and when reading stored evidence. Incompatible revisions,
unknown coverage or permission, sampling, loss, stale evidence and an incomplete
lateness horizon cannot qualify a capture.

Missing traffic remains “not observed”; it is not proof of removal. Current
bounded Cloud observations establish event receipt and sampled field presence
only; event counts do not qualify the source for complete dependency evidence.
They do not establish historical pod-to-controller identity, complete
dependencies, readiness intervals or measured failover headroom. See
[source observations](FEATURE_SOURCE_OBSERVATIONS.md).

The installed disabled/source-unavailable host contract passed on Enterprise
10.6.0.5 in a fresh task-owned single-head lab against archive
`21245b2804474d654d504b05a4f98c4db0f1fb3f6a167aec68ce6d8d416302a9`.
The test verified dedicated capability denial, disabled defaults, metadata
listing after explicit runtime opt-in, private storage ownership/modes, 422
responses for unavailable capture/evidence writes, duplicate headers/query
rejection, media validation and public purge denial. It did not install a fake
source provider. The earlier SDK-based shared case capture path also passed its independent
installed caller-filter revalidation test against this archive. That does not
qualify its later supervised transport replacement.

Positive installed baseline capture/version/watch evaluation, Splunk Web/CSRF
and operational backup/restore remain unqualified. A separate same-build
synthetic offline SQLite copy rehearsal passes; it does not qualify installed
recovery. Read-derived change labels have local store/API and browser checks,
not positive installed-source qualification. Both task labs were purged, with container,
network, volume, port, credential and TLS cleanup independently checked. See
[qualification evidence](FEATURE_QUALIFICATION.json) for exact test and backend
hashes and remaining limits. This is synthetic local qualification, not Cloud or
real-source qualification.

## Upgrade and rollback

The separate [watch execution contract](DEPENDENCY_WATCH_EXECUTION.md) adds a
disabled administrator/owner-only explicit-window action, immutable bindings
and durable uncertainty tracking. No complete source provider, automatic schedule
or administrator provisioning UI is shipped. Synthetic local execution tests do
not qualify installed scheduling. Its private `watch_runs.sqlite` must be retained
with the baseline database; disabling and re-enabling never clears unknown work.

The engine migrates earlier local inline captures into a deduplicated evidence
table transactionally. Missing legacy source references remain inaccessible;
the migration does not infer authorization. Tests cover preservation and quota
failure. Before any installed rollout, qualify filesystem ownership, backup and
restore, concurrency, source revocation, effective ACLs and the selected runtime.
Keep the endpoint disabled until those checks pass. Code rollback must preserve
the database and its evidence; do not run an older writer against a migrated
database without a separately validated compatibility path.
