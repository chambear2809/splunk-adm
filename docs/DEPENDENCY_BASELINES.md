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

The investigation Connections section offers dependency-baseline review. In
the packaged app there is currently no qualified complete dependency source or
authenticated baseline transport. It reports that limitation instead of saving
a ranked map. The injected source/repository workflow is covered by a synthetic
browser replay, including eligibility, comparison, lost-response retry, passive
watch definitions and denied-access clearing. This is not a deployed baseline
service.

## Dedicated persistence contract

`splunk_app/splunk_adm/bin/adm_baselines_lib` provides a SQLite domain engine and
a transport-neutral `BaselineAPI`. No REST handler, capability, Web proxy route,
schedule or notification is registered for it. It does not use settings or case
storage. Creating a store requires a trusted source validator; protected reads
also require the separate current-source entitlement callback, which denies by
default. A client-supplied qualification flag is never sufficient.

Baselines are private initially. Explicit principal sharing is revocable and
does not bypass current source access. Versions are immutable; watch definitions
retain their baseline version. Mutations use revision preconditions and stable
request keys. Captures are deduplicated within each baseline, with an aggregate
8 MiB default evidence limit, 100 versions, 100 watches and 10,000 occurrences.
The store also bounds baseline, membership, record and request counts. Listing,
versions, watches and occurrences are paginated.

Deleted-baseline request receipts remain available for safe retries for 30 days
by default. An independently authorized maintenance method can purge aged
deleted receipts. Live receipts remain subject to a quota; reserved revocation
and deletion capacity lets an owner remove access or delete data after ordinary
write capacity is reached. There is no automatic cleanup schedule, live-record
age retention, installed backup/restore qualification or standalone audit feed.

The API strictly validates methods, paths, JSON fields, media type, size,
revision and idempotency headers. The future host must derive the principal
from its authenticated server context, reject duplicate raw headers/query keys,
enforce CSRF and TLS, and configure source validation and current source access.
Do not expose the adapter directly or authorize by a routing-scope label.

## Evidence prerequisites

A baseline requires exact requested/returned bounds, stable semantic endpoint
identity, source/configuration/normalization versions, an adequate lateness
horizon and explicit complete, uncapped, unsampled collection. Source changes,
permission changes and incompatible normalization prevent comparison. Missing
traffic remains “not observed”; it is not proof of removal. Watch findings are
passive and require compatible source-backed captures; no owner-context search
or notification is exposed through the viewer.

Occurrence receipt times come from the store's trusted clock and must follow the
capture's knowledge horizon. Clients cannot supply `observedAt`; same-request
retries retain the original receipt time. Native event time and capture windows
remain separate from this receipt timestamp.

Current bounded Cloud observations establish event receipt and sampled field
presence only. They do not provide historical pod-to-controller identity,
complete dependencies, readiness intervals or measured failover headroom. See
[source observations](FEATURE_SOURCE_OBSERVATIONS.md). Those contracts and an
authenticated target-specific host must be implemented and qualified before
calling baseline monitoring complete.

## Upgrade and rollback

The engine migrates earlier local inline captures into a deduplicated evidence
table transactionally. Missing legacy source references remain inaccessible;
the migration does not infer authorization. Tests cover preservation and quota
failure. Before any installed rollout, qualify filesystem ownership, backup and
restore, concurrency, source revocation, effective ACLs and the selected runtime.
Keep the endpoint disabled until those checks pass. Code rollback must preserve
the database and its evidence; do not run an older writer against a migrated
database without a separately validated compatibility path.
