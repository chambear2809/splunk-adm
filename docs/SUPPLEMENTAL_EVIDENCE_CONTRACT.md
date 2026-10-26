# Supplemental evidence contract

Application Atlas supports optional sources alongside the existing DNS inspection. Each source is selected explicitly in deployment settings. An unselected source dispatches no search, changes no core graph behavior, and does not make a paid service mandatory.

## Shared boundaries

- `EvidenceSelection` v1 fixes workflow, verified routing scope, literal addresses, absolute interval, actual observed traffic contexts, identity basis and the configuration fingerprint. Routing scope is attribution context, not an authorization boundary. Searches run with the caller's Splunk permissions.
- A source record retains authority, producer/schema version, source index and fingerprint, event and index time, observation or validity interval, and the fields needed to explain a claim. Event time, flow aggregation interval and asset effective interval are separate concepts.
- DNS reports resolution observations; Envoy reports a request and its two explicitly reported transport legs; VPC Flow Logs report aggregated interface observations; CMDB/IPAM reports inventory and ownership candidates; Observability Cloud reports exported measured health. Detector alerts are not queried by this initial integration. None of these automatically establishes another relationship type or a network root cause.
- Source-specific bytes, packet counts, request counts and health metrics keep their original units, interval and aggregation. Observations from different sensors are never added to traffic totals.
- Each optional search uses reviewed literal index/authority selectors, at most 10,001 input rows, at most 64 displayed records plus one exact completion row, and 30-second server / 35-second client deadlines. The browser admits at most two optional jobs, one per source, behind core searches. Cancellation and configuration recheck invalidate stale associations.
- Missing or duplicated completion metadata, warnings, truncation, malformed records, denied access, stale collection, ambiguous or unqualified identity, and changed configuration remain visible as uncertainty. An input cap never supports a unique-association claim. A zero-result caller-visible search does not prove source coverage or absence of activity.
- Optional index selectors are disabled by `index=unconfigured_optional`. Operators must set the source-specific index macro, verified `adm_observer_scope` authority mapping, and schema qualification flag. The `optional_evidence` readiness tier does not affect core readiness.

## Source authority

| Source | Authority mapping kind | Initial producer contract | Relationship |
| --- | --- | --- | --- |
| Stream / Hubble DNS | `dns_sensor` / `cluster` | Stream DNS transaction and Hubble DNS L7 | observed resolution; candidate traffic name only with compatible client, scope and time |
| Envoy | `envoy_proxy` | Envoy v1.40.0 HTTP terminal access event JSON | explicit request with downstream and selected upstream sockets |
| AWS | `aws_vpc_flow` | fixed 29-field custom VPC Flow Logs v5 | aggregated interface flow observation; action is capture-point decision |
| Asset history | `asset_authority` | versioned CSV/JSON import | time-qualified inventory/ownership candidate only |
| Observability Cloud | `o11y_export` | completed SignalFlow historical export | time-aligned measured health; detector state remains unqueried |
| ThousandEyes | `thousandeyes_account_group` | explicitly qualified Cisco app 0.9.0 input families; strict synthetic OTLP v2 and native API contracts | synthetic measurements, probe paths, synthetic traces and vendor lifecycle/activity context; no passive counters or dependency edges |

AWS mappings additionally pin account ID, Region and VPC ID. Service health authority pins an exact custom APM Monitoring MetricSet ID, organization and realm; association also requires environment, service namespace/name and workload identity when available. Default and custom MetricSets must not be combined. Asset history uses half-open effective intervals and retains conflicts, retirement and current-only limits.

## Validation matrix

| Source | Focused failure cases | Non-lab checks | Final installed-app cases | External qualification |
| --- | --- | --- | --- | --- |
| DNS | negative replies, alias/TTL ambiguity, event timing, IP reuse, incomplete source | adapter and endpoint tests, browser panel | Stream/Hubble SPL, REST permissions, result caps, failure isolation | sanitized real feeds and clocks |
| Envoy | missing upstream/IDs, shared proxy, concurrent requests, port reuse, retries, XFF | parser/query/panel tests and frontend build | exact access-event SPL, two legs, optional absence | real configured Envoy logs |
| AWS | malformed/reordered 29 fields, overlap, status/action, duplicate subscriptions, ENI history | strict parser/query tests, props/static checks | ingestion time, interval and authority SPL, no cross-sensor sum | real VPC v5 feed and historical bindings |
| Asset history | changes, retirement, conflicts, current-only, duplicate/invalid import | importer and query tests, lint | indexed history before/after validity and ambiguity | actual export history completeness |
| Observability | identity collisions, units, gaps, timeout/partial export, stale data | export and metric tests, frontend build | indexed metric and completion readback, source absence | real realm/API/metric dimensions |
| ThousandEyes | native units/time, failed rounds, replay/conflict, scope/configuration history, proxy/address ambiguity, caps, cancellation | strict parser, query, attribution, comparator, panel and exporter tests | exact raw JSON query, caller permissions, installed optional assets, upgrade/rollback | genuine sanitized HEC/API readback, exact producer versions, clocks, deployment and capacity |

Final validation uses one task-owned disposable lab against the final package. Synthetic fixtures and lab ingestion establish implementation behavior, not production source qualification.

The existing Splunk page ships as one IIFE. The five optional inspection paths lift its measured gzip size to 665,855 bytes in the final candidate build, 255 bytes over the former 650 KiB release budget. The enforced release ceiling is raised proportionately to 660 KiB; it remains a hard package check. A future split loader can reduce the shared initial download, but it requires a separately reviewed Splunk page loading change.

For the optional integrations in 0.5.0, the same baseline commit
`b8f05490f3df8352ff88f9b803ca39d7df3a14d5` rebuilt with Node 22.13.0 and the
unchanged lockfile measures 666,623 gzip bytes using the release check's Python
gzip calculation. The initial integrated AppDynamics and detector inspection
build measures 676,261 bytes: 9,638 bytes (1.45%) of growth, and 421 bytes above
the prior 660 KiB ceiling. The hard ceiling is 670 KiB (686,080 bytes), a 10 KiB
increase covering these two bounded inspection paths with modest headroom.
The final package measurement and exact archive hashes belong in
`OPTIONAL_INTEGRATIONS_QUALIFICATION.md`. No runtime dependency was upgraded,
and external collectors remain outside the Splunk app archive.

For ThousandEyes in 0.6.0, the existing main-page ceiling stays at 670 KiB.
An explicit investigation action loads a separately versioned same-origin IIFE
and stylesheet, bounded to 48 KiB gzip and 16 KiB raw respectively. Main and
optional assets share a source-derived version; the package gate rejects stale
or missing assets. The optional bundle reuses the host React and search helpers.
It creates no second SDK runtime or automatic source query.

Native measurement time and source/index time remain separate. Since the
vendor CURRENT setting does not attest an explicit outer HEC timestamp's basis,
ThousandEyes retains `_time` as unqualified row time and `_indextime` as indexed
time. Its retained-index scan uses a conservative native-time prefilter before
the 10,001-row cap; unknown time shapes remain candidates for strict parsing.
A historical selection does not establish collection continuity or present
upstream health. See [the design](THOUSANDEYES_DESIGN.md) and
[qualification record](THOUSANDEYES_QUALIFICATION.md) for evidence and limits.
