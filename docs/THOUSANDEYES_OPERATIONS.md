# ThousandEyes operations and lifecycle

This document is the operator lifecycle for the optional ThousandEyes evidence
source. It complements the concise [setup handout](operators/thousandeyes.md)
and the [integration design](THOUSANDEYES_DESIGN.md). The exact vendor package,
input schemas, source/sourcetype names, and supported package placement are
versioned separately in [package research](research/thousandeyes.md) and the
[capability matrix](research/thousandeyes-capabilities.md). Confirm those
records before using any vendor-specific installation command.

## Operating boundary

The Cisco ThousandEyes Splunk integration owns collection and indexing. Atlas
reads only already-indexed events through its optional evidence workflow. Atlas
has no ThousandEyes credential, API client, collector, HEC sender, scheduled
vendor ingestion, test creation, test-editing, or alert-management path. An Atlas
source selection changes only Atlas search intent; it does not activate or
stop a ThousandEyes input.

Atlas selects source ID `thousandeyes` through shared app configuration. Its
index macro `adm_index_thousandeyes` starts at the inert literal
`index=unconfigured_optional`; `adm_thousandeyes_schema_qualified` starts at
`0`. Explicit JSON setting `te_families` selects admitted producer families:
`metric`, `path`, `trace`, `event`, `alert`, and `activity`. Select only
versioned families that pass producer and target readback gates. A verified
`adm_observer_scope` row uses
`observer_kind=thousandeyes_account_group`, the exact `te_account_group_id`,
`mapping_status=verified`, and administrator-reviewed time-qualified
`te_bindings`. Optional `thousandeyes_origin` is a configured HTTPS origin for
navigation only. These settings are not permission controls: the viewer's
Splunk role must still have access to the selected index.

Set `te_stream_account_id` only for verified `metric`, `trace`, or `activity`
families. Set `te_alert_account_id` and `te_organization_id` only when `alert`
is selected and verified; the raw IDs are not assumed equivalent. Static
package research reports that the CEA path output omits native `testId`/`aid`
identities needed for test/agent-bound attribution. Keep the
`path` family unqualified for that producer unless a separately approved,
versioned path preserves and qualifies those IDs. Atlas has no approved API
collector in this design; any supplemental path requires a separate design
decision. `te_path_sources` separately allowlists at most 16 exact index/source
pairs per mapping from target readback; it does not prove a path's test/agent
identity.

The source remains disabled until the exact vendor integration version, source
families, schemas, target index, time semantics, permissions, mapping, search
capacity, and deployment topology have passed qualification. No event count,
empty feed, test pass, missing span, absent alert, or current-state inventory
can fill a source-coverage gap or imply healthy/failed service state.

## Change gates

| Change | Required checks before Atlas selection resumes |
| --- | --- |
| New account group, test, agent, or location | Confirm account-group identity in the indexed event, target/test identity, permission and test entitlement, applicable mapping and time-qualified bindings, and sample readback. |
| New producer family or vendor input | Confirm the exact integration release documents the input and fields; inspect each schema and timestamp from the deployed input tier; review history/completeness semantics; validate the parser and index readback. |
| Vendor app/input upgrade | Review release notes and supported tier placement; compare effective input/credential config; inspect new sanitized samples and repeat indexed readback. |
| Atlas package upgrade | Deploy a compatible build to all serving search heads; inspect app-merged macro values and settings; verify query, ACL, cancellation, and installed readback gates. |
| Index rename, routing, retention, or ACL change | Update the literal selector and access policy through the reviewed admin path; recheck event time, viewer reads, retention window, and measured search work. |
| Test, agent, application, endpoint, or scope relationship changes | Update only administrator-attested time-qualified bindings; check overlapping validity, reused addresses, NAT/proxy/CDN boundaries, names, and historical boundaries. |
| Topology, role, or search quota change | Requalify on the exact topology, search head/indexer arrangement, effective role capabilities, quotas, and concurrent interactive load. |

For every change, retain the previous effective config and vendor package
checksum. If the event contract or effective mapping becomes uncertain, deselect
the source and set schema qualification to `0` until the change has been
reconciled.

## Capacity and data stewardship

Model three independent limits before launch:

1. **ThousandEyes consumption:** subscription limits and entitlements for tests,
   agents, API access, and collection frequency. Atlas creates no synthetic
   test, but the vendor integration's input cadence can consume vendor API
   capacity. Prefer the minimum cadence that supports the investigation window.
2. **Splunk ingestion and storage:** measure actual daily raw bytes and event
   counts for each selected family. Estimate first-pass daily ingest as
   `records/day × measured average raw event bytes ÷ 1,000,000,000`, then use
   the target deployment's license and storage tooling for the authoritative
   estimate. Account separately for replication, retention, indexes, field
   extractions, acceleration, and environment-specific billing.
3. **Interactive searches:** Atlas caps supplemental input at 10,000 records
   (scanning 10,001 to detect overflow), displays at most 64, and uses one
   completion row; server/client deadlines are 30/35 seconds. Those controls
   cap returned work and fail closed on overflow; they do not guarantee a
   limit on indexer scan cost. Measure actual scan/runtime/resource metrics at
   realistic tenant cardinalities and concurrency. Do not raise caps or search
   quotas without a measured review.

Set vendor-side and Splunk-side history retention independently. Keep the raw
index only as long as approved by legal, privacy, incident-response, and
capacity owners. A vendor API's history window can be shorter than Splunk's
retention, and Splunk retention can expire data still available from the
vendor. Atlas does not backfill expired data or reconstruct omitted events.

Treat test endpoints, agent identity/location, measured paths, synthetic spans,
account-group data, event/alert descriptions, and activity actors as potentially
sensitive. Use a dedicated index and least-privilege viewer role. Keep vendor
secrets in the vendor integration's protected credential store; they never
belong in Atlas shared settings, the browser, a macro, a command, a URL, source
control, or an evidence report. `scope` and `te_bindings` assist attribution;
they do not authorize a viewer to read another tenant's events.

## Rollout sequence

1. **Prepare:** name ThousandEyes, vendor integration, and Splunk owners. Record
   tenant/account group, intended tests/agents, needed families, cadence,
   target index, retention, cost/quota owners, Splunk topology, and accepted
   investigation window. Select only existing tests approved by the owner.
2. **Install:** use the exact vendor integration archive and official
   instructions recorded by package research. Confirm release hash, supported
   Splunk versions, where each input must run, and its protected credential
   workflow. Do not infer support from a package name or from successful app
   installation.
3. **Ingest:** create a dedicated index and route the vendor integration's
   selected existing test/agent output there. Record the actual source and
   sourcetype. Do not enable broad inputs or unrelated account groups to obtain
   more sample data.
4. **Read back:** search the target index as an administrator and then as a
   normal Atlas viewer. Compare sanitized events with the exact schema and
   semantics in research. Confirm time extraction, indexing delay, source
   identity, completeness, and absence of fields or data not authorized for the
   viewer role.
5. **Configure:** set `adm_index_thousandeyes` to the reviewed literal index;
   create a unique admin-attested account-group mapping and validated bindings;
   configure only an approved HTTPS origin if needed. Confirm the effective
   app-merged settings and selector read access on every serving search head.
6. **Qualify:** set schema qualification to `1` only once every selected family
   passes its sample and target readback gates. Configure source intent in
   Setup only after all search heads run the same compatible app and the
   deployment-settings persistence gate has passed.
7. **Canary:** inspect one known test, agent, target, protocol and narrow window.
   Review coverage, denominators, units, missing/partial events, status and
   binding basis. Compare with the vendor's authoritative view for the same
   interval. Increase scope only after discrepancies are resolved.
8. **Observe:** track input errors, vendor API usage, license/index growth,
   search scan/runtime, concurrency, role denial, caps, cancellation and
   stale/partial source status. Maintain the external qualification record
   with every material change.

App-merged selector reads use the existing Configuration Management API path.
Verify the exact required viewer capability on the target; prior standalone
DNS qualification needed `list_conf_objects`, which provides broader
configuration visibility. Do not grant `admin_all_objects` or use a private
macro shadow to bypass a denied shared read.

## Failure handling and disable

A failed or quiet vendor input is an ingestion issue. Inspect the vendor
integration's supported input diagnostics, credential status, API response
limits, account-group scope, and index routing. A returned Atlas status of
missing, denied, stale, capped, malformed, partial, ambiguous, or changed
configuration is an evidence limitation; do not reinterpret it as zero
measurements or a healthy/failed application.

Disable Atlas inspection before changing an integration or binding:

1. Mark `thousandeyes` `not_selected` in Atlas Setup on all serving members.
2. Cancel active ThousandEyes searches and confirm native terminal/deleted
   state before freeing capacity.
3. Set `adm_thousandeyes_schema_qualified=0`. If retiring the source, restore
   `adm_index_thousandeyes=index=unconfigured_optional` and withdraw the
   mapping's verified status after in-flight searches finish.
4. If data collection should also stop, disable only the relevant vendor
   input using the vendor-supported process. Atlas does not own or dispatch
   that action.
5. Keep existing indexed events under the separately approved retention and
   ACL policy. Deleting an Atlas setting or mapping does not purge index data.

After an ingestion outage or mapping change, recheck exact event-time windows,
all selected producer families, account-group identity, and completeness
before reselecting. A current test run cannot repair missing historical
collection. A green vendor status or an Atlas empty result does not establish
coverage for an earlier interval.

## Upgrade, rollback, and retirement

### Upgrade

- Keep the source unselected if either vendor or Atlas upgrade is in progress.
- Preserve the old package, checksum, Atlas app configuration, source settings,
  settings revision/ledger, account-group mapping, vendor input configuration,
  and credential backup according to the vendor's secure method.
- Upgrade the vendor integration only using its current supported procedure.
  Review input placement and field/time changes; don't assume its runtime can
  be rolled back by replacing Atlas.
- Deploy Atlas changes to every serving search head. Confirm its default
  selector is literal and qualification remains false until each source
  family passes exact target readback.
- Revalidate viewer/admin access and search/quota behavior after the target
  topology or role changes. Keep production enablement disabled while any
  member or data family is unqualified.

### Rollback

- Deselect `thousandeyes`, cancel and drain active searches, set schema
  qualification to `0`, and restore the safe index selector on all search
  heads before deploying an older Atlas package.
- Preserve the shared deployment-settings ledger and keys the older build may
  not recognize. If that build cannot round-trip the new source fields safely,
  keep or restore a compatible build; do not save a partial older settings
  payload over newer state.
- Roll back the vendor integration separately, if needed, using its owner and
  supported rollback procedure. Preserve the raw index and vendor evidence
  while deciding whether collection should resume.
- Restore selection only after the exact Atlas/vendor/index/topology combination
  has been checked again and its qualification record updated.

### Remove or reinstall

Remove only the Atlas component the owner intends to retire. Before uninstall,
export needed app configuration, mappings, ledger/revision and qualification
records; finish active inspection jobs and deselect the source. The vendor
integration, protected credentials, ThousandEyes tests, Splunk index, and
indexed evidence are independently managed. Removing Atlas does not disable or
remove those resources and does not authorize deleting the raw index.

For reinstall, start with source ID `thousandeyes` unselected,
`adm_index_thousandeyes=index=unconfigured_optional`, and
`adm_thousandeyes_schema_qualified=0`. Restore settings only after checking the
current integration version, actual source data, retention, index ACLs, mapping,
and target deployment qualification. If the raw index or mapping history was
removed, do not reconstruct historical identity from current names or addresses.

## Benchmark interpretation

The reproducible benchmark tool measures Atlas-side normalization and
attribution on deterministic synthetic data at defined record cardinalities.
It records the workload, source-family mix, selected identity/binding counts,
Node/V8 version, elapsed time, and memory observations. It must not contact
ThousandEyes, Splunk, customer systems, or the vendor API. Synthetic benchmark
results estimate application-side work only; they do not qualify producer
cadence, API quota, indexer scan cost, license use, storage, or any real
enterprise topology.

Run `node tools/benchmark_thousandeyes.mjs --help` for supported deterministic
profiles and output format. Preserve the command, tool revision, output, and
runtime metadata with the candidate's qualification artifacts. Do not use
customer events or tokens as benchmark input. Use target Splunk job metrics
and license/index statistics separately for an external capacity decision.
