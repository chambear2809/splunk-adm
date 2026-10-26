# ThousandEyes evidence setup

Application Atlas can inspect selected evidence already indexed by the
Cisco-supported ThousandEyes Splunk integration. Atlas does not call the
ThousandEyes API, create or change tests, run collectors, or deliver events.
Keep this optional source unselected until the exact vendor package, producer
schemas, target index, account-group mapping, and viewer permissions are
qualified. Read the [integration design](../THOUSANDEYES_DESIGN.md), the
[package research](../research/thousandeyes.md), and the
[capability matrix](../research/thousandeyes-capabilities.md) before enabling
it.

ThousandEyes measurements are synthetic observations from named tests and
agents. Paths describe the tested agent-to-target probe path; traces remain
synthetic spans; events and activity remain vendor-supplied lifecycle and
change context. These records do not add passive traffic, observed dependency
edges, service ownership, backend calls, or traffic counters. An empty or quiet
feed is not evidence of health or source coverage.

## Owners and prerequisites

Keep the responsibilities separate:

- **ThousandEyes owner:** selects existing tests and agents, account group,
  collection cadence, and any vendor-side retention or API access. Do not create
  tests just to make Atlas return records. Confirm the subscription permits the
  selected tests, agents, data access, and cadence.
- **Splunk integration owner:** installs and configures the exact supported
  Cisco ThousandEyes integration release using its documented placement and
  credential storage. Configure only the input families needed. A vendor input
  or credential failure is handled by that integration, not Atlas.
- **Splunk platform owner:** creates and retains the target index, places the
  vendor integration on the supported tier(s), controls index ACLs and search
  quotas, and checks timestamp parsing and searchable readback.
- **Atlas administrator:** configures the shared literal index selector,
  schema qualification, verified account-group mapping, and selected source
  intent. Updates to settings are subject to the existing
  [deployment-settings persistence gate](../DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate).
- **Atlas viewer:** needs read permission to the selected ThousandEyes index.
  Routing scope is attribution context and does not replace index ACLs.
  App-merged configuration reads use the existing Configuration Management
  API path. Verify the required viewer capability on the exact target; current
  DNS qualification required `list_conf_objects` on the tested standalone
  release, which exposes broader configuration visibility. Do not grant
  `admin_all_objects` or use private macro shadows to bypass a denied read.

Before setup, record the exact ThousandEyes tenant/account group, vendor
integration package/version and hash, Splunk release and topology, input and
search tiers, enabled data families, index, source/sourcetype values, test and
agent IDs, collection interval, and event-time behavior. Compare each item with
the exact release evidence in the research documents. A local synthetic test
or a successful vendor API request does not qualify the deployed integration,
indexing path, search permissions, or topology.

## Install and qualify vendor ingestion

1. Follow the exact package release's official installation and input
   configuration instructions. Verify the package signature/hash, supported
   Splunk releases, input placement, and every enabled source family against
   the [package research](../research/thousandeyes.md). Do not assume the
   candidate archive or a newer release has the same inputs, fields, or
   deployment placement.
2. Use a vendor-supported read-only identity scoped to the intended ThousandEyes
   account group and existing tests. Store its credential only in the vendor
   integration's supported protected credential store. Do not put tokens in
   Atlas settings, macros, test fixtures, commands, URLs, screenshots, support
   bundles, or this repository. Rotate credentials through the vendor
   integration's supported workflow.
3. Enable only the existing inputs and data families required for the
   investigation. Record the vendor-side cadence and the intended test/agent
   inventory. Check tenant API limits, test entitlements, agent limits, and
   data/event retention before increasing collection frequency or scope.
4. Create a dedicated Splunk index for the selected records, with retention
   approved by the data owner. Route the vendor integration to that index and
   install/configure it at the tier required by the exact vendor release.
   Do not point the Atlas selector at a general-purpose index containing
   unrelated or more sensitive data.
5. Wait for data from an approved existing test. Search the target index with a
   Splunk administrator account and save sanitized samples for each enabled
   producer family in approved internal evidence storage. Verify the exact
   source, sourcetype, account group, test/agent identities, field types,
   measurement units/aggregation, event time, indexing delay, and completeness
   semantics against the research matrix. Check both normal and negative test
   results, partial/missing fields, duplicate or conflicting events, quiet
   periods, and the vendor's actual event/activity history behavior.
   Static package research reports that the CEA path output omits native
   `testId`/`aid` identity. Keep the `path` family unqualified for test/agent
   attribution unless an approved, versioned ingestion path preserves those IDs
   and passes the same target readback checks. Do not synthesize IDs from names.
   The current
   design has no approved Atlas-side API collector; any proposed supplemental
   producer path needs a separate design decision.
6. Verify the whole indexing path preserves the producer fields and assigns
   `_time` according to the reviewed contract. A REST/API success, HEC
   acceptance, or vendor dashboard result alone does not prove that Atlas
   viewers can search the indexed records.
7. Confirm an Atlas viewer can read this index and cannot change the shared
   source selector, schema qualification, or account-group mapping. Review the
   effective search quotas and indexer/search-head capacity with the expected
   concurrent inspection load. Keep the source unselected when any gate is
   unresolved.

## Configure Atlas

The shipped settings are inert: source ID `thousandeyes` starts unselected,
`adm_index_thousandeyes` defaults to `index=unconfigured_optional`, and
`adm_thousandeyes_schema_qualified` defaults to `0`. The explicit JSON
`te_families` setting controls which reviewed source families are admitted. Its
allowed values are `metric`, `path`, `trace`, `event`, `alert`, and `activity`;
choose only families supported by the exact integration version and target
readback. The current CEA path gap leaves `path` unqualified for
test/agent attribution.

The placeholder neither selects an index nor proves that the vendor input is
running.

After vendor ingestion and searchable readback pass:

1. Set `adm_index_thousandeyes` to one reviewed literal index selector, such as
   `index=thousandeyes`; use the actual dedicated index name. Do not put an SPL
   search, wildcard, event-derived string, URL, or credential in this macro.
2. As an administrator, add one unambiguous row to the existing
   `adm_observer_scope` mapping for each account group. Use
   `observer_kind=thousandeyes_account_group`, the exact canonical
   `te_account_group_id` supplied by indexed events, the approved `scope` and
   optional `cluster`, and `mapping_status=verified`. Add `te_bindings` only
   after the relevant application/endpoint and test/agent relationships have
   been independently checked. Bindings are time-qualified assertions; use the
   exact versioned shape documented in the design and package evidence. Each
   binding names its authority, account group, scope, test ID, agent ID, target,
   endpoint address set, time validity, and configuration ID; application and
   agent location are optional labels. Validity is explicit, and at most 64
   bindings are accepted per account-group mapping. Do not join on display
   names, tags, current inventory, or IP equality alone.
3. Set `te_families` to an explicit JSON list of only the producer families
   whose installed integration version, event schema, identities, event time,
   completeness, and target readback have all passed. Do not infer that a
   family is available because its vendor input is enabled. For verified
   `metric`, `trace`, or `activity` families, set `te_stream_account_id` to the
   raw stream account ID. For `alert`, set `te_alert_account_id` and
   `te_organization_id` to their separately verified raw IDs. Never assume
   these account or organization IDs are equivalent to one another or to
   `te_account_group_id`.
4. For selected measured-path evidence, set `te_path_sources` only to exact
   index/source pairs observed in the sanitized target readback and approved for
   this account group. Do not wildcard or infer source names from test labels.
   The source/index pair is a separate admission check from the `path` family
   selection; the configuration accepts at most 16 exact pairs per mapping.
5. If source navigation is needed, set `thousandeyes_origin` to the approved
   HTTPS origin only (scheme and authority, with no credentials, path, query,
   or fragment). It is a configured navigation root; it does not establish an
   object deep-link route. Never construct a link from event-supplied hostnames,
   IDs, or URLs.
6. Set `adm_thousandeyes_schema_qualified=1` only after reviewing sanitized
   indexed examples for every selected family and confirming the exact schema,
   timestamps, account group, test/agent identity, and target deployment
   readback. A successful search or an existing index is not enough.
7. In Atlas Setup, select `thousandeyes` only after the literal selector,
   qualification flag, verified mapping, source permissions, and settings
   persistence have been checked on all serving search heads. Begin with one
   known test/agent and a narrow time window; inspect completeness, source
   failures, caps, and attribution before expanding the scope.

The app's bounded supplemental search scans at most 10,001 records to detect a
10,000-record input cap, returns at most 64 display records and one completion
record, and has a 30-second server / 35-second client deadline. These are
application bounds, not guarantees on indexer scan cost or vendor collection
completeness. A capped, stale, partial, denied, malformed, or configuration-
changed result must stay incomplete or unavailable. Do not raise the caps or
search quotas to conceal missing source coverage.

## Capacity, quota, cost, and retention

No fixed ThousandEyes or Splunk cost follows from enabling Atlas. Before a
pilot, estimate the vendor-side API/test/agent consumption from the selected
existing tests and collection cadence, then check the contracted tenant limits.
For Splunk, measure the actual indexed event count and uncompressed event bytes
for a representative day. A first-order daily ingest estimate is:

```text
records per day × measured average raw event bytes ÷ 1,000,000,000
```

Use the target deployment's license and workload tooling for the authoritative
capacity and cost decision; the estimate omits replication, acceleration,
search concurrency, storage policy, and local billing rules. Measure daily
index growth, data-model/field extraction overhead if configured, vendor input
API activity, scheduled and interactive search load, and concurrent Atlas
inspections. The 10,000-record Atlas result cap limits returned evidence, not
all indexed events evaluated by Splunk.

Set raw-index retention from the organization's legal, privacy, investigation,
and storage requirements. Vendor-side history retention and Splunk index
retention are independent. Shorter vendor retention can make historical tests,
alerts, or activity unavailable even while older Splunk events remain; index
expiry can likewise remove evidence still present at the vendor. Record both
policies and the intended investigation window. Do not use an Atlas display
window as an index retention policy.

Treat test targets, agent locations and addresses, paths, traces, actor names,
alert details, and activity as potentially sensitive operational data. Grant
index access only to approved Atlas viewers and the vendor integration owner.
Keep sanitized qualification evidence under the organization's approved data
handling policy; do not add customer event captures to the repository.

## Disable, rollback, upgrade, and removal

### Disable future Atlas inspections

1. In Atlas Setup, mark `thousandeyes` `not_selected` on every serving search
   head. Cancel any active ThousandEyes inspection and verify the search has
   reached a terminal or deleted state before treating its job capacity as
   available.
2. Set `adm_thousandeyes_schema_qualified=0`. Restore
   `adm_index_thousandeyes` to `index=unconfigured_optional` if the source is
   being retired. Remove or mark the ThousandEyes account-group mapping
   unverified only after the source is deselected and its in-flight inspections
   are finished.
3. Decide separately whether the vendor integration should keep collecting.
   Atlas selection does not enable, disable, or change vendor inputs. If
   collection should stop, the ThousandEyes and Splunk integration owners must
   disable only the intended vendor inputs using the vendor-supported process.
4. Keep indexed records under the index's normal retention and access policy.
   Disabling Atlas does not delete events or erase the vendor-side test history.

### Upgrade or package rollback

1. Record the candidate Atlas archive and checksum; back up the effective
   ThousandEyes macros, deployment-settings ledger/revision, account-group
   mapping, and any local app configuration. Preserve the vendor integration's
   own configuration and protected credentials using its documented backup
   method.
2. Update all Atlas search heads to a compatible package before selecting the
   source or saving settings. During a rolling update, keep the source
   unselected and schema qualification at `0`; mixed app versions can disagree
   about optional settings and bindings.
3. Recheck the exact vendor release and target index after either app or vendor
   integration update. Vendor input upgrades can change field shapes, time
   handling, package placement, or credential storage. Requalify sanitized
   samples and viewer readback before setting the qualification flag to `1`.
4. Before rolling Atlas back, first deselect `thousandeyes` on every member,
   reset the qualification flag, and restore the safe literal index selector.
   Keep the settings ledger and unknown keys intact. If the older package
   cannot preserve the current settings schema, restore a version that
   understands the schema; do not save an older partial settings record over
   it.
5. App-package rollback and vendor-input rollback are separate operations.
   Never remove or downgrade the vendor integration solely to undo an Atlas UI
   change. Requalify the exact combination before reselecting the source.

### Remove or reinstall

Before uninstalling Atlas, deselect the source, reset the flag and selector,
finish/cancel in-flight inspections, and preserve the app settings/mapping and
required recovery evidence. The ThousandEyes index, indexed records, vendor
inputs, vendor credentials, and vendor-side tests have separate owners and
lifecycles. App removal does not make a retention or deletion decision for
those resources. Reinstallation starts with the source unselected and schema
qualification false; restore settings only after confirming the installed
vendor release, index contents, mapping, ACLs, and topology still satisfy the
current qualification record.

## External qualification record

Keep this source unqualified until the target deployment has a dated record of
all of the following:

- exact ThousandEyes integration archive/version/hash and supported Splunk
  release, deployment topology, input/search tier placement, and selected input
  families;
- account group, selected existing tests/agents, vendor permission scope,
  test/API quotas, collection cadence, and both vendor and Splunk retention;
- actual sanitized samples and indexed readback for each selected producer
  family, including field names/types, units, aggregation/direction, event
  interval, `_time`, indexing delay, duplicate behavior, and event/history
  completeness;
- literal destination index and source/sourcetype values, viewer read access,
  administrator-only settings/mapping write access, and safe configured origin;
- unique verified account-group mapping, time-qualified bindings, clock and
  identity checks, and negative/ambiguous/partial/capped cases;
- measured index growth, license usage, search concurrency, scan/resource cost,
  result/cancellation behavior, and any target-specific deployment limits.

Synthetic tests, fixtures, a local Splunk lab, package inspection, and vendor
API access do not replace these real-source and topology checks. Keep only the
capabilities that pass each applicable gate qualified.
