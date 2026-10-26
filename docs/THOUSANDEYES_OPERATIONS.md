# ThousandEyes operations and lifecycle

This is the detailed operating procedure for Atlas's optional ThousandEyes
source. Use the [setup handout](operators/thousandeyes.md) for the short
checklist. Version-specific vendor contracts and known documentation conflicts
are recorded in [package research](research/thousandeyes.md), the
[capability matrix](research/thousandeyes-capabilities.md), and
[operating constraints](research/thousandeyes-operating-constraints.md).

## Ownership boundary

The Cisco ThousandEyes Splunk App owns its configured push/pull inputs and
index routing. Atlas reads already-indexed records in its optional caller-owned
evidence workflow. Atlas browser code has no ThousandEyes API credential and
does not create tests, run vendor collection, edit alerts, or change HEC.

CEA path identity and detail are an exception to the vendor package's raw path
output: the repository's optional operator exporter attaches the request's
account-group and test IDs to each CEA result and fetches per-agent/round
detail so actual hop arrays are available. It writes an explicit HEC envelope
and queues the capture in the existing durable sender. It is not a browser
capability or a replacement vendor input. The exporter passed mocked local
tests, but live producer collection, HEC delivery, and indexed readback remain
unqualified. No Cisco vendor code is executed to perform this export.

Atlas uses source ID `thousandeyes`, literal index macro
`adm_index_thousandeyes` (default `index=unconfigured_optional`), and schema
qualification macro `adm_thousandeyes_schema_qualified` (default `0`). The
explicit JSON `te_families` selects `metric`, `path`, `trace`, `event`, `alert`,
and/or `activity`. Each account-group mapping uses
`observer_kind=thousandeyes_account_group`, exact `te_account_group_id`,
`mapping_status=verified`, and optional time-qualified `te_bindings`.
`te_path_sources` admits exact path index/source pairs. `thousandeyes_origin` is
only a configured HTTPS navigation origin. None of these settings replaces
Splunk index ACLs.

Stream identity (`te_stream_account_id`) and webhook identity
(`te_alert_account_id`, `te_organization_id`) remain separate fields. Cisco's
OTel schema does not state that `thousandeyes.account.id` equals the native
account-group `aid`; attest this from the account-group list or target readback.
Webhook `accountId` and `orgId` are separate. Do not equate them to each other
or to `te_account_group_id` without evidence.

## Vendor release, topology, and authorization

As of 2026-10-26, Splunkbase lists Cisco ThousandEyes App 0.9.0 as Cisco
Supported and compatible with Enterprise/Cloud 9.1–10.6. The current Cisco app
guide and embedded README publish narrower ranges. Keep the mismatch in the
target qualification record and confirm the exact release with the platform
owner. The user-supplied archive hash is recorded but not publisher-verified.

A locked local co-install diagnostic on Splunk Enterprise 10.6.0.5 with the
unmodified Cisco TA 0.9.0 failed `btool check` with exit code 1. Its only
diagnostic was:

```text
Invalid key in stanza [triggers] in ta_cisco_thousandeyes/default/app.conf,
line 27: notable_event_actions = reload
```

The check was run as:

```sh
docker exec -u splunk "$ADM_LAB_NAME" /opt/splunk/bin/splunk cmd btool check
```

The package was not patched. This is a TA compatibility/configuration defect
independent of Atlas AppInspect: although Atlas AppInspect passed and Atlas
qualification remains disabled, neither clears this TA failure. Do not claim a
clean full-TA co-install on that release. Keep Atlas's ThousandEyes source
unselected until the target owner resolves the vendor package gate and records
a fresh check. Static inspection also found the trace `EVAL` expression in
`default/props.conf` at line 45 missing its closing `)`; trace parsing remains
unqualified pending syntax validation. Do not repair vendor files in place.

Atlas `adapterVersion=0.9.0` identifies the reviewed parsing contract against
the supplied Cisco package; it does not identify the installed producer
version. OTLP v2 can be verified from the native resource version, but records
without an explicit producer software version retain
`producerVersion=not_reported`. API v7 and the Atlas path wrapper are declared
contracts, not proof of a running vendor release. Do not infer producer
version continuity from a matching payload shape; comparisons with an
unreported version must keep that continuity limitation visible.

Cisco's distributed placement table requires the app on the heavy forwarder and
search head/search head cluster, and excludes indexers/indexer clusters. Its
guide lists standalone and SHC; the public guide lacks deployer-specific SHC
steps. Splunk Cloud is listed as supported for Victoria; Cloud Classic is
unsupported by the current Cisco UI guide. Validate actual placement, tenant
experience, app vetting, runtime, and rollout on every serving tier. Do not
infer a production topology from the local synthetic lab.

Cisco app setup uses an OAuth device-code flow. The published TE permissions
include edit rights for connectors/operations, streaming integrations, and
alert rules, as well as broad test, endpoint, user, activity, label, and alert
read access. Treat these vendor permissions as configuration authority and
have the TE owner approve them. App configuration pages require Splunk
`admin_all_objects` or `sc_admin_all_objects`; do not give those capabilities to
Atlas viewers. Cisco's Alerts input changes webhook resources and selected
alert rules. Keep it disabled unless an owner has approved those changes.

Atlas viewers need read access to the chosen events index. App-merged selector
reads use the Configuration Management API path; check the exact required
viewer capability on the target. A previous standalone optional-source test
required `list_conf_objects`, which exposes broader configuration visibility.
Do not grant `admin_all_objects` or use a private macro shadow to bypass a
shared read denial. Atlas settings and scope mappings remain admin-controlled.

## Indexes, HEC, and family contracts

For Cisco App 0.9.0, configure **events indexes** for all six families. Cisco's
separate direct OTel-to-Splunk guide describes other endpoints and metrics
indexes; those are not this app's HEC contract.

Enable and expose HEC to the ThousandEyes producer, use TLS with a valid
non-self-signed certificate, and provide an enabled HEC token whose allowed
indexes include the destination. Cisco's app examples use
`/services/collector/event`. Verify the actual target configuration and indexed
readback; HEC acceptance alone is insufficient.

| Family                | Producer / package source and sourcetype                                   | Readback requirements                                                                                                                                               |
| --------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metrics               | OTel v2 push; `cisco:thousandeyes:stream` / `cisco:thousandeyes:metric`    | Verify actual HEC body, flattened metric/time fields, units, source/test-agent IDs, and `thousandeyes.account.id` equivalence.                                      |
| Traces                | OTel v2 push; `cisco:thousandeyes:stream` / `cisco:thousandeyes:trace`     | Verify trace/span hierarchy and nanosecond fields. API traces remain unqualified until Cisco confirmation or an actual supported sample.                            |
| Activity              | OTel v2 push; `cisco:thousandeyes:stream` / `cisco:thousandeyes:activity`  | Verify timestamps and account identity; actor and activity resource are context, not test/agent identity.                                                           |
| Detected events       | API poll; `cisco:thousandeyes:event`; source unspecified                   | Verify `aid`, event times, page history, event delay and interval. Affected-ID arrays remain context unless a scalar identity contract is documented.               |
| Alerts                | Webhook; `cisco:thousandeyes:webhook` / `cisco:thousandeyes:alerts`        | Verify separate `accountId`/`orgId`, conditional test ID, alert lifecycle fields, HEC time, and the approved rule-change scope.                                     |
| Cisco path            | API pull; `cisco:thousandeyes:path-vis`; source unspecified                | Endpoint result IDs may be native; raw CEA responses omit per-result `aid`/`testId`, and summaries do not contain real hop details. Verify source and detail shape. |
| Atlas CEA path export | Operator API export; `atlas:thousandeyes:path` / `atlas:thousandeyes:path` | Verify wrapper schema, explicit CEA account/test IDs, agent/round detail hops, HEC delivery, and indexed source/index/time readback.                                |

The Cisco package sets `DATETIME_CONFIG=CURRENT` for its six sourcetypes. Public
package/docs do not demonstrate each actual outer HEC `time` or final indexed
`_time`. Preserve raw producer timestamps and qualify the staged HEC envelope
and `_time` from a sanitized readback. Atlas retains native measurement time,
Splunk row time, and `_indextime` separately. It uses the native timestamp
contract to select a measurement window; `_time` and `_indextime` do not stand
in for native measurements.

For event and Cisco path modular inputs, the package does not explicitly set
`source` or `host`. For OTel, Cisco's guide publishes a stream source and
sourcetype but asks the operator to configure a HEC token source override.
Treat the published mapping as an expectation, not proof of target metadata.
Read back `_raw`, `host`, `source`, `sourcetype`, `index`, HEC metadata, `_time`,
and `_indextime` for every selected family. Never use Splunk `host` as a
substitute test or agent ID.

## CEA path export operations

The Cisco package asks the test-level [Path Visualization API](https://developer.cisco.com/docs/thousandeyes/get-path-visualization-test-results-by-agent-and-round/)
for a selected account group and test, but it serializes CEA results without
those request IDs.
The public CEA response has `agent.agentId`, `roundId`, and path summary
fields; it does not define per-result account-group/test IDs. To inspect
measured hops, a separate `/test-results/{testId}/path-vis/agent/{agentId}/round/{roundId}`
detail call is needed. The exporter paginates summaries and then fetches
per-agent/round detail, preserves native result fields and units, and wraps
them with `authority`, `account_group_id`, `test_id`, and `test_domain=cea`.

Use the repository CLI only from an approved operator environment. It accepts
one to 16 literal test IDs and a whole-second UTC-offset date range of at most
24 hours. It has bounded response bytes, API request count, page count, round
count, event size, and capture bytes. Before an export, confirm the account
group, existing CEA test IDs, request window, API read permission, current rate
limit, target events index, HEC TLS/token, protected output path, and spool
owner. Provide `THOUSANDEYES_API_TOKEN` only through the protected process
environment; it is not a command-line argument. The API credential and HEC
credential are separate. Do not call the vendor endpoint manually or execute
scripts extracted from the Cisco archive.

```sh
python3 tools/export_thousandeyes_paths.py \
  --authority <configured-lowercase-id> \
  --aid <account-group-id> \
  --test-id <existing-test-id> \
  --index <events-index> \
  --start 2026-10-26T10:00:00Z \
  --end 2026-10-26T11:00:00Z \
  --output /var/spool/atlas/thousandeyes/capture.ndjson \
  --spool-dir /var/spool/atlas/hec
```

Use a new private output file outside the checkout. The exporter writes the
file and enqueues it into the shared HEC spool; it does not perform HEC network
delivery or maintain a separate API checkpoint. Each invocation gets a new
capture ID; do not rerun after an unknown outcome until the output and shared
spool have been inspected because a new capture can duplicate rounds already
queued or indexed. The HEC sender reads
`ATLAS_HEC_SPOOL_DIR` (which must equal `--spool-dir`), `ATLAS_HEC_URL`, and
`ATLAS_HEC_TOKEN`; `ATLAS_HEC_CA_BUNDLE` is optional. Run
`python3 tools/hec_delivery.py status` for safe backlog counts and
`python3 tools/hec_delivery.py send` only in the approved sender environment.
Keep pending captures and sender checkpoints outside source-control worktrees
until searchable indexed readback completes.

The wrapper schema is `application_atlas.thousandeyes_path.v1`; its exact
source and sourcetype are both `atlas:thousandeyes:path`. Configure
`te_path_sources` with the one exact index/source pair verified from target
readback. HEC acceptance or indexer acknowledgment is not readback. The wrapper
attaches account/test identity; it does not assert that
the path reached an application backend. Hops are the probe's reported path,
not a proof of every forwarding device. Missing hop numbers do not independently
prove packet loss.

## API limits, schedule, and retention

The [ThousandEyes v7 rate-limit documentation](https://developer.cisco.com/docs/thousandeyes/v7/rate-limits/)
currently sets a default organization limit of 240 API requests per rolling 60
seconds. Responses may include
`X-Organization-Rate-Limit-Limit`, `X-Organization-Rate-Limit-Remaining`, and
`X-Organization-Rate-Limit-Reset`; reset is UTC epoch time. Cisco says wait
until the applicable reset on 429. Its 0.9.0 generic retry logic does not read
these headers. Event pagination and path summary/detail calls add requests, and
all API consumers in the organization share the limit. Check actual headers and
avoid relying on a fixed retry delay as rate-limit qualification.

The detected-event input sets its query `endDate` to now minus eight minutes
because CEA events can take up to eight minutes to become queryable. It
checkpoints and paginates. Its packaged input stanza says 3,600 seconds, while
the README spec says 300; configure and read back the intended value. The
Cisco path poll interval is 300 seconds and is separate from OTel push cadence.

| Vendor data                                                                   | Published accessibility boundary                                                                         |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| General Network/App Synthetics API test data                                  | 90 days                                                                                                  |
| Detailed Page Load, BGP, detailed Web Transaction, detailed path per-hop data | 30 days                                                                                                  |
| Endpoint Experience API data                                                  | 30 days                                                                                                  |
| Event Detection API                                                           | 90 days; UI history is 31 days (14 for trial organizations)                                              |
| Network/App Synthetics alert history                                          | 90 days                                                                                                  |
| Activity log                                                                  | 13 months in the accessibility guide; another guide says two years, so confirm the API window with Cisco |

The vendor's [data-accessibility guide](https://docs.thousandeyes.com/product-documentation/user-management/user-activity/how-long-is-data-accessible)
contains the cited family windows. TE and Splunk retention windows are
independent. Splunk cannot retrieve data after vendor API retention expires;
vendor history cannot restore an event
removed from the Splunk index. Record both policies and the intended
investigation window. Activity logs can include names and email addresses;
paths, endpoints, and traces can contain internal infrastructure details.
Apply the organization's privacy, access, and retention policies to both vendor
and Splunk storage.

## Capacity, quota, and cost decisions

Measure vendor API request use for each selected family. Path export demand
includes summary pages plus one or more detail calls for each returned
agent/round; it can materially increase organization API usage. Alert webhook
traffic is push-based. Do not estimate per-test costs or account entitlements
from this integration; verify any plan-specific limits and costs with the TE
owner and contract.

Measure Splunk event count and raw event bytes per day for each family. A first
pass at licensed ingest is:

```text
records per day × measured average raw event bytes ÷ 1,000,000,000
```

Use the target deployment's license, storage, indexer and search tools for the
actual decision. The estimate omits replication, acceleration, search
concurrency, retention policy, and local billing rules. Atlas's 10,000-row
input cap and 64-row display cap limit returned evidence, not all events Splunk
may scan. Measure scan/runtime, concurrency, cancellation, and memory in the
actual target before approving scale.

Do not increase Atlas limits or Splunk search quotas to conceal missing data.
A cap, malformed row, rejected identity, incomplete producer history, stale
receipt, or changed configuration must remain visible as incomplete evidence.

## Identity and attribution settings

Use one verified `adm_observer_scope` row per account group and selected scope.
The native account-group identifier is `aid`; verify it against `/account-groups`
or a received event. The OTel account field is separate evidence and must be
matched to the account group before setting `te_stream_account_id`. For alerts,
store webhook `accountId` under `te_alert_account_id` and `orgId` under
`te_organization_id` after independent verification. No automatic ID
equivalence is assumed.

`te_families` is a non-empty explicit JSON selection per verified mapping.
Select only families with target readback. `te_bindings` are administrator
assertions; each includes exact authority, account group, scope, test ID, agent
ID, `testDomain` (`cea` or `endpoint`), target, one or more endpoint addresses,
valid-from/to, and configuration ID. Application identity and agent location
are optional labels. Current configuration accepts up to 32 account-group
mappings, 64 bindings per group, 16 indexes, and 16 exact path source pairs per
mapping. Keep overlapping bindings visible as ambiguous; do not merge them by
name or address.

For the optional CEA path exporter, the `path` family requires a verified CEA
binding plus `te_path_sources` matching the export index and
`atlas:thousandeyes:path`. The exporter supplies the native CEA `test_domain`
explicitly. Endpoint path results keep `testDomain=endpoint` and require their
own target/source identity checks. Do not use the CEA wrapper to turn an
endpoint result into CEA data.

## Rollout, disable, rollback, and removal

### Rollout

1. Record package version/hash, Splunk release/topology, install tiers, Python
   runtime, vendor account-group IDs, intended tests/agents/families, index,
   retention, HEC endpoint, token/index allowlist, and owners.
2. Install/configure Cisco 0.9.0 per its supported topology. Use a dedicated
   vendor account with the documented permission scope; separately review
   alert input side effects.
3. Create destination events indexes and verify HEC TLS/reachability and token
   allowlists. Configure the intended event interval rather than relying on
   conflicting defaults.
4. Collect a bounded staging sample for each selected family. Compare raw
   shape, native time, HEC metadata, source and sourcetype, event status, and
   searchability. Keep sanitized samples in approved internal storage.
5. If CEA path is required, use the exporter after vendor owner and target
   operator approval. Inject its API token securely, bound the request window
   and selected tests, respect current organization rate headers, and send its
   queued capture through the approved HEC sender. Inspect wrapper and actual
   hop detail in target indexed readback; until this live gate passes, do not
   select the `path` family.
6. Set literal Atlas index selector, account-group IDs, separate OTel/webhook
   IDs, exact path source allowlist, time-qualified bindings, and navigation
   origin. Check effective app-merged settings, viewer ACLs, and all search
   heads.
7. Set schema qualification to `1` only when all selected family gates pass.
   Select `thousandeyes` in Atlas Setup only after the deployment-settings
   persistence gate and per-member configuration checks pass. Canary one known
   test/agent and a narrow interval.

### Failure and disable

For vendor ingestion errors, inspect the Cisco input, OAuth/device-code status,
source cadence, HEC endpoint/TLS/token/index permissions, and organization API
rate headers. For exporter errors, preserve its output and the shared HEC
spool/checkpoint; inspect the reported API status, pagination, rate reset,
per-agent/round results, and HEC sender status. An HEC acceptance or completed
local capture does not prove searchable data.

To disable Atlas inspection:

1. Set source `thousandeyes` to `not_selected` on each serving search head.
2. Cancel active caller-owned searches and confirm native terminal/deleted
   status before reusing the slot.
3. Set the schema macro to `0`; when retiring the source, restore the index
   macro to `index=unconfigured_optional` and withdraw mapping verification
   after in-flight jobs finish.
4. Separately decide whether to stop Cisco inputs, the CEA exporter, or its HEC
   sender. Atlas selection does not change collection. Coordinate alerts with
   the ThousandEyes owner because the vendor integration edits alert rules.
5. Keep indexed events and pending exporter spool under their separate
   retention/recovery owners. Do not delete data to clear a stale UI status.

### Upgrade or rollback

Preserve Atlas package/checksum, effective macros, deployment-settings ledger
and revision, scope mappings, vendor input config, OAuth credential recovery
records, path exporter version/config/output, HEC spool/checkpoints, and target
readback. Upgrade Cisco and Atlas separately. Deploy one compatible Atlas
version to all search heads before reselecting the source. Recheck input tier,
Python runtime, API cadence, HEC metadata/time, and each selected family after
any version change.

For Atlas rollback, first deselect the source, cancel/drain searches, set schema
qualification to `0`, and restore the safe selector on every serving member.
Preserve settings-ledger keys an older app may not understand. Do not overwrite
new settings with a partial older client payload. Roll the vendor integration
back separately through Cisco's supported topology steps. A package rollback
does not reverse vendor webhook changes, delete indexed events, or restore an
exporter's pending HEC capture.

### Removal and reinstall

Before removing Atlas, deselect the source, drain searches, reset the selector
and schema flag, and export required app settings, mappings, revision ledger,
and external qualification evidence. The Cisco app, vendor OAuth identity,
alert rules, exporter spool, HEC token, Splunk indexes, and indexed events have
separate owners. Removing Atlas does not disable or delete them, and it does
not authorize deleting the index.

A reinstall starts unselected with the safe index placeholder and schema
qualification false. Restore configuration only after verifying the current
vendor package, exporter tool (if used), HEC/index readback, permissions,
retention, mapping, and topology.

## Local benchmark and measured envelope

The deterministic benchmark measures Atlas's current query builder, raw-row
adapters, attribution, and comparison code using the checked-in synthetic
fixtures. It varies test/agent/path cardinality, exact/overlapping bindings,
input/output caps, malformed rows, exact replay, and conflicting replay. It
writes a JSON report with Node/V8 environment, run statistics, memory
observations, fixture/module SHA-256 values, and an aggregate source fingerprint.
Each scenario also records the generated search's character count and UTF-8
byte length, including the maximum mapping/binding configuration. These sizes
describe the local generated query string; they do not establish a Splunk
parser limit or prove that the query executes on a target.

Run it without a lab or producer credentials:

```sh
node --expose-gc tools/benchmark_thousandeyes.mjs \
  --output dist/thousandeyes-qualification/thousandeyes-benchmark.json
```

The final recorded run used Node 26.12.1 / V8 14.6.202.34-node.40 on an Apple
M3 Pro (macOS arm64), with seven timed runs and two warmups per operation. Its
source fingerprint is
`adaca10dabad98c38f7b5189b0b8a331d8fb3ce2eec46e490a8bc06668708656`; the
measured code revision is `c7a536f7238792746fbb1822c6a55c2407417a43`. Integrated
normalization plus attribution and generated query size measured:

| Synthetic scenario                                           |       Median / P95 | Query UTF-8 bytes | Output and rejection behavior                      |
| ------------------------------------------------------------ | -----------------: | ----------------: | -------------------------------------------------- |
| Six-family mix: 64 rows, one group, 32 bindings              |   2.381 / 2.459 ms |            37,238 | 64 records; 52 bound, 12 context-only; no rejects  |
| Maximum config: 32 groups × 64 bindings, 64 rows             | 13.529 / 13.917 ms |           449,804 | 64 records; 52 bound, 12 context-only; no rejects  |
| Overlap: 64 overlapping path bindings, 64 rows, 32 hops each |   7.468 / 7.815 ms |            59,926 | 64 records explicitly ambiguous; 2,048 output hops |
| Path expansion at display cap: 32 rows × 2 traces × 24 hops  |   3.690 / 3.694 ms |            59,926 | 64 records; 1,536 output hops; no rejects          |
| Path expansion overflow: 33 rows × 2 traces                  |   3.452 / 3.848 ms |            59,926 | 64 records retained; 1 overflow rejected           |
| 65-row adapter cap                                           |   0.381 / 0.417 ms |            59,926 | Batch rejected: 0 records, 65 rejects              |

The 32-mapping × 64-binding configuration generated the largest query at
449,804 UTF-8 bytes (about 439.3 KiB; the query is ASCII, so its character
count is also 449,804). A single mapping with 64 bindings generated 59,926
bytes. These local sizes help assess the query string sent toward Splunk but
measure the builder-returned SPL text before REST/form framing. They do not
establish the target's parser or request-size limit; qualify that boundary
against the deployed Splunk endpoint before enabling maximum configuration
cardinality.

The representative mix used 69,218 raw input bytes and reported median
`heapUsed` delta 3,688,712 bytes during operation, with 149,144 bytes retained
after forced GC while keeping results live. At maximum mapping/binding
cardinality, those figures were 16,271,872 bytes and 155,384 bytes; in the
overlap-heavy case, 16,885,776 and 459,600 bytes. These are heap observations,
not peak RSS or a production memory envelope. The replay/malformed scenario
returned 49 normalized records and rejected 10 rows. The checked-in BGP monitor
fixture was not loaded or exercised; this report makes no BGP benchmark claim.
The comparison stage produced 48 groups in the representative and maximum
configuration scenarios (0.421 ms and 0.366 ms median), 32 groups for path
expansion at the display cap (0.493 ms), and zero groups when every overlapping
path record was ambiguous. It does not compare unmatched or ambiguous records.
The complete JSON report contains per-operation timings/memory, query strings'
UTF-8 byte length, input/config sizes, scenario counts, and sorted component
hashes. Re-run it after code, fixture, or runtime changes; record its aggregate
fingerprint and Git revision with any internal qualification artifact.

This benchmark does not execute SPL. It inspects generated search ordering and
times local application code only; it does not measure Splunk index scans,
license, storage, API requests, HEC throughput, cancellation, concurrent users,
or production topology. Heap delta after forced GC retains the returned value
and is not peak-memory usage. Use the report fingerprint when comparing runs;
rebenchmark after adapter, query, fixture, or runtime changes. Keep measured
results out of a production-capacity claim until the matching real source and
Splunk topology have also been qualified.
