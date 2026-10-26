# ThousandEyes evidence setup

Application Atlas reads selected ThousandEyes evidence that is already indexed
by the Cisco ThousandEyes Splunk App, plus an optional repository-provided CEA
path export. The browser does not call ThousandEyes, create or edit tests, or
manage vendor alert rules. Keep the source unselected until the exact vendor
package, input settings, indexed payloads, source identities, account-group
mapping, viewer access, and target topology pass qualification.

Read the [integration design](../THOUSANDEYES_DESIGN.md),
[package research](../research/thousandeyes.md),
[capability matrix](../research/thousandeyes-capabilities.md), and the
[operating constraints](../research/thousandeyes-operating-constraints.md)
before rollout. The research records preserve vendor-document conflicts and
static package findings; they are not evidence that a live account, input,
HEC route, or customer topology was qualified.

Measurements describe synthetic tests from specific tests and agents. Path
records describe measured probe rounds. Traces remain synthetic spans. Events,
alerts, and activity records retain the lifecycle or change context supplied
by ThousandEyes. These families do not create passive traffic, production
service-call edges, service ownership, backend calls, or traffic counters. An
empty or quiet feed does not prove health or complete source coverage.

## Package and deployment gates

As checked on 2026-10-26, [Splunkbase](https://splunkbase.splunk.com/app/7719)
lists Cisco ThousandEyes App for Splunk 0.9.0 as the current Cisco-supported
package. The supplied archive's SHA-256 is
recorded in the [research note](../research/thousandeyes.md); Splunkbase does
not publish a matching publisher digest, so that local hash is not publisher
verification. Cisco's package README and app guide publish narrower Splunk
compatibility ranges than the Splunkbase listing. Confirm the exact Splunk
release and app support with the target owner before rollout; do not treat the
listing alone as a target qualification.

| Target                 | Cisco-published placement and gate                                                                                                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standalone Enterprise  | Supported. Configure the app and its modular inputs on the instance.                                                                                                                                                       |
| Distributed Enterprise | Install on the heavy forwarder and search head/search head cluster. Do not install it on indexers or indexer clusters. Follow the target's deployment procedure for inputs versus search-head configuration.               |
| Search head cluster    | Cisco lists the search head cluster as an install target. The public guide does not give deployer-specific steps; qualify the exact SHC deployment procedure and all serving members.                                      |
| Splunk Cloud           | Listed as supported, but the Cisco UI guide supports the Victoria experience and says Cloud Classic is unsupported. Confirm tenant experience and private-app requirements. The published Cloud HEC example uses port 443. |

The Cisco package declares Python 3.9 and 3.13 for its modular inputs. Confirm
the runtime supported on the exact input tier and Splunk release. Package
inspection alone does not establish that the runtime is available on a target.

**Co-install gate:** On a locked Splunk Enterprise 10.6.0.5 diagnostic, the
unmodified Cisco TA 0.9.0 failed `btool check` at
`ta_cisco_thousandeyes/default/app.conf:27` (`[triggers]` key
`notable_event_actions = reload`). Atlas AppInspect passed separately, but it
does not clear this vendor TA failure; Atlas qualification remains disabled.
Static inspection also found the trace `EVAL` expression in
`default/props.conf:45` missing its closing `)`, so trace parsing is
unqualified. Do not patch vendor files in place; keep the ThousandEyes source
disabled until the target owner resolves and rechecks these gates. See the
[detailed operations record](../THOUSANDEYES_OPERATIONS.md#vendor-release-topology-and-authorization).

Atlas's `adapterVersion=0.9.0` names the reviewed parsing contract, not the
installed Cisco producer version. If a record omits the producer version,
Atlas preserves `producerVersion=not_reported`; a matching payload shape does
not prove package version or continuity.

## Ingestion, HEC, and authorization

For Cisco ThousandEyes App 0.9.0, route its configured inputs to **events
indexes**. The app input guide says the metrics, path, trace, event, activity,
and alert indexes must be events indexes. The separate direct OTel-to-Splunk
guide has different endpoint and metrics-index options; do not apply those
instructions to this Cisco app.

Before enabling any Cisco input, follow the
[Cisco input guide](https://docs.thousandeyes.com/product-documentation/integration-guides/custom-built-integrations/splunk-app/inputs)
and verify that HEC is enabled and reachable from ThousandEyes, SSL is enabled
with a valid non-self-signed certificate, and the
enabled HEC token allows the destination index. The app examples use
`/services/collector/event`. A Splunk HEC response is not proof of indexed
readback.

Cisco's app authorization uses an OAuth device-code flow described in its
[configuration guide](https://docs.thousandeyes.com/product-documentation/integration-guides/custom-built-integrations/splunk-app/configuration). Its published
permission list includes API access, edit rights for connectors/operations,
streaming integrations, and alert rules, along with test, endpoint-test,
activity, user, label, and alert read permissions. This is not a read-only
vendor role. Use a dedicated account, review the full permission list with the
ThousandEyes owner, and enable only the required inputs. Splunk configuration
pages also require `admin_all_objects` or `sc_admin_all_objects`; keep vendor
setup and Atlas viewer roles separate. The Alerts input creates or updates a
ThousandEyes webhook operation/connector and associates alert rules, so treat
its setup as a vendor-side configuration change requiring the ThousandEyes
owner's approval.

Atlas viewers need read permission to the selected events index. Atlas
account-group mappings and shared selectors are administrator-controlled;
routing scope does not grant index access. App-merged selector reads use the
Configuration Management API. Verify the required viewer capability on the
exact target; earlier standalone optional-source qualification required
`list_conf_objects`, which exposes broader configuration visibility. Do not
grant `admin_all_objects` or use a private macro shadow to work around a denied
read.

## Enable and verify vendor collection

The Cisco package has six families. The listed source/sourcetype values are
package expectations, not a substitute for inspecting what the target indexed.
The package does not establish a canonical Splunk `host`, and event/path
modular inputs do not explicitly set `source` in the inspected code.

| Family             | Package source / sourcetype                                 | Collection and qualification note                                                                                                                                                                  |
| ------------------ | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metrics            | `cisco:thousandeyes:stream` / `cisco:thousandeyes:metric`   | OTel v2 push to HEC. Confirm exact flattened datapoint fields, units, account ID, test/agent IDs, source, and time from a staged indexed sample.                                                   |
| Traces             | `cisco:thousandeyes:stream` / `cisco:thousandeyes:trace`    | OTel v2 push to HEC. API trace support conflicts across Cisco descriptions; qualify API only after a received sample or Cisco confirmation.                                                        |
| Activity           | `cisco:thousandeyes:stream` / `cisco:thousandeyes:activity` | OTel v2 push to HEC. It identifies account/users/resources, not a test/agent pair. Activity can contain user email/address.                                                                        |
| Detected events    | source is not specified / `cisco:thousandeyes:event`        | API polling input. It adds account-group `aid`, paginates, checkpoints, and queries through an eight-minute delay. Verify the configured poll interval; packaged defaults conflict.                |
| Alerts             | `cisco:thousandeyes:webhook` / `cisco:thousandeyes:alerts`  | Real-time webhook to HEC. Keep `accountId` and `orgId` distinct; test identity is conditional. Setup changes ThousandEyes alert configuration.                                                     |
| Path visualization | source is not specified / `cisco:thousandeyes:path-vis`     | Optional API pull attached to the metrics input. Endpoint results include account/test/agent IDs; raw CEA results omit per-result account/test IDs and contain summaries unless detail is fetched. |

Configure one approved existing account group and a small set of existing
tests/agents. Do not create tests to manufacture fixture-like production data.
Check vendor permissions, source scope, API request use, the actual configured
input cadence, HEC routing, destination index, and sanitized event readback.
Compare raw field types and native timestamps against the exact
[versioned schema evidence](../research/thousandeyes-capabilities.md). Verify
`_raw`, `source`, `sourcetype`, `host`, `index`, outer HEC metadata when
available, `_time`, and `_indextime` on the target.

### CEA measured paths

The Cisco CEA path API request is scoped by account group and test ID, but its
raw result does not repeat those IDs. The package emits each result unchanged.
It also returns path summaries; actual intermediate hops require the separate
agent-and-round detail request. Never attribute raw CEA path rows by hostname,
agent name, source host, or address coincidence.

The optional repository CEA exporter paginates selected tests' path summaries,
fetches each agent/round detail for actual hop arrays, and wraps the unchanged
result with the configured account-group ID, test ID, and `test_domain=cea`.
It writes explicit HEC NDJSON and queues it through the existing durable
sender. It is not part of the browser or scheduled Atlas query path. The live
producer and indexed readback remain unqualified. Do not pass credentials in
command arguments, URLs, source files, shell history, or reports.

Do not execute scripts from the downloaded Cisco archive or make manual API
requests to reproduce the export. Until the exporter, HEC delivery, and target
readback pass qualification, keep CEA path evidence out of the selected
`path` family. Its output source and sourcetype are both
`atlas:thousandeyes:path`; qualify the destination index and exact source in
Splunk before adding that pair to `te_path_sources`.

The CLI accepts one to 16 literal test IDs and a whole-second time range with a
UTC offset, at most 24 hours. It bounds API response/request/page/round counts,
event size, and total capture size. Supply the API token through the protected
process environment as `THOUSANDEYES_API_TOKEN`. The output file must be new,
private, and outside the checkout. The exporter enqueues that capture into the
shared HEC spool; it does not send HEC itself or maintain a separate API
checkpoint. Each invocation uses a new capture ID, so do not rerun after an
unknown outcome until you have checked the protected output and spool; a new
capture can duplicate rounds already queued or indexed. Keep output and spool
files under restricted permissions and preserve pending captures until
indexed readback completes.

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

The shared sender uses `ATLAS_HEC_SPOOL_DIR` (the same directory as
`--spool-dir`), `ATLAS_HEC_URL`, and `ATLAS_HEC_TOKEN`; optionally set
`ATLAS_HEC_CA_BUNDLE` for its trust bundle. The API and HEC credentials are
separate. Use `python3 tools/hec_delivery.py status` to inspect safe backlog
counts and `python3 tools/hec_delivery.py send` to send pending captures only
from an approved operator environment. HEC acceptance or indexer
acknowledgment is not searchable readback. After delivery, verify the exact
index, source, sourcetype, outer time, wrapper identity, and hop detail from a
sanitized Splunk query before qualifying `path`.

Endpoint path results have native account/test/agent IDs in the documented
response, but the exact deployed source/index and intermediate-hop detail still
require target readback. Keep `test_domain=endpoint` separate from CEA. Never
join across these domains or infer a missing test/agent ID.

## Configure Atlas

The optional source starts unselected. `adm_index_thousandeyes` defaults to the
inert literal `index=unconfigured_optional`, and
`adm_thousandeyes_schema_qualified` defaults to `0`. Set the explicit JSON
`te_families` list only to families that pass the installed integration,
schema, permissions, and target readback gates. Accepted values are `metric`,
`path`, `trace`, `event`, `alert`, and `activity`.

After vendor ingestion and searchable readback pass:

1. Set `adm_index_thousandeyes` to a reviewed literal events-index selector,
   such as `index=thousandeyes`. Use the actual index name; do not put SPL,
   wildcards, event-derived text, URLs, or credentials in the selector.
2. As an administrator, add one verified row per account group to the existing
   `adm_observer_scope` mapping. Use
   `observer_kind=thousandeyes_account_group`, the native
   `te_account_group_id` (`aid`), approved `scope`, optional `cluster`, and
   `mapping_status=verified`. Verify the ID against `/account-groups` or a
   sanitized indexed record.
3. For metric/trace/activity input, set `te_stream_account_id` to the
   account ID actually present on the stream. Cisco's OTel schema calls this
   an account ID but does not normatively state it is the native account-group
   `aid`; verify the value before mapping it. For alerts, set
   `te_alert_account_id` from the webhook's `accountId` and
   `te_organization_id` from its separate `orgId`. Do not assume these IDs are
   interchangeable.
4. Set `te_families` to an explicit JSON list of qualified families. Do not
   infer a family from an enabled vendor input. Activity is account context,
   not test/agent identity. Events preserve affected test/agent arrays as
   context; they do not imply one scalar test or agent.
5. Add `te_bindings` only for administrator-verified test/agent relationships.
   Each binding requires an exact authority, account group, scope, native test
   ID, agent ID, `testDomain` (`cea` or `endpoint`), target, endpoint-address
   set, half-open validity interval, and configuration ID. Bindings are
   time-qualified assertions; do not join on names, tags, current inventory,
   or IP equality alone. The configuration accepts at most 64 bindings per
   account-group mapping.
6. For `path`, set `te_path_sources` only to exact `(index, source)` pairs
   confirmed in sanitized target readback. The exporter source is
   `atlas:thousandeyes:path`; a Cisco-package source must be observed, not
   guessed. This exact pair allowlist is separate from `te_families` and does
   not supply missing native identity.
7. If source navigation is needed, set `thousandeyes_origin` to a credential-
   free HTTPS origin only. It is a configured navigation root, not a deep-link
   template; never construct a URL from event-supplied values.
8. Set `adm_thousandeyes_schema_qualified=1` only after every selected family
   passes exact source/time/schema readback. In Atlas Setup, select source ID
   `thousandeyes` only after the selector, mapping, ACLs, and settings
   persistence are verified on all serving search heads.

The app's supplemental search is bounded by its 30-second server and 35-second
client deadlines, a 10,000-row input cap detected with a 10,001st scan row, a
64-record display cap, and one completion row. A guarded native-time coarse
filter runs before the input cap; unknown or malformed native timestamps remain
candidates for strict normalization. These are application bounds, not an
indexer scan-cost limit. A cap, warning, malformed/conflicting row, incomplete
producer, stale/changed configuration, or missing completion row must remain
incomplete or unavailable. Do not raise limits to conceal missing coverage.

## Local benchmark

Run the deterministic local benchmark without a Splunk lab or producer
credentials:

```sh
node --expose-gc tools/benchmark_thousandeyes.mjs \
  --output dist/thousandeyes-qualification/thousandeyes-benchmark.json
```

The report records exact source/fixture hashes, runtime, configuration
cardinality, timing distributions, and heap observations. Keep CEA exporter
qualification separate; this benchmark does not exercise vendor API or HEC
collection. Its measured envelope and limitations are recorded in the
[detailed operations guide](../THOUSANDEYES_OPERATIONS.md).

## Rate, retention, capacity, and cost

The current [ThousandEyes v7 API rate-limit documentation](https://developer.cisco.com/docs/thousandeyes/v7/rate-limits/)
sets a default **240 requests per rolling 60 seconds per organization**.
Responses can include
`X-Organization-Rate-Limit-Limit`, `X-Organization-Rate-Limit-Remaining`, and
`X-Organization-Rate-Limit-Reset`; on 429, the vendor says to wait until the
reported reset. The Cisco 0.9.0 static client retries 429 and 5xx without
reading those headers. Event pagination, path summary/detail calls, and other
organization API users share the limit. Monitor the live headers and keep
operator collection within the target's current rate limit; vendor limits can
change.

Cisco's detected-event input delays its query end by eight minutes and
checkpoints its cursor. Its packaged event interval is 3,600 seconds, while
`README/inputs.conf.spec` says 300 seconds. Set and read back the intended
interval on the target. The packaged path-poll interval is 300 seconds; it is
not the OTel metrics push cadence. Do not treat the event query delay as missing
current events or as a reason to broaden time windows without review.

Cisco's 0.9.0 `props.conf` sets `DATETIME_CONFIG=CURRENT` for all six source
families. Splunk's [HEC event format](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector)
defines optional outer event time; Cisco's public material does not demonstrate
the actual outer HEC
`time` for each input or the resulting `_time`. Preserve the producer's native
timestamps separately and verify the exact HEC envelope and indexed `_time` on
the target. Atlas does not use `_time` or `_indextime` as a measurement-window
substitute; it retains row time and indexed receipt separately.

ThousandEyes data accessibility and Splunk index retention are separate:

| Vendor data                                                                                 | Published accessibility boundary                                                                                  |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| General Network and App Synthetics API test data                                            | 90 days                                                                                                           |
| Detailed Page Load, BGP, detailed Web Transaction, and detailed Path Visualization hop data | 30 days                                                                                                           |
| Endpoint Experience API data                                                                | 30 days                                                                                                           |
| Event Detection API                                                                         | 90 days; UI history is 31 days (14 days for trial organizations)                                                  |
| Network/App Synthetics alert history                                                        | 90 days                                                                                                           |
| Activity log                                                                                | 13 months in the accessibility guide; another guide says two years, so confirm the API recovery window with Cisco |

See Cisco's [data-accessibility guidance](https://docs.thousandeyes.com/product-documentation/user-management/user-activity/how-long-is-data-accessible)
for the current vendor limits. Choose Splunk raw-index retention for legal,
privacy, investigation, and capacity needs. Splunk cannot recover source data
after ThousandEyes API
retention expires, and the vendor cannot restore events after Splunk retention
expires. Keep user names/emails, test targets, agent locations, traces, paths,
alerts, and activity within the organization's approved data-handling policy.

No fixed ThousandEyes or Splunk price follows from this integration. Measure
event count and raw bytes for representative staged data. A first-pass Splunk
ingest estimate is `records/day × measured average raw event bytes ÷ 1e9`; use
the target deployment's license and storage tooling for the actual decision.
The estimate does not model replication, search concurrency, storage policy, or
local billing. No local benchmark can estimate ThousandEyes account pricing,
API traffic, or indexer cost.

## Disable, upgrade, rollback, and removal

### Disable Atlas evidence

1. Set source `thousandeyes` to `not_selected` in Atlas Setup on every serving
   search head. Cancel active inspections and verify native terminal/deleted
   status before freeing the caller's search slot.
2. Set `adm_thousandeyes_schema_qualified=0`. If retiring the source, restore
   `adm_index_thousandeyes=index=unconfigured_optional` and withdraw the
   account-group mapping's verified status after in-flight jobs finish.
3. Decide separately whether Cisco inputs, the CEA path exporter, or the HEC
   sender should stop. Atlas selection does not activate or stop any of them.
   Alerts/webhook changes must be coordinated with the ThousandEyes owner.
4. Keep indexed data under normal index retention and access policy. Disabling
   Atlas does not delete Splunk events or ThousandEyes-side history.

### Upgrade or rollback

Preserve the app package/checksum, effective macros, deployment-settings
ledger/revision, account-group mappings, vendor app configuration and protected
credentials, exporter config/output, HEC spool and sender checkpoints, and the
relevant raw index readback. Update all serving Atlas search heads to one compatible package
before selecting the source. Update the Cisco vendor integration separately
using Cisco's supported topology procedure; do not assume replacing Atlas rolls
back vendor inputs. Re-read versions, input interval, OAuth/HEC configuration,
source/index mappings, timestamp behavior, and sanitized event samples after
any upgrade.

Before rolling Atlas back, deselect `thousandeyes`, cancel/drain active jobs,
set the schema flag to `0`, and restore the safe index selector on all members.
Preserve newer settings-ledger keys that an older app may not understand; do
not save a partial older payload over them. Keep Splunk index data and vendor
history under their separate retention owners. Requalify the exact combination
before selecting the source again.

### Remove or reinstall

Before uninstall, deselect the source, drain inspections, reset the selector and
qualification flag, and export needed Atlas settings, mappings, revision
ledger, and qualification records. Cisco inputs, OAuth credentials, webhook
rules, the CEA exporter spool, Splunk indexes, and indexed evidence have
separate owners and lifecycles. Atlas removal does not disable or delete them.
Do not delete the index as an app-cleanup step.

A reinstall starts with source unselected, selector placeholder, and schema
qualification false. Restore settings only after verifying the current vendor
package, exporter version if used, raw sample/readback, mappings, index ACL,
retention, and deployment topology.

## External qualification record

Keep each family unselected or unqualified until the target record includes:

- exact Cisco package version/hash, current compatibility evidence, Splunk
  release/topology and per-tier placement;
- actual input configuration, account group, test/agent scope, API credentials
  and permission owner, HEC reachability/TLS/token/index allowlist;
- sanitized staged sample and searchable readback for each family, including
  `source`, `sourcetype`, `host`, index, HEC envelope/time, raw field types,
  event/measurement timestamps, indexing delay, completeness, and history;
- current API rate headers, request cadence, 429 behavior, and eight-minute
  event-delay/interval settings;
- source/index ACLs, required Configuration Management API read capability,
  admin-only Atlas settings and unique time-qualified mappings;
- independent ThousandEyes and Splunk retention, measured index growth/license
  use, search quotas/concurrency, cancellation behavior, and target scan cost;
- for CEA paths, exporter version/command and mock-test result,
  account/test/agent/round request scope, summary pagination, actual hop-detail
  readback, HEC delivery/readback, and rate usage. Keep the family unavailable
  until live target qualification exists.

Package inspection, synthetic fixtures, the local benchmark, a successful API
response, an HEC response, and a vendor dashboard do not qualify live collection
or a customer deployment.
