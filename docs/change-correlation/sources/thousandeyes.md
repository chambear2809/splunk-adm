# ThousandEyes activity and test-configuration evidence

Status: allowlisted, offline activity adapters and documentation-shaped unit
tests. The adapters cover the published API v7 `UserEvent` shape and the
published OTel v2 `resourceLogs` activity shape as separate inputs. There is no
sanitized native sample, package installation, HEC readback, configuration
snapshot history, measurement comparator, resource attribution, or live
qualification. The HEC replay is prepared but awaits the orchestrator's lab
gate. This source note records W10 dispositions; shared source-capability
status remains authoritative.

## Package and current vendor evidence

The statically inspected artifact is **Cisco ThousandEyes App for Splunk 0.9.0**,
Splunkbase app 7719, SHA-256
`2206fe9a288060a0a8d4e780cbba8c56ecd1c18cf53c965b60b505c3524cf6af` from the
[`package manifest`](../../../research/package-manifest.json). It was supplied
locally, not installed, and no vendor code was executed. Relevant files in the
ignored extracted archive are:

- `ta_cisco_thousandeyes/default/inputs.conf`
- `ta_cisco_thousandeyes/default/props.conf`
- `ta_cisco_thousandeyes/README.md`
- `ta_cisco_thousandeyes/bin/activity_logs_stream.py`
- `ta_cisco_thousandeyes/bin/thousandeyes_client.py`
- `ta_cisco_thousandeyes/bin/thousandeyes_constant.py`

The configured `[activity_logs_stream]` input names
`cisco:thousandeyes:activity`. The modular-input `stream_events` callback is
empty; README setup directs activity collection through a ThousandEyes OTel v2
stream pushed to HEC. Package code also has a `get_activity` helper for
`/audit-user-events`, but static search found no caller and no polling input
that uses it. The API adapter below is an offline normalizer for a separately
exported API response; it does not create a collector or claim that the TA
polls this endpoint. The package's `DATETIME_CONFIG=CURRENT` and the lack of a
sanitized received event mean HEC `_time` is not qualified as the native event
time.

The package manifest records the locally computed archive checksum, not a
publisher signature. The package's exact tenant/API versions, effective input
settings, configured stream/account scope, HEC flattening, received timestamp
fields, retries, delivery guarantees, stream retention, and indexed field paths
remain unverified.

The package pins only the `/v7` API path, not a patch version. The official
Administrative API overview reported `7.0.109` when checked on 2026-10-28;
the endpoint and `UserEvent` model pages expose older embedded OpenAPI metadata.
No tenant's deployed API patch version is established. The adapter is limited
to the documented v7 fields above and does not infer patch-level compatibility.

## Native records and adapter boundaries

### API v7 `UserEvent`

Cisco DevNet documents `GET /v7/audit-user-events` with an `auditEvents` array.
Its `UserEvent` has `aid`, `accountGroupName`, `date`, `event`, `ipAddress`,
`uid`, `user`, and optional `resources[]` objects with `type` and `name`. The
API describes `aid` as the account-group identifier, `uid` as the user ID, and
`event` as the event type. The offline adapter requires the caller's explicit
receipt partition to equal the row's `aid`; it does not use the account-group
display name. It projects `aid` into `account_id`, `event` into `event_name`, a
`uid`-based actor key, and at most one typed resource name as context. It omits
the `user` name/email and `ipAddress`. The frozen projection has scalar resource
fields, so records with multiple resource entries fail closed rather than lose
or join resource identities. The API schema has no stable event ID; the adapter
hashes authority, partition, event time, actor, and projected fields. Identical
projected rows collapse, so that derived ID cannot establish unique native
event counts.

The endpoint documents `aid`, optional account-wide activity, date-window
parameters, and HAL pagination links. A caller must follow every `_links.next`
page and attest its page counts, permissions, requested window, and successful
completion. The caller provides `query_start` and `query_end`; the adapter
retains those exact values inside the safe `source_reference` because the
frozen collection envelope has no structured query-window field. The API's
window boundary inclusivity is not qualified. A `useAllPermittedAids` result
must be split into one receipt per native `aid`; multi-account-group batches
fail partition validation. The adapter does not fetch pages or validate the
permission claim. It permits a `complete` receipt only when both query bounds,
all reported pages, and a permission fingerprint are present. This means the
caller attests that its bounded query completed; it does not prove no source
retention, late-event, permission, or poll-gap loss. Source `date` is an
offset-qualified UTC event time; `effective_at` stays null because audit time
does not establish when a configuration took effect.

The v0.9.0 package's dormant `get_activity` helper calls the same endpoint and
passes `aid`/`startDate`/`endDate` (or `useAllPermittedAids` plus dates), but does
not implement pagination itself. The configured stream path is the separate
OTel input described below.

### OTel v2 Activity Log

The current ThousandEyes OTel v2 Logs reference identifies the Activity Log
fields `Body`, `Timestamp`, `ObservedTimestamp`, `SeverityText`, and
`SeverityNumber`; resource attributes include stream and account IDs, while log
attributes include user ID/name/email/address and
`thousandeyes.activitylog.resources`. Its published JSON example uses
`resourceLogs`, `scopeLogs`, `logRecords`, and OTel `stringValue` wrappers. The
OTel adapter accepts only this documented camel-case envelope, v2 marker, one
stream ID, and one account ID per receipt. It records the exact source account
ID and copies the unclassified `Body` text to `event_name`; `event_type` is not
emitted. It preserves a user ID as actor, maps the native event timestamp to
`event_at`, and the native observed timestamp to `observed_at`. Nanosecond
timestamps finer than the contract's exact millisecond precision are rejected.

The OTel model describes `account.id` as the account associated with telemetry;
it does not establish equivalence with API `aid`. The receipt partition is the
exact `stream:<stream.id>` identity, and the `account_id` field retains the
source value without mapping it to an account group. The OTel resource attribute
`activitylog.resources` is documented as a comma-separated list, but the
resource type/name grammar is not documented; the adapter drops it. User names,
emails, addresses, stream names, and account names are also dropped. No test or
agent identity is assumed.

OTel delivery has no reviewed sequence/checkpoint or completeness
acknowledgment. The adapter therefore always writes a partial receipt with no
page counts, even if metadata asks for complete. It does not treat missing log
rows as deletions or establish stream coverage. It consumes the official OTel
envelope example only; actual TA-to-HEC raw fields and event flattening require
a sanitized indexed readback before normalizing production rows.

The API model and OTel stream expose no stable activity-event ID. The
deterministic identity hashes the retained timestamp, actor, scope, and context;
different source events identical after projection may therefore collapse.

Current vendor pages disagree on activity-history retention: the Activity Log
guide says two years, while the data-accessibility guide says 13 months with
rolling expiry. Treat source-side recovery retention as unresolved until Cisco
clarifies the scope/version difference; neither duration proves ingestion
completeness. The Activity Log guide also says a Regular User sees their own
login/logout history, an Account Admin sees their account, and an Organization
Admin sees organization-wide activity. Verify exact API read permissions and
account-group scope for the configured user; the receipt's
`permissions_fingerprint` is only caller attestation.

### Shared frozen contract

The only ThousandEyes projection in
[`projections.py`](../../../tools/change_correlation/projections.py) is
`activity_log`, with the scalar fields `event_name`, `event_type`, `account_id`,
`resource_type`, and `resource_name`. It is explicitly `context_only` and has
no qualified native sample. The adapters do not change that contract. A
configuration audit row remains an `audit` observation with reported time,
unknown clock uncertainty, no effective time, and no inferred relationship.
The exact named object in an activity row is not enough to associate a test
with an application, endpoint, network dependency, or probe.

## Feature dispositions

Generic activity-log context is covered by the adapter and described above; it
is not a separate W10 feature ID. The table below uses the exact ten ThousandEyes
IDs in the shared coverage register. These dispositions do not promote any
coverage-register stage or establish live qualification.

| Coverage-register ID | Feature | Disposition | Evidence boundary and next evidence needed |
| --- | --- | --- | --- |
| `thousandeyes.test_crud` | Test create, update and delete | Adapter-tested context only | API event labels and optional resource names may describe actions but do not identify a test by native ID or establish an effective revision. Require versioned test snapshots and an explicit ID/time binding. |
| `thousandeyes.target_interval` | Target, protocol, port and interval changes | Blocked | No ThousandEyes test-configuration snapshot projection is frozen. Add a reviewed, allowlisted test snapshot/revision family and complete enumeration semantics before comparing settings. |
| `thousandeyes.agent_assignment` | Agent assignment and location | Blocked | Activity records do not provide a versioned test-agent assignment or probe-location relationship. Require stable test/agent/domain IDs and validity intervals from a qualified native config source. |
| `thousandeyes.alert_rule` | Alert-rule changes | Blocked | No alert-rule snapshot, stable rule revision, or versioned association projection is available here. Separate rule configuration from triggered/cleared alerts. |
| `thousandeyes.stream_configuration` | Stream configuration | Blocked | The package input's `thousandeyes_stream_id` is setup context, not an immutable stream-configuration history. Require a reviewed stream snapshot/revision and change semantics. |
| `thousandeyes.account_resource_mapping` | Account and resource mapping | Blocked | API `aid` is an account-group ID; OTel `account.id` is not proven equivalent. API resource names and OTel's comma-separated resource string are not test/application IDs. Require a reviewed crosswalk and native stable identifiers. |
| `thousandeyes.metric_units_config` | Metric units and configuration version | Blocked | No measurement or config revision projection is added. Require matching test/domain, target, agent cohort, units, aggregation, measurement window, and exact configuration revision. |
| `thousandeyes.path_events` | Path changes and event lifecycle | Unsupported as configuration history | Path visualizations are probe measurements; they are not the customer's passive traffic path and do not establish a test configuration transition. Detected events and alert notifications are operational/measurement context, not a source configuration revision. |
| `thousandeyes.cea_endpoint_identity` | CEA versus Endpoint identity | Blocked | Activity projection carries no test domain. Require exact `cea`/`endpoint` native identities and explicit compatible bindings before joining evidence. |
| `thousandeyes.api_trace_support` | API and trace support limits | Blocked | The reviewed package selects trace streams, but official pages disagree on API test trace support and no received stream sample was inspected. Obtain sanitized readback or vendor clarification before admitting API trace measurements. |

## Evidence stages and tests

| Stage | API `UserEvent` | OTel Activity Log |
| --- | --- | --- |
| `documented` | Official v7 schema and pagination | Official OTel v2 model and sample |
| `package_verified` | v0.9.0 helper statically calls the endpoint; no input calls it | v0.9.0 input/sourcetype statically selects the push stream; callback does no polling |
| `sample_verified` | No; fixture is documentation-shaped synthetic | No; fixture is documentation-shaped synthetic, not received HEC |
| `adapter_tested` | Yes, offline unit tests | Yes, for published OTel JSON envelope only |
| `local_pipeline_tested` | Not run in this adapter slice; the installed replay remains gated on an explicitly allocated task lab and confirms only local HEC/history projection, never native collection | Not tested against installed HEC flattening |
| `live_qualified` | No | No |

Unit tests cover field allowlisting, actor and account identity, page
completeness metadata, timestamp precision, duplicate handling, resource
cardinality, OTel partial completeness, mixed stream/account rejection,
history observations, and explicit blocked configuration disposition. The
installed replay test is present but was not run for this adapter slice; when
run, it must use only the synthetic API fixture, write to a task lab's
`atlas_changes` index, and never contact ThousandEyes. This source note does
not promote shared coverage-register feature stages and makes no live
qualification claim.

## Primary references

- [Cisco DevNet, List activity log events, ThousandEyes API v7](https://developer.cisco.com/docs/thousandeyes/v7/list-activity-log-events/)
- [Cisco DevNet, UserEvent model](https://developer.cisco.com/docs/thousandeyes/userevent/)
- [Cisco DevNet, Administrative API overview](https://developer.cisco.com/docs/thousandeyes/administrative-api-overview/)
- [ThousandEyes OTel Data Model v2, Logs](https://docs.thousandeyes.com/product-documentation/integration-guides/opentelemetry/data-model/data-model-v2/logs)
- [ThousandEyes OTel Data Model v2, Logs example](https://docs.thousandeyes.com/product-documentation/integration-guides/opentelemetry/data-model/data-model-v2/logs/data-format)
- [ThousandEyes activity log semantics and permissions](https://docs.thousandeyes.com/product-documentation/user-management/user-activity/working-with-the-activity-log)
- [ThousandEyes API-accessible retention guide](https://docs.thousandeyes.com/product-documentation/user-management/user-activity/how-long-is-data-accessible)
- [Cisco Splunk app configuration guide](https://docs.thousandeyes.com/product-documentation/integration-guides/custom-built-integrations/splunk-app/configuration)
- [Cisco ThousandEyes App for Splunk 0.9.0 listing](https://splunkbase.splunk.com/app/7719)
