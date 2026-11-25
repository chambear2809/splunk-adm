# Catalyst SD-WAN audit source

Status: offline, allowlisted audit adapter with documentation-shaped synthetic
tests. There is no sanitized Manager output or live qualification. No collector
or service was started for this source task.

## Native API and TA evidence

Cisco DevNet's current Release 26.1 API guide documents `GET
/dataservice/auditlog/severity` under the `/dataservice` base path. It requires a
`query` and accepts optional `page` (minimum 0), `pageSize` (minimum 1),
`sortBy`, `sortOrder`, and `site-id`. The documented response has `data` and
`header`; it also describes `total_records`. The 26.1 operation describes the
query as audit logs from the last three hours. Cisco documents `entry_time` as
an integer and the field model's example is `1659003590292` (Unix epoch
milliseconds), although the schema labels that integer `int32`, which cannot
represent the example. The adapter therefore accepts only a non-boolean Python
integer in the supported epoch-millisecond range, rejects floats and numeric
strings, and converts exactly to seconds at millisecond precision.

The 26.1 `AuditLogEntry` model marks these fields required:

| Native field | Published schema | Adapter handling |
| --- | --- | --- |
| `logid` | UUID text | Native audit-record `object_id`; validated as UUID. It identifies the audit record, not the changed policy or template. |
| `entry_time` | Integer; documented example is epoch milliseconds | `event_at` only. `effective_at` stays null and clock uncertainty stays unknown. |
| `loguser` | String, UUID format | Shared `actor`, after UUID validation. It is not a person-name lookup. |
| `logdeviceid` | String; the API example is an IP address | `device_id` context field only. It is not treated as a stable device key or joined to site/VPN data. |
| `logfeature`, `logmodule`, `tenant` | Strings | The same-named reviewed projection fields, with no action or policy semantics inferred. `tenant` does not supply routing scope. |
| `auditdetails`, `logmessage`, `logusersrcip`, `statcycletime` | String array, strings, and integer per the model | Shape-checked where practical, then discarded. No raw detail/message, source IP, config snapshot, URL, or raw-content hash is retained. |

The 26.1 API model specifies `auditdetails` as `string[]`. The statically
inspected Splunk TA 4.0.60 helper `build_audit_extra_fields` passes its input to
`json.loads` and can emit decoded `audit_log_details`, `audit_config_before`,
and `audit_config_after`. This indicates a serialized JSON-string shape is
also handled by the TA. The adapter accepts only these two known shapes for
`auditdetails`, never decodes either, and drops the value. The native Manager
shape and release-specific detail completeness remain sample-gated.

The TA input is
`research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/bin/cisco_catalyst_sdwan_audit_logs.py`
from the ignored, immutable Cisco Enterprise Networking Add-on 4.0.60 tree;
the package manifest records SHA-256
`bbf2ace479e3fc9b15fbe5c8c30b212fdf474931a7b428f361219e6c19a1172d`. Its
`default/inputs.conf` stanza uses `cisco:sdwan:audit:logs`, a 300-second
interval, seven-day initial backfill, and `disabled=1`; `audit_log_details=0`
and `config_difference=0` by default. Static source inspection shows a bounded
collector with four API strategies, including `/auditlog/severity` numbered
pages. For that strategy it sends `query`, `page`, `pageSize`, `sortBy=entry_time`
and `sortOrder=asc`, expects a stable total count, and detects zero- versus
one-based page numbering. It checkpoints only after completed emission
boundaries. The TA's seven-day initial backfill is not proof of Manager-side
retention. No vendor script was executed.

The offline adapter accepts the documented native `data` entries as a list and
separate collection metadata. A collector must extract the page's `data` array
and attest its own page count, time window, permissions and source version in
the receipt. A complete receipt needs all pages and a permission fingerprint;
an empty complete page is allowed. Audit receipts are incremental and never
authorize deletions. The adapter does not fetch or prove page completeness.

## Attribution and time limits

The fields in `sdwan/audit_log` identify an audit record and provide limited
source context. No returned `AuditLogEntry` property identifies a changed
policy/template object, a device UUID, a site, a VPN, an applied configuration,
or successful deployment. `site-id` is a request filter on the audit query,
not an event-level target field. `logdeviceid` is documented only as a string
and exemplified by an IP address. `tenant`, Manager authority and native
`partition` remain separate from the opaque shared routing `scope` such as
`change-b`.

Cisco's 26.x audit guide says audit logs show create/update/delete actions for
device and feature templates and localized, centralized and security policies,
including when those items are not attached to a device. It says Config Diff
for previous/current configurations is limited to `template` modules. Those
statements do not establish a native object ID, safe field-diff schema,
successful application time, or policy enforcement. The API log's `entry_time`
is the reported audit time only. Attach/deploy status is a separate workflow;
the current Manager API guide describes an attach request that returns a
process ID followed by `GET /dataservice/device/action/status/{processId}` for
the detailed status. Cisco's operator guide separately documents a per-device
Template Log with attach status. Neither expands the `AuditLogEntry` schema,
and the reviewed API page does not define per-device result fields for this
adapter. The audit adapter does not combine these sources. Observed traffic and
operational health remain independent evidence.

For Track B, the required unrelated SD-WAN change is described as a different
edge/site `202`/VPN `30` from the primary site `201`/VPN `20`. The audit schema
does not carry those target fields. This source can preserve an audit record as
context, but cannot validate either target or claim a known scope mismatch.
Until a version-matched source supplies explicit native object/site/VPN
bindings with validity, relevance stays unresolved; names, time, tenant or
shared scope do not create a join or prove a tunnel path.

## Feature dispositions

These dispositions cover the nine IDs in the shared source register. “Adapter
tested” describes the generic offline row projection with documentation-shaped
data; it does not mean that a feature or live source was qualified.

| Feature ID | Disposition | Evidence boundary / next evidence needed |
| --- | --- | --- |
| `sdwan.template_changes` | Adapter tested, context only | Cisco documents template create/update/delete audit actions, but the safe row has no template object ID or attachment fan-out. A version-matched sanitized row and binding contract are still needed. |
| `sdwan.policy_changes` | Adapter tested, context only | Cisco documents localized/centralized/security policy audit actions, but this projection cannot identify the changed policy or interpret policy behavior. Require reviewed native object IDs and safe details before field-specific claims. |
| `sdwan.device_template_revisions` | Blocked | The audited row does not expose a reviewed template ID/revision. Config Diff is UI detail for template modules; sanitized native before/after schema and object identity are needed. |
| `sdwan.deployment_action_status` | Unsupported in this audit family | Attach status uses a separate action/process workflow. A dedicated adapter needs the exact target-release status schema, per-device result fields, stable process/device IDs, time semantics and sanitized sample. |
| `sdwan.site_vpn_device` | Blocked | The audit row has no site/VPN or qualified device UUID; the `site-id` query parameter is not a row binding. Require explicit native relationships and their authority/time validity. |
| `sdwan.routing_transport_aar_qos` | Blocked | `logfeature`/`logmodule` are generic labels; this source does not document a safe routing, transport, AAR or QoS object/field mapping. Require version-matched sanitized audit detail or a reviewed snapshot schema. |
| `sdwan.tunnel_health` | Unsupported in the audit family | Separate health/tunnel inputs are operational observations, not configuration changes, applied state or ordered tunnel paths. |
| `sdwan.exporter_sampling` | Unsupported; history not verified | The reviewed TA audit input establishes no exporter/sampling configuration history. A separate exact-version source and stable resource/change schema are required. |
| `sdwan.detail_completeness_retention` | Blocked | Optional TA detail is disabled by default; the native detail sample, role visibility, actual Manager retention and full replay/late-event coverage are unqualified. Seven-day TA backfill is only collector configuration. |

No additional projection fields are proposed. The sole fixture is
`fixtures/change-correlation/sdwan/audit_log_documentation_shaped.json`; its
values are synthetic or copied from published schema examples. It is not a
native source sample and does not qualify Manager release, permissions,
retention, pagination or live behavior.

## Primary references

- [Cisco DevNet, Get vManage Audit Log, Release 26.1](https://developer.cisco.com/docs/sdwan/administration-audit-log-get-vmanage-audit-log/)
- [Cisco DevNet, AuditLogEntry model, Release 26.1](https://developer.cisco.com/docs/sdwan/auditlogentry/)
- [Cisco Catalyst SD-WAN Network Monitoring Guide, Audit logging, Releases 26.x and later](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/network-monitoring/network-monitoring-guide/sys-and-network-logs/audit-logging.html)
- [Cisco Catalyst SD-WAN Network Monitoring Guide, Configuration template activity log, Releases 26.x and later](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/network-monitoring/network-monitoring-guide/sys-and-network-logs/view-log-of-configuration-template-activities.html)
- [Cisco DevNet, Device Template attach and action-status workflow, current Manager API guide](https://developer.cisco.com/docs/sdwan/device-template/)
