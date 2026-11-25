# AppDynamics configuration evidence

Status: generic Controller audit observations have an allowlisted adapter and
offline unit coverage. No live Controller sample, installed AppDynamics source,
complete audit archive, configuration snapshot history, timeline attribution, or
live qualification is established. This document gives a source-specific
disposition for all AppDynamics features in
[`SOURCE_CAPABILITIES.json`](../SOURCE_CAPABILITIES.json); that shared register
remains authoritative for stage statuses.

## Package and current vendor evidence

The statically reviewed package is **Cisco Splunk Add-on for AppDynamics 3.2.1**,
Splunkbase app 3471, SHA-256
`10c0c7ec606fcbf0e03c24352e3e69935ff4ed76ba3f95b9fa4db4dd6b851c6c` from
[`research/package-manifest.json`](../../../research/package-manifest.json).
The inspected files are:

- `research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/default/inputs.conf`
- `research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/README/inputs.conf.spec`
- `research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/bin/appdynamics_audit.py`
- `research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/bin/controller_service.py`

The manifest records this package as not installed and not executed. The
extracted files were inspected as data; no vendor script was run. The package
provides an `appdynamics_audit` modular input and `appdynamics_audit`
sourcetype. Its input implementation calls
`GET /controller/ControllerAuditHistory?startTime=...&endTime=...`, receives
JSON records and emits each record. The README input specification says an
instantiated input defaults to a 300-second interval and a 5-minute duration,
with duration configurable from 5 to 60 minutes. The checked-in
`default/inputs.conf` contains only the sourcetype template; an actual modular
input instance and its configuration are deployment facts, not established by
that file.

The packaged poller makes a rolling time-window request. The reviewed call has
no durable cursor, native row checkpoint, or pagination loop. Its time conversion
uses local system time when constructing the request. The current SaaS API page
documents ISO-8601 start/end parameters, JSON/CSV output, and a maximum 24-hour
query window. It does not document pagination, a stable audit-row identifier, or
a complete permission attestation in the result. The reviewed TA path has no
retry/checkpoint loop. Its request helper returns `None` on an HTTP failure by
default, and `get_audit_logs()` turns a missing/falsy response into an empty
list. An API failure can therefore look like a successful zero-row collection
when consuming TA events alone. A caller must separately prove request success
before attesting `status=complete`; an empty array by itself does not suffice.
The TA's 5–60 minute window is within the API's stated query bound, but repeated
polling cannot prove that no rows were missed or that the caller can see the
whole tenant.
[Controller audit history API, SaaS 26.4](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.4.0/extend-splunk-appdynamics/splunk-appdynamics-apis/controller-audit-history-api),
[SaaS audit report retrieval, 26.4](https://help.splunk.com/en/appdynamics-saas/get-started/26.4.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/retrieve-the-audit-log-report).

The public release listing checked on 2026-10-28 showed Reports Service 26.10.0
and Controller 26.7.2 as the latest listed components; that is not a claim about
any specific tenant's deployed version. The detailed audit API contract cited
here is 26.4.0. Confirm the tenant's Controller version before using a native
schema beyond this adapter's narrow allowlist.
[SaaS Controller release listing](https://help.splunk.com/en/appdynamics-saas/product-announcements-and-alerts/product-announcements-and-alerts-home/splunk-appdynamics-saas-controller-releases).

The SaaS audit configuration documentation reports a default 30-day audit-log
retention and warns that longer retention requires regular report downloads or
vendor assistance. This is a SaaS-specific documented default, not a retention
guarantee for another Controller deployment. A scheduled Controller Audit report
requires Company Admin permissions to view/configure. That UI permission is not
evidence of the least privilege required for API polling; the exact read role for
the API endpoint remains unverified. Customers cannot access the SaaS tenant's
`audit.log` file directly, so the supported retrieval options are the report/API
paths.
[SaaS audit retention settings](https://help.splunk.com/en/appdynamics-saas/get-started/26.4.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/audit-log-default-configuration-settings),
[Create a Controller Audit report, SaaS 26.5](https://help.splunk.com/en/appdynamics-saas/get-started/26.5.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/create-an-audit-report).

The reviewed TA logs the complete API row as JSON at debug level and sends the
raw row to Splunk; it also adds `controller_url`. This may expose audit diffs or
personal/configuration data in raw indexed events and debug logs. The offline
Atlas adapter drops those fields from its own normalized collection, but cannot
sanitize data already written by the vendor input. Do not describe TA raw output
as an Atlas-safe projection.

## Native audit mapping and limits

The vendor example identifies `timeStamp` (epoch milliseconds),
`auditDateTime` (offset-qualified text), `accountName`,
`securityProviderType`, `userName`, `action`, `objectType`, and `objectName`.
It may also include fields such as `objectId`, `applicationName`, API key
attributes, and object-change/diff content. The adapter projects only the five
fields already allowed by the frozen schema: `accountName`,
`securityProviderType`, `action`, `objectType`, and `objectName`; it maps
`userName` to the observation actor. It prefers `timeStamp`, accepts
`auditDateTime` as a fallback, requires the two times to agree when both are
present, and never substitutes collection or receipt time for an unknown event
time. `effective_at` remains null because an audit action time does not prove the
exact effective transition.

The documented API example includes an `objectId`, but the reviewed source
contract does not define its uniqueness, lifetime, or replay semantics. The
adapter therefore does not treat it as a stable event identity. It derives a
SHA-256 `object_id` from Controller authority, partition, reported event time,
actor, and projected fields. Exact duplicate rows collapse; two native actions
that differ only in omitted data are indistinguishable. That ID supports replay
of the projected row only and cannot establish audit completeness or unique
source event counts. The adapter always marks enumeration incremental and
deletions non-authoritative. A complete receipt means the caller attests that
the bounded query completed; it does not attest source retention, role coverage,
absence of late records, or gap-free polling.

The adapter drops `objectChanges`, arbitrary details, object/API IDs, application
labels, Controller URLs, nested values, and all unreviewed keys. `userName` and
`objectName` can still be identifying or sensitive; an operator must approve
their handling before storing the projection. The fixture is explicitly
documentation-shaped synthetic data, not a sanitized Controller sample.

## Feature dispositions

| Register feature | AppDynamics evidence and safe Atlas disposition | Remaining gate |
| --- | --- | --- |
| Application and agent configuration audit | The Controller Audit API records configuration and user activity. The adapter emits generic `audit` observations only. | Sanitized, version-matched records; API role and tenant scope; actor privacy policy; observed pagination, retention, late rows, and replay. No complete audit archive is established. |
| Instrumentation and transaction-discovery changes | Audit records can include configuration actions. A 26.7 Controller release note says machine-agent monitoring enable/deactivate details are added to the audit table. This adapter preserves only generic action/object context and does not infer discovery semantics. | Exact event subtype mapping, affected application/tier/node identity, current tenant schema, and a reviewed signal that invalidates incompatible performance comparisons. |
| Backend-discovery rules | Existing Atlas AppDynamics inventory contains current backend candidates. Vendor documentation describes automatic backend discovery, but the audit adapter does not collect discovery-rule configuration or revisions. | A versioned native rule schema/history, safe field allowlist, and same-Controller binding to affected applications/tier/nodes. |
| Tier, node, and model changes | The current Application Model API exposes numeric application, tier, node, and backend identifiers. Existing Atlas inventory is a current snapshot; the frozen change schema has no AppDynamics configuration-snapshot projection. | Historical ID lifecycle and observation intervals, complete enumeration/permission evidence, and a reviewed source-native snapshot contract. |
| Health-rule and alert changes | Controller Audit reports include application/configuration activity; health-rule APIs and alert events are separate current configuration/operational paths. Audit action is not a health-rule revision or violation result. | Exact audit-to-health-rule object mapping and versioned read snapshots or source revisions. Preserve audit edits separately from operational alerts. |
| Release and deployment markers | The audited TA has no deployment-receipt family. The documented Agent Configuration Deployment API is a privileged `POST` operation, not a historical deployment-result feed. | A read-only native deployment receipt/event schema with target scope, status, source revision, effective time, and permissions. Never infer success from an audit row or a missing row. |
| Performance and call coverage | AppDynamics metrics, transaction snapshots, and backend status are measurement/operational evidence in existing integrations, not configuration-change history. | A qualified common metric comparator (application/tier/node, metric, unit, aggregation, interval, and source revision). Instrumentation/config changes must invalidate incompatible comparisons; the current frozen audit projection does not provide a typed invalidation signal. |
| Same-Controller stable application/tier/node IDs | The 26.10 Application Model API documents internal numeric IDs; existing Atlas inventory uses IDs scoped by configured Controller authority and application. Names alone are not identity. | Vendor lifecycle guarantees and version-matched historical bindings. A current inventory match does not prove identity across deletion/recreation or supply an interval-valid relationship chain. |

No audit action string, object-name heuristic, or raw diff is promoted into an
instrumentation, health-rule, deployment, or policy change type. AppDynamics
monitoring edits must invalidate incompatible metric comparisons in the shared
history/UI path, but this source adapter cannot encode that behavior under the
frozen AppDynamics audit projection. Integration requires a separately reviewed
shared contract or bounded event classifier; no source-specific guess is made.

## Tests and qualification

`tests/test_change_appdynamics.py` exercises the documentation-shaped input,
timestamp validation, replay identity, discarded fields, and audit-only history
rows. These are offline unit tests; they do not establish native-sample
compatibility. `tests/splunk/test_change_appdynamics.py` prepares an installed
HEC/history replay against a task-owned Splunk lab and does not contact a
Controller. It is not run until the orchestrator grants the lab lifecycle gate
for this workstream. No AppDynamics package or collector is installed by that
test.

Use the existing read-only Atlas inventory workflow for current application,
tier, node, and backend context; its limits are documented in
[`docs/APPDYNAMICS_EVIDENCE_DESIGN.md`](../../APPDYNAMICS_EVIDENCE_DESIGN.md).
Before enabling any AppDynamics source, obtain a sanitized version-matched audit
sample and exact API role/tenant scope, review username/object-name privacy,
qualify poll overlap and retention, and separately validate AppDynamics change
invalidation against metric units, interval, aggregation, and application/tier/
node identity. Do not enable broad collectors or use a failed live query as a
synthetic fallback.

Primary vendor references:

- [Controller Audit History API, SaaS 26.4](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.4.0/extend-splunk-appdynamics/splunk-appdynamics-apis/controller-audit-history-api)
- [Retrieve the Audit Log Report, SaaS 26.4](https://help.splunk.com/en/appdynamics-saas/get-started/26.4.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/retrieve-the-audit-log-report)
- [SaaS audit retention settings, 26.4](https://help.splunk.com/en/appdynamics-saas/get-started/26.4.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/audit-log-default-configuration-settings)
- [SaaS Controller release listing](https://help.splunk.com/en/appdynamics-saas/product-announcements-and-alerts/product-announcements-and-alerts-home/splunk-appdynamics-saas-controller-releases)
- [Platform API index, SaaS 26.10](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/platform-api-index)
- [Application Model API, SaaS 26.10](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/application-model-api)
- [Default automatic backend discovery, SaaS 26.3](https://help.splunk.com/en/appdynamics-saas/application-performance-monitoring/26.3.0/configure-instrumentation/backend-detection-rules/default-automatic-backend-discovery)
- [Controller enhancements, SaaS 26.7](https://help.splunk.com/en/appdynamics-saas/release-notes-and-references/controller-release-notes/26.7.0/appdynamics-saas-controller-enhancements)
- [Agent Configuration Deployment API, SaaS 26.1](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.1.0/extend-splunk-appdynamics/splunk-appdynamics-apis/agent-management-api/agent-configuration-deployment-api)
