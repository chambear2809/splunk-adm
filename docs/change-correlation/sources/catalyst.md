# Catalyst Center and ISE evidence

## Status and scope

The Catalyst Center audit adapter is an offline allowlist based on the published
API 2.3.7.5 response schema and static review of Cisco Enterprise Networking
Add-on for Splunk 4.0.60. Its fixture is documentation-shaped synthetic data, not
a controller capture. The adapter has no network client and cannot prove the
controller version, permissions, complete audit retention, or task/deployment
outcomes. The 4.0.60 package manifest records SHA-256
`bbf2ace479e3fc9b15fbe5c8c30b212fdf474931a7b428f361219e6c19a1172d`; the
reviewed archive and extracted source are in the ignored research paths named
there. Vendor files were read as data; no input script was executed.

The ISE/TrustSec features are explicitly blocked from native normalization.
Cisco documentation and the TA catalog expose useful source families, but the
shared projection registry has no ISE family, there is no sanitized
version-matched row or notification sample, and the relevant histories have no
qualified lineage, expiry, removal, or time contract. The code rejects these
native inputs with `unsupported_source_schema`; it does not reuse a Catalyst,
ACI, or other product projection to make the data appear supported.

No controller, ISE database, pxGrid service, or Splunk lab was contacted or
started for this workstream. The source fixtures and tests qualify only the
offline mapping and rejection boundaries.

## Catalyst Center audit source

Cisco's [2.3.7.5 Get AuditLog Records API](https://developer.cisco.com/docs/catalyst-center/2-3-7-5/get-auditlog-records/)
defines a record array with string `instanceId` and `eventId`, optional
`parentInstanceId`, event name/type/category/domain/subdomain/source fields,
integer `severity` and `timestamp`, and additional identity, hierarchy, context,
network and details fields. The operation accepts paired `startTime` and
`endTime` in epoch milliseconds plus `offset`/`limit`; `sortBy` and `order`
support timestamp ordering. Its response also includes unconstrained nested
`details` and `additionalDetails`, free text, links, tags and other contextual
fields. The API contract is documentation, not a capture from the deployed
controller.

The static TA 4.0.60 input
`research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/bin/cisco_catalyst_dnac_audit_logs.py`
emits `cisco:dnac:audit:logs` every 300 seconds with `disabled=1` in
`default/inputs.conf` (lines 58–65). The collector requests the prior configured
interval through the current time, sorts by `timestamp` ascending, and walks
offset/limit pages with a 10,000 page, 200,000 record and 256 MiB response-byte
ceiling (`bin/cisco_catalyst_dnac_audit_logs.py`, lines 35–97). Its page walker
requires unique `instanceId` values and the TA emits per-record JSON after
renaming native `source` to `src` (lines 82–97 and 181–199). It records poll
completion and page counts in TA diagnostics (lines 201–215), not as versioned
Atlas collection receipts in the audit sourcetype. A late page, denied
permission, truncated output, or overlapping poll therefore needs an explicit
export receipt before it may be labeled complete by the history contract. The
interval/lookback and configured API window do not establish controller
retention.

The TA's `props.conf` hoists native `timestamp` (epoch milliseconds) to Splunk
`_time` (lines 687–704), aliases `instanceId` to `object_id` and derives
`status="success"` for CIM search (lines 706–722). That derived CIM value is not
a task outcome or proof that a device configuration was applied. The adapter
uses only the native timestamp and `userId`; it never copies or interprets the
search-time status. Native `source` and TA-renamed `src` are both accepted. If
both appear in one record, the adapter rejects the ambiguous shape.

| Native field | Normalized field | Evidence meaning and limit |
| --- | --- | --- |
| `instanceId` | `object_id` | Identifies this audit record. It is not the affected configuration object, device, template, task, or policy. It is also the TA's page-deduplication identity. |
| `timestamp` | `event_at` | Integer epoch milliseconds converted to seconds with millisecond precision. It remains reported audit time; `effective_at` is null and clock uncertainty is unknown. Missing time stays unknown. |
| `userId` | `actor` | The source-reported actor identifier. No person lookup or intent is inferred. |
| `parentInstanceId` | `parent_event_id` | Parent audit-event context only; it does not identify a changed configuration object. |
| `name`, `type`, `category`, `domain`, `subDomain` | `event_name`, `event_type`, `category`, `domain`, `subdomain` | Bounded scalar audit labels. They do not independently establish task completion, a policy edit, or applied configuration. |
| native `source` or TA `src` | `source` | Bounded scalar source context. The API field is not treated as the Catalyst controller authority. |
| `severity` | `severity` | Nonnegative integer only; no alert or impact interpretation is added. |
| `eventHierarchy` | `event_hierarchy` | Bounded source hierarchy text; it is not an Atlas routing scope. |
| `childCount` | `child_count` | Retained only as an exact nonnegative integer, even though the API schema says `number`. |

The frozen projection deliberately does not emit API `eventId`, `network`,
`siteId`, `deviceId`, `tenantId`, `tntId`, `context`, or `clientId`. The shared
projection has no native event-reference field, and `network` is not documented
as a stable network ID, so it is not mapped to `network_id`. Request filters
such as `siteId` and `deviceId` do not add event-level target fields to the
response.
`description`, `details`, `additionalDetails`, `message`, `messageParams`,
`note`, `ciscoDnaEventLink`, tags, URLs and all unreviewed nested values are
discarded before storage. The adapter does not hash excluded payloads.

Each input receipt must carry the verified controller authority, exact source
version, explicit partition and independent routing scope, start/end/received
times, status, permission fingerprint and page counts. Audit collections are
incremental, never authoritative for deletion, and do not establish a complete
state snapshot. The adapter validates those supplied contract fields, but does
not fetch pages or verify an upstream collector's attestations. A normalized
audit record remains a context observation; it is not a configuration
difference, deployment result, or change to an identified target object.

## Existing Catalyst client and topology context

The existing `cisco:dnac:client` feed is an independent current client snapshot.
Its `lastUpdatedTime` is snapshot freshness, not an association start time.
When its native payload actually contains a wired client's connected network
device and interface, that is an observed attachment context beginning at the
first qualified indexed receipt. Do not backdate that interval to
`lastUpdatedTime`. The snapshot does not establish a configuration change,
successful provisioning, applied VLAN, software deployment, SGT authorization,
or enforcement. Separate network-device, site, software-image, topology and
wireless inputs do not become historical relationships merely because their
collector stanzas exist.

Track B's client receipt remains a prerequisite before its dependent client
flow at offset `+120s`. Installed replay must capture the actual indexed
Catalyst receipt and verify its observer routing scope is exactly `change-b`;
only a fixture or a planned timestamp is not that receipt. The selected scenario
uses a separate `cisco:dnac:client` operational context record. This audit
adapter does not create or replace it. Until the installed receipt/order/scope
check passes, Track B stays blocked. Neither the Catalyst receipt nor the
client snapshot establishes SGT enforcement or that the unrelated SD-WAN event
was applied.

## Feature dispositions

These rows cover every Catalyst Center and ISE/TrustSec feature in the shared
capability register. “Offline adapter tested” means the generic Catalyst audit
projection has documentation-shaped tests. It does not promote the source
register's native sample, immutable history, attribution, UI/export, installed,
demo, or live qualification stages.

| Feature ID | Disposition | Boundary and next evidence |
| --- | --- | --- |
| `catalyst_center.audit_task_status` | Offline adapter tested for generic audit rows; task status remains blocked | API categories include task-related audit events, but the projected response has no qualified task result schema or target-device completion mapping. Need sanitized task and target-device output for the deployed release. |
| `catalyst_center.provisioning_templates` | Blocked | Audit labels are not a template/task identity or per-device result. Need version-matched task/template records, affected device IDs, completion/error semantics, collection coverage and sample. |
| `catalyst_center.device_site_profile` | Blocked | The audit projection supplies no qualified target device, site or profile key. Need source rows binding those exact IDs and evidence linking the audit record to a target. |
| `catalyst_center.software_activation` | Blocked | SWIM/image inputs are separate operational/collection families. No reviewed activation row is linked to a successful target-device image transition. Need exact SWIM task and device-result schema plus a sanitized receipt. |
| `catalyst_center.interface_client_vlan` | Blocked | Current client/device observations are not a complete historical port/client/VLAN binding. Need time-valid, version-matched before/after attachment and VLAN evidence. |
| `catalyst_center.network_device_identity` | Blocked in audit family | `deviceId` is an API request filter; the audit response has no reviewed row-level device identity. Need authority-qualified inventory mapping and an explicit audit-to-device relationship. |
| `catalyst_center.compliance_actual_diff` | Unsupported in audit family | Compliance status is not an actual configuration diff. Need an exact safe config snapshot/diff schema and completeness contract before comparing device state. |
| `catalyst_center.wireless_config` | Blocked | The API lists wireless configuration operations, but audited event/resource coverage and safe object identity are not established. Need version-matched rows and an explicit object schema. |
| `catalyst_center.historical_bindings` | Blocked | Current client/site/device snapshots have no qualified historical validity interval. Need complete bounded snapshots or explicit lifecycle events with stable native IDs. |
| `ise_trustsec.configuration_audit` | Blocked | Data Connect documents `CHANGE_CONFIGURATION_AUDIT`, including a numeric row `ID`, timestamps, actor, object keys and `MODIFIED_PROPERTIES` CLOB. No ISE projection is frozen, and the CLOB/details require privacy review. Need a version-matched sanitized row, primary authority/permission evidence and an approved scalar allowlist. |
| `ise_trustsec.sgt_definitions` | Blocked | Data Connect documents `SECURITY_GROUPS` scalar columns; pxGrid exposes TrustSec metadata and change topics. This does not define versioned notification rows or a frozen history projection. Need sanitized rows, stable revision/ID rules and notification/readback completeness. |
| `ise_trustsec.sxp_bindings` | Blocked | TA catalogs pxGrid `getBindings`, but exact binding identity, expiry, replacement and removal semantics are not established. Need version-matched rows/topic sequence, validity/deletion behavior and an authority-qualified SGT/endpoint relation. |
| `ise_trustsec.session_context` | Unsupported as configuration history | pxGrid Session Directory reports active session context and updates. It is separate operational attribution input, not a policy edit or durable SGT enforcement record. A separate operational family and sanitized lifecycle sample would be needed for historical session context. |

## ISE package and primary-source boundary

The 4.0.60 TA catalogs
`research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/bin/ise/ise_data_connect_views.json`
lists `CHANGE_CONFIGURATION_AUDIT` and TrustSec views `SECURITY_GROUPS` and
`SECURITY_GROUP_ACLS` (lines 37 and 130–131); its
`ise_pxgrid_services.json` catalog lists TrustSec query operations and topics
plus SXP `getBindings` and Session Directory (lines 25–34). The relevant Data
Connect, pxGrid, and other modular inputs are disabled in packaged defaults at
a 3,600-second interval (`default/inputs.conf`, lines 540–569). Static TA review
establishes allowlisted view/service
selection and bounded collector loops, not a change-history adapter or actual
ISE collection. Data Connect needs a compatible Oracle thin driver, enabled and
licensed Data Connect, and a Data Connect-enabled Monitoring persona. The
package catalog currently claims ISE 3.2–3.5 for Data Connect and 3.1–3.5 GA for
pxGrid; a target deployment release remains unverified.

Cisco's [Data Connect view catalog](https://developer.cisco.com/docs/dataconnect/database-views/)
lists the `CHANGE_CONFIGURATION_AUDIT` fields, including potentially sensitive
modified properties, operation details and identity metadata. It lists
`SECURITY_GROUPS` fields `NAME`, `SGT_DEC`, `SGT_HEX`, `DESCRIPTION`, and
`LEARNED_FROM`, while the published `SECURITY_GROUP_ACLS` view describes only
name, description and IP version. These documentation field lists do not prove
which rows, columns or semantics a particular deployed ISE release will return.
The TA's Data Connect input uses bounded `SELECT` statements for catalogued
views, fetches rows in bounded batches, and emits view rows with a collection
time; it does not emit the configuration-history envelope required by Atlas.

Cisco's [ISE API framework](https://developer.cisco.com/docs/identity-services-engine/v1/)
describes separate ERS and Open APIs, the API Gateway requirement, role
requirements and TrustSec/Task service families. [ISE as a pxGrid provider](https://developer.cisco.com/docs/pxgrid/ise-as-a-provider/)
documents active session context, endpoint profile metadata and TrustSec
security-group metadata, including queries and notifications. These separate
surfaces do not prove that every trust-policy, SXP, or endpoint event is emitted
with a durable object ID, sequence, effective time, deletion event, or applicable
device. Current bindings and session context cannot be treated as past
authorization or enforcement.

The TA's ISE data-connect catalog documents an allowlisted, fixed read-only
Oracle TCPS connection (port 2484, service `cpm10`, fixed user `dataconnect`),
fetch size 1,000 (maximum 5,000), and bounded query/row/byte/deadline limits.
Its pxGrid collector performs service lookup, routes to an explicitly trusted
service host, uses bounded request/page/record limits, and tracks topic/service
pagination when supplied. These collection guardrails do not supply the
missing Atlas field projection or verify a particular ISE role's dataset
visibility. No ISE collector was enabled or executed here.

## Primary references

- [Cisco Catalyst Center API 2.3.7.5 — Get AuditLog Records](https://developer.cisco.com/docs/catalyst-center/2-3-7-5/get-auditlog-records/)
- [Cisco Data Connect — Database Views](https://developer.cisco.com/docs/dataconnect/database-views/)
- [Cisco Data Connect — Getting Started](https://developer.cisco.com/docs/dataconnect/getting-started/)
- [Cisco Identity Services Engine API v1](https://developer.cisco.com/docs/identity-services-engine/v1/)
- [Cisco pxGrid API — ISE as a Provider](https://developer.cisco.com/docs/pxgrid/ise-as-a-provider/)
