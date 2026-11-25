# Meraki configuration evidence

## Evidence and package findings

The reviewed source package is Cisco Meraki Add-on for Splunk 3.5.0 at
`research/extracted/cisco-meraki-add-on-for-splunk_350/Splunk_TA_cisco_meraki`
with SHA-256 `edd12274203a367e73c8f3ae2115ad18008b6f20f46614602b724fc7758ac8e8`.
The package was inspected as static data; no vendor script was executed. Its
`[cisco_meraki_audit]` input defaults to a 86,400-second interval and a seven-day
initial lookback. `bin/cisco_meraki_connect.py` calls
`getOrganizationConfigurationChanges`, streams all API pages, and enriches a
row with `organizationId` when the response omitted it. The resulting sourcetype
is `meraki:audit`. This is source collection evidence, not a live qualification
or durable audit-event identity.

The current official Dashboard API reference is v1.75.1 (dated October 16,
2026). The audit endpoint accepts an organization ID and time range, supports
API pagination, and has a maximum 365-day lookback. Its response has no native
event ID. Meraki TA 3.5.0 and current Dashboard API documentation do not provide
a sanitized controller sample or establish that each audit record maps to one
device or one applied configuration change.

## Audit projection

`adapt_meraki_audits` accepts the documented configuration-change response
shape and optional TA-added `organizationId`. Receipt `authority` is the
organization ID. If a row includes `organizationId`, it must exactly match the
receipt authority. The API response may omit that field; in that case the
collector's explicit receipt authority remains the organization source.

An organization-wide audit collection uses the organization ID as its
`partition`; a network-filtered audit collection uses `network:<networkId>`.
The independent routing `scope` is retained as supplied and is never parsed to
derive organization or network identity. If a network-filtered receipt and row
both identify a network, the IDs must match.

| Native field | Normalized value | Handling |
| --- | --- | --- |
| `ts` | `event_at` | Parsed as offset-qualified ISO-8601. Missing time stays unknown; it is never replaced with index or receipt time. |
| `adminId` | `actor` | Preserved when present. |
| `networkId` | `network_id` | Preserved when present. |
| `ssidNumber` | `ssid_number` | Preserved only when that row also contains `networkId`; the SSID number alone is not globally unique. |
| `page` | `page` | Preserved as bounded text. |
| `label` | `label` | Preserved as bounded text. |
| `client.type` | `client_type` | Only the documented `oauth` value is accepted. `client.id` is omitted. |

The adapter does not copy `adminName`, `adminEmail`, `networkName`,
`networkUrl`, `ssidName`, `oldValue`, `newValue`, arbitrary nested values or
URLs. It never parses or hashes the old/new configuration strings. A row without
`networkId` remains organization-level context, and a row without a network ID
or SSID number cannot be attached to an SSID. Device identity is not present in
this projection; no device, client, application, or endpoint join is inferred
from names or IP addresses.

Because the source has no native event ID, the adapter hashes organization
authority, source partition, `event_at`, `actor`, and the safe projected fields
to make a deterministic local identity. Rows identical after projection
collapse, including rows that may have differed only in excluded
`oldValue`/`newValue` data. The audit family therefore does not
claim source event counts, changed-field diffs, device scope, or successful
application. These audit rows are context-only observations. Distinct source
actions that become identical after sanitization are not distinguishable, and
the adapter deliberately does not retain a digest of secret-bearing payloads to
try to distinguish them.

## SSID snapshot projection

`adapt_meraki_ssid_snapshots` accepts the array returned by
`GET /networks/{networkId}/wireless/ssids`. The operation's path provides the
network context; the collection must therefore use `partition` exactly as
`network:<networkId>`. The independent routing `scope` is preserved verbatim.
Each native response object supplies `number`, not a durable SSID UID. The
object ID combines that network ID and number. A row-level `networkId`, when
included by an export wrapper, must match the partition.

| Native field | Projected field | Documented type |
| --- | --- | --- |
| `number` | `ssid_number` | integer |
| network from explicit receipt scope | `network_id` | string |
| `name` | `ssid_name` | string |
| `enabled` | `enabled` | boolean |
| `authMode` | `auth_mode` | string |
| `ipAssignmentMode` | `ip_assignment_mode` | string |
| `defaultVlanId` | `default_vlan_id` | optional integer |
| `useVlanTagging` | `use_vlan_tagging` | optional boolean |

The API documents `defaultVlanId` only for `Bridge mode` or `Layer 3 roaming`
when VLAN tagging is enabled; `useVlanTagging` is documented for those modes.
The adapter rejects VLAN fields that contradict those documented conditions.
It ignores RADIUS server details, PSKs, URLs and every other response field. A
projected VLAN difference describes configured SSID intent only. It does not
show client reassociation, effective VLAN assignment, DHCP behavior, routing,
or traffic impact.

SSID identity is only `(organization authority, networkId, number)`. The
composite object ID includes all three values. Meraki does not document a
durable SSID UID, so a deletion and recreation that reuses the
same number between two polls cannot be identified as such from these
snapshots. A known incomplete collection, permission change, or comparison gap
must reset the baseline; do not report a definite modification across that
known continuity break. A continuous sequence with no observed gap still cannot
rule out an unseen delete/recreate between polls. The adapter can preserve
caller-attested authoritative deletions only for a complete full enumeration;
offline parsing cannot verify API permissions or collector completeness.

## Qualification status and references

The audit and SSID response examples in
`fixtures/change-correlation/meraki/` are synthetic documentation-shaped data,
not Meraki captures. This adapter is offline-tested only. Live source samples,
deployed Dashboard version, organization permissions, API pagination under
concurrent changes, late-event behavior, SSID snapshot completeness, identity
reuse behavior and actual controller collection remain unqualified. The TA's
audit input does not itself collect these SSID snapshots; they use a separate
Dashboard API read path.

Primary references:

- [Get organization configuration changes](https://developer.cisco.com/meraki/api-v1/get-organization-configuration-changes/)
- [List network wireless SSIDs](https://developer.cisco.com/meraki/api-v1/get-network-wireless-ssids/)
- [Return a single network wireless SSID](https://developer.cisco.com/meraki/api-v1/get-network-wireless-ssid/)
- [Meraki Dashboard API v1.72 changelog](https://developer.cisco.com/meraki/whats-new/v1-72-0/), which records the optional `defaultVlanId` and `useVlanTagging` SSID fields.
- [Current Meraki OpenAPI specification](https://api.meraki.com/api/v1/openapiSpec)
