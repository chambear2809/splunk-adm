# NX-OS, Nexus Dashboard, and Orchestrator

## Disposition

No native NX-OS, Nexus Dashboard, or Nexus Dashboard Orchestrator (NDO) source
record is currently admitted to configuration history. The normalized export
projection registry contains `nxos.device_snapshot` with `kind=operational`,
`qualification=normalized_export_only`, and `native_sample_unqualified=true`.
The native adapter gate below is independently marked
`native_adapter_blocked_pending_versioned_command_sample`. It lists `hostname`, `serial`,
`model`, `software_version`, `interface_name`, `if_index` (integer),
`admin_state`, and `oper_state`; those names are normalized candidates, not
evidence that each native command returns those fields consistently. The adapter entry point
[`adapt_nxos_device_snapshots`](../../../tools/change_correlation/adapters/nxos.py)
therefore fails closed for all input until a versioned sanitized sample and
projection approval exist.

Track A may use existing NX-OS inventory and topology as independent context.
That context does not identify a cause for an application change or outage.
NDO controller intent, controller-reported deployment, applied APIC/device
state, and packet enforcement are separate evidence types. None is inferred
from another.

## Reviewed package evidence

The exact package inspected was Cisco DC Networking App for Splunk 1.2.2,
archive `research/packages/cisco-dc-networking_122.tar.gz`, SHA-256
`9e2b8534b4c0ddfd5750d3d5924e07ba6d4cf689300164bed041f5cfadb08497`. This
matches the entry in [`research/package-manifest.json`](../../../research/package-manifest.json).
Static inspection used the ignored extract at
`research/extracted/cisco-dc-networking_122/cisco_dc_networking_app_for_splunk`;
the archive was not installed and no vendor script was run.

`default/inputs.conf` defines the following NX-OS snapshot commands at a
300-second interval, all `disabled=1`: `show hostname`, `show version`,
`show module`, `show inventory`, `show interface`, and `show cdp neighbors
detail`. They use `cisco_nexus_9k` with per-input component labels. Generic CLI
and DME selectors are also present. The NX-API implementation accepts a
configured command or command list, parses command responses into `Row_info`,
and emits component-specific events. CLI events use `cisco:dc:nexus9k`; DME
events use `cisco:dc:nexus9k:dme`. Both wrappers add a local collection-time
`timestamp`; the CLI event's Splunk event time is also set from the collector's
current `time.time()`. Neither value is a native configuration-transition or
effective time. The emitted `device` value is the configured device address and
port, not a verified durable chassis identity. The response body is not a
version-independent schema.

The `show interface` snapshot does not establish stable ifIndex mapping,
interface lifecycle, VLAN/VRF/port-channel membership, or every operational
transition. The shipped neighbor command supplies periodic CDP context, not a
complete neighbor history or packet path. Generic command selection is not
permission to ingest full running configuration; no arbitrary command output
is projected or stored here.

The package also defines disabled 300-second Nexus Dashboard inputs for
endpoints, flows, anomalies, congestion, advisories, fabrics, switches, and
Orchestrator-named `mso_tenant_site_schema`, `mso_fabric_policy`, and
`mso_audit_user`. The latter use historical `mso/api/v1` endpoints. In the
reviewed `cisco_nexus_dashboard.py`, the audit collector uses an offset loop
with a 250-row limit and updates its checkpoint from the last record on each
page. The response flattener recursively emits source keys into
`cisco:dc:nd:mso`; it does not define a reviewed, secret-safe NDO history
projection or qualify a complete page set. The package's historical names and
stanzas do not establish compatibility with a current Nexus Dashboard/NDO
release.

## Current primary documentation and limits

Cisco's current [Nexus Dashboard Infra API v1, Release 4.2 and later: Get Audit
Records](https://developer.cisco.com/docs/nexus-dashboard/latest/get-audit-records/)
documents `GET /api/v1/infra/auditRecords` (Infra API spec version 1.2.109).
Its documented `auditRecord` model
requires `id`, `creationTime`, `resourceType`, `affectedResource`, `action`,
`username`, `clientIp`, and `description`; `fabricName`, `tenants`, and
`traceId` are optional. The endpoint documents `startDate`, `endDate`, `sort`,
`filter`, `offset`, and `max` query fields and response pagination metadata
(`counts` and next/previous links). `creationTime` is an audit-record time; it
does not assert when a configuration became effective. The description and
resource path remain free-form source text and have not been admitted to the
projection. The documented role list includes super-admin, support-engineer,
fabric-admin, approver, designer, and device-upg-admin; it is not a substitute
for verifying a deployed account's effective permissions.

Cisco's [audit log settings API](https://developer.cisco.com/docs/nexus-dashboard/latest/get-audit-logs-settings/)
separately describes record streaming, rollover count, and a retention setting
of up to 12 months. These settings apply to the documented Nexus Dashboard
infrastructure audit log; they do not establish retention or coverage for the
older MSO-named TA inputs or for every NDO policy revision.

The current NDO Orchestration API documentation identifies version 5.3.1 for
Release 4.2 and later. Its [`schema.PolicyStates` model](https://developer.cisco.com/docs/nexus-dashboard/latest/schema-policystates/)
distinguishes a controller policy `state` from site-side `apicState` and
includes schema/template/site and policy references. This is useful evidence
that future controller and applied-state collection should remain separate.
It is a response model, not a retained change stream, complete deployment
receipt, or packet-enforcement verdict. The target Nexus Dashboard/NDO and
NX-OS releases for this app have not been supplied or sampled. Cisco's
[NX-OS 10.5(x) show-command reference](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/command-reference/show/b_n9k_show_commands_1051/m_i_showcmds.html)
and [NX-OS programmability guide](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-105x.pdf)
describe release-specific commands and structured output, but cannot select a
mapping for an unknown device release or replace a sanitized response sample.

## Feature coverage

All nine rows have `documentation=documented`. `package_inspection=package_verified`
applies only to the listed TA stanzas or generic selector, never a feature's
complete payload. `sanitized_source_sample=blocked`, `normalization=blocked`,
`immutable_history=blocked`, `attribution=blocked`, `ui_and_export=blocked`,
`local_pipeline_tested=blocked`, `installed_tests=blocked`, `demo=blocked`, and
`live_qualification=blocked` throughout. Feature-specific `collection` is
`package_verified` only for the periodic command/input path described in the
table; it is `blocked` where a dedicated path is missing or current API
compatibility is unknown. `synthetic_tests=adapter_tested` covers only the
negative fail-closed adapter gate; there is no positive source mapping or
installed Splunk replay.

| Feature | Package or API evidence | Collection disposition | Evidence needed to unblock |
| --- | --- | --- | --- |
| Durable chassis/interface identity | NX-OS hostname, version, inventory, and interface command stanzas | Snapshot path is `package_verified`; no stable identity contract | Exact NX-OS/device releases; sanitized responses; serial-to-device and interface identity behavior across replacement and renumbering |
| ifIndex mapping | `show interface` command stanza; ifIndex is only a projection candidate “if present” | `package_verified` for the command path; mapping remains blocked | Versioned response proving ifIndex source field, scope, uniqueness, and lifecycle/reuse semantics |
| Administrative/operational state | `show interface` snapshot stanza | `package_verified` for periodic snapshot collection; no transition stream | Versioned complete interface response, command failure/coverage evidence, and bounded clock/observation semantics |
| VLAN, VRF, and port-channel membership | Generic/custom NX-API/DME exists; fixed command list does not establish complete membership boundaries | Feature-specific collection blocked | Explicit version-matched commands or DME classes, complete partitioning and membership samples, and change/removal semantics |
| Neighbor/attachment changes | `show cdp neighbors detail` snapshot stanza | `package_verified` for periodic CDP context only | Versioned samples, interface/peer identity, complete discovery scope, and lifecycle gaps; never infer traffic traversal |
| Routing/BGP changes | Generic custom command selector only; no fixed route/BGP command is in the reviewed default list | Feature-specific collection blocked | Narrow named commands/classes, exact device release, structured sanitized responses, and completeness/permission evidence |
| Device/software revisions | `show version`, `show module`, and `show inventory` stanzas | `package_verified` for current snapshots; no append-only change history | Versioned inventory samples and a complete immutable polling/permission/retention qualification |
| ND endpoint lifecycle/anomalies | Disabled endpoint/anomaly inputs in the package | Package input names are verified; current API version, payload fields, deletion semantics, and pagination are blocked | Deployed ND version, sanitized endpoint/anomaly records, native identity/time, page/checkpoint behavior, RBAC, retention, and incremental/tombstone semantics |
| NDO audit/schema/policy revisions | Disabled historical MSO-named audit/schema/policy inputs; current Cisco audit and policy-state APIs are documented separately | Historical TA compatibility blocked; no NDO projection is frozen | Exact ND/NDO release and collector/API path, sanitized records, native IDs/revisions and time meanings, tenant/site/schema scope, page completeness, permissions, retention, and separate intent/deployment/APIC-state evidence |

The coverage register's Track A role remains independent inventory/topology
context. A NDO policy edit is not attributed to an application unless a
separately retained, authority-qualified relationship chain and compatible
time interval exist under the [source producer contract](../../SOURCE_PRODUCER_CONTRACT.md). A controller
state or configured route does not establish switch forwarding, route
selection, packet traversal, or policy enforcement.

## Test and qualification record

`python3 -m unittest tests.test_change_nxos` exercises the blocked-projection
guard with an empty baseline, an opaque record, and an NDO-shaped record. The
fixture [`qualification_gate_v1.json`](../../../fixtures/change-correlation/nxos/qualification_gate_v1.json)
is explicitly a synthetic gate control and contains no vendor payload. An
installed Splunk replay is not meaningful before any source-native record is
admitted; no services or vendor controller were started for this source.

To reopen this path, first add versioned sanitized input evidence without
changing the frozen projection, then have the contract owner explicitly admit
the exact source family and fields. Keep source snapshots, NDO audit records,
controller intent, deployment result, APIC/device-applied state, topology, and
traffic observations as separate evidence. Use the existing collection
contract for capture boundaries, permissions fingerprints, page counts,
source references, and conservative observation intervals.
