# Cisco Catalyst and Meraki networking

**Purpose:** provide scoped wired-client observations from Catalyst Center and wireless association events from Meraki Dashboard for Application Atlas. These sources enrich endpoint identity and attachment context; they do not prove a physical packet path.

## Data flow and ownership

| Source                  | Splunk input / raw sourcetype                                  | Atlas index macro                       | Evidence provided                                                                                                                  |
| ----------------------- | -------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Catalyst Center clients | Cisco Enterprise Networking Add-on, `cisco:dnac:client`        | `adm_index_catalyst` → `cisco_catalyst` | Periodic client observations; a connected network-device reference may be present. It is not a complete physical attachment proof. |
| Meraki wireless events  | Cisco Meraki Add-on Access Points input, `meraki:accesspoints` | `adm_index_meraki` → `cisco_meraki`     | Dashboard network events, including association events when returned by the API and visible to the configured account.             |

Install and configure the vendor add-ons using your normal Splunk change process. Put modular inputs on supported collection-tier instances, store credentials in the vendor account configuration, and send the raw events to the dedicated indexes above. The Atlas app reads these indexes through the macros; it does not contain vendor packages or credentials.

For the Cisco Enterprise Networking Add-on, enable the Catalyst Center client input and verify the effective read permissions for the client endpoint. Its packaged client input is disabled by default and polls hourly unless configured otherwise. Give the account access only to the organizations, sites, and client data in the approved pilot scope.

For the Meraki add-on, configure an organization account and an Access Points input for the pilot organization. Confirm the credential can read the relevant wireless network events. The packaged default interval is 86400 seconds, while the input validator excludes that endpoint value; select a supported interval below 86400 seconds and validate it on the target Splunk/Python runtime before enabling the input. Check that the chosen interval and API request volume fit the organization’s rate limit.

Keep collection limited to the approved pilot organizations, networks, sites, and time windows. No unrestricted organization-wide polling or capacity assumption is qualified.

The Meraki collector requests the network event feed for wireless networks without an association-only event filter. Confirm association records actually arrive; the input’s successful status does not prove that the organization returned association events. The observed event may contain `clientMac` or `eventData.client_mac`, IP, AP identity, and SSID number as optional fields. Treat a Catalyst client ID as a MAC address only when the documented response field is the client MAC; do not reinterpret an opaque identifier. Do not assume optional properties are present. The raw event’s `occurredAt` is event time. Inventory snapshots and generic custom API responses are not association history.

## Stream and release dependencies

Catalyst SD-WAN traffic is a separate optional Stream/IPFIX source. The reviewed flow contract preserves ingress and egress overlay session references for investigation, but does not join those references to router or tunnel topology. The add-on's `tloc_tunnel_proto` belongs to separate TLOC option records; the option envelope and its correlation to flows are unverified and unsupported. Do not use it as a flow field or infer TLOC, router, or tunnel attribution. Keep these flows separate from campus NetFlow and preserve exporter, observation domain, VPN/routing domain, interfaces, direction, sampling and counter semantics. Do not apply SD-WAN-specific field names to ordinary NetFlow/IPFIX or sum ingress and egress observations as independent traffic.

The Stream Forwarder 8.1.7 compatibility listing covers Splunk Enterprise through 10.5, while this pilot’s core is Splunk Enterprise 10.6. Treat Stream Forwarder placement on 10.6 as an unresolved compatibility gate: verify the exact supported deployment arrangement and run the approved staged qualification before production use. Package inspection or a successful local synthetic lab does not close this gate.

## Scope and correlation rules

- Configure explicit, source-specific records in the `adm_network_source_scope` profile collection. A source authority, source ID, and any exporter domain/VPN/routing scope must resolve to one unambiguous profile. Do not let a new source inherit a fleet-wide or shared default scope that could join unrelated networks.
- Keep Catalyst Center authority distinct from Meraki organization/network authority. Use stable native device identifiers as keys; names and addresses are aliases that can be ambiguous. Retain raw source identifiers and event times.
- Keep each Kubernetes cluster’s forwarding and source-scope configuration explicit. A cluster must not silently inherit a conflicting fleet-wide mapping.
- A Catalyst client snapshot is eligible for correlation from its indexed receipt time onward. `lastUpdatedTime` is source time when present; preserve it separately from receipt time. The inspected records do not provide a collector timestamp, so collection time remains unavailable. A snapshot does not establish earlier attachment history or a complete switch-port path.
- Correlate a Meraki wireless association with a client and flow only when MAC/IP identity, organization/network scope, and event/flow times are compatible. The map labels a client wireless only when supported association and flow evidence agree. Do not infer a disassociation event, DHCP lease, NAT translation, physical route, or AP identity from a missing optional field.
- Preserve gaps, stale observations, conflicting claims, capped query windows, and ambiguous mappings as unresolved evidence. Never bridge a history gap as though continuity were observed.
- The positive SD-WAN scenario retains flow-level overlay session references for investigation; it does not derive router or tunnel topology. Parsing TLOC option envelopes and joining those options to flows are unsupported, so do not infer a TLOC relationship from these references.
- Keep the vendor’s raw JSON field names and sourcetypes. These inputs are not CIM-mapped merely because their fields resemble a CIM field. Do not add aliases that label an unverified raw field as CIM.

V2 retains handoff evidence for the exact client-to-frontend edge, including its server port and transport. Paths, inspectors, and CSV exports use that edge's complete evidence to show backend subsets, receiving-node sets, and matching observers. Missing, ambiguous, or capped evidence leaves an unresolved backend boundary. An observed aggregate frontend-to-backend edge may still be supported by another client; it never supplies a selected client's backend or receiving node. A frontend can have partial aggregate coverage while one client's represented connections are fully determined.

Handoff counts describe represented raw-tuple connections, not all traffic or the graph edge's separate identity-deduplicated count. Each backend retains its evidence basis and connection count; timing inference is not promoted to observed evidence. Multiple backends or receiving nodes describe sets across those connections, not an ordered packet route. Relevant input-list truncation, inventory limits, or more than 64 backend/basis records, receiving nodes, or observers cause the client handoff to fail closed.

## Readiness checks

From the reviewed repository checkout, after collection and scope profiles are configured, run the read-only readiness report with only the source or sources being qualified. These tools are operator tooling and are not installed in the app package:

```sh
python3 tools/pilot_readiness.py --source catalyst --json
python3 tools/pilot_readiness.py --source meraki --json
```

Readiness distinguishes index visibility from verified API permission, raw-schema coverage, source-to-scope ambiguity, history continuity, and actual collection. The report can only evaluate those categories when its input snapshot includes the corresponding evidence; absent evidence stays unknown. The current `--lab` collector does not query Catalyst Center or Meraki APIs and does not establish their permissions or source-history continuity. Synthetic fixture events are reported separately and do not count as actual source collection. Partial permissions or invalid raw schema block readiness; ambiguous mappings block correlation. A “ready” report alone is not production qualification.

Useful initial checks in Splunk are:

```spl
index=cisco_catalyst sourcetype="cisco:dnac:client" | stats count, latest(_time) AS latest_event
index=cisco_meraki sourcetype="meraki:accesspoints" | spath input=_raw path=type output=event_type | where event_type="association" | stats count, latest(_time) AS latest_event by organizationId networkId
```

Inspect representative raw JSON as well as counts. Verify event time against `occurredAt` or the supplied Catalyst timestamp, organization/network/site scope, optional identity properties, collection time, and index time. Do not export credentials or unredacted customer records into fixtures or documentation.

## Staged upgrade and rollback

For an incompatible derived-summary contract change, the repository provides a bounded, journaled v2 staging helper. It writes to the separate `adm_summary_v2` index, additive `adm_network_client_history`, and separate `adm_app_catalog_v2`; v1 readers and data remain available. It requires an owner-only local journal and validation scenario, checks persisted coverage and complete collection readbacks, and waits for observed successful scheduled jobs before changing public selectors. An interrupted cutover must resume from the same journal or be rolled back. Rollback restores the captured effective REST settings and retains staged data. See the [migration procedure](../CISCO_CONTRACT_MIGRATION.md). The disabled-origin local synthetic run passed staging, scheduled-cycle validation, cutover, and rollback after retaining scheduler artifacts during diagnosis. The enabled-origin run also passed missed-window recovery after session refresh, scheduler-artifact retention and same-journal resumption. See the [qualification record](../CISCO_NETWORKING_QUALIFICATION.md) for evidence and limitations; no production deployment is qualified.

## What to send back

- Splunk Enterprise, search-head/indexer/collector topology, add-on versions, and Stream Forwarder version and placement.
- Catalyst Center version, enabled client input and poll interval, account permission scope, and a redacted sample `cisco:dnac:client` event.
- Meraki add-on version, organization/network scope, validated Access Points interval, account role, and a redacted association event showing which optional fields are actually present.
- Source-authority and routing-domain mapping for each profile, plus the time range and known gaps of available history.
- Collection, indexing, and search-head-cluster behavior observed during the staged qualification.

## Evidence and limitations

Package-level findings are recorded in [Catalyst evidence](../../research/cisco-catalyst-evidence.json), [Meraki evidence](../../research/cisco-meraki-evidence.json), and the checksummed [package manifest](../../research/package-manifest.json). Those findings come from static inspection of downloaded packages and official schemas; they do not prove that an API is configured or returning data in your environment. Vendor archives and extracted vendor files are research inputs and are not redistributed with Application Atlas.
