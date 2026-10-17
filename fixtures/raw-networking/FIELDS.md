# Combined campus and Meraki raw fixture provenance

`scenario.json` is a synthetic, local qualification fixture. It does not represent
captured Dashboard API responses, Catalyst Center client records, or decoded NetFlow
templates. Use `python3 tools/gen_raw_fixtures.py --scenario networking --base-time
2026-10-16T13:00:00Z` to regenerate the checked-in example at a stable anchor. Use
`--output-dir /tmp/networking-capture` to write a separate qualification dataset and
its `capture-manifest.json` without changing checked-in fixtures. The manifest lists
the intended 15-minute graph window separately from the ingestion window calculated
from the minimum and maximum HEC event times across all raw files, plus event counts
by file, index, and sourcetype and the source profile file. Load/count qualification
must use the wider ingestion window because some events predate the graph window.
Omit `--base-time` to anchor the generated flow window to current UTC. Catalyst snapshot
`lastUpdatedTime` is the event's source timestamp; no collection timestamp is added.
Splunk receipt time remains `_indextime`.

`source-profiles.json` holds the explicit synthetic seven-dimension Stream lookup
profiles, source-qualified client mappings, legacy observer/scope mappings, graph
arguments, and intended Cilium settings. Its exporter authorities, observation-domain
IDs, scopes, cluster names and Cilium configuration values are lab configuration
examples only; validate them against the real exporter and cluster before use.
The two Isovalent `hec_source` scope rows pair configured HEC input sources
`http:isovalent-aci` and `http:isovalent-nxos` with their clusters. This distinguishes
identical node names and IPs in the lab without adding a native
`k8s.cluster.name` field to `processConnect` events.

## Client source records

* `catalyst_clients.ndjson` projects a Catalyst Center client response into the
  verified TA 4.0.50 `cisco:dnac:client` shape. The client input writes JSON, adds
  `cisco_catalyst_host`, chooses the connected switch name for Splunk host, and uses
  `cisco_catalyst_dnac_client://<input>` as source. See
  `research/extracted/cisco-enterprise-networking-add-on-for-splunk_4050/TA_cisco_catalyst/bin/cisco_catalyst_dnac_client.py:463-481`.
  The positive record includes documented API fields `type=Wired`,
  `connectionStatus=connected`, `connectedNetworkDeviceType=Switch`, and
  `connectedNetworkDevice.interfaceName`; the chosen switch port name is a synthetic
  example. Cisco's current Assurance Clients OpenAPI documents the type values
  `Wired`/`Wireless`, status values `connected`/`disconnected`/`connecting`/`unknown`,
  connected device type values `Switch`/`Access Point`, and the wired interface field:
  <https://raw.githubusercontent.com/cisco-en-programmability/catalyst-center-api-specs/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml>
  (schema includes these fields and a wired client example). `lastUpdatedTime` is not
  an association start time; snapshot attachment validity starts at receipt. Client
  IP/MAC and connected-device references can be absent in real responses.
  `connectionStatus` is inventory connection status, not traffic permission or denial.
* `meraki_associations.ndjson` uses only the official documented `type=association`
  event shape. Cisco Meraki TA 3.5.0 requests wireless network events, all pages,
  with no event type or client filter (`cisco_meraki_connect.py:583-599`); it writes
  event JSON with `organizationId` filled only when absent (`:1455-1473`). Its
  `meraki:accesspoints` props parse `occurredAt`; no association-specific IP/MAC
  alias is assumed. The current Cisco API example documents `occurredAt`, `networkId`,
  association type, `clientMac`, AP `deviceSerial`/`deviceName`, `ssidNumber`, and
  `eventData.client_mac`/`client_ip`:
  <https://developer.cisco.com/meraki/api-v1/get-network-events/> (API v1.74.0,
  documentation dated 2026-09-02). API fields may be absent on actual events; the TA
  preserves what it receives. Sequential association events on two APs show a roam;
  there is no invented disassociation type.
* Repeated/old/conflicting association rows, an unassociated flow, and later reuse of
  the same IP by a second MAC are deliberate negative evidence. They should remain
  unresolved, stale, duplicate, or conflicting according to the normalized time
  policy. The stale association is at `base_time - 3600s`, and is still shifted with
  the selected anchor. They do not support filling an AP/SSID on a flow without a
  compatible observed association.

## Inventory, topology, and traffic

* `meraki_inventory.ndjson` uses the documented `getOrganizationDevices` device
  response fields and `meraki:devices`. This is current inventory, not association
  history.
* `meraki_topology.ndjson` is a response-shaped event for the TA 3.5.0 cataloged
  `getOrganizationSwitchPortsTopologyDiscoveryByDevice` custom API input. The TA
  decorates each response with organization, operation, endpoint path/name, and
  collection time (`cisco_meraki_custom_api_helper.py:579-595`). Cisco documents
  per-switch-port most-recent LLDP/CDP neighbor data at
  <https://developer.cisco.com/meraki/api-v1/get-organization-switch-ports-topology-discovery-by-device/>.
  This is discovery evidence, not a route. The fixture only supplies a named LLDP
  neighbor; there is no claim that a complete AP uplink or physical path was collected.
* `sdwan_netflow.ndjson` uses Stream's `stream:netflow` standard fields plus only the
  Cisco enhanced-NetFlow fields mapped by TA 4.0.0 (`ipfixmap.conf:63-79` and
  `default/cisco.hsl.json:646-689,1303,1809`). Values are illustrative; an exporter
  template/decoder match is not established. Absolute packet times use integer
  `flow_start_time_milli` / `flow_end_time_milli` (IANA 152/153); the corresponding
  fields without `_milli` are unsigned integer seconds, not fractional seconds.
  Flow records carry ingress/egress overlay session IDs only. TLOC addresses,
  colors, and `tloc_tunnel_proto` belong to separate option records, as described
  in the add-on's `default/data/ui/views/home.xml:84`. No option-table join is
  fabricated here. The decoded option record's complete time/exporter/domain
  envelope is not established, so these fixtures cannot qualify TLOC inventory,
  tunnel attribution, or a complete SD-WAN packet route.
* `campus_netflow.ndjson` is a standard-only `stream:netflow` observation of the same
  wired tuple as the enhanced SD-WAN record. It intentionally omits SD-WAN `vpn_id`,
  overlay session, and TLOC fields. It includes the synthetic exporter IP and
  observation-domain ID needed by the exact source-profile lookup.
* `meraki_ms390_ipfix.ndjson` is a synthetic standard Stream/IPFIX record for the
  documented bridged wireless-to-MS390 observation. The Meraki MS390 documentation
  describes standard IPv4/IPv6 IPFIX with tuples, best-effort counters, MACs,
  direction/interface and first/last times. Decoder support for this exact exporter
  record is not validated here. These records intentionally omit SD-WAN `vpn_id`,
  TLOC and overlay fields. Cisco's TA `vendor_product` alias is broad for
  `stream:netflow`, so it must not be used alone to classify an MS390 exporter as
  SD-WAN. The sample includes a synthetic exporter IP and observation-domain ID;
  `src_mac` is selected from the documented best-effort MS390 IPFIX fields and does
  not establish this model's actual export or decoder support.
* `aci_stats.ndjson`, `aci_class.ndjson`, `aci_netflow.ndjson`,
  `aci_nd_flows.ndjson`, and `aci_nd_endpoints.ndjson` use the existing ACI
  TA-shaped builders, including `fvCEp` class/stat rows, standard Stream NetFlow
  observations from three synthetic ACI exporters, and ACI ND flow/endpoint
  records. The `standard_netflow` source profiles register exporter IPs
  `192.0.2.101`, `.102`, and `.103` with no observed observation-domain ID, VPN,
  or routing-domain value. Profile mapping controls visibility only; traffic
  counters remain non-authoritative (`counter_semantics=unknown`,
  `metrics_authoritative=0`). These synthetic profile values do not validate live
  exporter identity or template decoding. `nxos_inventory.ndjson`,
  `nxos_nd_flows.ndjson`, and `nxos_nd_endpoints.ndjson` use the existing Nexus 9K
  and Nexus Dashboard fixture builders with the NX-OS dashboard fabric configured
  as `nxos-campus-1`. NX-OS inventory begins at `base_time - 900s`. Inventory and
name matches do not establish client attachment or packet route. The synthetic
`nxversion` rows include `Row_info.proc_board_id` as the native chassis identity:
Cisco's NX-OS 10.5(x) Programmability Guide documents this field in the JSON
result from `clid('show version')`; the DC Networking TA serializes NX-API
`Row_info` into the event without removing fields. Synthetic authority mappings
use the explicitly registered collector `host` as source authority and
`proc_board_id` as native identity. The exact, lowercased operator lookup key is
JSON `[host, proc_board_id]`. Device endpoint `device` (IP:port) is only an alias to
join `nxversion` and `nxneighbor` records within that collector; it is not part
of the durable device ID. If the collector is not registered or the serial
mapping is absent or ambiguous, the device remains unresolved and no physical
peer link is emitted. Nexus Dashboard fabric/name evidence may corroborate an
already resolved identity but does not establish it.
The NX-OS ND flow uses the synthetic client-to-LoadBalancer-VIP tuple
(`destination_ip:destination_port`) as the fabric-observed pre-DNAT destination;
the Hubble flow separately carries the client-to-backend-pod tuple. This follows
the selected ordinary LoadBalancer Service contract with
`externalTrafficPolicy: Local` and the documented Cilium behavior for local
endpoints; it does not invent a post-NAT translation in the fabric record. The
Nexus Dashboard TA flow schema passes `dstIp` through and aliases it to
`dest_ip` for `cisco:dc:nd:flows`. The synthetic tuple still requires live capture
to validate a real data-plane path.
NX-OS ND endpoint
  records are deliberately timestamped at `base_time - 9600s` (with endpoint creation
  time at `base_time - 9900s`) to retain older endpoint-inventory context. These
  timestamps rebase with `base_time`.

NX-OS field provenance: [Cisco Nexus 9000 Series NX-OS Programmability Guide,
Release 10.5(x), Python API](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-105x/m-python-api.html)
shows `proc_board_id` in the JSON output of `clid('show version')`. Verified TA
passthrough is `research/extracted/cisco-dc-networking_122/cisco_dc_networking_app_for_splunk/bin/cisco_nexus_9k.py` (NX-API response to `Row_info`, serialized into the event).

## Cluster and application evidence

`kube_objects.ndjson`, `hubble_flows.ndjson`, `isovalent.ndjson`, and
`otel_traces.ndjson` reuse the existing ACI Cilium fixture schema with two distinct
`k8s.cluster.name` values. Both clusters intentionally reuse display names and
service/pod addresses. Each added inbound client request has a Hubble
`TO_ENDPOINT` record and a matching server span with client address. No Tetragon
`processConnect` is synthesized for either external client; existing processConnect
rows remain only where the source template contains actual pod-initiated outbound
conversations. The fixed Kubernetes Node `metadata.creationTimestamp` of
`2026-09-01T00:00:00Z` is an intentional absolute fixture invariant; generated HEC
event times and other scenario timestamps rebase with `base_time`. Kubernetes pod
start events begin at `base_time - 9900s`, inherited from the prior Cilium scenario
relative to the 15-minute graph window; this offset is included in the manifest's
ingestion window.

The fixture's logical scope names are configuration identifiers, not raw source
fields. Catalyst site/controller and VRF mapping, Meraki network mapping, collection
permissions, API retention/completeness, SHC/Cloud deployment, and live IPFIX decoding
remain deployment qualification gates.

## Primary documentation

* Meraki MS NetFlow/ETA capabilities:
  <https://documentation.meraki.com/Switching/MS_-_Switches/Operate_and_Maintain/Monitoring_and_Reporting/MS_NetFlow_and_Encrypted_Traffic_Analytics>
* Meraki organization device inventory:
  <https://developer.cisco.com/meraki/api-v1/get-organization-devices/>
* Cisco Meraki API `getNetworkEvents` association schema and example:
  <https://developer.cisco.com/meraki/api-v1/get-network-events/>
* Cisco Meraki LLDP/CDP topology discovery schema:
  <https://developer.cisco.com/meraki/api-v1/get-organization-switch-ports-topology-discovery-by-device/>
