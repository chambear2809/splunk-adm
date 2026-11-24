# LLDP source qualification

Status: collection spike, 2026-11-24. Validation lab, NX-OS Leaf1, Leaf2 and Spine1. Not yet read by Atlas. This record supports the Topology view in the [multicast views design](superpowers/specs/2026-11-24-multicast-views-design.md).

## Result

Two collection paths were enabled side by side and compared against `show lldp neighbors` on each switch.

| Path | Neighbors (Spine1 / Leaf1 / Leaf2) | Matches CLI |
|---|---|---|
| Cisco DC Networking TA 2.0.10, NX-API DME class `lldpAdjEp` | 5 / 14 / 14 | Yes, every (local port, peer chassis, peer port) |
| gNMI, OpenConfig `/lldp/interfaces/interface/neighbors/neighbor/state`, gnmic → OTLP → Splunk OTel → HEC metrics | 5 / 14 / 14 | Yes |

The two paths produced identical normalised neighbor sets (33 rows). Comparison key: reporting device, local interface, peer chassis ID, peer port, after interface-name normalisation (below).

## Path 1: DC Networking TA (`lldpAdjEp`)

**Input.** One `cisco_nexus_9k` input per switch account with `nexus_9k_input_type = nexus_9k_custom`, `nexus_9k_custom_catalog_mode = 1`, `nexus_9k_custom_endpoint = api/class/lldpAdjEp.json`. NX-API (`feature nxapi`, HTTPS 443) must be enabled.

**Event.** Sourcetype `cisco:dc:nexus9k:custom`, one event per adjacency. `host` and `device` are the **switch management IP**, not its hostname. Atlas must map this IP to the device key (lower-cased hostname). Relevant `payload.lldpAdjEp.attributes`:

| Field | Example shape | Use |
|---|---|---|
| `dn` | `sys/lldp/inst/if-[eth1/54]/adj-1` | Local interface is inside `if-[…]` |
| `chassisIdT` / `chassisIdV` | `mac` / `ecbb.78bf.42a2` | Peer identity |
| `portIdT` / `portIdV` | `if-name` / `Ethernet1/5` | Peer port |
| `sysName` | `sw2` (may be empty, or an FQDN) | Peer name |
| `mgmtIp` | IPv4 | Peer management address |
| `portDesc`, `sysDesc`, `capability` | text | Display only |
| `linkAggStatus`, `linkAggID` | `aggregated`, `106` | Port-channel membership |
| `portVlan`, `vlanName` | `1`, `10: VLAN0010, …` | Segment hints |
| `modTs` | ISO 8601 | Last adjacency change |
| `ttl` | `120` | Freshness |

**Finding.** New TA accounts default to `verify_ssl = 1`. The switches' NX-API certificates are not trusted, so the first cycles failed with `error_type=SSLError`. The spike set `verify_ssl = 0` on its accounts (lab only). Production deployments should use the account's custom CA option.

## Path 2: gNMI (OpenConfig LLDP)

**Finding: the Splunk OTel `gnmi` receiver (0.161.0) cannot carry LLDP adjacency.** It emits each string leaf as a separate `*_info` gauge whose only data-point attributes are `value` and `index`; the list keys (local interface name, neighbor ID) are dropped. Rows cannot be joined back into a neighbor record. It also requires a typed `default` or `overrides` entry for every subscription. NX-OS also closed one session with `GOAWAY ENHANCE_YOUR_CALM too_many_pings`.

**Working path: gnmic → OTLP → Splunk OTel.** gnmic keeps the list keys in its event paths (`/openconfig:/lldp/interfaces/interface.N/name`, `…/neighbors/neighbor.M/state/<leaf>`). A gnmic `event-starlark` processor splits each notification into one event per neighbor. It sets string leaves as **tags**, so they reach Splunk as dimensions on one metric. (With `strings-as-attributes`, gnmic instead emitted every string as its own metric.)

**Metric.** `lldp_neighbor` (value `1`), sampled every 60 s, in a metrics index. Dimensions:

| Dimension | Example shape |
|---|---|
| `atlas.device` | `leaf1` (set by the processor from the gNMI target) |
| `local_interface` | `eth1/49` |
| `neighbor_id` | `1` |
| `lldp.chassis_id`, `lldp.chassis_id_type` | `9433.d8ed.aafa`, `MAC_ADDRESS` |
| `lldp.port_id`, `lldp.port_id_type` | `Ethernet1/1`, `INTERFACE_NAME` |
| `lldp.system_name` | `spine1` (absent for host NICs) |
| `lldp.management_address` | IPv4 (absent for host NICs) |
| `lldp.port_description` | text |
| `atlas.scope`, `server.address` | collector-assigned |

An adjacency is the latest `lldp_neighbor` per (`atlas.device`, `local_interface`, `neighbor_id`). Group-by searches must not require `lldp.system_name` or `lldp.management_address`: 12 of 33 neighbors (ESXi and UCS NICs) report only a MAC chassis ID and a MAC port ID.

## Normalisation required for both paths

- **Interface names.** Local interfaces are `eth1/49` (gNMI, DME `dn`) or `Eth1/49` (CLI). Peer ports are `Ethernet1/49` for NX-OS peers and `Eth1/9` for some others. Normalise `ethernet`/`eth` prefixes and case before matching a link's two ends.
- **Peer names.** `sysName` may be a bare hostname (`sw2`) or an FQDN (`sw1.dcloud.cisco.com`). Match by chassis ID or management address before name, and never merge devices by name alone.
- **MAC-only peers.** Hosts advertise MAC chassis and port IDs with no name or address. These attach to a device only through endpoint or NIC inventory (see the design's receiver attachment rule).
- **Reciprocity.** A switch-to-switch link is confirmed when both ends report each other. Out-of-band `mgmt0` neighbors (lab management switch) must be excluded from the data-plane topology.
- **Device identity.** TA events identify the reporter by management IP; gNMI by the collector-assigned device name. Both resolve to the lower-cased hostname key.

## Lab objects created (still running)

The spike left collection running for development use:

- Splunk: indexes `atlas_lldp_spike` (metrics) and `atlas_lldp_spike_events` (events); HEC token `atlas-lldp-spike` restricted to `atlas_lldp_spike`. In the DC Networking TA, accounts and inputs `atlas_lldp_spike_{spine1,leaf1,leaf2}` (interval 300 s).
- Kubernetes namespace `atlas-gnmi-telemetry`: Deployment and ConfigMap `lldp-spike-bridge`, Secret `lldp-spike-hec`. Everything carries the label `atlas.spike=lldp`.

To remove: delete the `atlas.spike=lldp` Kubernetes objects; disable and delete the three TA inputs and accounts; disable the HEC token; then remove the two indexes. No existing input, collector or device configuration was changed.
