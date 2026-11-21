# Splunk Stream / NetFlow / IPFIX owner

Receives NetFlow v9 / IPFIX on the **heavy forwarder** and indexes it as `stream:netflow`. Atlas uses each record to mark a device "Seen" (ACI leaf, ESXi VDS, campus exporter) with its interfaces. Source selection: [deployment options](deployment-options.md).

## Checklist

- [ ] Splunk Add-on for Stream Forwarders 8.1.3 on the HF; Splunk App for Stream 8.1.6 and Stream Wire Data 8.1.6 where stream definitions and search-time parsing run.
- [ ] One `netflowReceiver` on the HF, filtered to the expected exporters.
- [ ] **Netflow** stream enabled (ships disabled), index `netflow` (or `adm_index_netflow`).
- [ ] Receiver IP/UDP port sent to the ACI, VMware and campus teams; firewall allows UDP from exporters.
- [ ] Every exporter in `adm_observer_scope` as an `exporter` row (V1, [routing scope](splunk-platform.md#routing-scope-lookup)) and in `adm_network_source_scope` with a profile (V2 and source-qualified VDS, [checklist](README.md#source-scope-profile-registration)).

| Exporter | V2 profile | Observation domain |
| --- | --- | --- |
| ACI leaf (OOB source) | `aci_leaf_netflow` | Required |
| NX-OS exporter (including spine) | `nexus_nxos_netflow` | Required |
| ESXi host via VDS IPFIX | `vmware_vds_ipfix` | Required |
| Generic NetFlow without domain | `standard_netflow` | Must be absent |
| Catalyst / SD-WAN / Meraki MS390 | see [cisco-enterprise-networking](cisco-enterprise-networking.md) | Required |

## Native NX-OS observations in Live Trace

The scoped `adm_path_trace(3)` reader accepts native `stream:netflow` records through `adm_path_trace_netflow(3)`. Register the exact exporter and observation domain in `adm_network_source_scope` with `nexus_nxos_netflow`, `mapped`, one unambiguous mapping, and finite `valid_from` / `valid_end` epoch seconds containing the entire selected search window. Unregistered, ambiguous, expired, or wrong-scope observations do not qualify. Renew authority only after verifying the exporter configuration; do not widen an old qualification window merely to populate a demonstration.

The reader retains each record's tuple, direction, exporter/domain, timestamps, positive interface indexes and indexed-event reference. The UI groups records by exporter for display, with explicit gaps between independent observations. This does not establish adjacency, device order, NAT or a complete route. At most 32 records are returned, interleaved across exporters, and truncation remains visible. Interface index zero is unknown, not a verified egress.

Some exporters report zero byte counts and omit the egress index. Treat a populated ingress index as evidence at that interface. Verify the producer's timestamp and counter semantics before using Stream fields to report duration or traffic volume.

For an alternate-path comparison, scope each exact tuple to its recorded
window. Keep forward and reverse records separate even when the client port
is reused in another run. Resolve each interface index under its own exporter
and domain. Where a reported egress and another reporter's ingress are
adjacent, show that link as corroborating context. The observed interface
diversity supports maintenance planning. An outage or failover claim needs a
measured change and an independent application result.

## Check prerequisites for a separate switch input

Qualify a sampled flow input on an eligible physical interface with an
independent collector. Verify the installed switch build's coexistence rules
with existing flow monitors before enabling sampling.

For native switch-to-HEC telemetry, qualify a single sensor and dedicated
destination first. Test HTTPS from the intended routing domain and explicitly
bind the telemetry destination to it. Check transport counters or receiver
evidence for the native session. A temporary invalid marker can exercise
transport and show whether the device exposes the configured value. Before provisioning a real
token, verify certificate validation and credential handling. Enable the ADM
source mapping once the receiver has indexed and parsed the intended sensor.

## Receiver (`Splunk_TA_stream/local/streamfwd.conf` on the HF)

```ini
[streamfwd]
netflowReceiver.0.ip = <receiver IP>
netflowReceiver.0.port = <UDP port>
netflowReceiver.0.decoder = netflow
netflowReceiver.0.filter = <exporter IP>,<exporter IP>,...
netflowReceiver.0.decodingThreads = 4
netflowReceiver.0.templateExpiry = 3600
```

`filter` = leaf OOB addresses plus ESXi management addresses. Size `decodingThreads` to flow rate.

## Stream fields

Keep enabled:

```text
src_ip dest_ip src_port dest_port protoid bytes packets
exporter_ip input_snmpidx output_snmpidx ingress_vlan
exporter_sampling_interval exporter_sampling_mode
flow_start_time flow_end_time flow_start_rel flow_end_rel
observation_domain_id tcp_flags
```

- Stream adds `timestamp` (start) and `endtime` (end).
- ACI: ingress only; `output_snmpidx` usually empty. `ingress_vlan` is an observed access VLAN, not a BD ([VLAN facts](aci-network.md#optional-epg-to-bridge-domain-and-vlan-facts)).
- Bytes are scaled by `exporter_sampling_interval` when present.

## VMware VDS IPFIX

Marks the VDS hop "Seen" on path trace and lists the host on the Device page.

| Setting | Value |
| --- | --- |
| Collector | HF receiver IP / UDP port |
| Observation domain ID | Set (non-zero); register it with the profile |
| Switch IP address | Blank, so each host exports from its management IP (Atlas matches `exporter_ip` to APIC `compHv.mgmtIp`) |
| Enable on | Distributed port groups carrying the application |
| Internal flows only | Off |
| Profile | `vmware_vds_ipfix` |

- APIC-managed VDS (VMM domain): configure NetFlow through the APIC VMM domain policy; direct vCenter edits may be overwritten. Confirm for your APIC release.
- Requires the APIC VMM and adjacency classes ([ACI_VMM_ADJACENCY_CLASSES](ACI_VMM_ADJACENCY_CLASSES.md)) so the exporter resolves to a VDS.
- Unverified: that VDS `input_snmpidx`/`output_snmpidx` carry DVS port IDs.

## Sizing

Events/s ≈ active flows per exporter ÷ export interval × exporters. Size the HF, `netflow` index and license. Sampling reduces volume.

## Verify

```spl
`adm_index_netflow` sourcetype=stream:netflow | stats count dc(src_ip) AS sources by exporter_ip observation_domain_id
`adm_index_netflow` sourcetype=stream:netflow | table _time timestamp endtime exporter_ip src_ip src_port dest_ip dest_port protoid bytes input_snmpidx | head 20
```

- [ ] Every leaf OOB and ESXi management address appears as `exporter_ip`.
- [ ] `timestamp` ≤ `endtime`.
- [ ] **Admin → Data health**: no unmapped exporters; Stream source scope profiles `mapped` (V2).

## Skill

[`splunk-stream-setup`](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-stream-setup): Stream, `streamfwd`, `netflowReceiver`. Run with `--dry-run` first.

## Send back

- Stream and forwarder versions, receiver IP/port.
- Exporter list with observation domain IDs and profiles.
- Events/s per exporter after one day; sampling rate if any.
- One hour of `stream:netflow` samples.

## Sources

Stream Forwarders 8.1.3 `README/streamfwd.conf.spec:214-236`; Stream App 8.1.6 `default/streams/netflow`; Wire Data 8.1.6 `default/props.conf:4-10`; APIC MIM 6.1(x) NetFlow record policy; profile rules: `adm_profile_supported` in `macros.conf`.
