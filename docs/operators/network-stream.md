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
| ESXi host via VDS IPFIX | `vmware_vds_ipfix` | Required |
| Generic NetFlow without domain | `standard_netflow` | Must be absent |
| Catalyst / SD-WAN / Meraki MS390 | see [cisco-enterprise-networking](cisco-enterprise-networking.md) | Required |

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
