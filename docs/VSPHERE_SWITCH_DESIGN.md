# vSphere virtual switching, path trace and device flows

## Model

| Item | Source | Notes |
| --- | --- | --- |
| `hypervisor` device | APIC `comp:Hv` (DC Networking TA `cisco:dc:aci:class`) | `mgmt_ip` = `compHv.mgmtIp` when collected. That address is the VDS IPFIX exporter. |
| `virtual_switch` device (`switch_type=vds`) | APIC VMM domain from the `comp:Hv` DN `comp/prov-<P>/ctrlr-[<domain>]-<controller>/hv-<oid>` | Name = VMM domain (APIC-created VDS). `ipfix_observers` = member host management IPs, or `ip\|observation_domain_id`. |
| `virtual_port` link | `fv:CEp` + `fv:RsHyper` (host) + `fv:RsVm`/`comp:Vm` (name) + `fv:RsCEpToPathEp` or `fabricPathDn` (leaf path) | `a_device` = VDS, `b_device` = `vm:<mac>`, `hypervisor`, `mac`, `ip`, `vlan` (encap), `portgroup` (`tenant\|ap\|epg`), `attach_nodes` (two for vPC `protpaths`), `attach_interface`. |
| `uplink` link | `adm_vsphere_uplinks`: APIC `hvs:Adj` (LLDP neighbour per host) + `comp:HpNic` + leaf `lldpAdjEp` + `topSystem` | `nbrKey` = a leaf `oobMgmtAddr` gives VDS→leaf port; the vmnic is pinned only when the leaf LLDP `chassisIdV` on that port equals a host `comp:HpNic` MAC. Any other neighbour (UCS FI) becomes a `network_device` keyed by `nbrId`, with VDS→FI (`ifId` vEthernet, vmnic not pinned) and FI→leaf uplinks from leaf `lldpAdjEp` where `chassisIdV`=`nbrId` or `mgmtIp`=`nbrKey`. Uplinks never become switch adjacency, so FIs and hosts are never transit. |

IDs: macro arg `1` gives readable `vsphere:<apic>/vmm/<prov>/<domain>/<controller>` and `vsphere:<apic>/<compHv dn>`. Arg `2` gives `vsphere:sha256(...)`, along with `apic` scope mapping. Identity joins use APIC relation DNs. A VM is never merged with a host, and an ESXi host is never matched to an LLDP `sysName`, by name. If an `fvCEp.hostingServer` disagrees with `fv:RsHyper`, the port is dropped.

Path stages: VM → `virtual_switch` (VDS · on host · portgroup · VLAN, out vmnic when pinned) → [FI pair "host uplinks", vEthernet port] → [gap "Uplink from <host> to the fabric not collected" only when no uplink row exists] → leaf (or "One of 2 leaves · vPC") → shortest fabric path (ECMP spines) → … → VDS → VM. When both ends share a leaf or vPC pair, the path is that layer alone: no spine. Same host, switch and VLAN means the traffic is switched locally. Overlay ports (`overlay`, e.g. NSX) get a single gap, "underlay hops not attributed".

Observation: `netflow:<ip>[:ifIndex a>ifIndex b]` resolves to a VDS only through a unique `ipfix_observers` match. Source-qualified (v2) switches also require the record's scope. The key is per host instance, so only the exporting host's VDS stage is marked Seen. Interfaces are shown as `port a → port b`. VSS hops, and VDS hops with no record, show "Inferred".

## Searches

- `adm_vsphere_topology(1|2)` (includes `adm_vsphere_uplinks`): topology rows, concatenated by the reader. It is not appended to `adm_topology`/`adm_topology_v2`, so existing topology outputs are unchanged.
- `adm_fabric_path_evidence(src_ip,dst_ip)` (appended to `adm_path_trace`): up `isisAdjEp` rows, with the peer node resolved through `fabricLink` at the same node and port (`sysId` is never decoded), and `coopEpRec` rows for the pair's MACs. `pathTrace.ts` narrows an ECMP spine hop to spines that have both an up adjacency from the source leaf and a COOP record for the destination MAC. The hop stays `inferred`, with `support` listed and the forwarding spine never marked observed. If no spine qualifies, the hop keeps all topology candidates and a note explains why.
- `adm_path_trace(src_ip,dst_ip)`: bounded. It uses `TERM()` prefilters on both IPs across Stream, ACI ACL log, ND flows and FTD, capped at `adm_path_trace_limit`. It returns per-observer `observation` rows, `endpoint` rows from `adm_ip_identity`, and the vSphere rows for the two IPs. Names go through `adm_path_trace_resolve(1)` first.
- `adm_graph_edge_cut` / `adm_graph_edge_limit` (10000): ends `adm_graph(4)` and `adm_graph_v2(4)`. Ranks edges by structure first, then bytes, then connection count. Adds the `Map shows the top N of M edges` warning and `edges_returned`; meta `nodes`/`edges` stay pre-cut totals. The old 500/2,000 warning is removed.
- `adm_device_flows(device)`: device = exporter IP (including an ESXi VDS exporter), `pod-N/node-N` (ACL log), ND leaf name or FTD device IP. Rows are aggregated by src, dst, dest_port and protocol, and carry bytes, packets, flows, first/last seen, interfaces, blocked, vlans, segments and app. The top `adm_device_flows_limit` rows by bytes are returned, with totals over all rows, plus the flags `truncated` and `records_capped`. The record cap (`adm_path_trace_limit`) counts only records that name the device, after the device filter, so unrelated free-text Hubble or Nexus Dashboard matches cannot use it up; `records_capped=1` means more device records existed and totals are lower bounds.

Client: `frontend/src/data/pathTrace.ts` (`tracePath`) and `frontend/src/data/deviceFlows.ts` (`rowsToDeviceFlows`).

## Unverified

- `comp:Hv.mgmtIp`, `fv:CEp.fabricPathDn`, `fv:CEp.hostingServer`, and the `hvsAdj`/`compHpNic` attributes are APIC MIM attributes taken from live APIC 6.x class output (`classInfo_adm` with `apic_arguments` extended by `compHpNic compVNic hvsAdj`; see docs/operators/ACI_VMM_ADJACENCY_CLASSES.md). None of them is in the DC Networking data model (`Cisco_DCN_Systems.json`). `compVNic` is not used yet.
- The vmnic→FI pairing is not explicit in `hvsAdj`; behind an FI the vmnic stays unpinned. Live, the hosts' MACs are not the FI-side LLDP chassis IDs.
- That VDS IPFIX `input_snmpidx`/`output_snmpidx` carry DVS port IDs is VMware behaviour, not verified against the Stream TA.
- The VDS name is assumed to equal the VMM domain name, which is APIC's default.
- The optional VMware TA path (`fixtures/raw-vmware`, `Splunk_TA_vmware` 4.2.1) has no SPL yet. Host `config.network` is collected only with `hostsystem_inv_config = config.network`. VDS portgroup VLANs are not collected at all, because the TA has no `DistributedVirtualPortgroup` inventory. See `fixtures/raw-vmware/FIELDS.md`.
