# ACI and Nexus Dashboard team

Gives Atlas read-only fabric inventory, policy and flow observations. All DC Networking inputs run on the **heavy forwarder**; on Splunk Cloud the search tier carries the TA for search time only. Source selection: [deployment options](deployment-options.md). Class summary: [operator index](README.md#required-aci-classes).

## Checklist

- [ ] Read-only APIC and Nexus Dashboard accounts in DC Networking 1.2.2 on the HF (**Configuration → ACI Account / ND Account**; password or certificate).
- [ ] Shipped APIC inputs enabled: `stats`, `classInfo_faultInst`, `classInfo_fvRsCEpToPathEp`, `health_fvTenant`.
- [ ] Custom `classInfo_adm` input with the 13 classes below.
- [ ] Optional: `classInfo_adm_network` (`fvRsBd`), `classInfo_adm_policy`.
- [ ] LLDP receive on leaf ports facing Kubernetes nodes and ESXi hosts / UCS FIs.
- [ ] NetFlow v9 from **leaves** to the HF Stream receiver; each leaf OOB address in `adm_observer_scope` (V1) and registered with profile `aci_leaf_netflow` (V2, [checklist](README.md#source-scope-profile-registration)).
- [ ] ND `endpoints` and `flows` inputs for the site.
- [ ] TA dashboard macros `cisco_dc_aci_index`, `cisco_dc_nd_index`, `cisco_dc_n9k_index` set to your index (default `main`).

## APIC inputs

Index: `cisco_dc` (or the value of `adm_index_dcn`).

| Input | Type | Atlas reads |
| --- | --- | --- |
| `stats` (shipped) | stats | `fvCEp` + `fvIp`, `fvRsCEpToPathEp` → endpoint IP/MAC, EPG, leaf port |
| `classInfo_faultInst` (shipped) | classInfo | `topSystem compVm compHv fvCEp fvRsCons fvRsProv fvRsVm fvRsHyper` → switch roles, VM/host, contracts |
| `health_fvTenant` (shipped) | health | Tenant/EPG names, filters, node roles |
| `classInfo_fvRsCEpToPathEp` (shipped) | classInfo | Attachment paths; `acllogPermitL3Pkt`/`acllogDropL3Pkt` |
| `classInfo_adm` (custom) | classInfo | Fabric links, host LLDP, contracts, L3Out subnets, vSphere uplinks, spine evidence |

`classInfo_adm` classes:

```text
fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet compHpNic compVNic hvsAdj isisAdjEp coopEpRec
```

`vzBrCP`/`vzEntry` repeat because `health_fvTenant` merges them with health records. The pinned skill preset `application-atlas` (alias `adm`) creates only the first eight; pass the full list:

```sh
cd vendor/splunk-cisco-skills
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-input classInfo_adm --account "<ACI account>" --index cisco_dc \
  --classinfo-classes "fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet compHpNic compVNic hvsAdj isisAdjEp coopEpRec" \
  --dry-run   # review, then rerun without --dry-run
```

Equivalent stanza (HF, `local/inputs.conf`):

```ini
[cisco_nexus_aci://classInfo_adm]
apic_account = <ACI account>
apic_input_type = classInfo
apic_arguments = fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet compHpNic compVNic hvsAdj isisAdjEp coopEpRec
interval = 300
index = cisco_dc
disabled = 0
```

vSphere and spine details: [ACI_VMM_ADJACENCY_CLASSES](ACI_VMM_ADJACENCY_CLASSES.md), [ACI_SPINE_PATH_EVIDENCE](ACI_SPINE_PATH_EVIDENCE.md).

### Optional: EPG to bridge-domain and VLAN facts

Input `classInfo_adm_network`, class `fvRsBd`, 300 s. APIC only.

```sh
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-input classInfo_adm_network --classinfo-classes "fvRsBd" \
  --account "<ACI account>" --index cisco_dc --dry-run
bash skills/cisco-dc-networking-setup/scripts/validate.sh \
  --classinfo-input classInfo_adm_network --classinfo-classes fvRsBd --index cisco_dc
```

| Fact | Authority | Not authority |
| --- | --- | --- |
| EPG → BD | `fvRsBd.tDn`, `tnFvBDName` | VLAN number |
| Endpoint access VLAN | `fvCEp.encap` | Not one VLAN for the whole EPG |
| Observed ingress VLAN | NetFlow `ingress_vlan` (when the record carries it) | No egress VLAN, no BD |
| ND display BD | `displayBd` | Not an APIC EPG relation |

### Optional: complete policy evaluation

Default: the map names a permitting contract when one matches, else "Policy not evaluated" — never "no contract permits this". To allow "no permitting contract", add input `classInfo_adm_policy`:

```sh
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-preset adm-policy --account "<ACI account>" --index cisco_dc --dry-run
```

Classes: `fvCtx fvAEPg fvEPg fvESg vzAny vzRsAnyToCons vzRsAnyToProv vzRsAnyToConsIf vzInTerm vzOutTerm vzTaboo fvRsProtBy vzRsSubjGraphAtt`.

Then set macro `adm_aci_policy_complete=1` — only when every policy construct in the VRF is covered. Validate each input with `validate.sh --classinfo-preset application-atlas|adm-policy --index cisco_dc`.

## LLDP on host ports

Leaf access ports facing Kubernetes nodes need LLDP receive. Nodes run an LLDP agent advertising the Kubernetes node name (needed for floating-SVI L3Out nodes, whose IPs are not ACI endpoints). ESXi uplinks are learned from `hvsAdj` plus leaf `lldpAdjEp`.

## ACI NetFlow export

| Setting | Value |
| --- | --- |
| Version | v9 |
| Source IP type | `oob-mgmt-ip` (exporter = leaf OOB address = `topSystem.oobMgmtAddr`) |
| Destination | HF Stream receiver IP / UDP port ([network-stream](network-stream.md)) |
| Record match | src/dst IPv4, src/dst port, protocol |
| Attach to | BDs of K8s nodes, client and server VMs; K8s L3Out interface profile |
| Nodes | **Leaves only.** Spines have no NetFlow attach point (APIC 6.1) |
| Atlas scope | `adm_observer_scope` `exporter` row (V1); profile `aci_leaf_netflow` (V2) |

- Records carry ingress interface only (no egress, no VRF).
- Confirm per APIC release: GUI path, leaf hardware support, NetFlow vs ND flow telemetry per leaf (fabric node control policy). Either source alone works; without NetFlow on the LoadBalancer ingress leaf, DSR receiving node is unknown.

## Nexus Dashboard inputs

Enable `endpoints` and `flows` with the ND account, index `cisco_dc`, and the site. Enable flow telemetry for the application VRFs.

## Contract logging (optional)

Set `log` on contract subject filters for the application ports. ACL-log records are sampled and bounded: they confirm traffic, not count it.

## Verify

```spl
`adm_index_dcn` sourcetype=cisco:dc:aci:class | stats count by component
`adm_index_dcn` sourcetype=cisco:dc:aci:stats component=fvCEp | head 5
`adm_index_dcn` sourcetype=cisco:dc:nd:flows | head 5
`adm_index_netflow` sourcetype=stream:netflow | stats count by exporter_ip observation_domain_id
```

- [ ] Every class in the tables above appears as a `component`.
- [ ] Every leaf OOB address appears as an `exporter_ip`; no spine does.
- [ ] Events come from the HF `host`, not the Cloud search tier.

## Send back

- APIC, ND versions; leaf/spine models; node list (ID, name, role, OOB address).
- Tenants, VRFs, BDs, EPGs, L3Outs, external EPGs, VMM domains used by the application.
- LoadBalancer VIP and pod CIDR prefixes in L3Out external EPG subnets.
- Which leaves run NetFlow vs ND flow telemetry.
- Whether vzAny, preferred groups, ESGs, PBR service graphs, unenforced VRFs or `est`/source-port filters are used (Atlas shows "Policy not evaluated" for these).

## Sources

DC Networking 1.2.2 `default/inputs.conf:81-127`, `bin/cisco_nexus_aci.py:467-609`, `default/props.conf:191`. APIC MIM 6.1(x): `fvRsBd`, `fvBD`, `netflow:ExporterPol`, `netflow:RecordPol`, `hvs:Adj`, `comp:HpNic`, `isis:AdjEp`, `coop:EpRec`. Stream 8.1.6 NetFlow docs. Data use: [DATA_LAYER](../DATA_LAYER.md), [VSPHERE_SWITCH_DESIGN](../VSPHERE_SWITCH_DESIGN.md).
