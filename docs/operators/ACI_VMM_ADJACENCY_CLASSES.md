# ACI VMM adjacency classes (ESXi vmnic → UCS FI → ACI leaf)

Adds vSphere host uplink and spine evidence to the HF `classInfo_adm` input. Used by `adm_vsphere_uplinks` and `adm_fabric_path_evidence` ([design](../VSPHERE_SWITCH_DESIGN.md)).

| Class | What it is | Atlas use |
| --- | --- | --- |
| `hvsAdj` | LLDP/CDP neighbour seen by a hypervisor vmnic | VDS → leaf or VDS → FI uplink |
| `compHpNic` | Hypervisor physical NIC (vmnic name, MAC) | Pins the vmnic when the leaf LLDP `chassisIdV` equals its MAC |
| `compVNic` | VM vNIC (MAC, port group) | Collected; not read yet |
| `isisAdjEp` | Leaf–spine IS-IS adjacency | Spine-hop support ([spine evidence](ACI_SPINE_PATH_EVIDENCE.md)) |
| `coopEpRec` | Spine COOP endpoint record | Spine-hop support |

The shipped `classInfo_faultInst` input already collects `compHv compVm fvRsHyper fvRsVm fvCEp vmmCtrlrP`. The skill will not edit shipped stanzas, so add the new classes to `classInfo_adm`.

## Where the input runs

- [ ] Heavy forwarder only. On Splunk Cloud, every `cisco_nexus_aci://*` input on the search tier stays disabled with no account.
- [ ] Confirm the source: `` `adm_index_dcn` sourcetype=cisco:dc:aci:class source=*classInfo_adm* | stats count by host component ``.

## Pre-checks

- [ ] Read-only APIC query per class returns objects: `/api/class/hvsAdj.json?page-size=1` (repeat for each class).
- [ ] Back up `cisco_dc_networking_app_for_splunk/local/inputs.conf` on the HF.

## Change (HF)

From `vendor/splunk-cisco-skills`, with `SPLUNK_CREDENTIALS_FILE` set and the HF profile selected. `<ACCOUNT>`/`<INDEX>` come from the existing stanza. Run with `--dry-run`, review, then without.

```sh
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-input classInfo_adm --account <ACCOUNT> --index <INDEX> \
  --classinfo-classes "fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet compHpNic compVNic hvsAdj isisAdjEp coopEpRec"
```

The pinned `application-atlas` preset covers only the first eight classes; use the explicit list. This is a modular-input REST edit; no restart is expected. If the edit is done by file instead, restart through [`splunk-platform-restart-orchestrator`](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-platform-restart-orchestrator).

## Verify (after one 300 s interval)

```sh
bash skills/cisco-dc-networking-setup/scripts/validate.sh --classinfo-input classInfo_adm --index <INDEX>
```

```spl
`adm_index_dcn` sourcetype=cisco:dc:aci:class component IN (hvsAdj, compHpNic, compVNic, isisAdjEp, coopEpRec) | stats count by component
```

## Rollback

Re-run the command with the original eight classes, or restore `apic_arguments` from the backup. Indexed events need no cleanup.

## Lab record

Applied on the lab HF on 2026-11-04 (`compHpNic compVNic hvsAdj` at 03:44Z, `isisAdjEp coopEpRec` at 04:24Z); none of these classes reached the index before. Host details: [INTERSIGHT_VMWARE_LAB_SETUP](INTERSIGHT_VMWARE_LAB_SETUP.md).
