# Official Splunkbase TA install and migration guide

Application Atlas works with **official, unmodified Splunkbase add-ons**. Operators do not need modified vendor TA builds or a companion ACI add-on.

| Source | Official Splunkbase TA | Version | Splunkbase ID | Companion add-on required? |
| --- | --- | --- | --- | --- |
| ACI / Nexus Dashboard / NX-OS | Cisco DC Networking Add-on for Splunk (`cisco_dc_networking_app_for_splunk`) | `2.0.10` | `7777` | **No** — configure `classInfo` + `apic_arguments` |
| AppDynamics topology | Cisco Splunk Add-on for AppDynamics (`Splunk_TA_AppDynamics`) | `3.3.0` | `3471` | **No** — use official `appdynamics_topology`; supply node IPs via SIM or external HEC collector |

> **Historical modified vendor builds:** Existing modified vendor TA snapshots under `integrations/ta-releases/` (`atlas-20261031-r1`, `atlas-20261031-r2-candidate`) are **historical and deprecated**. They remain retained in the repository for rollback and audit reference until live validation completes and removal is explicitly approved. Setup and Data health automatically warn when a modified build or its custom events are detected.

---

## 1. Cisco DC Networking Add-on 2.0.10 (Splunkbase 7777)

### Key differences from 1.2.2

- **No pre-populated APIC inputs in `default/inputs.conf`:** 2.0.10 ships only the `[cisco_nexus_aci]` defaults. Operators configure inputs explicitly on the Heavy Forwarder (HF) using `apic_input_type = classInfo` (or `stats` for `fvCEp`).
- **No `fvRsCtx` or `fvRsBd` preset:** Neither the guided `aci_collection` areas nor custom groups in 2.0.10 include `fvRsCtx` or `fvRsBd`. Include them explicitly in `apic_arguments`.
- **Compact JSON output:** `cisco:dc:aci:class` events are emitted as single-line JSON with `event_timestamp`, `apic_host` (lowercase, `:443` stripped), `actual_host`, `component`, and top-level APIC object attributes.
- **Vendor `EVAL-action` rewrite preserved:** `default/props.conf` on `[cisco:dc:aci:class]` still rewrites `action` from `ind`, blanking `vzRsSubjFiltAtt.action`. Atlas's `[adm_aci_policy_build]` extracts `action` directly from `_raw` for both 2.0.10 JSON and legacy 1.2.2 tab-separated KV payloads.
- **Single-pass provenance:** Official 2.0.10 `classInfo` polls each class independently without a two-pass transaction boundary. Atlas's `adm_aci_bd_vrf_map` macro and `adm_aci_lib` official-format helpers label single-pass results honestly as `qualification=unverified_single_pass` (`source_mode=official_dc_networking_classinfo`).

### Required and optional `apic_arguments` classes

Every class name in `apic_arguments` is space-separated and validated by the TA against `^[A-Za-z][A-Za-z0-9_-]{0,127}$`.

| Input stanza (HF) | `apic_input_type` | `apic_arguments` | Purpose in Atlas |
| --- | --- | --- | --- |
| `stats_fvcep` | `stats` | `fvCEp` | Endpoint IP (`fvIp`) and attachment path (`fvRsCEpToPathEp`) children (`sourcetype=cisco:dc:aci:stats`) |
| `classInfo_adm_core` | `classInfo` | `topSystem compVm compHv fvCEp fvRsCEpToPathEp fvRsCons fvRsProv fvRsVm fvRsHyper fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet` | Core fabric inventory, host LLDP, contracts, L3Out external subnets |
| `classInfo_adm_network` | `classInfo` | `fvRsBd fvBD fvRsCtx fvCtx l1PhysIf ethpmPhysIf l3EncRtdIf` | **EPG → BD → VRF mapping (`fvRsCtx` explicitly included)** and routed/physical leaf interfaces |
| `classInfo_adm_vmm_spine` | `classInfo` | `compHpNic compVNic hvsAdj isisAdjEp coopEpRec` | Optional: vSphere host uplinks and spine-hop path evidence |
| `classInfo_adm_acllog` | `classInfo` | `acllogPermitL3Pkt acllogDropL3Pkt` | Optional: contract ACL-log permit/drop confirmation |
| `classInfo_adm_policy` | `classInfo` | `fvAEPg fvEPg fvESg vzAny vzRsAnyToCons vzRsAnyToProv vzRsAnyToConsIf vzInTerm vzOutTerm vzTaboo fvRsProtBy vzRsSubjGraphAtt` | Optional: complete policy evaluation (`adm_aci_policy_complete=1`) |

### Complete single-line `apic_arguments` (recommended non-policy-complete baseline)

```text
topSystem compVm compHv fvCEp fvRsCEpToPathEp fvRsCons fvRsProv fvRsVm fvRsHyper fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet fvRsBd fvBD fvRsCtx fvCtx l1PhysIf ethpmPhysIf l3EncRtdIf compHpNic compVNic hvsAdj isisAdjEp coopEpRec acllogPermitL3Pkt acllogDropL3Pkt
```

### Example HF `local/inputs.conf` for Cisco DC Networking 2.0.10

```ini
[cisco_nexus_aci://stats_fvcep]
apic_account = <ACI account>
apic_input_type = stats
apic_arguments = fvCEp
interval = 300
index = cisco_dc
disabled = 0

[cisco_nexus_aci://classInfo_adm_core]
apic_account = <ACI account>
apic_input_type = classInfo
apic_arguments = topSystem compVm compHv fvCEp fvRsCEpToPathEp fvRsCons fvRsProv fvRsVm fvRsHyper fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet
interval = 300
index = cisco_dc
disabled = 0

[cisco_nexus_aci://classInfo_adm_network]
apic_account = <ACI account>
apic_input_type = classInfo
apic_arguments = fvRsBd fvBD fvRsCtx fvCtx l1PhysIf ethpmPhysIf l3EncRtdIf
interval = 300
index = cisco_dc
disabled = 0

[cisco_nexus_aci://classInfo_adm_vmm_spine]
apic_account = <ACI account>
apic_input_type = classInfo
apic_arguments = compHpNic compVNic hvsAdj isisAdjEp coopEpRec
interval = 300
index = cisco_dc
disabled = 0
```

### Verify ACI 2.0.10 ingestion

```spl
`adm_index_dcn` sourcetype="cisco:dc:aci:class" | stats count by component
`adm_aci_bd_vrf_map` | head 20
```

Confirm `fvRsCtx`, `fvBD`, `fvRsBd`, `fvCtx`, and `vzRsSubjFiltAtt` all appear, and that `adm_aci_bd_vrf_map` returns EPG → BD → VRF rows for your tenant.

---

## 2. Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)

### Official `appdynamics_topology` input schema

The unmodified Splunk Add-on for AppDynamics 3.3.0 ships the modular input `[appdynamics_topology://<name>]`, emitting `sourcetype=appdynamics_topology` (`source=appdynamics_topology`, `schema_version=1`, `source_system=appdynamics`).

| `record_type` | `entity_kind` / `relationship_type` | Covered by official input? | Notes |
| --- | --- | --- | --- |
| `entity` | `application`, `tier`, `node`, `backend` | **Yes** | Hierarchy and backend targets (`entity_id`, `application_id`, `tier_id`, `backend_type`, `machine_id`) |
| `entity` | `server`, `network_interface` | **Only when SIM is licensed** | Carries `ipv4_addresses`, `ipv6_addresses`, `mac_address`, `server_id` |
| `relationship` | `contains`, `uses`, `runs_on`, `has_interface` | **Yes** | Links app → tier → node → server → network_interface and tier/node → backend |

### Node IP boundary (critical)

Official `appdynamics_topology` `node` entities emit `machine_id` and `properties`, **not** IP addresses. Supply node IPs through one of two supported paths:

1. **AppDynamics Server Visibility (SIM) licensed:** Enable SIM collection in `appdynamics_topology`. Atlas's `adm_appdynamics_topology_entities` macro and `tools/appdynamics_topology.py` automatically join `node.machine_id` (and `runs_on` relationships) to `network_interface.ipv4_addresses` / `ipv6_addresses` and tag those rows `ip_source=sim_network_interface`.
2. **Without SIM (external HEC collector):** Run Atlas's read-only external collector (`tools/export_appdynamics.py` → `tools/import_appdynamics.py` → `tools/hec_delivery.py`) as documented in [appdynamics-evidence.md](appdynamics-evidence.md). That delivers `source=appdynamics_inventory` and `source=appdynamics_asset_history` (`adm:asset_history`) over HEC with full node IPs from the Application Model XML API — without modifying `Splunk_TA_AppDynamics`.

### Configure Atlas for official `appdynamics_topology`

1. Install unmodified **Splunk Add-on for AppDynamics 3.3.0** (Splunkbase 3471) on the HF and configure an `appdynamics_topology` input targeting your chosen index (default `appdynamics`).
2. Set macro `adm_index_appdynamics_topology` to that literal index (e.g., `index=appdynamics`).
3. Inspect indexed events for `schema_version=1`, `controller_id`, `snapshot_id`, `observed_ts`, and SIM interface coverage; then set `adm_appdynamics_topology_schema_qualified=1`.
4. Verify with:

```spl
`adm_appdynamics_topology_entities` | stats count by entity_kind ip_source
```

---

## 3. Migrating away from historical modified vendor TAs

Atlas's **Admin → Setup** and **Admin → Data health** pages automatically detect:

1. Installed custom input stanzas `atlas_aci_snapshot` (in `cisco_dc_networking_app_for_splunk`) or `atlas_appdynamics_inventory` (in `Splunk_TA_AppDynamics`) via Splunk REST.
2. Recent (7-day) indexed events from modified builds (`sourcetype=adm:aci_poll:v1`, `sourcetype=adm:aci_poll:v2`, `source=atlas:aci_poll`, or `source=atlas_appdynamics_inventory*`) via `` `adm_health_modified_vendor_tas` ``. External HEC delivery (`source=appdynamics_inventory`) is **not** flagged.

To clear the warning:

1. Disable `atlas_aci_snapshot` and/or `atlas_appdynamics_inventory` on the HF.
2. Replace the modified TA package on the HF (and search tier if installed there) with the official unmodified Splunkbase package (`7777` version `2.0.10`, `3471` version `3.3.0`).
3. Configure the official inputs documented above and confirm readback.
4. Historical events age out of the 7-day `adm_health_modified_vendor_tas` lookback automatically.
