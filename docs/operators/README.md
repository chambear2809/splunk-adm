# Application Atlas operator guides

Index for operators. Support targets: **Splunk Cloud Platform** and **Splunk Enterprise 10.6+**. Configure only the sources you select; see [deployment options](deployment-options.md). Ordered runbook: [splunk-setup-guide.md](splunk-setup-guide.md).

## Reference topology

| Tier | Runs | Does not run |
| --- | --- | --- |
| Splunk Cloud search tier | Application Atlas (`splunk_adm`), search-time TAs, indexes (ACS), HEC tokens | Modular inputs. Leave every vendor input there disabled. |
| Heavy forwarder (HF) | All modular inputs: DC Networking (ACI/ND/NX-OS), Stream forwarder (NetFlow/IPFIX receiver), Intersight, VMware (DCS + DCN), Security Cloud eStreamer | Atlas, Atlas searches |
| Kubernetes | Splunk OTel Collector (Helm) → HEC on Cloud | — |
| Enterprise (on-prem) | Same split; search head replaces the Cloud search tier, indexes via `indexes.conf` | — |

Cloud indexes: [`splunk-cloud-acs-admin-setup`][s-acs]. HEC: [`splunk-hec-service-setup`][s-hec]. Restarts: [`splunk-platform-restart-orchestrator`][s-restart].

## Data-source matrix

Versions are the inspected pins in [`research/package-manifest.json`](../../research/package-manifest.json). Index = default; change the matching `adm_index_*` macro if yours differs.

| Source | TA / app (version) | Install | Index / sourcetype | Atlas uses it for | Skill | Runbook |
| --- | --- | --- | --- | --- | --- | --- |
| ACI / APIC | Cisco DC Networking 1.2.2 (7777) | HF inputs; Cloud search-time | `cisco_dc` (`adm_index_dcn`) / `cisco:dc:aci:class`, `cisco:dc:aci:stats` | Endpoints, EPG/BD, fabric topology, contracts, ACL log, VMM/vSphere ports and uplinks, spine evidence | [`cisco-dc-networking-setup`][s-dcn] | [aci-network](aci-network.md), [VMM classes](ACI_VMM_ADJACENCY_CLASSES.md), [spine evidence](ACI_SPINE_PATH_EVIDENCE.md) |
| Nexus Dashboard | DC Networking 1.2.2 | HF inputs | `cisco_dc` / `cisco:dc:nd:flows`, `cisco:dc:nd:endpoints` | Fabric flow observations, endpoint history | [`cisco-dc-networking-setup`][s-dcn] | [aci-network](aci-network.md#nexus-dashboard-inputs) |
| NX-OS (NX-API) | DC Networking 1.2.2 | HF inputs | `cisco_dc` / `cisco:dc:nexus9k` | Device names, ifIndex → interface, CDP links | [`cisco-dc-networking-setup`][s-dcn] | [aci-network](aci-network.md) |
| NetFlow v9 — ACI leaves | Stream Forwarders 8.1.3 (HF); Stream App 8.1.6 + Wire Data 8.1.6 (search tier) | HF receiver | `netflow` / `stream:netflow` | Observed conversations; leaf + ingress port "Seen". V2 profile `aci_leaf_netflow` | [`splunk-stream-setup`][s-stream] | [network-stream](network-stream.md) |
| IPFIX — VMware VDS (ESXi) | Same Stream packages | HF receiver | `netflow` / `stream:netflow` | VDS hop "Seen" on path trace and Device page. V2 profile `vmware_vds_ipfix` | [`splunk-stream-setup`][s-stream] | [network-stream](network-stream.md#vmware-vds-ipfix) |
| IPFIX — Catalyst / SD-WAN / Meraki MS390 | Same Stream packages; Enterprise Networking NetFlow Add-on 4.0.0 | HF receiver | `netflow` / `stream:netflow` | V2 traffic observations. Profiles `catalyst_campus_fnf`, `catalyst_sdwan_ipfix`, `meraki_ms390_ipfix` | [`cisco-catalyst-enhanced-netflow-setup`][s-cefn] | [cisco-enterprise-networking](cisco-enterprise-networking.md) |
| Catalyst Center | Enterprise Networking Add-on 4.0.60 + App 4.0.20 | HF inputs | `cisco_catalyst` / `cisco:dnac:client` | V2 wired-client identity | [`cisco-catalyst-ta-setup`][s-cat] | [cisco-enterprise-networking](cisco-enterprise-networking.md) |
| Meraki | Meraki Add-on 3.5.0 | HF inputs | `cisco_meraki` / `meraki:accesspoints` | V2 wireless association | [`cisco-meraki-ta-setup`][s-mer] | [cisco-enterprise-networking](cisco-enterprise-networking.md) |
| Kubernetes objects + traces | Splunk OTel Collector for Kubernetes, Helm 0.161.0 | Cluster → HEC | `k8s` / `kube:object:*`; `otel_traces` / `otel:traces` | Pod/Service/Node identity history, service calls | [`splunk-observability-otel-collector-setup`][s-otel] | [kubernetes-platform](kubernetes-platform.md), [application-teams](application-teams.md) |
| Cilium / Hubble flows | OTel Collector file tail | Cluster → HEC | `cilium_hubble` / `cilium:hubble:flow` | Pod flows, Service → backend handoff | [`cisco-isovalent-platform-setup`][s-iso], [`splunk-observability-isovalent-integration`][s-isoint] | [cilium-isovalent](cilium-isovalent.md) |
| Isovalent Runtime Security | Cisco Security Cloud 3.7.2 (7404) | HEC; app on search tier (index-time rename) | `cisco_isovalent` / `cisco:isovalent:processConnect` | Process connection evidence | [`cisco-security-cloud-setup`][s-scc] | [cilium-isovalent](cilium-isovalent.md) |
| FMC / FTD | Cisco Security Cloud 3.7.2 | HF eStreamer input | `cisco_secure_fw` / `cisco:sfw:estreamer` | Firewall observations, same-event NAT | [`cisco-security-cloud-setup`][s-scc] | [firewall-security](firewall-security.md) |
| AppDynamics | Atlas importer (`tools.import_appdynamics`); AppD Add-on 3.3.0 | Operator host → HEC | `adm_index_appdynamics_inventory` (unset) / `adm:appdynamics_inventory` | Node/IP inventory, backend candidates | [`cisco-appdynamics-setup`][s-appd] | [appdynamics-evidence](appdynamics-evidence.md) |
| ThousandEyes | ThousandEyes App 0.9.0 (7719) | Vendor app | `thousandeyes` / `cisco:thousandeyes:*` | Synthetic tests, measured paths (optional) | [`cisco-thousandeyes-setup`][s-te] | [thousandeyes](thousandeyes.md) |
| VMware vCenter | Splunk Add-on for VMware 4.2.1 + SA-Hydra 4.3.0 (3215); VMware Extractions 4.0.4 (5641) on search tier | HF (DCS + DCN). Not ACS self-service on Cloud | `vmware-inv`, `vmware-perf`, `vmware-taskevent` / `vmware:inv:*`, `vmware:perf:*` | VDS port keys and vmnic uplink names (`adm_interface_names`). vSphere topology itself comes from APIC VMM classes | [`splunk-vmware-ta-setup`][s-vmw] | [lab setup](INTERSIGHT_VMWARE_LAB_SETUP.md) |
| VMware ESXi logs | ESXi Logs 4.2.2 (5603) | Syslog | syslog sourcetypes | **Not used**; no topology value. Skip | — | — |
| Cisco Intersight (UCS FI, adapter vNIC, ports) | Intersight Add-on 3.2.2 (7828) on HF; 3.1.1 on Cloud 10.6 | HF inputs | `intersight` / `cisco:intersight:*` | **Not consumed yet**. The FI hop comes from APIC `hvsAdj`/`lldpAdjEp`; Intersight vNIC MACs are planned to pin vmnic ↔ FI port | [`cisco-intersight-setup`][s-int] | [lab setup](INTERSIGHT_VMWARE_LAB_SETUP.md) |
| DNS (Stream / Hubble L7) | Stream App 8.1.6; Hubble | HF / cluster | `adm_index_dns_stream` (unset) / `stream:dns` | Optional resolution evidence | [`splunk-stream-setup`][s-stream] (platform only) | [dns-evidence](dns-evidence.md) |
| Envoy access logs | Customer producer | HEC | `adm_index_proxy_envoy` (unset) / `atlas:proxy:envoy_access` | Optional request evidence | — | [proxy-evidence](proxy-evidence.md) |
| AWS VPC Flow Logs | AWS add-on | Vendor input | `adm_index_aws_vpc_flow` (unset) | Optional cloud flow evidence | [`splunk-aws-ta-setup`][s-aws] (platform only) | [aws-vpc-flow-evidence](aws-vpc-flow-evidence.md) |
| Observability Cloud health / detectors | Atlas exporters | Operator host → HEC | `adm_index_o11y_health`, `adm_index_o11y_detector_events` (unset) | Optional health evidence | — | [o11y-health](o11y-health.md), [o11y-detector-events](o11y-detector-events.md) |
| Asset history (CMDB/IPAM export) | Atlas importer | Operator host → HEC | `adm_index_asset_history` (unset) / `adm:asset_history` | Optional ownership history | — | [asset-history](asset-history.md) |

"Unset" = macro defaults to `index=unconfigured_*` until the administrator sets it.

## Required ACI classes

All on the HF, `apic_input_type = classInfo` unless noted, interval 300 s, index `cisco_dc` (or your `adm_index_dcn`).

| Input | Classes Atlas reads | Status |
| --- | --- | --- |
| `stats` (shipped, `stats` type) | `fvCEp` (+ `fvIp`, `fvRsCEpToPathEp` children) | Required |
| `classInfo_faultInst` (shipped) | `topSystem compVm compHv fvCEp fvRsCons fvRsProv fvRsVm fvRsHyper` | Required |
| `classInfo_fvRsCEpToPathEp` (shipped) | `fvRsCEpToPathEp acllogPermitL3Pkt acllogDropL3Pkt` | Required (ACL log optional) |
| `classInfo_adm` (custom) | `fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet` | Required |
| `classInfo_adm` (custom, extension) | `compHpNic compVNic hvsAdj` — vSphere host uplinks | Required for vSphere paths ([VMM classes](ACI_VMM_ADJACENCY_CLASSES.md)) |
| `classInfo_adm` (custom, extension) | `isisAdjEp coopEpRec` — spine evidence | Required for spine-hop support ([spine evidence](ACI_SPINE_PATH_EVIDENCE.md)) |
| `classInfo_adm_network` (custom) | `fvRsBd` | Optional: EPG → BD |
| `classInfo_adm_policy` (custom) | `fvCtx fvAEPg fvEPg fvESg vzAny vzRsAnyToCons vzRsAnyToProv vzRsAnyToConsIf vzInTerm vzOutTerm vzTaboo fvRsProtBy vzRsSubjGraphAtt` | Optional: "no permitting contract" (`adm_aci_policy_complete=1`) |

- The pinned skill's `application-atlas` preset covers only the first eight `classInfo_adm` classes. Pass the full 13-class list with `--classinfo-classes`.
- `compVNic` is collected but not read yet.
- Spines cannot export NetFlow (APIC 6.1). Spine hops are inferred and labelled with their evidence; never "Seen".

Full list for `classInfo_adm`:

```text
fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet compHpNic compVNic hvsAdj isisAdjEp coopEpRec
```

## Source-scope profile registration

Applies to the V2 contract (`adm_flows_netflow_v2`, staged) and source-qualified VDS matches: each NetFlow/IPFIX exporter must map to exactly one profile and scope, or its flows stay `unmapped`. Stored in KV collection `adm_network_source_scope`. V1 readers scope exporters through `adm_observer_scope` `exporter` rows ([routing scope lookup](splunk-platform.md#routing-scope-lookup)); do both. Supported `stream_ipfix` profiles: `standard_netflow`, `aci_leaf_netflow`, `vmware_vds_ipfix`, `catalyst_campus_fnf`, `catalyst_sdwan_ipfix`, `meraki_ms390_ipfix`.

| Profile | `domain_kind` | `observation_domain_present` / `_id` | `vpn_id` | `routing_domain` |
| --- | --- | --- | --- | --- |
| `standard_netflow` | `exporter` | `0` / blank | blank | blank |
| `aci_leaf_netflow` | `exporter` | `1` / required | blank | blank |
| `nexus_nxos_netflow` | `exporter` | `1` / required | blank | blank |
| `vmware_vds_ipfix` | `exporter` | `1` / required | blank | blank |
| `catalyst_campus_fnf` | `exporter` | `1` / required | blank | any |
| `catalyst_sdwan_ipfix` | `exporter` | `1` / required | required | = `vpn_id` |
| `meraki_ms390_ipfix` | `exporter` | `1` / required | blank | blank |

`nexus_nxos_netflow` is for explicitly registered NX-OS exporters (including
spines) when the record carries a non-empty observation domain. It is an
observation profile only: Atlas preserves the tuple and exporter interfaces,
but does not infer adjacent switch hops or packet ordering from NetFlow.

Checklist (administrator):

- [ ] List live exporters: `` `adm_index_netflow` sourcetype=stream:netflow earliest=-15m | stats count by exporter_ip observation_domain_id ``.
- [ ] Build `adm_network_source_scope.csv`, one row per exporter + observation domain: `source=stream_ipfix`, `source_authority=<exporter_ip, lowercase>`, `domain_kind=exporter`, `observation_domain_present`, `observation_domain_id`, `vpn_id`, `routing_domain`, `scope`, `cluster`, `profile`.
- [ ] Use the same `scope` as the ACI/Kubernetes observers that share the routing domain (see [routing scope lookup](splunk-platform.md#routing-scope-lookup)). No fleet-wide default.
- [ ] Upload the CSV to the app (Lookup File Editing or lookup upload).
- [ ] Enable **ADM - Migrate network source scope**, run once from the app (`| savedsearch "ADM - Migrate network source scope"`), then disable it. Expect `blocked=0`, `rows_written` = row count.
- [ ] If `blocked=1`: fix blank, duplicate or conflicting rows; nothing was written.
- [ ] **Admin → Data health**: Stream source scope profiles show `mapped`, not `unmapped`, `ambiguous`, `unsupported` or `incomplete`.
- [ ] Upgrades: run the [IPFIX authority normalization](../UPGRADES.md#ipfix-exporter-authority-normalization) check.

## Team handouts

| Team | Handout |
| --- | --- |
| Splunk platform | [splunk-platform](splunk-platform.md), [splunk-setup-guide](splunk-setup-guide.md), [deployment-options](deployment-options.md) |
| ACI / Nexus | [aci-network](aci-network.md), [ACI_VMM_ADJACENCY_CLASSES](ACI_VMM_ADJACENCY_CLASSES.md), [ACI_SPINE_PATH_EVIDENCE](ACI_SPINE_PATH_EVIDENCE.md) |
| Stream / NetFlow / IPFIX | [network-stream](network-stream.md), [ingest-processors](ingest-processors.md) |
| Campus / Meraki | [cisco-enterprise-networking](cisco-enterprise-networking.md) |
| Kubernetes | [kubernetes-platform](kubernetes-platform.md) |
| Cilium / Isovalent | [cilium-isovalent](cilium-isovalent.md), [qualified-native-network](qualified-native-network.md) |
| Firewall | [firewall-security](firewall-security.md) |
| Application owners | [application-teams](application-teams.md) |
| Observability Cloud | [o11y-health](o11y-health.md), [o11y-detector-events](o11y-detector-events.md), [o11y-navigation](o11y-navigation.md) |
| VMware / UCS | [INTERSIGHT_VMWARE_LAB_SETUP](INTERSIGHT_VMWARE_LAB_SETUP.md) (lab) |

Lab runbooks and records (lab addresses allowed; not deployment contracts): [local-access-and-tenant-jobs](local-access-and-tenant-jobs.md), [INTERSIGHT_VMWARE_LAB_SETUP](INTERSIGHT_VMWARE_LAB_SETUP.md), [netflow-trial-2026-10-31](netflow-trial-2026-10-31.md), [device-path-trial-follow-up](device-path-trial-follow-up.md).

## Using Atlas

| Section | Pages | Needs |
| --- | --- | --- |
| Explore | Applications (catalog, Find), Endpoints, Device (all flows through one device), path-trace form | Identity + flow sources |
| Map | Dependency map (network, services, devices, table); src → dst path trace | Path trace adds ACI topology + VMM/spine classes. Limit 4,000 nodes / 10,000 edges; above that the top N edges are kept (structure, then bytes, then connections) with a warning |
| Multicast | Standalone IPv4 group investigation for sender traffic, IGMP receiver interest, and device-reported forwarding | One verified routing scope, a bounded time window, and an active source profile for the evidence you need. [Multicast operator guide](multicast.md) |
| Admin | Setup, Data health | Admin role for writes; writes ship disabled |

Help is a separate page.

Macros behind path trace and Device: `adm_path_trace`, `adm_path_trace_resolve`, `adm_fabric_path_evidence`, `adm_vsphere_topology`, `adm_vsphere_uplinks`, `adm_device_flows`, `adm_graph_edge_cut`, `adm_graph_edge_limit`. Design: [VSPHERE_SWITCH_DESIGN](../VSPHERE_SWITCH_DESIGN.md).

## Automation skills

Vendored at `vendor/splunk-cisco-skills` (pinned submodule, commit `1c93cd8`). Run from that directory: `cd vendor/splunk-cisco-skills && bash skills/<skill>/scripts/setup.sh --help`. Always `--dry-run` first. Check [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md][s-compat]. Setup in Claude Code / Cursor / Codex: [main README](../../README.md#operator-setup-skills). Mutation through the MCP server stays disabled.

## Minimum data checklist

For application mapping, start with one supported traffic feed that sees the conversation, a verified routing scope, and the endpoint or application you want to investigate. Add sources for the evidence you need. The table lists what to request from each source owner. Use the linked runbook for the full schema and qualification steps.

| What you want to verify | Minimum data to request | Runbook |
| --- | --- | --- |
| Address conversations and exporter observations | NetFlow/IPFIX or Nexus Dashboard flow records with source and destination IPs, ports where applicable, protocol, observation time or flow interval, and exporter or fabric identity. Include bytes, packets, and sampling where reported for volume, and interface IDs for port context. | [Stream](network-stream.md), [Nexus Dashboard](aci-network.md#nexus-dashboard-inputs) |
| Endpoint identity and candidate fabric paths | Endpoint IP, MAC, and attachment in scope, plus switch identities, fabric links, and LLDP or CDP neighbors. Include contract rules for policy, external attachments for L3Out paths, and VMM adjacency for VM paths. To name exported interfaces, include exporter-scoped ifIndex mappings. | [ACI and NX-OS](aci-network.md), [Splunk interface lookup](splunk-platform.md) |
| Observed VMware VDS hop | VDS IPFIX from the ESXi management address, the observation domain and `vmware_vds_ipfix` profile, and matching ACI VMM attachment data. Include host uplink and VM distributed-port keys when interface names are needed. | [VMware VDS IPFIX](network-stream.md#vmware-vds-ipfix) |
| Workload identity and service calls | Kubernetes Pod, Node, and Service history with the initial state, cluster identity, stable UIDs, IPs, and changes or deletions. Add EndpointSlices for backend attribution. For service calls, include OpenTelemetry service and pod identity, trace/span/parent IDs and span times. Add CLIENT peer IP, destination port, and pod UID to correlate calls with traffic. | [Kubernetes](kubernetes-platform.md), [Application teams](application-teams.md) |
| Pod handoffs or firewall observations | For Hubble, include the flow timestamp, cluster/node, IP and transport tuple, verdict, direction, and observation point. Include translation and Layer 7 handoff fields when attributing a backend. For FTD, include the device, initiator and responder tuple, protocol, and first-packet time. Include a complete same-event translation tuple for NAT attribution. | [Cilium and Isovalent](cilium-isovalent.md), [Firewall](firewall-security.md) |
| IPv4 multicast | Match the evidence to the question. For receiver interest, request indexed IGMP records and a verified sensor/interface-to-segment mapping. For sender traffic, request multicast flow tuples and the verified exporter, observation domain, template, direction, sampling, and replication context. For forwarding branches, request scoped NX-OS route snapshots with matching interfaces and adjacency evidence. | [Multicast](multicast.md) |

Ask each source owner to provide:

- [ ] An owner, product and add-on versions, collection cadence and expected delay, required jobs, and known gaps. Record any intentionally omitted sources.
- [ ] The index, sourcetype, expected event timestamp, and fields the investigation depends on. Verify the fields and timestamps in Splunk using the intended reader role.
- [ ] Observer-to-routing-scope and exporter-to-profile mappings as applicable. Include the relevant address ranges, VLANs or VNIs, VRFs, attachments, and any overlapping address space. [Routing scope lookup](splunk-platform.md#routing-scope-lookup) · [Source-scope profiles](#source-scope-profile-registration)
- [ ] A representative sanitized sample for each new sourcetype, covering about one hour when available. For a point-in-time source, provide a complete snapshot with its capture time and provenance. [Data handling](#data-handling)

## Data handling

Flows and traces contain internal IPs, host/pod names and, for Hubble L7 and spans, HTTP paths and headers. Redact per handout. Never put tokens or passwords in tickets, chat or docs; use your secret manager.

## Optional evidence and endpoint/service investigations

DNS, Envoy, AWS VPC Flow Logs, asset history, AppDynamics, ThousandEyes and Observability Cloud stay unselected by default. Each handout defines its producer schema, index, scope mapping and qualification limits. Shared rules: [SUPPLEMENTAL_EVIDENCE_CONTRACT](../SUPPLEMENTAL_EVIDENCE_CONTRACT.md). DNS gates: [DNS_EVIDENCE_QUALIFICATION](../DNS_EVIDENCE_QUALIFICATION.md).

[s-compat]: https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md
[s-acs]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-cloud-acs-admin-setup
[s-hec]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-hec-service-setup
[s-restart]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-platform-restart-orchestrator
[s-dcn]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-dc-networking-setup
[s-stream]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-stream-setup
[s-cefn]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-catalyst-enhanced-netflow-setup
[s-cat]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-catalyst-ta-setup
[s-mer]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-meraki-ta-setup
[s-otel]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-otel-collector-setup
[s-iso]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-isovalent-platform-setup
[s-isoint]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-isovalent-integration
[s-scc]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-security-cloud-setup
[s-appd]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-appdynamics-setup
[s-te]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-thousandeyes-setup
[s-vmw]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-vmware-ta-setup
[s-int]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-intersight-setup
[s-aws]: https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-aws-ta-setup
