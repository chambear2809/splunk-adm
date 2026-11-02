# Configuration change product and feature coverage

Research baseline: October 27, 2026, checkout `ca91cb8b1a8c6c4da72c215e2820eb514a0785ad`. This register supports the [execution prompt](CHANGE_CORRELATION_EXECUTION_PROMPT.md). It separates concrete collection evidence from features the implementation must research, build and qualify. None of the proposed cross-product change stories is asserted to be implemented or live-qualified here.

## Coverage standard

“Full coverage” means every named product and feature below has an explicit evidence-backed disposition: collected and supported; available but requiring setup; requiring a new collection/normalization path; or unsupported with a concrete reason. It does not mean every feature of every vendor product is supported. Extend the register when primary research discovers a relevant feature; do not silently narrow it to convenient feeds.

For each feature, maintain collection, normalization, history, attribution, UI/export, synthetic tests, installed tests, demo and live qualification as separate fields. Record exact versions, source citations, sample provenance and uncertainty. A fixture passing a parser does not qualify collection or effective policy enforcement.

The reviewed package versions are in [the manifest](../research/package-manifest.json): DC Networking 1.2.2; Enterprise Networking TA 4.0.60; Cisco NetFlow TA 4.0.0; Meraki TA 3.5.0; Security Cloud 3.7.2; AppDynamics TA 3.2.1; ThousandEyes 0.9.0; Stream App/Wire Data 8.1.6; OTel host TA 0.162.0 and Kubernetes chart 0.161.0. Recheck versions and behavior during implementation. Older high-level research documents are not exhaustive inventories of those packages.

## Priority source research and acceptance

### ACI

**Verified starting point:** DC Networking's configurable class collector can retrieve audit and managed objects. Its README/default inputs include `aaaModLR`, endpoint/attachment classes and policy families. Atlas already stores bounded VLAN/BD history; `adm_aci_policy_build` retains one row per APIC host/object DN rather than policy versions. Its graph avoids using later policy rows for older windows. See [data layer](DATA_LAYER.md), [package analysis](TA_PACKAGE_ANALYSIS.md), [ESG/SGT evidence](ESG_SGT_EVIDENCE.md), and the ignored package's `README.md`/`default/inputs.conf`.

**Feature inventory:** user audit; endpoint/VM/attachment change; EPG membership and EPG-to-BD relation; VLAN and BD context; BD-to-VRF relationship when actually collected; consumer/provider contract relations; subject/filter/entry ports/protocol/action; preferred group and enforcement settings; unsupported ESG/taboo/service-graph/vzAny constructs; explicit deployment/operational evidence where available.

**Acceptance:** version complete policy/object state; associate only supported relationships with observed dependencies; distinguish audit, observed membership and configured selectors; show varying/gapped historical context. Do not infer VRF from a name, map `pcTag` to SGT, or expand policy evaluation beyond implemented semantics. [Cisco audit semantics](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/all/faults/guide/b_APIC_Faults_Errors/b_IFC_Faults_Errors_chapter_010.pdf) distinguish configuration audits from other operational events.

### NX-OS, Nexus Dashboard and Orchestrator

**Verified starting point:** DC Networking collects NX-OS version/inventory/interface/CDP snapshots and exposes generic NX-API CLI/DME collection. ND has flows, incremental endpoints, inventory, anomalies and congestion. Its input configuration includes Orchestrator `mso_audit_user`, `mso_fabric_policy`, and `mso_tenant_site_schema`. Input presence establishes a collection path, not current NDO API compatibility or full fabric history. See [package analysis](TA_PACKAGE_ANALYSIS.md) and `research/extracted/cisco-dc-networking_122/cisco_dc_networking_app_for_splunk/default/inputs.conf`.

**Feature inventory:** durable chassis/interface identity; ifIndex mapping; admin/oper state; VLAN/VRF and port-channel membership; neighbor/attachment changes; routing/BGP changes where supported; device/software revisions; ND endpoint lifecycle and anomalies; NDO audit/schema/policy revisions. Determine which require custom collection or a separate syslog/configuration source. Full running-configuration diffs are not established by the reviewed default show-command inputs.

**Acceptance:** distinguish configured intent from operational changes, retain native scope/time, preserve incremental endpoint deletion semantics and topology gaps. A configured neighbor or route does not establish actual packet traversal. Qualify reordered/paginated snapshots and interface renumbering. NDO support must identify exact controller/API versions rather than relying on the historical MSO input name.

### Catalyst SD-WAN

**Verified starting point:** `cisco_catalyst_sdwan_audit_logs` emits `cisco:sdwan:audit:logs`. Optional `audit_log_details` and `config_difference` settings enable decoded `audit_config_before`/`audit_config_after` when source detail supports them; both default to off. Separate inputs cover health, site/tunnel health, insecure-configuration findings and selected realtime/API context. Enhanced NetFlow is a separate traffic source.

**Feature inventory:** template edits/attachments; centralized/local policy changes; device/feature-template revisions; deployment/action success/failure; site/VPN/device relationships; routing, transport, application-aware-routing and QoS changes where exposed; tunnel/health transitions; exporter/sampling changes; before/after detail completeness and retention.

**Acceptance:** preserve Manager authority and native action/device/policy IDs; separate audit action from applied state; require qualified affected-site/VPN relationships. Do not translate retained overlay-session IDs into TLOC or ordered tunnel paths. See [packaged audit collector](../research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/bin/cisco_catalyst_sdwan_audit_logs.py), [networking qualification](CISCO_NETWORKING_QUALIFICATION.md), and [Cisco audit logging](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/26x-later/network-monitoring/network-monitoring-guide/sys-and-network-logs/audit-logging.html).

### Meraki

**Verified starting point:** dedicated audit input calls `getOrganizationConfigurationChanges`, emitting `meraki:audit`. Association, inventory and availability history are separate evidence. Custom API catalog entries include Adaptive Policy groups and topology discovery; catalog presence does not enable a collector automatically.

**Feature inventory:** organization/network/device change identity; SSID configuration; VLAN/access/trunk configuration; firewall/group-policy revisions; Adaptive Policy groups and required IP mappings; uplink/site-to-site VPN changes if returned; device/client assignment; firmware and availability events; actor/time and old/new-value completeness; configuration-template fan-out to affected networks.

**Acceptance:** join audit resources to the correct organization/network/device/SSID before attaching client/application impact. Preserve association/IP reuse ambiguity. Keep availability transitions and wireless association events distinct from configuration changes. Verify the documented payload actually identifies changed resources before emitting field-specific claims. See [Meraki evidence](../research/cisco-meraki-evidence.json), [networking operator guide](operators/cisco-enterprise-networking.md), [ESG/SGT evidence](ESG_SGT_EVIDENCE.md), and [configuration changes API](https://developer.cisco.com/meraki/api-v1/get-organization-configuration-changes/).

### Catalyst Center

**Verified starting point:** dedicated `cisco_catalyst_dnac_audit_logs` input emits `cisco:dnac:audit:logs`; client, device, site/topology, software/image and event inputs are separate. Current client snapshots provide observed attachment context, not historical attachment start times. See [Catalyst evidence](../research/cisco-catalyst-evidence.json) and the TA's `default/inputs.conf`.

**Feature inventory:** controller audit actions and task status; provisioning/template pushes; device/site/network-profile changes; software activation; interface/client attachment and VLAN changes; network-device identity; compliance changes versus actual configuration differences; supported wireless configuration where relevant; historical device/port/site bindings.

**Acceptance:** correlate task/resource/device references and compatible client snapshots, retaining receipt and source-update time separately. Audit activity is not necessarily an entire device diff or proof of deployment success. Generic topology API availability does not establish complete physical links. [Cisco audit API](https://developer.cisco.com/docs/catalyst-center/2-3-7-5/get-auditlog-records/) is a source contract to compare with the exact deployed version.

### FMC and FTD

**Verified starting point:** three separate paths matter: `cisco:sfw:estreamer` connection records; selected firewall syslog; and `sbg_sfw_api_input`/`cisco:sfw:policy` policy polling. The inspected FMC collector lists/fetches access, intrusion and file policy objects, then uses Splunk `| delete` on older matching events during refresh. This removes their search visibility; do not describe it as an immutable historical archive or physical index erasure. Full access-rule children, NAT rule sets, referenced object contents and deployment history are not established by this policy-object polling loop.

**Feature inventory:** policy/object/rule identity and revisions; access-rule order/action/ports/protocol/zones; referenced network/service groups; NAT configuration; intrusion/file policy changes; audit actor/time; deployment version/targets/status and partial failures; device/rule-linked connection verdicts; same-event translated tuples; HA identity and duplicate reports.

**Acceptance:** design append-only evidence preservation without modifying vendor archives or weakening vendor permissions. Validate collection completeness before claiming rule/policy evaluation. An FMC edit and FTD application can differ in time. NAT configuration can identify candidates; actual translation evidence remains source-specific and does not select a Cilium backend. V2 must preserve needed FTD evidence before the combined Meraki track depends on it. See [policy collector](../research/extracted/cisco-security-cloud_372/CiscoSecurityCloud/bin/CiscoSecurityCloud/fmc_api/collect_events.py), [FTD operator guide](operators/firewall-security.md), [data layer](DATA_LAYER.md), and [FMC audit/deployment API families](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html).

### Kubernetes and Cilium or Isovalent

**Verified starting point:** configured Kubernetes object watches supply Pods, Services, EndpointSlices, Nodes, Ingresses, Gateways and HTTPRoutes; initial state is required. Hubble and Isovalent provide traffic/process evidence, not a universal Cilium configuration audit. The chart's stock object list and Atlas's operator list differ; selected resource kinds and RBAC must be explicit.

**Feature inventory:** Service selectors/ports/traffic policy; EndpointSlice readiness and backend membership; Pod rollout/replacement/labels; Ingress/Gateway/HTTPRoute changes; standard NetworkPolicy; version-specific CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy; supported BGP/L2 announcement resources; LB mode, masquerading and native/tunnel mode; policy revision/application evidence; watch reconnect/resourceVersion gaps; actor from Kubernetes audit when separately collected.

**Acceptance:** use cluster/namespace/UID identity and explicit lifecycle events. Do not infer historical deployment configuration from current Helm values or policy enforcement from a resource object. Do not collect Secret payloads to explain a rollout. Match Hubble verdicts and backend selection only under existing supported evidence rules. See [platform setup](operators/kubernetes-platform.md), [Cilium setup](operators/cilium-isovalent.md), [data layer](DATA_LAYER.md), and [proxy boundaries](PROXY_EVIDENCE_DESIGN.md).

### AppDynamics

**Verified starting point:** TA 3.2.1 includes `appdynamics_audit`; `ControllerService.get_audit_logs` calls `/controller/ControllerAuditHistory` and preserves Controller authority. Atlas has a separate current Application Model inventory importer/panel. Current node address snapshots do not establish historical ownership intervals. Existing TA backend status is application-scoped and is not a complete node/IP binding dataset.

**Feature inventory:** application/agent configuration audit; instrumentation and transaction-discovery changes; backend-discovery rules; tier/node/model changes; health-rule/alert changes; release/deployment markers only if explicitly emitted; application performance/call coverage; same-Controller stable application/tier/node IDs.

**Acceptance:** separate actual application changes from changed monitoring/discovery semantics. Do not present Controller configuration audit as a complete application deployment log. Establish historical model bindings before using them for historical attribution. See [AppDynamics design](APPDYNAMICS_EVIDENCE_DESIGN.md), [packaged audit call](../research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/bin/controller_service.py), and [official audit report](https://help.splunk.com/en/appdynamics-saas/get-started/26.4.0/getting-started/controller-tenant-overview-and-administration/saas-deployment-audit-log/retrieve-the-audit-log-report).

### ThousandEyes

**Verified starting point:** activity is an OTel log stream, not a polling input. Metrics, synthetic traces, detected events, alerts and paths have separate identities/time bases. Activity resources and user attributes do not guarantee a test or agent ID. Atlas already has bounded optional evidence and comparison contracts; reuse them.

**Feature inventory:** test creation/edit/delete; target/protocol/port/interval changes; agent assignment/location; alert-rule changes; stream configuration; account/resource mapping; metric units/aggregation/configuration version; path changes and event lifecycle; CEA versus Endpoint identity; applicable API/trace support limits.

**Acceptance:** require explicit resource resolution before associating an activity with a test/application. Use only comparable before/after measurements and make a changed measurement configuration visible. A synthetic probe path is the probe's path, not the customer's passive traffic path. See [package research](research/thousandeyes.md), [capabilities](research/thousandeyes-capabilities.md), [design](THOUSANDEYES_DESIGN.md), and [official activity semantics](https://docs.thousandeyes.com/product-documentation/user-management/user-activity/working-with-the-activity-log).

## Other existing sources

| Source | Required coverage disposition |
| --- | --- |
| ISE / TrustSec | Dedicated Data Connect catalog includes `CHANGE_CONFIGURATION_AUDIT`; SGT definitions, SXP bindings and session/context observations are separate. Research policy changes, authorization/session lifecycle and authority-scoped tags. Preserve checkpoint/removal/expiry uncertainty. See [ESG/SGT evidence](ESG_SGT_EVIDENCE.md). |
| Secure Workload | Reviewed integration is syslog alert/policy context. Full workload-label, segmentation-policy and deployment history need a qualified API/export. Do not claim existing TA polling of those datasets. |
| Secure Network Analytics | Reviewed inputs poll insights/reporting, selected top flows, performance and alarms, with application/tag enrichment. Research host-group/classification changes and audit availability separately; summaries are not full configuration or connection history. |
| Secure Client NVM | Process/user flow context exists in the reviewed Security Cloud package. No configuration-audit history was established. Keep this outside the two required tracks unless a concrete customer story and source contract justify it. |
| Stream and OTel | Exporter templates, sampling, collector filters, routing, resource-tag enrichment and receiver configuration affect visibility. Establish a configuration/deployment evidence source; traffic/span output alone does not provide one. |
| Splunk Observability Cloud | Existing health capture and detector-event export can corroborate behavior; the detector-event exporter explicitly does not read detector definitions. Research detector/configuration revisions separately before explaining monitoring changes. |
| DNS, Envoy/proxy and asset history | Use existing optional contracts for same-scenario context. DNS answers do not establish backend selection; proxy legs need native evidence; current asset snapshots do not create historical ownership. Each optional source must fail independently. |
| AWS VPC flow evidence | Retain its existing observation contract and explicit coverage/status. Configuration audit would require a separately scoped source; flow logs do not establish security-group/route change history. AWS infrastructure changes remain outside this task's live mutation authority. |

## Cross-product feature checklist

- Native audit and semantic snapshot differences coexist without duplicate change inflation.
- Configuration edits, deployment/application results, operational state and telemetry changes have distinct meanings and labels.
- Historical identity and configuration are resolved at the selected time, including change-overlapping windows and late data.
- Changes are associated through explicit authority/object/scope/time relationships, with inclusion/exclusion reasons.
- Potential impact stays bounded to observed dependencies and coverage; supported policy interpretation is separated from observed traffic verdicts.
- Before/after behavior is comparable in source, configuration, units, aggregation and interval.
- Permission loss, collector failure, partial snapshots, input/output caps, retention gaps and schema changes remain visible.
- Timeline, graph/endpoint selection and exports carry the same source/time/uncertainty context.
- Source enablement, retention, migration, capacity and rollback are documented and tested.
- Across the two tracks, every priority product has a meaningful primary or required-variant change; each track covers its assigned products. AppDynamics and ThousandEyes monitoring-change controls are required in both, along with controls that prevent false causal conclusions.

## Evidence to retain at handoff

Each source owner supplies a capability table, primary citations, exact package/input code references, sanitized schemas/examples, golden and negative fixtures, test outcomes, configured versus effective-time limitations, and collection/retention estimates. The orchestrator reconciles these against the UI and demo claims. Unverified live fields remain explicit qualification requirements; they are never filled with invented vendor data.
