# TA Package Inspection and Data Coverage

## Inspection status

Nine archives have been downloaded and inspected as files. Archives live under `research/packages/`; extracted configuration/source files are under `research/extracted/`. These local artifacts are ignored by Git. Versions, provenance, computed SHA-256 hashes, and pending packages are recorded in [the manifest](../research/package-manifest.json).

| Package | Inspected version | Artifact source |
| --- | --- | --- |
| Splunk Add-on for Stream Wire Data | 8.1.6 | Public mirror linked in Splunk's `security_content` configuration |
| Splunk Add-on for Stream Forwarders | 8.1.3 | Same officially referenced mirror; newer deployments require matching-version inspection |
| Splunk App for Stream | 8.1.6 | Authenticated Splunkbase download; publisher digest verified |
| Cisco Splunk Add-on for AppDynamics | 3.2.1 | Same officially referenced mirror |
| Splunk Add-on for OpenTelemetry Collector, Linux x86_64 | 0.162.0 | Publisher's GitHub release; local SHA-256 matches its release digest |
| Cisco Security Cloud | 3.6.5 and 3.7.2 | Mirror baseline plus authenticated Splunkbase 3.7.2 download; 3.7.2 publisher digest verified |
| Cisco DC Networking | 1.2.2 | Authenticated Splunkbase download; local SHA-256 matches the displayed publisher digest |
| Splunk OpenTelemetry Collector for Kubernetes (Helm chart) | 0.161.0 | Publisher's GitHub release; local SHA-256 matches its release digest; rendered statically with `helm template` only |

The mirror references come from [Splunk's package configuration](https://github.com/splunk/security_content/blob/b3eabf7af2e7f556838b18b3c08b07e33f058c50/contentctl.yml). OTel comes from [the publisher release](https://github.com/signalfx/splunk-otel-collector/releases/tag/v0.162.0); DC Networking comes from [its Splunkbase listing](https://splunkbase.splunk.com/app/7777). DC Networking extraction retains regular static source/configuration files up to 5 MB and excludes symlinks and executables. No add-on was installed and no downloaded scripts or collector binaries were executed. Package inspection identifies extraction and collection behavior; representative events are still required to verify which fields the deployed sources actually emit.

## Stream: flow timing and endpoint normalization

Base: `research/extracted/splunk-add-on-for-stream-wire-data_816/Splunk_TA_stream_wire_data/`.

- `default/props.conf:4` defines the common `source::stream:*` JSON parsing configuration. `TIME_PREFIX` at line 10 selects `endtime` for `_time`; `timestamp` represents the event's start. Correlate the explicit interval rather than treating `_time` as flow start.
- `default/transforms.conf:1` and `:13` map IP, name, and MAC into generic `src` and `dest` fields. Preserve explicit endpoint IPs and their address domains as graph join keys; generic fields can contain several forms of identity.
- `default/props.conf:218` defines `stream:netflow` direction from `flow_dir`. Confirm its observation-point semantics before interpreting it as application caller direction.
- `default/eventtypes.conf` defines broad Stream network-traffic tagging. `lookups/stream_app_lookup.csv` maps protocol sourcetypes to names such as `http` and `mysql`; it does not identify a business application. There is no NetFlow business-application lookup in this file.

The Forwarders 8.1.3 package supplies `README/streamfwd.conf.spec:214` with `netflowReceiver` IP, port, decoder, exporter filter, decoding threads, and template expiry settings. Its vocabulary includes exporter, interface, next-hop, sampling, and application classification terms. Vocabulary support does not guarantee these terms are exported or enabled in a deployed Stream definition. Inspect the collector version and exporter templates used in the pilot. [Stream receiver configuration](https://help.splunk.com/en/splunk-enterprise/collect-stream-data/install-and-configure-splunk-stream/8.1/configure-your-splunk-stream-installation/use-splunk-stream-to-ingest-netflow-and-ipfix-data).

### Stream App 8.1.6: concrete NetFlow field selection

Base: `research/extracted/splunk-app-for-stream_816/splunk_app_stream/`.

`default/streams/netflow` is a reference definition: the stream is disabled at line 4, while all 156 field entries are enabled. It declares `statsOnly=true`, `sourcetype=stream:netflow`, and `streamType=event` at `:1142`–`:1145`. The transport protocol is the numeric `protoid` (`:133`); the definition has no `protocol` or `transport` field, and Wire Data adds no `transport` evaluation for `stream:netflow`. These are shipped settings, not evidence that the deployed stream collects every field.

| Field group | Named fields in the reference | Correlation use |
| --- | --- | --- |
| Endpoint tuple | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `protoid`, MACs | Preserve the raw communication tuple; resolve workload ownership using time and address domain. |
| Observer and attachment | `exporter_ip`, `input_snmpidx`, `output_snmpidx`, `interface_name`, `ingress_interface`, `egress_interface`, VLANs, `observation_domain_id` | Join exporter/interface inventory; an observation domain ID is local to an exporting process and does not establish the routing VRF. |
| Timing and volume | `bytes`, `packets`, `time_taken`, relative times, `flow_start_time`/`flow_end_time` and milli/micro/nano variants | Validate exporter encoding and units. `time_taken` is described as milliseconds; the Wire Data duration alias performs no unit conversion. |
| Sampling and classification | `exporter_sampling_mode`, `exporter_sampling_interval`, `selector_algorithm`, `app_tag`, `app`, `app_desc` | Preserve sampling metadata and protocol classification separately from business/service identity. |

`default/vocabularies/netflow.xml:685` defines post-NAT addresses and post-NAPT ports; `:732` defines ingress/egress VRF IDs and VRF name. The reference has `nat_event`/`nat_type` but no explicit fields selecting those translated tuples or VRF terms. It includes generic `netflow_elements` key/value pairs at `default/streams/netflow:1135`; examine actual decoded values before deciding whether additional field definitions or normalization are needed. NAT flags alone cannot resolve a translated endpoint.

The shipped Flow Visualization uses `source=stream:Splunk_IP` and IPv4 source/destination heatmap queries (`appserver/static/js/views/FlowVisualizationView.js:58`). Its default search does not select `stream:netflow` or join application/workload identities. It can inform the pilot visualization; the application dependency map requires searches over the normalized and enriched records.

## AppDynamics: useful identity, incomplete endpoint binding

Base: `research/extracted/cisco-splunk-add-on-for-appdynamics_321/Splunk_TA_AppDynamics/`.

`default/inputs.conf` declares ten inputs for status, analytics, security, events, custom metrics, databases, hardware, snapshots, audit, and licenses. Status events include application/tier/node IDs and names plus health and performance context. In `bin/controller_service.py:290`, node health requests select node/tier/health columns. The ID-to-name enrichment at `:955` uses node metadata but returns names; it does not emit the node `ipAddresses` collection as an address-binding dataset.

Backend collection exists at application level. `bin/controller_service.py:1377` (`get_remote_services_status`) calls `/controller/restui/backend/list/remoteService`, and `bin/appdynamics_status.py:164` writes each backend as `source=remote_services` when the `appdynamics_status` input enables "Remote Services Status". Records carry backend ID, name, exit-point subtype, application ID, calls/min and response time. They supply application→backend dependencies, but no tier, node or address binding, and no flow map.

The design therefore needs Controller node/machine/address metadata alongside TA status events. This does not require changing the vendor TA; a separate enrichment input can preserve its upgrade path. Confirm Controller version and actual API responses before specifying that input. [Official package](https://splunkbase.splunk.com/app/3471), [Application Model API](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/25.4.0/extend-splunk-appdynamics/splunk-appdynamics-apis/application-model-api).

## OTel: configured data routing is the bridge

Base: `research/extracted/Splunk_TA_otel_linux_x86_64_01620/Splunk_TA_otel_linux_x86_64/`.

`default/inputs.conf` starts the collector and selects a configuration file. The archive includes a compiled collector/input binary; inspection here covers the extracted agent/gateway YAML and input configuration. Configuration inspection cannot prove all runtime behavior. In `configs/agent_config.yaml:231`, traces go through resource detection to `otlp_http` for Observability. Metrics go to `signalfx`; the logs pipeline at `:264` uses HEC exporters. This configuration does not create Splunk lookup tables or import an APM service graph.

This host package has no Kubernetes components: no `k8sattributes` processor and no `k8s_cluster` or `k8sobjects` receiver. Its resource detectors are `[gcp, ecs, ec2, azure, system]` (`:136`). With the shipped configuration, traces reach Observability Cloud only; neither spans nor pod inventory reach Splunk Platform.

### Kubernetes Helm chart 0.161.0 (primary pilot collector)

Base: `research/extracted/splunk-otel-collector-chart_01610/splunk-otel-collector/`. Findings come from the chart templates, a static `helm template` render with only `splunkPlatform.*` set (endpoint, token, `index`, `metricsIndex`, `tracesIndex`, `metricsEnabled`/`tracesEnabled: true`), and the upstream contrib v0.161.0 translator code that the collector's `go.mod` pins. Nothing was installed.

Defaults (`values.yaml:130`–`:134`): only logs go to Splunk Platform. `metricsEnabled` and `tracesEnabled` default to `false` and need `metricsIndex`/`tracesIndex` (`:51`–`:55`). `clusterName` (`:28`) becomes `k8s.cluster.name` on every signal.

| Data | Evidence | Sourcetype / index | Body and indexed fields |
| --- | --- | --- | --- |
| Pod objects | `clusterReceiver.k8sObjects` default `pods`, `mode: pull`, `interval: 6h` (`values.yaml:636`); pipeline `logs/objects` (`templates/config/_otel-k8s-cluster-receiver-config.tpl:51`, `:482`); sourcetype `Concat("kube:object:", k8s.resource.name)` (`:213`) | `kube:object:pods`, `splunkPlatform.index` | Pull: body is the full Pod object (`metadata.uid/name/namespace/ownerReferences`, `spec.nodeName`, `status.podIP/podIPs/hostIP/phase/startTime`). Watch: body is `{"type": "ADDED|MODIFIED|DELETED", "object": <Pod>}` plus `event.domain`/`event.name`. Fields: `k8s.resource.name`, `k8s.namespace.name`, `k8s.cluster.name`, `metric_source`. `_time` is collection time (upstream `unstructured_to_logdata.go:70` sets only the observed timestamp). `host` is the cluster receiver's node (`resource/add_cluster_host`), not the pod's node. |
| Other objects | Defaults also pull `networkpolicies` and CRDs every 6h. Services are allowed by RBAC (`templates/clusterRole.yaml:48`); EndpointSlices (`discovery.k8s.io`) are not, so they need `rbac.customRules`. | `kube:object:<resource>` | Same shape as pods. |
| Kubernetes events | `clusterReceiver.eventsEnabled: true` (`values.yaml:583`) | `kube:events` | Event objects with `k8s.<kind>.name/uid` fields. Useful for pod lifecycle timing. |
| Container logs | filelog `/var/log/pods/*/*/*.log`; sourcetype `EXPR("kube:container:"+k8s.container.name)` (`templates/config/_otel-agent.tpl:707`) | `kube:container:<container>` | Fields include `k8s.pod.name`, `k8s.pod.uid`, `k8s.namespace.name`, `k8s.node.name`, `container.id`, `k8s.cluster.name`. |
| Spans (opt-in) | `splunkPlatform.tracesEnabled` → `splunk_hec/platform_traces` (`templates/config/_otel-agent.tpl:1257`, `:1281`; exporter `templates/config/_common.tpl:559`) | `tracesIndex`; no sourcetype unless `splunkPlatform.sourcetype` is set, so the HEC token default (normally `httpevent`) applies | One event per span (`traces_to_splunk.go`): `trace_id`, `span_id`, `parent_span_id` (32/16-hex; empty for roots), `name`, `kind` (`SPAN_KIND_SERVER`/`CLIENT`/…), `start_time`/`end_time` (Unix ns integers), `status{code,message}`, `attributes`, `events`, `links`. `_time` = start time in epoch seconds. Resource attributes become indexed `fields`: `service.name`, `deployment.environment.name` (from the chart's `environment` value, `_otel-agent.tpl:902`), `k8s.cluster.name`, plus `k8s_attributes` metadata. |
| Metrics (opt-in) | `k8s_cluster`, `kubelet_stats`, `host_metrics` → `splunk_hec/platform_metrics` | `metricsIndex` (metrics index) | Pod/node/container dimensions. Pod network rx/tx byte counters have no peer, so they are not dependency evidence. |

`k8s_attributes` on traces and logs (`templates/config/_common.tpl:195`–`:215`) associates telemetry by `k8s.pod.uid`, then `k8s.pod.ip`, then `ip`, then connection IP. It adds `k8s.namespace.name`, `k8s.node.name`, `k8s.pod.name`, `k8s.pod.uid`, `container.id`, `container.image.name/tags`, and the pod label `app` (`extraAttributes.fromLabels`, `values.yaml:320`). It does not add `k8s.pod.ip` to the resource, because that metadata key isn't extracted (upstream `processor.go:201`). Pod IPs therefore come from `kube:object:pods`, not from spans. Deployment and ReplicaSet names are also not extracted; derive them from `ownerReferences`.

Implications for the ADM app:
- Pod IP ownership comes from `kube:object:pods`: bind `status.podIPs[].ip` to `metadata.uid` with `valid_from` = first observation (or `status.startTime`) and `valid_to` = DELETED event or last observation plus the pull interval.
- The default 6h pull cannot bound IP reuse. The pilot must configure `pods` in `mode: watch` (or a short pull interval) and should add `services` and, with custom RBAC, `endpointslices`.
- Spans reach Splunk Platform only with `tracesEnabled` and a `tracesIndex`. Set `splunkPlatform.sourcetype` (or an `otel:span`-style annotation strategy) so span events are identifiable. Parent/child edges join `parent_span_id` to `span_id` within `trace_id`, and cross-service calls compare the `service.name` field of each side.
- No receiver in the chart produces connection tuples. Network evidence still comes from Stream and the Cisco sources.

For correlation, inspect the deployed collector configuration and representative span/resource attributes. Decide whether to export selected span evidence through HEC, collect workload inventory as structured events, or use a documented product API. Avoid assuming a gateway's IP is the emitting workload's address. [OTel TA](https://splunkbase.splunk.com/app/7125), [HEC exporter](https://help.splunk.com/splunk-observability-cloud/manage-data/splunk-distribution-of-the-opentelemetry-collector/get-started-with-the-splunk-distribution-of-the-opentelemetry-collector/collector-components/exporters/splunk-hec-exporter).

## Cisco Security Cloud: four requested products in one package

Current base: `research/extracted/cisco-security-cloud_372/CiscoSecurityCloud/`. Paths below are relative to that base. The older 3.6.5 archive is retained for comparison.

| Product | Actual input and extraction evidence | Implication for the graph |
| --- | --- | --- |
| Cisco FTD | `default/inputs.conf:44` defines `cisco:sfw:estreamer`; `README/inputs.conf.spec:50` requires selected event types. `default/props.conf:985` maps initiator/responder IPs and ports, interfaces/zones, application, bytes, rule/device identifiers and action. `cisco:ftd:syslog` parsing begins at `:813`; its input at `default/inputs.conf:30` has no default sourcetype. | Supplies connection and policy evidence when those event families are enabled. Configure the correct sourcetype and verify NAT payload fields; inventory/topology collection was not found. |
| Cisco Secure Network Analytics | `default/inputs.conf:75` defines `cisco:sna`. Network insights collect traffic/top applications/top flows with host groups, tags, byte counts, hosts, ports and conversation context; `default/props.conf:704` defines normalization. | Useful flow summaries and endpoint context, with top-flow selection and freshness gating. It cannot be assumed to contain every dependency. |
| Isovalent | HEC inputs are in `default/inputs.conf:120`; `default/transforms.conf:98` routes process/event families. `default/props.conf:2355` defines `cisco:isovalent:processConnect`, which maps `process_connect` IPs/ports/protocol, pod name/namespace/container, node and process IDs; `cisco:isovalent:processExec` starts at `:2326`. Edge variants are separate sourcetypes. | Candidate workload-to-connection bridge. Generic `dest` is aliased to `node_name` (`:2366`), the reporting node, not the destination; use explicit `process_connect` IP fields for network joins. No Hubble or Connection Logs API collector was found. |
| Secure Client NVM | `default/inputs.conf:134` defines `sbg_nvm_input`; `default/props.conf:1` parses `cisco:nvm:flowdata:v2`. | Per-flow process, process hash and user on managed hosts. Outside the Nexus-only pilot scope, but the only shipped process-to-flow source for VMs. |
| Cisco Secure Workload | `default/inputs.conf:141` defines syslog ingestion. `default/props.conf:2523` extracts alert scope, source/destination, ports, protocol, VRF and threat context. Its event logger receives syslog rather than querying workload inventory. | Adds security/policy annotations. Full workload labels, application dependency inventory and flow history need another validated export/API. |

Compared with 3.6.5, 3.7.2 revises eStreamer bookmark/UTC handling and FTD JSON/legacy parsing, while the SNA, Isovalent and Secure Workload collection scope remains substantially unchanged. The current inputs declare `python.required=3.13`; confirm the deployed Splunk input runtime before installation. Telemetry network/process sourcetypes retain JSON with minimal aliases (`default/props.conf:2380`), so their schema still needs sample inspection.

Explicit translated-address/port extraction is present in legacy ASA mappings (`default/transforms.conf:192`, `default/props.conf:1085`). That does not establish a NAT binding in every FTD syslog or eStreamer event. The [listing](https://splunkbase.splunk.com/app/7404) also describes a separate 4.0 FTD sourcetype transition; 4.x packages have not been inspected. Use names from the actual intended release. The separate [SNA App](https://splunkbase.splunk.com/app/6398) primarily queries SNA on demand for dashboards; that does not establish a persisted enrichment dataset.

## Cisco DC Networking: endpoint and attachment enrichment

Base: `research/extracted/cisco-dc-networking_122/cisco_dc_networking_app_for_splunk/`. Paths below are relative to that base. The three API input families are `cisco_nexus_dashboard`, `cisco_nexus_aci`, and `cisco_nexus_9k`. The supplied collection stanzas are disabled until configured; package presence alone does not establish inventory coverage.

| Input family | Collection and field evidence | Dependency-map use |
| --- | --- | --- |
| Nexus Dashboard | `bin/cisco_dc_nd_collector.py:83` lists Insights flow/endpoint/protocol APIs and inventory switch/fabric APIs. `default/props.conf:330` maps `srcIp`, `dstIp`, ports, `flowId`, `protocolName`, and `stats{}` interface/byte/packet fields for `cisco:dc:nd:flows`. The flow writer at `:191` adds `nd_host` and `fabricName`. | Additional communication evidence and fabric context. Preserve raw nested statistics; multiple interface/counter values need sample validation before aggregation. |
| ND endpoints | `default/props.conf:357` maps `endpointId`, `vmName`, `nodeName`, `encap`, and `modType` for `cisco:dc:nd:endpoints`; the event writer at `bin/cisco_dc_nd_collector.py:252` preserves API JSON and adds `nd_host`. | Candidate endpoint/VM attachment and change history. Verify address fields in actual payloads; the shown aliases do not establish a complete IP binding. |
| ACI / APIC | `default/inputs.conf:81` selects stats, microsegment, health, and class queries. Classes include `fvCEp`, `fvVmAttr`, `fvIpAttr`, `fvMacAttr`, `compVm`, `compHv`, `fvCtx`, `fvRsCEpToPathEp`, `fvRsVm`, and `fvRsHyper`. `bin/cisco_nexus_aci.py:697`–`:703` requests child objects and writes `addr` plus object attributes, `apic_host`, `actual_host`, and `component`. The `stats` input (`default/inputs.conf:81`) collects `fvCEp` with `fvRsCEpToPathEp` and `fvIp` children as `cisco:dc:aci:stats`; `classInfo_faultInst` (`:117`) also collects `fvCEp` with `fvIp` children as `cisco:dc:aci:class`. `classInfo_fvRsCEpToPathEp` (`:111`) adds `acllogPermitL3Pkt`/`acllogDropL3Pkt` and `dbgEpToEpRslt` contract-level flow records. | Resolve endpoint IP/MAC, VM/hypervisor association, EPG and attachment paths through APIC object DNs. Derive tenant/VRF through verified object relationships and retain collection history. ACI ACL-log records are candidate permitted/dropped flow evidence between EPGs. |
| Nexus 9000 | `default/inputs.conf:136` supplies hostname/version, module/inventory, interface and CDP-neighbor commands. `bin/cisco_nexus_9k.py:118` supports NX-API CLI; DME collection at `:205` queries classes or object DNs. `default/props.conf:1` extracts inventory and interface fields. | Identify devices, interfaces and neighbor links to enrich Stream exporter/interface observations. Command support and identifier formats require device-specific samples. |

ACI events are flattened key/value records, while ND events retain JSON. Keep repeated child addresses and interface statistics as separate associations when normalizing. `default/props.conf:203` coalesces ACI `ip`/`addr`, but its generic `dest` is the APIC host. ND flow `dvc` is the Dashboard host. These aliases must not be mistaken for the communicating endpoint or traversed switch. ND endpoint `_time` is collection time (`DATETIME_CONFIG=CURRENT`), so distinguish observed change timestamps from collection time.

The package supplies network context; no automatic AppDynamics/OTel/Kubernetes identity join was found. It also does not prove the entire routed path of an observed flow. ACI queries paginate, and ND flow collection uses time windows and checkpoints; validate API completeness, retention, duplicates and polling lag with the enabled inputs.

## Switch coverage

The pilot uses Nexus switches only, managed through Nexus Dashboard, standalone NX-OS and ACI. All three are covered by the DC Networking package above; Catalyst/IOS XE (Cisco Enterprise Networking) is out of scope. Command and API support still varies by NX-OS release and switch model, so confirm identifier formats with device-specific samples.

## Next package and event analysis

The approved Security Cloud 3.7.2, Stream App 8.1.6 and Helm chart 0.161.0 downloads are complete and their publisher digests match. Inspect the exact collector/deployment versions and the pilot's Helm values before implementation. Next inspect enabled input selections, exporter templates, runtime compatibility, pagination/checkpoints, timestamps, routing and knowledge-object permissions. Compare representative VM and Kubernetes events to the proposed [identity and relationship records](TELEMETRY_CORRELATION_DESIGN.md).

Package contents show how input data is handled; defaults do not establish that a particular input is enabled, that a source exports every field, or that an indexed dataset covers the whole network.
