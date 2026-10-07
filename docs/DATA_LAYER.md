# Splunk-native data layer (v1)

The app builds the dependency map inside Splunk from the installed TAs' events. Scheduled searches normalize flow records, roll them up into conversations, and maintain time-bounded identity in KV store. An on-demand graph macro joins them for the UI. No external projector, HEC token or hand-normalized input is required.

Everything is SPL in `macros.conf`, `savedsearches.conf`, `collections.conf` and `transforms.conf`; there are no custom commands or scripts. Supported on Splunk Enterprise 10.x (pilot) and Splunk Cloud. The app ships no `indexes.conf`; create the summary index through your normal process (ACS on Cloud). Summary events use the `stash` sourcetype and do not count against license.

## Sources

| Source | Sourcetype | Role |
| --- | --- | --- |
| Splunk Stream NetFlow/IPFIX from NX-OS leaves | `stream:netflow` (`source=stream:netflow`) | Unidirectional flow records, exporter and ifIndex |
| Nexus Dashboard Insights | `cisco:dc:nd:flows`, `cisco:dc:nd:endpoints` | Fabric flow records; endpoint change records (creation/deletion) |
| ACI (APIC) | `cisco:dc:aci:stats` (`fvCEp` with `fvIp`, `fvRsCEpToPathEp`), `cisco:dc:aci:class` (`fvRsVm`, `compVm`) | Endpoint IP/MAC, tenant, application profile, EPG, leaf path, VM name |
| NX-OS (NX-API) | `cisco:dc:nexus9k` (`nxhostname`, `nxneighbor`) | Device names; ifIndex to interface name for CDP-connected ports |
| Cisco FTD | `cisco:sfw:estreamer` with `EventType=ConnectionEvent` | Edge connections with initiator/responder |
| Isovalent (Tetragon on Cilium) | `cisco:isovalent:processConnect` (renamed at index time from the HEC sourcetype `cisco:isovalent` by the TA) | Pod/process-initiated connection setup |
| Splunk OTel Collector for Kubernetes | `kube:object:pods` (watch or pull mode), traces sourcetype set by `splunkPlatform.sourcetype` (pilot: `otel:traces`) | Pod IP ownership history; service calls and service→pod binding |

Span resource attributes (`k8s.cluster.name`, `k8s.namespace.name`, ...) must arrive as HEC indexed fields, as the Helm chart sends them; the graph search filters with `k8s.cluster.name::<cluster>`.

## Configuration

| Macro | Default | Meaning |
| --- | --- | --- |
| `adm_index_netflow` | `index=netflow` | Stream NetFlow |
| `adm_index_dcn` | `index=cisco_dc` | DC Networking (ND, ACI, NX-OS) |
| `adm_index_ftd` | `index=cisco_secure_fw` | Security Cloud FTD (TA default) |
| `adm_index_isovalent` | `index=cisco_isovalent` | Security Cloud Isovalent (TA default) |
| `adm_index_k8s` | `index=k8s` | Kubernetes objects |
| `adm_index_traces` / `adm_traces_sourcetype` | `index=otel_traces` / `sourcetype="otel:traces"` | Spans in Splunk Platform |
| `adm_index_summary` / `adm_summary_index_name` | `index=adm_summary` / `adm_summary` | Summary index read and written; keep them consistent |
| `adm_identity_retention` | `604800` | Seconds identity rows are kept after their validity ended |
| `adm_poll_interval` | `300` | APIC polling interval in seconds |
| `adm_k8s_node_staleness` | `0` | Seconds after the last pod observation at which a node row ends; `0` disables it (watch mode). Use about twice the pull interval in pull mode. |
| `adm_identity_max_matches` | `1000` | Must equal `max_matches` of the `adm_ip_identity` lookup (1000 is the maximum Splunk allows) |
| `adm_kv_max_rows` | `50000` | Must equal `limits.conf [kvstore] max_rows_per_query` |
| `adm_kv_page_size` | `10000` | Page size of `adm_kv_read_all`; requires `max_rows_per_query` of at least 10,000 |
| `adm_trace_limit` | `10000` | Boundary traces whose out-of-boundary spans are read; at most `limits.conf [subsearch] maxout` |

`adm_observer_scope` (`lookups/adm_observer_scope.csv`, columns `observer_kind,observer,scope,cluster`) maps observers to a routing `scope`. Observer kinds: `exporter` (NetFlow `exporter_ip`), `fabric` (ND `fabricName`), `firewall` (FTD `DeviceIP`), `hec_source` (Isovalent HEC `source`, one token per cluster), `cluster` (`k8s.cluster.name`), `apic` (`apic_host`), `nd_host` (`nd_host`). The shipped file has only the header; unmapped observers fall into scope `default`. Identity only joins within one scope.

## Normalized flow records

Generating macro `adm_flows` (call as `` | `adm_flows` ``) runs `multisearch` over `adm_flows_netflow`, `adm_flows_nd`, `adm_flows_ftd` and `adm_flows_isovalent`, then applies the interface and scope lookups:

| Field | Meaning |
| --- | --- |
| `adm_source` | `netflow`, `nd`, `ftd`, `isovalent` |
| `adm_observer`, `adm_observer_kind` | Exporter IP / ND fabric / FTD device IP / Kubernetes node; `exporter`, `fabric`, `firewall`, `host_sensor` |
| `adm_scope`, `adm_cluster` | From `adm_observer_scope` |
| `adm_src_ip`, `adm_src_port`, `adm_dest_ip`, `adm_dest_port` | Tuple as recorded. IPs are lower-cased and IPv4-mapped IPv6 (`::ffff:a.b.c.d`, full and hexadecimal forms) is unwrapped. Ports are empty for portless protocols such as ICMP. |
| `adm_transport` | `tcp`, `udp`, `icmp`, `ipv6-icmp` or the lower-cased value; NetFlow `protoid` mapped |
| `adm_bytes_fwd`, `adm_bytes_rev`, `adm_packets` | Bytes src→dest and dest→src. NetFlow is scaled by `exporter_sampling_interval` when > 1. ND uses the first `stats{}` entry's ingress counters (the TA's `EVAL-bytes` adds ingress and egress and double counts). FTD uses initiator/responder bytes. Isovalent has none (empty, not 0). |
| `adm_start`, `adm_end` | Epoch seconds from explicit fields: NetFlow `timestamp`/`endtime`; ND `ts`; FTD `FirstPacketSecond`; Isovalent `time`. ND, FTD and Isovalent expose a start only, so `adm_end = adm_start`. |
| `adm_in_if`, `adm_out_if` | NetFlow: interface name from `adm_interfaces`, otherwise `ifIndex <n>` (default NX-OS commands report ifIndex only for CDP-connected ports). ND: `<node>:<vif>`. FTD: interface names. |
| `adm_initiator` | `src` for FTD and Isovalent (the source names the initiator); otherwise `unknown` |

No inspected TA extracts a translated (NAT) tuple, so no NAT fields are produced. NetFlow `flow_dir` is never used.

## Conversations

Saved search **ADM - Conversation rollup** (`` | `adm_conversation_rollup` | collect ``) runs every 5 minutes and selects flow records **by index time**: `dispatch.index_earliest = -10m@5m`, `dispatch.index_latest = -5m@5m`, with event-time bounds `-24h` to `+15m` (records older than 24 hours when indexed, or more than 15 minutes in the future, are not counted). Consecutive runs read disjoint index-time slices, so every record is counted exactly once, however late it arrives. Continuous scheduling (`realtime_schedule = 0`) makes delayed runs catch up instead of skipping slices.

Records are bucketed by `adm_end` into 5-minute buckets. Each run writes `source="adm:conversation"`, `sourcetype=stash`, `adm_record=conversation`, `_time` = bucket start, one event per (`scope`, `client_ip`, `server_ip`, `server_port`, `transport`, bucket, `observer`):

`flow_source`, `observer` (`source:observer`), `observations` (pipe-delimited `source:observer[:in_if>out_if]`, because `collect` flattens multivalue fields), `bytes_c2s`, `bytes_s2c`, `packets`, `records`, `client_ports` (distinct), `first_seen`, `last_seen`, `direction_basis`, `encapsulation`. Ports are `-` for portless protocols. A late record of a bucket produces another row for the same bucket and observer in a later run; the graph adds them.

Client and server are decided per record, in this order, and recorded in `direction_basis`:

1. `initiator`: the source names the initiator (FTD, Isovalent).
2. `port_rule`: one side uses a port below 1024 and the other does not, or one side uses an ephemeral port (≥ 32768) and the other does not; the other side is the server.
3. Reconciliation: a record with neither inherits the orientation of another record in the same run with the same address pair, transport and bucket whose server endpoint (IP and port) is one of its endpoints; it keeps that record's basis (`initiator` or `port_rule`). A gRPC server on port 50051 seen by NetFlow and by Isovalent therefore yields one conversation.
4. `unknown`: endpoints are ordered by IP so both directions merge; the UI shows the edge undirected.

UDP to port 8472 (VXLAN) or 6081 (Geneve) is merged regardless of direction (`direction_basis=unknown`, server port = tunnel port). `encapsulation` is `vxlan` or `geneve` when both IPs are Kubernetes node identities. Reverse-direction NetFlow records of one conversation produce one conversation, never a reversed edge.

## Identity (KV store)

Collection `adm_ip_identity` (lookup `adm_ip_identity`, `max_matches = 1000`), one row per (source, entity, IP, scope):

`ip`, `scope`, `entity_kind` (`pod`, `k8s_node`, `vm`, `endpoint`), `entity_id` (pod UID, `<cluster>/<node>`, ACI endpoint DN, ND endpoint ID), `entity_name`, `cluster`, `namespace`, `owner_kind`, `owner_name`, `node`, `tenant`, `app_profile`, `epg`, `attach_device`, `attach_interface`, `mac`, `vm_name`, `valid_from`, `valid_to` (empty while present), `valid_end` (end used for resolution and pruning), `first_seen`, `last_seen`, `priority`, `source`, `ek` (entity key), `updated`, and `desc` (JSON of these fields, returned by lookups). VRF is not stored: the collected ACI objects do not relate an endpoint to its VRF.

**ADM - Identity builder** (`adm_identity_build`, every 5 minutes, index time `-10m@m` to `@m`, event time `-24h` to `+15m`, continuous scheduling) reads new observations and upserts them:

- **Kubernetes pods** (`source=k8s_pods`, priority 1): watch events (`type` ADDED/MODIFIED/DELETED) or pull snapshots. `valid_from` is `status.startTime`, else the first ADDED, else the first observation; `valid_to` is the DELETED event time. Each `status.podIPs` entry is a row. Pods with `spec.hostNetwork: true`, or whose pod IP equals `status.hostIP`, are not IP owners. A ReplicaSet owner becomes a Deployment only when its name is `<deployment>-<pod-template-hash label>`. Events without `k8s.cluster.name` are stored with cluster `unknown` and reported in the builder's warnings.
- **Kubernetes nodes** (`source=k8s_nodes`, priority 2): `status.hostIP` and `spec.nodeName` of pod objects (including hostNetwork pods); not created for cluster `unknown`.
- **ACI endpoints** (`source=aci`, priority 3): `fvCEp` IPs (`ip` and child `fvIp addr`). Tenant, application profile and EPG come from the DN; `attach_device`/`attach_interface` from `fvRsCEpToPathEp tDn` (`pod-<n>/node-<id>`, `eth1/5`); `vm_name` through `fvRsVm`→`compVm`. Switch names are not resolved because the default inputs do not relate `topSystem` to paths. `valid_end` is the last report plus two polling intervals, so an endpoint that stops being reported expires.
- **Nexus Dashboard endpoints** (`source=nd_endpoints`, priority 3): the input collects endpoint changes incrementally from a checkpoint (`bin/cisco_dc_nd_collector.py:757-800`), so stable endpoints are not re-reported and no staleness applies. `valid_from` is `createTime`; `valid_to` is a `modType=deletion` record or the start of another endpoint with the same IP and scope.

The builder never reads the whole collection. For each new observation it reads the stored rows of the same IP and scope through the lookup (at most `max_matches`), merges first/last seen and validity, keeps the newest non-empty attribute values, and closes an open pod, node or ND endpoint interval at the `valid_from` of the next different entity with that IP. Changed rows are written with `outputlookup append=true key_field=_key override_if_empty=false`. When an IP returns `adm_identity_max_matches` stored rows, closing is skipped for it and the builder's summary row carries a warning. The builder returns one row: `rows_written`, `rows_observed`, `rows_closed`, `truncated_ips`, `rows_missing_cluster`, `warnings`. Overlapping index-time windows are harmless (merges are idempotent). Backfill by dispatching it once with `dispatch.index_earliest=-7d`.

**ADM - Identity prune** (daily 03:04) reads the collection with `adm_kv_read_all`: 20 pages of 10,000 rows plus a probe at offset 1. It rewrites the collection without rows whose `valid_end` is older than `adm_identity_retention` only when the read is provably complete: pages contiguous, every page before the last full, the page after the last read and empty, and a short first page whose probe returned exactly one row fewer (otherwise the store capped the read). Otherwise it writes nothing and returns a warning. It never empties the collection (`override_if_empty=false`). **ADM - Service binding prune** (daily 03:09) does the same for `adm_service_workload` by `last_seen`.

**Concurrency.** Each saved search runs one instance at a time (`max_concurrent` default 1). The builder and prune both write `adm_ip_identity`; a row upserted by the builder while the prune reads could be dropped by the prune's rewrite. The prune is scheduled at 03:04, when no builder run starts (`schedule_window = 0`), and a dropped row reappears when its entity is next observed. Do not run the prune by hand while builders run.

Collection `adm_service_workload` (**ADM - Service binding**, every 5 minutes, same windows) binds an OTel service (`service.name`, `deployment.environment.name`, `k8s.cluster.name`, `k8s.namespace.name`) to `k8s.pod.uid` with first/last seen (upsert by `_key`). Collection `adm_interfaces` (**ADM - Interface inventory**, hourly, index time `-2h@m`) maps (`device_ip`, `ifindex`) to `interface` and CDP neighbor (upsert; bounded by device ports, never pruned).

**Resolution.** For a conversation bucket `[first_seen, last_seen]`, an identity row covers it when `valid_from ≤ first_seen` and `last_seen < valid_end` (or `valid_end` is empty). Among covering rows at the best (lowest) priority, rows with the same entity key count as one entity: a pod or node is one entity; ACI and ND rows with the same scope, IP and MAC are one endpoint (a row without MAC joins it). One entity is `resolved`; several are `ambiguous`; none is unresolved. Attributes come from the first non-empty value across covering rows in priority order, ACI before ND, so a Kubernetes node shows its ND leaf port.

## Graph search

Macro `adm_graph(service, environment, cluster, namespace)` runs on demand over the search time range. The application boundary is the Kubernetes namespace. It returns rows with `row_type=node`, `edge` or `meta`; the UI assembles them into its graph model and rejects rows that break the contract (unknown node kinds, edges whose endpoints are missing or of the wrong kind, more than 500 nodes or 2,000 edges). Stages are separate macros: `adm_graph_inputs`, `adm_graph_resolve`, `adm_graph_edges`, `adm_graph_output`.

**Argument validation.** `adm_graph` and every stage macro reject arguments not matching (PCRE, `\z` = end of string; identical to the UI's `ARG_RULES`):

| Argument | Pattern |
| --- | --- |
| service | `^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\z` |
| environment | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z` |
| cluster | `^[A-Za-z0-9][A-Za-z0-9._-]{0,252}\z` |
| namespace | `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\z` |

- **Inputs:** summary rows whose `client_ip` or `server_ip` is an IP of a boundary pod or of a node hosting one during the window (subsearch over `adm_ip_identity`; the IP list is inserted into the search string, so very large namespaces are bounded by search-string size and the identity read cap, which is reported). Spans of the boundary (`k8s.cluster.name::` and `k8s.namespace.name::` indexed fields) plus all spans of at most `adm_trace_limit` boundary traces (subsearch), each with its parent's service found within the trace. Summary rows are summed per (conversation, bucket, observer) across rollup runs.
- **Resolution per bucket:** each (conversation, bucket) is resolved over that bucket's interval, so an IP reused inside the window resolves to the right pod in each bucket. Edges then aggregate by the resolved entity IDs.
- **Services and `calls`:** a service is `service:<cluster>/<namespace>/<service.name>/<environment>`. `calls` edges (`confidence=observed`) are cross-service parent/child spans whose parent service is in the boundary; `count` is the number of child spans; `evidence` lists `span:<trace>/<span>`.
- **`runs_on`:** service → `pod:<cluster>/<uid>` from `adm_service_workload` rows overlapping the window (`confidence=correlated`).
- **`communicates_with`:** conversations where either side resolves to a boundary pod. The other side is a pod (any namespace, e.g. ingress or CoreDNS), `node:<cluster>/<node>`, `vm:<scope>/<ip>` (ACI/ND endpoint with EPG/tenant/VM/leaf attributes), or `ip:<scope>/<ip>` with `endpoint_kind` `external` (public address), `unresolved` or `ambiguous`. Tunnel conversations are included only between nodes that host boundary pods and only connect `node:` endpoints. `confidence` is `correlated` when both sides resolve in every bucket, otherwise `unresolved`.
  - `bytes`: per observer, `bytes_c2s + bytes_s2c` summed across buckets and runs; the edge takes the largest observer total. Empty when no observer reports bytes (for example Isovalent only).
  - `count`: flow records, computed the same way (per observer summed, then the largest).
  - `evidence` (sources plus `span_peer`), `observers`, `sources`, `server_port` (empty for portless protocols), `transport`, `direction_basis`, `encapsulation`, `span_ids`.
- **Span association (`span_peer`):** a CLIENT span is attached to a conversation when its `network.peer.address` and `server.port` equal the conversation's server IP and port, its `k8s.pod.uid` is the pod that owns the client IP, and the span overlaps the conversation interval within one second.
- **Nodes:** `id`, `label`, `kind` (`service`, `workload`, `endpoint`), `endpoint_kind`, `namespace`, `cluster`, `addresses` (union), `reason`, and `attr_*` (`attr_environment`, `attr_owner`, `attr_owner_kind`, `attr_node`, `attr_tenant`, `attr_app_profile`, `attr_epg`, `attr_vm_name`, `attr_mac`, `attr_attach_device`, `attr_attach_interface`, `attr_scope`). Pod and service facts from identity and spans win over edge-derived copies.
- **Meta row:** `window_start`, `window_end`, `spans`, `conversations`, `conversations_in_scope`, `matched_conversations`, `unresolved_conversations`, `ambiguous_conversations` (counts of (conversation, 5-minute bucket) pairs), `missing_parent_spans`, `root_present`, `nodes`, `edges`, `warnings`, `generated_at`. Warnings cover a missing entry service, missing parents, ambiguous identities, identity reads that reached `adm_identity_max_matches`, more boundary traces than `adm_trace_limit`, spans without `k8s.cluster.name`, a boundary pod read that reached `adm_kv_max_rows`, and graphs over 500 nodes or 2,000 edges.
- The root is the requested entry service. Without spans for it in the boundary, only the meta row is returned, with a warning. Evidence and span lists are capped at 20 values; oversized graphs produce a warning instead of being truncated.

`evidence`, `observers`, `sources`, `span_ids`, `addresses` and `warnings` are multivalue fields.

## Topology search

Macro `adm_topology` (no arguments) runs on demand over the search time range and returns the network inventory the UI uses to draw candidate paths and to name observers. It reads only collected inventory; it never infers links from traffic.

- `row_type=device`: `device_id` (= `name`, the hostname), `name`, `mgmt_ip`, `device_kind` (`switch`, `firewall`, `controller`), `platform`, `os_version`, `serial`, `fabric`, `aci_node`, `sources` (mv: `nxos`, `cdp`, `nd`, `aci`, `ftd`). Devices are keyed by lower-cased hostname; a device's own report (`show hostname`, ACI `topSystem`, FTD `Device`) wins over the name a CDP neighbor reports.
  - NX-OS (`cisco:dc:nexus9k`): `show hostname` → `name` and `mgmt_ip` (host part of the `device` field); `show version` `nxos_ver_str` → `os_version`; neighbors' `show cdp neighbors detail` → `platform` (`platform_id`), `serial` (from `device_id` `name(serial)`) and `mgmt_ip` (`v4mgmtaddr`).
  - ACI (`cisco:dc:aci:class` `component=topSystem`, input `classInfo_faultInst`): `name`, `oobMgmtAddr` (unset when `0.0.0.0`), `serial`, `role` (`controller` → `device_kind=controller`), `fabric=apic:<apic_host>`, and `aci_node=pod-<podId>/node-<id>` from the `dn`. The UI uses `aci_node` to show identity `attr_attach_device` values such as `pod-1/node-201` as the leaf name.
  - FTD (`cisco:sfw:estreamer` connection events): `Device` → `name`, `DeviceIP` → `mgmt_ip`, `DeviceSerialNumber` → `serial`.
  - Nexus Dashboard (`cisco:dc:nd:flows`): `fabric` from `fabricName` for each switch named in `stats{}.nodeNames{}`.
  - FTD and ND flow records are high-volume, so only the most recent `adm_topology_sample` (default 10,000) events of each are read. A firewall or fabric member seen only in older records appears unnamed. `cisco:dc:nd:switches` inventory is not used: the TA defines no fields for it, so its payload schema is not grounded.
- `row_type=link`: `a_device`, `a_interface`, `b_device`, `b_interface`, `link_source` (`cdp`), `last_seen`. One row per physical adjacency: both directions of a CDP report merge into one row, with the endpoints ordered by `device|interface`. The peer is named by its own `show hostname` when its `v4mgmtaddr` matches a collected switch, otherwise by the CDP `device_id` without the serial.
- `row_type=interface`: `device_id`, `interface` (canonical `EthernetX/Y`), `ifindex` (only for CDP-connected ports, the only default command that reports it), `description`, `state` (from `show interface`).
- `row_type=meta`: `devices`, `links`, `interfaces`, `warnings`, `generated_at`. Warnings report missing inventory, missing CDP adjacencies, and interfaces without ifIndex (NetFlow access ports then stay as `ifIndex N` unless `show interface snmp-ifindex` output is collected).

Observer strings in graph edges (`<source>:<observer>[:<in_if>><out_if>]`) are resolved by the UI against device `mgmt_ip`/`device_id` and interface `ifindex`. Interface names from different sources are compared case-insensitively after normalizing `ethX/Y`, `EthX/Y` and `EthernetX/Y` to one form.

**Candidate path (UI).** For a selected `communicates_with` edge the UI builds an ordered candidate path: client entity → its attachment (pod → node → node's leaf and port; VM/endpoint → ACI or ND attachment) → shortest CDP path between the two attachment switches → server attachment → server entity. Each hop is marked *observed* when an observer string names that device (and interface when given), otherwise *not observed*. Where no collected link connects two segments (for example between the NX-OS fabric and ACI, or to the internet edge), the path shows an explicit gap. Candidate paths come from inventory and are never presented as proof that packets took that route; ECMP, asymmetric routing and sampling are noted.

## Access paths, ACI fabric and contracts (v2, pilot: single ACI fabric)

**Status: design, implementation in progress.** The fixtures (`fixtures/raw-aci/`) and the UI support exist; the searches below are not yet in `macros.conf`.

External clients (for example a Windows VM in an ACI EPG) reach a Kubernetes app through a Cilium LoadBalancer VIP (LB IPAM, BGP), a NodePort, Cilium Ingress/Gateway API (Envoy; the only supported ingress), or a pod IP directly, with `externalTrafficPolicy` `Cluster` or `Local` and Cilium load balancing in SNAT, DSR or hybrid mode. The NX-OS design above stays supported; the pilot path is ACI.

### Additional sources

| Source | Sourcetype | Use |
| --- | --- | --- |
| Hubble flow export (open source), tailed by the Splunk OTel Collector (`logsCollection.extraFileLogs`) | `cilium:hubble:flow` (set by the collector configuration; macro `adm_hubble_sourcetypes`) | Post-translation flows at the backend (`TO_ENDPOINT`), forwarding traces with `IP.source_xlated` when emitted, L7 HTTP flows with headers and trace context. Schema: Cilium `flow.proto`; envelope `{"flow":{…},"node_name":"<cluster>/<node>","time":…}`. |
| Isovalent Enterprise flow export | Pending a real sample | Same role; added to `adm_hubble_sourcetypes` with its own normalization once a sample is inspected. Not modeled until then. |
| Kubernetes objects (Helm `clusterReceiver.k8sObjects`, watch) | `kube:object:services`, `kube:object:endpointslices`, `kube:object:ingresses`, `kube:object:gateways`, `kube:object:httproutes`, `kube:object:nodes` | Service frontends (LoadBalancer ingress IPs, external IPs, NodePorts, ports, traffic policy), backends (EndpointSlice addresses, `targetRef.uid`, `nodeName`), host/path routes, Cilium per-node ingress IP (`network.cilium.io/ipv4-Ingress-ip`). |
| ACI fabric (DC Networking `classInfo`) | `cisco:dc:aci:class` | `topSystem`/`fabricNode` (leaf/spine names, roles, OOB addresses), `fabricLink` (leaf↔spine links), `lldpAdjEp` (host attachment by LLDP system name), contracts (`vzBrCP`, `vzSubj`, `vzRsSubjFiltAtt`, `vzFilter`, `vzEntry`, `fvRsCons`, `fvRsProv`, `l3extInstP`, `l3extSubnet`), ACL-log records (`acllogPermitL3Pkt`, `acllogDropL3Pkt`). |
| ACI NetFlow v9 via Stream, Nexus Dashboard flows for the ACI site | `stream:netflow`, `cisco:dc:nd:flows` | Fabric observations. ACI exports from each leaf's OOB address, so `exporter_ip` maps to `topSystem.oobMgmtAddr`; records carry the ingress interface only. |

### Identity additions

- **Service frontends** (`entity_kind=k8s_service`) are keyed by (`scope`, `ip`, `port`, `transport`): each `status.loadBalancer.ingress[].ip` and `spec.externalIPs` × `spec.ports[].port`, and every Kubernetes node IP × `spec.ports[].nodePort`. Rows carry the Service, its type, `externalTrafficPolicy`, and the backend set from EndpointSlices (pod UIDs, addresses, target ports, nodes) over the same validity interval.
- **Cilium ingress (Envoy) addresses** (`entity_kind=k8s_node_proxy`) come from the Node annotation, and are tied to their node.
- **Conversation resolution** checks the server side against port-qualified frontends first, then IP identity. A frontend hit resolves the server to the Service, never directly to a pod.
- **Node attachment on ACI** comes from the node's `fvCEp` path when nodes sit in an EPG/BD, otherwise from `lldpAdjEp` whose `sysName` equals the Kubernetes node name (floating-SVI L3Out designs, where node IPs are not endpoints). Pod IPs and VIPs are never ACI endpoints.

### Attribution from frontend to backend pod

Each client→frontend conversation is linked to the backend pod that served it by the strongest rule that applies. The edge from the Service to the pod records the rule in `handoff_basis`.

| Access method and policy | Rule (`handoff_basis`) | Confidence |
| --- | --- | --- |
| LoadBalancer or NodePort, `Local`; any policy with DSR; direct pod IP | `hubble_client_tuple`: a Hubble `TO_ENDPOINT` flow with the same client IP and port within one second whose destination pod is a backend of the Service | observed |
| LoadBalancer or NodePort, `Cluster` with SNAT to a remote backend | `hubble_xlate`: a forwarding trace with `IP.source` = client and `IP.source_xlated` = receiving node, joined to the backend's `TO_ENDPOINT` flow on the translated tuple | observed |
| Same, when no forwarding trace exists (Hubble's default monitor aggregation can suppress it) | `time_inferred`: exactly one flow from the receiving node to a backend of the Service starts within one second of the client conversation | inferred |
| Cilium Ingress/Gateway (Envoy) | `l7_forwarded_for`: a Hubble L7 HTTP flow whose `X-Forwarded-For` contains the client IP links the Envoy upstream connection (source = the node's ingress IP) to its backend; host/path route from Ingress/HTTPRoute | observed |
| None of the above | `service_only`: the edge ends at the Service; candidate backends are listed but none is chosen | — |

Kubernetes drops `Local` traffic at nodes without a local endpoint, and L2 announcements cannot be combined with `Local`; both are reported as warnings when the objects show them. DSR returns traffic from the backend node with the VIP as source, so return records appear at a different leaf; this is noted rather than flagged as an anomaly. With per-Service DSR (`bpf.lbModeAnnotation=true`, `loadBalancer.dsrDispatch=ipip`), the receiving node forwards to the backend node as IPIP (IP protocol 4, no ports). Those records are node-to-node encapsulation (`encapsulation=ipip`), like VXLAN, and never attach to pods. With masquerading on, pod traffic to destinations outside `ipv4NativeRoutingCIDR` shows the node IP on the fabric while Isovalent and Hubble show the pod.

Graph rows gain `endpoint_kind=k8s_service` nodes (label `<service> · <frontend ip>:<port>`, attributes type, traffic policy, LB mode when known) and a `forwards_to` relationship from a Service node to a pod with `handoff_basis`, `confidence` (`observed` or `inferred`) and `count`.

### ACI topology

`adm_topology` adds ACI leaves and spines (`topSystem`/`fabricNode`: name, role, model, serial, OOB address), leaf↔spine links (`fabricLink`, `link_source=aci`) and host attachments (`lldpAdjEp`, `link_source=lldp`). Between two leaves the candidate path shows every equal-cost spine as one stage ("one of 2 spines"); no collected source gives the hop order.

### Contract annotation

For each `communicates_with` edge the graph adds the ACI policy that should permit it, as intent, not proof:

- The client and server are classified as ACI classifies them. An ACI endpoint (`fvCEp`) belongs to its EPG. An address behind an EPG-attached host belongs to that host's EPG, because ACI classifies by the EPG of the ingress port and encapsulation: pod IPs on nodes in EPG `nodes` are EPG `nodes`. Only traffic entering through an L3Out, and non-endpoint destinations reached through it (VIPs, pod CIDRs of floating-SVI nodes), use the L3Out external EPG by `l3extSubnet` longest-prefix match.
- A contract applies when the client class consumes it (`fvRsCons`) and the server class provides it (`fvRsProv`), and one of its subjects' filters (`vzRsSubjFiltAtt` → `vzFilter` → `vzEntry`) matches the transport and server port.
- Edge fields: `contract`, `contract_subject`, `contract_filter`, `contract_entry` (`tcp 443` style), `contract_basis` (`intent`).
- ACL-log records add `acl_action` (`permit` or `drop`), `acl_leaf` and counts. Logging exists only where a subject uses `directives=log`.
- A conversation seen only in drop records becomes an edge with `acl_action=drop` ("Blocked by fabric"). Drops are logged only by contracts whose subject has `directives=log` (for example an explicit deny-with-log contract); a flow that simply matches no contract is not logged, so the absence of a drop record proves nothing.
- vzAny, preferred groups, taboo contracts, service graphs/PBR, ESGs and unenforced VRFs are not evaluated. When the collected objects show any of them in the VRF, the edge says "Policy not fully evaluated" instead of naming a contract.

## Saved searches

All ship `disabled = 1` with `enableSched = 1` and `dispatchAs = owner`. Set the macros and `adm_observer_scope.csv`, backfill the identity builder, then enable them. `schedule_priority = higher` is honored only for owners with the `edit_search_schedule_priority` capability.

| Saved search | Schedule | Index time | Event time | Scheduling |
| --- | --- | --- | --- | --- |
| ADM - Identity builder | `1-56/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Service binding | `2-57/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Interface inventory | `7 * * * *` | `-2h@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Conversation rollup | `*/5 * * * *` | `-10m@5m` → `-5m@5m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Identity prune | `4 3 * * *` | — | — | — |
| ADM - Service binding prune | `9 3 * * *` | — | — | — |

## Validation

`tests/splunk/` runs a local Splunk 10.6 container with the TAs' search-time configuration only (no inputs or vendor scripts):

```sh
tests/splunk/lab.sh up && tests/splunk/lab.sh install
ADM_LAB=1 python3 -m unittest tests/splunk/test_data_layer.py -v
```

The test resets the lab indexes and collections, ingests `fixtures/raw/*.ndjson`, writes a scope mapping, runs the builders, runs the rollup over one index-time slice, ingests `fixtures/raw/late/` and rolls up a second slice, runs `adm_graph`, and compares the result with `tests/splunk/expected/graph.json`, which is derived from `fixtures/raw/scenario.json` (edge cases are labelled `ec-` or `edge_case`). It also checks argument validation, per-bucket resolution, hostNetwork exclusion, ACI/ND endpoint merging, node replacement, orientation reconciliation, the boundary prefilters, ICMP, IPv4-mapped addresses, exact-once counting, and the prune's complete and incomplete paged reads (with lab-only macro overrides of the page size).
