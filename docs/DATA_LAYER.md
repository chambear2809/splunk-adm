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
| `adm_index_hubble` / `adm_hubble_sourcetypes` | `index=cilium_hubble` / `sourcetype="cilium:hubble:flow"` | Hubble flow export tailed by the OTel Collector |
| `adm_cilium_lb_mode` | `"snat"` | Cluster default Cilium `loadBalancer.mode` (quoted) for Services without `service.cilium.io/forwarding-mode` |
| `adm_cilium_ingress_mode` | `"dedicated"` | Cluster default Cilium Ingress mode (quoted) for Ingresses without `ingress.cilium.io/loadbalancer-mode` |
| `adm_k8s_object_staleness` | `0` | Seconds after the last observation at which Service frontend, Envoy address, backend and route rows end without a DELETED event or newer listing; `0` disables it (watch mode with `include_initial_state`). Use about twice the pull interval in pull mode. |
| `adm_handoff_window` | `1` | Seconds of tolerance when matching a client connection with Hubble evidence or a node's leg to a backend |
| `adm_conn_cap` | `50` | Connections (`client_port@start@end`) listed per summary row; rows with more are flagged `conns_capped` and reported by a graph warning |
| `adm_conn_gap` | `60` | Records of one client port to one server whose start is within this many seconds of the previous record's end are one connection |
| `adm_scope_peer_limit` | `500` | Boundary clients and dependencies whose direct conversations are included; more are reported |
| `adm_aci_policy_complete` | `0` | Set to `1` only when every ACI class that can permit traffic is collected; with `0`, a conversation no collected filter permits is `not_evaluated`, not `none` |
| `adm_index_summary` / `adm_summary_index_name` | `index=adm_summary` / `adm_summary` | Summary index read and written; keep them consistent |
| `adm_identity_retention` | `604800` | Seconds identity rows are kept after their validity ended |
| `adm_poll_interval` | `300` | APIC polling interval in seconds |
| `adm_k8s_node_staleness` | `0` | Seconds after the last pod observation at which a node row ends; `0` disables it (watch mode). Use about twice the pull interval in pull mode. |
| `adm_identity_max_matches` | `1000` | Must equal `max_matches` of the `adm_ip_identity` lookup (1000 is the maximum Splunk allows) |
| `adm_kv_max_rows` | `50000` | Must equal `limits.conf [kvstore] max_rows_per_query` |
| `adm_kv_page_size` | `10000` | Page size of `adm_kv_read_all`; requires `max_rows_per_query` of at least 10,000 |
| `adm_trace_limit` | `10000` | Boundary traces whose out-of-boundary spans are read; at most `limits.conf [subsearch] maxout` |

`adm_observer_scope` (`lookups/adm_observer_scope.csv`, columns `observer_kind,observer,scope,cluster`) maps observers to a routing `scope`. Observer kinds: `exporter` (NetFlow `exporter_ip`), `fabric` (ND `fabricName`), `firewall` (FTD `DeviceIP`), `hec_source` (Isovalent HEC `source`, one token per cluster), `cluster` (`k8s.cluster.name`; also Hubble flows and Kubernetes Service frontends), `apic` (`apic_host`; also ACI ACL-log records), `nd_host` (`nd_host`). The shipped file has only the header; unmapped observers fall into scope `default`. Identity only joins within one scope.

## Normalized flow records

Generating macro `adm_flows` (call as `` | `adm_flows` ``) runs `multisearch` over `adm_flows_netflow`, `adm_flows_nd`, `adm_flows_ftd`, `adm_flows_isovalent`, `adm_flows_hubble` and `adm_flows_acllog`, then applies the interface and scope lookups:

| Field | Meaning |
| --- | --- |
| `adm_source` | `netflow`, `nd`, `ftd`, `isovalent`, `hubble` (backend flows), `hubble_xlate` and `hubble_l7` (hand-off evidence, see below), `aci_acllog` |
| `adm_kind` | `conv` for flow records; `xlate` and `l7` for Hubble hand-off evidence |
| `adm_observer`, `adm_observer_kind` | Exporter IP / ND fabric / FTD device IP / Kubernetes node (Isovalent, Hubble) / ACI leaf `pod-N/node-N` (ACL log); `exporter`, `fabric`, `firewall`, `host_sensor`, `acl_leaf` |
| `adm_scope`, `adm_cluster` | From `adm_observer_scope` |
| `adm_src_ip`, `adm_src_port`, `adm_dest_ip`, `adm_dest_port` | Tuple as recorded. IPs are lower-cased and IPv4-mapped IPv6 (`::ffff:a.b.c.d`, full and hexadecimal forms) is unwrapped. Ports are empty for portless protocols such as ICMP. |
| `adm_transport` | `tcp`, `udp`, `icmp`, `ipv6-icmp`, `ipip`, `sctp` or the lower-cased value; NetFlow `protoid` mapped |
| `adm_bytes_fwd`, `adm_bytes_rev`, `adm_packets` | Bytes src→dest and dest→src. NetFlow is scaled by `exporter_sampling_interval` when > 1. ND uses the first `stats{}` entry's ingress counters (the TA's `EVAL-bytes` adds ingress and egress and double counts). FTD uses initiator/responder bytes. Isovalent has none (empty, not 0). |
| `adm_start`, `adm_end` | Epoch seconds from explicit fields: NetFlow `timestamp`/`endtime`; ND `ts`; FTD `FirstPacketSecond`; Isovalent `time`. ND, FTD and Isovalent expose a start only, so `adm_end = adm_start`. |
| `adm_in_if`, `adm_out_if` | NetFlow: interface name from `adm_interfaces`, otherwise `ifIndex <n>` (default NX-OS commands report ifIndex only for CDP-connected ports). ND: `<node>:<vif>`. FTD: interface names. |
| `adm_initiator` | `src` for FTD, Isovalent and Hubble (FTD and Isovalent name the initiator; Hubble `TO_ENDPOINT` flows are kept only in the original direction, `is_reply` false); otherwise `unknown` |
| `adm_acl` | `permit` or `drop` for ACI ACL-log records (`acllogPermitL3Pkt`, `acllogDropL3Pkt`) |
| `adm_xlate_ip`, `adm_xff`, `adm_trace_id` | Hubble: `IP.source_xlated` of SNAT forwarding traces; for L7 requests the rightmost `X-Forwarded-For` entry (the address Envoy appends for its immediate downstream peer; with `xff_num_trusted_hops` 0 earlier entries are client-supplied and never used), kept only when it is an IP literal (requests without one are dropped); the trace ID only as 32 lower-case hex digits. |

Hubble records come from the open-source exporter's JSON lines (`{"flow":{…},"node_name":"<cluster>/<node>","time":…}`, Cilium `flow.proto` field names) and rely on Splunk's automatic JSON field extraction; the base search keeps only events mentioning `TO_ENDPOINT`, `TO_NETWORK` or `REQUEST`. Only `L3_L4` `TO_ENDPOINT` forwarded flows in the original direction become flow records (the post-translation tuple at the backend pod); `TO_NETWORK` traces with `IP.source_xlated` and `L7` HTTP requests are evidence. Hubble flows carry no byte counts. The Isovalent Enterprise export is not modeled: `adm_flows_hubble_enterprise` is a documented placeholder outside `adm_flows`. ACL-log records count logged packets at the enforcing leaf. A record stays in the leaf's buffer and is re-reported by later polls, so only the report from the first poll after its `timeStamp` (poll time minus `timeStamp` at most `adm_poll_interval` + 60 s) is counted.

No inspected TA extracts a translated (NAT) tuple, so no NAT fields are produced. NetFlow `flow_dir` is never used.

## Conversations

Saved search **ADM - Conversation rollup** (`` | `adm_conversation_rollup` | collect ``) runs every 5 minutes and selects flow records **by index time**: `dispatch.index_earliest = -10m@5m`, `dispatch.index_latest = -5m@5m`, with event-time bounds `-24h` to `+15m` (records older than 24 hours when indexed, or more than 15 minutes in the future, are not counted). Consecutive runs read disjoint index-time slices, so every record is counted exactly once, however late it arrives. Continuous scheduling (`realtime_schedule = 0`) makes delayed runs catch up instead of skipping slices.

Records are bucketed by `adm_end` into 5-minute buckets. Each run writes `source="adm:conversation"`, `sourcetype=stash`, `adm_record=conversation`, `_time` = bucket start, one event per (`scope`, `client_ip`, `server_ip`, `server_port`, `transport`, bucket, `observer`):

`flow_source`, `observer` (`source:observer`), `observations` (pipe-delimited `source:observer[:in_if>out_if]`, because `collect` flattens multivalue fields), `bytes_c2s`, `bytes_s2c`, `packets`, `records`, `client_ports` (distinct), `client_port_list` and `conns` (up to `adm_conn_cap` client ports and `client_port@start@end` triples, pipe-delimited), `conns_capped` (1 when there were more), `sampled` (1 when a NetFlow record was sampled at more than 1:1), `first_seen`, `last_seen`, `direction_basis`, `encapsulation`, `acl_permits`, `acl_drops`. Hubble SNAT traces are written as `adm_record=hubble_xlate` rows with `xlate_ip`; Hubble L7 requests as `adm_record=hubble_l7` rows grouped per X-Forwarded-For client (`xff`) with `trace_ids`. ACL-log records are also deduplicated by APIC object DN within a run.

Client and server are decided per record, in this order, and recorded in `direction_basis`:

1. `initiator`: the source names the initiator (FTD, Isovalent).
2. `port_rule`: one side uses a port below 1024 and the other does not, or one side uses an ephemeral port (≥ 32768) and the other does not; the other side is the server.
3. Reconciliation: a record with neither inherits the orientation of another record in the same run with the same address pair, transport and bucket whose server endpoint (IP and port) is one of its endpoints; it keeps that record's basis (`initiator` or `port_rule`). A gRPC server on port 50051 seen by NetFlow and by Isovalent therefore yields one conversation.
4. `unknown`: endpoints are ordered by IP so both directions merge; the UI shows the edge undirected.

UDP to port 8472 (VXLAN) or 6081 (Geneve) and IPIP (IP protocol 4) are merged regardless of direction (`direction_basis=unknown`, server port = tunnel port, `-` for IPIP). `encapsulation` is `vxlan`, `geneve` or `ipip` when both IPs are Kubernetes node identities. Reverse-direction NetFlow records of one conversation produce one conversation, never a reversed edge.

## Identity (KV store)

Collection `adm_ip_identity` (lookup `adm_ip_identity`, `max_matches = 1000`), one row per (source, entity, IP, scope):

`ip`, `scope`, `entity_kind` (`pod`, `k8s_node`, `k8s_node_proxy`, `k8s_service`, `vm`, `endpoint`), `entity_id` (pod or Service UID, `<cluster>/<node>`, ACI endpoint DN, ND endpoint ID), `entity_name`, `cluster`, `namespace`, `owner_kind`, `owner_name`, `node`, `tenant`, `app_profile`, `epg`, `attach_device`, `attach_interface`, `mac`, `vm_name`, `valid_from`, `valid_to` (empty while present), `valid_end` (end used for resolution and pruning), `first_seen`, `last_seen`, `priority`, `source`, `ek` (entity key), `updated`, Service frontend fields (`port`, `transport`, `service`, `svc_type`, `traffic_policy`, `lb_mode`, `controller`, `owner_ref_kind`, `owner_ref_name`, `target_port`), and `desc` (JSON of these fields, returned by lookups). VRF is not stored: the collected ACI objects do not relate an endpoint to its VRF.

**ADM - Identity builder** (`adm_identity_build`, every 5 minutes, index time `-10m@m` to `@m`, event time `-24h` to `+15m`, continuous scheduling) reads new observations and upserts them:

- **Kubernetes pods** (`source=k8s_pods`, priority 1): watch events (`type` ADDED/MODIFIED/DELETED) or pull snapshots. `valid_from` is `status.startTime`, else the first ADDED, else the first observation; `valid_to` is the DELETED event time. Each `status.podIPs` entry is a row. Pods with `spec.hostNetwork: true`, or whose pod IP equals `status.hostIP`, are not IP owners. A ReplicaSet owner becomes a Deployment only when its name is `<deployment>-<pod-template-hash label>`. Events without `k8s.cluster.name` are stored with cluster `unknown` and reported in the builder's warnings.
- **Kubernetes nodes** (`source=k8s_nodes`, priority 2): `status.hostIP` and `spec.nodeName` of pod objects (including hostNetwork pods), and `status.addresses` (InternalIP, ExternalIP) of Node objects (`valid_from` = `metadata.creationTimestamp`); not created for cluster `unknown`.
- **Cilium ingress (Envoy) addresses** (`source=k8s_node_proxy`, `entity_kind=k8s_node_proxy`, priority 2): the Node annotations `network.cilium.io/ipv4-Ingress-ip` / `ipv6-Ingress-ip`, tied to the node (`node`).
- **Service frontends** (`source=k8s_services`, `entity_kind=k8s_service`, priority 0): one row per Service, frontend address, port and transport: each `status.loadBalancer.ingress[].ip` and `spec.externalIPs` with `spec.ports[].port`, and each `spec.ports[].nodePort` of NodePort and LoadBalancer Services under the pseudo-address `nodeport:<cluster>:<nodePort>/<transport>` (an exact lookup key; resolution builds it for any node IP and port). `port_name` is the Service port name, used to pick the EndpointSlice port (m3: a named `targetPort` is resolved through it). `lb_mode` is `service.cilium.io/forwarding-mode`, else `adm_cilium_lb_mode`; `controller` is `cilium_gateway` (owner Gateway or `io.cilium.gateway/owning-gateway` label) or `cilium_ingress` (owner Ingress or `cilium.io/ingress=true`). A frontend row ends with the Service's DELETED event, when another Service later takes the same address, port and transport, or after `adm_k8s_object_staleness`; a LoadBalancer IP that changes while the Service lives is not closed.
- **hostNetwork pods** (`source=k8s_hostnet`, `entity_kind=k8s_hostnet_pod`, priority 9) on the node IP: they never resolve an address, but they mark nodes whose own processes could have opened a connection, which blocks time-inferred hand-offs from that node.
- **ACI endpoints** (`source=aci`, priority 3): `fvCEp` IPs (`ip` and child `fvIp addr`). Tenant, application profile and EPG come from the DN; `attach_device`/`attach_interface` from `fvRsCEpToPathEp tDn` (`pod-<n>/node-<id>`, `eth1/5`); `vm_name` through `fvRsVm`→`compVm`. Switch names are not resolved because the default inputs do not relate `topSystem` to paths. `valid_end` is the last report plus two polling intervals, so an endpoint that stops being reported expires.
- **Nexus Dashboard endpoints** (`source=nd_endpoints`, priority 3): the input collects endpoint changes incrementally from a checkpoint (`bin/cisco_dc_nd_collector.py:757-800`), so stable endpoints are not re-reported and no staleness applies. `valid_from` is `createTime`; `valid_to` is a `modType=deletion` record or the start of another endpoint with the same IP and scope.

The builder never reads the whole collection. For each new observation it reads the stored rows of the same IP and scope through the lookup (at most `max_matches`), merges first/last seen and validity, keeps the newest non-empty attribute values, and closes an open pod, node, Envoy address, Service frontend (same port and transport) or ND endpoint interval at the `valid_from` of the next different entity with that IP. Changed rows are written with `outputlookup append=true key_field=_key override_if_empty=false`. When an IP returns `adm_identity_max_matches` stored rows, closing is skipped for it and the builder's summary row carries a warning. The builder returns one row: `rows_written`, `rows_observed`, `rows_closed`, `truncated_ips`, `rows_missing_cluster`, `warnings`. Overlapping index-time windows are harmless (merges are idempotent). Backfill by dispatching it once with `dispatch.index_earliest=-7d`.

**ADM - Identity prune** (daily 03:04) reads the collection with `adm_kv_read_all`: 20 pages of 10,000 rows plus a probe at offset 1. It rewrites the collection without rows whose `valid_end` is older than `adm_identity_retention` only when the read is provably complete: pages contiguous, every page before the last full, the page after the last read and empty, and a short first page whose probe returned exactly one row fewer (otherwise the store capped the read). Otherwise it writes nothing and returns a warning. It never empties the collection (`override_if_empty=false`). **ADM - Service binding prune** (daily 03:09) does the same for `adm_service_workload` by `last_seen`.

**Concurrency.** Each saved search runs one instance at a time (`max_concurrent` default 1). The builder and prune both write `adm_ip_identity`; a row upserted by the builder while the prune reads could be dropped by the prune's rewrite. The prune is scheduled at 03:04, when no builder run starts (`schedule_window = 0`), and a dropped row reappears when its entity is next observed. Do not run the prune by hand while builders run.

Collection `adm_service_workload` (**ADM - Service binding**, every 5 minutes, same windows) binds an OTel service (`service.name`, `deployment.environment.name`, `k8s.cluster.name`, `k8s.namespace.name`) to `k8s.pod.uid` with first/last seen (upsert by `_key`). Collection `adm_interfaces` (**ADM - Interface inventory**, hourly, index time `-2h@m`) maps (`device_ip`, `ifindex`) to `interface` and CDP neighbor (upsert; bounded by device ports, never pruned).

**ADM - Service backends** (`adm_k8s_service_build`, every 5 minutes, same windows) upserts two collections from Kubernetes objects:

- `adm_service_backends`: one row per EndpointSlice endpoint (`targetRef` pod), Service (`kubernetes.io/service-name`) and slice port: `cluster`, `namespace`, `service`, `slice_uid`, `pod_uid`, `pod_name`, `ip`, `node`, `target_port`, `protocol`, `port_name`, validity. Endpoints with `conditions.ready=false` and endpoints without `targetRef` (the placeholder endpoint Cilium adds to Gateway and Ingress Services) are not backends.
- `adm_service_routes`: one row per HTTPRoute rule backend × `parentRefs` (`parent_kind=Gateway`, `parent_namespace` = the parentRef's namespace or the route's) and per Ingress rule path (`parent_kind=Ingress`, or `IngressShared` when `ingress.cilium.io/loadbalancer-mode` or `adm_cilium_ingress_mode` is shared): `host`, `path`, `backend_namespace`, `backend_service`, `backend_port`, validity. A Gateway in another namespace (for example a shared Gateway in `gateway-system`) is matched through `parent_namespace`.

Each run merges with the stored rows of the same EndpointSlice or route (lookup by `slice_uid`/`route_uid` and cluster): a child present in the run continues its stored open interval (same `_key`, earliest `valid_from` and `first_seen` kept), so later MODIFIED events and pull re-polls never move `valid_from`. A child absent from a later listing of its parent (including a listing whose endpoints are all not ready) or from a DELETED event is closed at that listing; a child that reappears after being closed starts a new interval (new `_key`). When a parent returns `max_matches` stored rows the builder warns that intervals may not have been merged or closed. **ADM - Service backends prune** and **ADM - Service routes prune** (daily) remove rows whose validity ended before `adm_identity_retention`, after a complete paged read.

**ADM - ACI policy** (`adm_aci_policy_build`, every 5 minutes) upserts `adm_aci_policy`, one row per APIC object DN: contracts (`vzBrCP`, with `contract_scope`), subjects (`vzSubj`), subject-filter relations (`vzRsSubjFiltAtt`: `filter_dn`, `action`, `directives`), filter entries (`vzEntry`: `prot`, `d_from`, `d_to`, `s_from`, `s_to`, `tcp_rules`, `ether_t`), consumer and provider relations (`fvRsCons`, `fvRsProv`: `class_dn`, `contract_dn`), external EPG subnets (`l3extSubnet`), preferred-group membership and enforcement preference (`l3extInstP`, `fvAEPg`/`fvEPg`, `fvCtx` `pcEnfPref`), subject in/out terms (`vzInTerm`, `vzOutTerm`), and policy the graph does not evaluate (`vzRsAnyToCons`, `vzRsAnyToProv`, `vzRsAnyToConsIf`, `vzTaboo`, `fvRsProtBy`, `fvESg`, `vzRsSubjGraphAtt`: `object_kind=unsupported`). The graph uses objects polled within three polling intervals of the window. **ADM - ACI policy prune** removes objects not polled within `adm_identity_retention`.

**Kubernetes object collection.** With `mode: watch`, the k8sobjects receiver of the collector that chart 0.161.0 pins (contrib v0.161.0) emits only changes unless the receiver-level option `include_initial_state: true` is set; it then sends existing objects once as synthetic `ADDED` events (`receiver/k8sobjectsreceiver/README.md:61-62`, `internal/k8sinventory/watch/observer.go:225-299`). The chart renders only `auth_type` and `objects` for that receiver (`templates/config/_otel-k8s-cluster-receiver-config.tpl:50-53`), so the option must be set through `clusterReceiver.config`, which the chart merges over its default configuration (`templates/configmap-cluster-receiver.yaml:21`). Without it, stable objects that existed before the collector started (for example a Service or Node that never changes) are never seen in watch mode. The builders accept watch events (`type`, `object`), pull snapshots (the object as the body) and both mixed; use `adm_k8s_node_staleness` / `adm_k8s_object_staleness` in pull mode.

**Resolution.** For a conversation bucket `[first_seen, last_seen]`, an identity row covers it when `valid_from ≤ first_seen` and `last_seen < valid_end` (or `valid_end` is empty). Among covering rows at the best (lowest) priority, rows with the same entity key count as one entity: a pod or node is one entity; ACI and ND rows with the same scope, IP and MAC are one endpoint (a row without MAC joins it). One entity is `resolved`; several are `ambiguous`; none is unresolved. Attributes come from the first non-empty value across covering rows in priority order, ACI before ND, so a Kubernetes node shows its ND leaf port.

## Graph search

Macro `adm_graph(service, environment, cluster, namespace)` runs on demand over the search time range. The application boundary is the Kubernetes namespace. It returns rows with `row_type=node`, `edge` or `meta`; the UI assembles them into its graph model and rejects rows that break the contract (unknown node kinds, edges whose endpoints are missing or of the wrong kind, more than 500 nodes or 2,000 edges). Stages are separate macros: `adm_graph_inputs`, `adm_graph_resolve`, `adm_graph_handoffs`, `adm_graph_edges`, `adm_graph_contracts`, `adm_graph_output` (and the subsearch body `adm_graph_scope_filter(cluster, namespace)`).

**Argument validation.** `adm_graph` and every stage macro reject arguments not matching (PCRE, `\z` = end of string; identical to the UI's `ARG_RULES`):

| Argument | Pattern |
| --- | --- |
| service | `^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\z` |
| environment | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z` |
| cluster | `^[A-Za-z0-9][A-Za-z0-9._-]{0,252}\z` |
| namespace | `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\z` |

- **Inputs:** summary rows (conversations and Hubble hand-off evidence) whose `client_ip` or `server_ip` is an IP of a boundary pod, of a node hosting one, or of a LoadBalancer frontend of the namespace's Services or of a Gateway its HTTPRoutes attach to (also in another namespace); conversations to any node of the cluster on a NodePort of those Services (also nodes without application pods); and conversations from the boundary's clients (other than Kubernetes nodes and Envoy addresses) to the boundary's dependencies, so that direct or blocked attempts to bypass the application show (at most `adm_scope_peer_limit` clients and dependencies; a meta warning reports more). The filter is built by the subsearch `adm_graph_scope_filter` over `adm_ip_identity`, `adm_service_routes` and the summary; only IP literals and port numbers are inserted into the search string, so very large namespaces are bounded by search-string size and the identity read cap, which is reported. A Splunk subsearch that hits its time or result limit is reported by Splunk as a job message, not by the graph. Spans of the boundary (`k8s.cluster.name::` and `k8s.namespace.name::` indexed fields) plus all spans of at most `adm_trace_limit` boundary traces (subsearch), each with its parent's service found within the trace. Summary rows are summed per (conversation, bucket, observer) across rollup runs.
- **Resolution per bucket:** each (conversation, bucket) is resolved over that bucket's interval, so an IP reused inside the window resolves to the right pod in each bucket. Edges then aggregate by the resolved entity IDs.
- **Services and `calls`:** a service is `service:<cluster>/<namespace>/<service.name>/<environment>`. `calls` edges (`confidence=observed`) are cross-service parent/child spans whose parent service is in the boundary; `count` is the number of child spans; `evidence` lists `span:<trace>/<span>`.
- **`runs_on`:** service → `pod:<cluster>/<uid>` from `adm_service_workload` rows overlapping the window (`confidence=correlated`).
- **`communicates_with`:** conversations where either side resolves to a boundary pod or the server to a Service frontend of the namespace, and client-to-dependency conversations as above. The other side is a pod (any namespace, e.g. CoreDNS), `node:<cluster>/<node>`, `k8s_service:<cluster>/<namespace>/<service>/<frontend ip>:<port>`, `k8s_node_proxy:<cluster>/<node>` (Envoy), `vm:<scope>/<ip>` (ACI/ND endpoint with EPG/tenant/VM/leaf attributes), or `ip:<scope>/<ip>` with `endpoint_kind` `external` (public address), `unresolved` or `ambiguous`. Tunnel conversations (VXLAN, Geneve, IPIP) are included only between nodes that host boundary pods and only connect `node:` endpoints. Backend-side connections that a hand-off explains (a Hubble backend flow matched by client tuple; a receiving node's SNAT leg matched by a trace or by timing) are not shown separately. `confidence` is `correlated` when both sides resolve in every bucket, otherwise `unresolved`.
  - `bytes`: per observer, `bytes_c2s + bytes_s2c` summed across buckets and runs; the edge takes the largest observer total. Empty when no observer reports bytes (for example Isovalent only).
  - `count`: client connections: the `conns` of every observer row of the edge, merged per client port when a record starts within `adm_conn_gap` seconds of the previous record's end (return records, other observers, active-timeout re-exports); ACL-log-only conversations count logged records.
  - `evidence` (sources plus `span_peer`), `observers`, `sources`, `server_port` (empty for portless protocols), `transport`, `direction_basis`, `encapsulation` (`vxlan` or `geneve`; IPIP stays visible as `transport=ipip`), `span_ids`, `via_node` (receiving node, on conversations to a Service frontend), `acl_action` (`drop` when any drop was logged, else `permit`), `acl_leaf` (`pod-N/node-N`), `acl_permits`, `acl_drops`, and the contract fields below.
- **Span association (`span_peer`):** a CLIENT span is attached to a conversation when its `network.peer.address` and `server.port` equal the conversation's server IP and port, its `k8s.pod.uid` is the pod that owns the client IP, and the span overlaps the conversation interval within one second.
- **Nodes:** `id`, `label`, `kind` (`service`, `workload`, `endpoint`), `endpoint_kind`, `namespace`, `cluster`, `addresses` (union), `reason`, and `attr_*` (`attr_environment`, `attr_owner`, `attr_owner_kind`, `attr_node`, `attr_tenant`, `attr_app_profile`, `attr_epg`, `attr_vm_name`, `attr_mac`, `attr_attach_device`, `attr_attach_interface`, `attr_scope`; Service frontends: `attr_service`, `attr_frontend`, `attr_type`, `attr_traffic_policy`, `attr_lb_mode`, `attr_controller`, `attr_route`, and `attr_handoff=service_only` with `attr_candidates` when no backend could be determined; Envoy: `attr_node`). Pod and service facts from identity and spans win over edge-derived copies.
- **Meta row:** `window_start`, `window_end`, `spans`, `conversations`, `conversations_in_scope`, `matched_conversations`, `unresolved_conversations`, `ambiguous_conversations` (counts of (conversation, 5-minute bucket) pairs), `missing_parent_spans`, `root_present`, `nodes`, `edges`, `warnings`, `generated_at`. Warnings cover a missing entry service, missing parents, ambiguous identities, identity reads that reached `adm_identity_max_matches`, more boundary traces than `adm_trace_limit`, spans without `k8s.cluster.name`, a boundary pod, Service backend or ACI policy read that reached `adm_kv_max_rows`, summary rows whose connection list was capped at `adm_conn_cap`, fabric records folded into a client-tuple hand-off (DSR with `dsrDispatch=opt`), a capped scope filter, and graphs over 500 nodes or 2,000 edges. `window_start` and `window_end` are integer epoch seconds.
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

External clients (for example a Windows VM in an ACI EPG) reach a Kubernetes app through a Cilium LoadBalancer VIP (LB IPAM, BGP), a NodePort, Cilium Ingress/Gateway API (Envoy; the only supported ingress), or a pod IP directly, with `externalTrafficPolicy` `Cluster` or `Local` and Cilium load balancing in SNAT, DSR or hybrid mode. The NX-OS design above stays supported; the pilot path is ACI. Validated by `tests/splunk/test_aci.py` against `fixtures/raw-aci/`.

### Additional sources

| Source | Sourcetype | Use |
| --- | --- | --- |
| Hubble flow export (open source), tailed by the Splunk OTel Collector (`logsCollection.extraFileLogs`) | `cilium:hubble:flow` in `cilium_hubble` (macros `adm_hubble_sourcetypes`, `adm_index_hubble`) | Post-translation flows at the backend (`TO_ENDPOINT`), SNAT forwarding traces (`TO_NETWORK` with `IP.source_xlated`), L7 HTTP requests with `X-Forwarded-For` and trace context. Schema: Cilium `flow.proto`; envelope `{"flow":{…},"node_name":"<cluster>/<node>","time":…}`. |
| Isovalent Enterprise flow export | Not modeled | `adm_flows_hubble_enterprise` is a documented placeholder outside `adm_flows`; it is filled in after a real sample is inspected. |
| Kubernetes objects (Helm `clusterReceiver.k8sObjects`) | `kube:object:services`, `kube:object:endpointslices`, `kube:object:ingresses`, `kube:object:httproutes`, `kube:object:nodes` (`kube:object:gateways` is not needed: Cilium's Gateway Service names its Gateway as owner) | Service frontends, backends, routes, Cilium per-node ingress IP. |
| ACI fabric (DC Networking `classInfo`) | `cisco:dc:aci:class` | `topSystem` (names, roles, OOB addresses), `fabricLink` and fabric `lldpAdjEp` (leaf↔spine), host `lldpAdjEp` (attachment by LLDP system name), contracts and external EPG subnets, ACL-log records. `fabricNode` and `vzFilter` are not used (the subject-filter relation carries the filter DN). |
| ACI NetFlow v9 via Stream, Nexus Dashboard flows for the ACI site | `stream:netflow`, `cisco:dc:nd:flows` | Fabric observations; either or both. ACI exports from each leaf's OOB address, so `exporter_ip` maps to `topSystem.oobMgmtAddr`; records carry the ingress interface only. |

### Identity

Service frontends, Envoy addresses and Node objects are identity rows (see Identity above); backends and routes are in `adm_service_backends` and `adm_service_routes`. Conversation resolution checks the server side against port-qualified frontends first (priority 0): the server IP's own rows, and for a Kubernetes node IP also the `nodeport:<cluster>` rows; only frontends with the conversation's port and transport cover it. A frontend hit resolves the server to the Service, never directly to a pod. Pod IPs and VIPs are never ACI endpoints. Node attachment on ACI comes from the node's `fvCEp` path when nodes sit in an EPG/BD; for floating-SVI L3Out nodes, whose IPs are not endpoints, the topology's LLDP host links attach the node by name.

### Attribution from frontend to backend pod

`adm_graph_handoffs` links each client connection to a Service frontend with the backend pod that served it. A connection is a client port's records from all observers (forward and return NetFlow records, Nexus Dashboard copies, active-timeout re-exports) merged when a record starts within `adm_conn_gap` seconds of the previous one's end. Candidate backends are the EndpointSlice pods of the frontend's Service port (matched by port name) valid during the conversation; for Cilium Gateway and Ingress Services, the pods of the backend Services of the routes attached to that Gateway or Ingress (by namespace and name, so a shared Gateway in another namespace works). Rules, strongest first; times match within `adm_handoff_window` seconds:

| Access method and policy | Rule (`handoff_basis`) | Confidence | Receiving node (`via_node`) |
| --- | --- | --- | --- |
| LoadBalancer or NodePort with `Local`; any policy with DSR; Cluster when the receiving node served it locally | `hubble_client_tuple`: a Hubble backend (`TO_ENDPOINT`) flow at a candidate with the connection's client IP and port | observed | NodePort: the frontend's node; DSR: the source node of an IPIP/VXLAN tunnel record to the backend's node at that time; otherwise the backend's node |
| LoadBalancer or NodePort, Cluster with SNAT to a remote backend | `hubble_xlate`: Hubble SNAT traces (`TO_NETWORK` with `IP.source_xlated`) from the client to a candidate (from the NodePort node for NodePorts). Traces carry the post-SNAT port, not the client port, so pairing is by client and time: a connection is attributed only when its conversation has at least as many traces as connections with traces, and its traces all lead to one backend. | observed | The node that emitted the trace |
| Same, without a usable trace | `time_inferred`: exactly one leg from a Kubernetes node (the NodePort node for NodePorts) to a candidate starts within the window, the leg is not explained by any SNAT trace, a leg with the client's source port is preferred when one exists, and no other connection could use that leg. Never when the records are sampled, the leg's node hosts a candidate (the connection may have been served locally), or a hostNetwork pod runs on that node. | inferred | That leg's node |
| Cilium Ingress/Gateway (Envoy) | `l7_forwarded_for`: Hubble L7 requests at a candidate during the connection, sent from the Envoy address of the node that reported them, whose rightmost X-Forwarded-For (the address Envoy appends for its immediate peer) is the client. Earlier, client-supplied entries are never used, and the client must have a conversation to this Gateway or Ingress frontend at that time; a request that matches several connections is ignored. | observed | The node whose Envoy reported the requests |
| None of the above | No `forwards_to` edge for the connection; a frontend with no determined connection carries `attr_handoff=service_only` and `attr_candidates` | — | — |

A direct pod-IP connection needs no hand-off: the server resolves to the pod, and the Hubble backend flow adds its observer to that edge.

`forwards_to` edges go from the frontend node to the pod, one per (frontend, pod, `handoff_basis`), with `confidence`, `count` (connections), `via_node` (all receiving nodes, multivalue), `evidence` (the basis) and `observers` (`hubble:<node>`). One frontend–pod pair can have an observed and an inferred edge. On a client→frontend edge, `via_node` lists the receiving nodes of that client's connections; for `hubble_client_tuple` the Hubble observer is added to that edge. The backend-side records a hand-off explains are consumed per connection and not drawn: Hubble backend flows of matched connections, SNAT legs (node to pod) explained by any trace or assigned by timing, and VM-to-pod fabric records of a client-tuple match (see the DSR note). Legs of connections no rule can attribute stay visible as node-to-pod conversations. The Envoy upstream connection (`k8s_node_proxy` → pod) stays a separate conversation.

**Caveats.**

- Connections are listed per summary row up to `adm_conn_cap`; a row with more is flagged `conns_capped`, its connections beyond the cap cannot be matched, and the meta row warns. A capped backend-side row is consumed when all its listed connections are.
- Hubble backend flows and the fabric observations of the frontend conversation must resolve in the same routing scope: map the Kubernetes cluster (`cluster` rows of `adm_observer_scope`) and the ACI exporters, fabric and APIC to one scope.
- DSR: with `loadBalancer.dsrDispatch=ipip` (or Geneve) the receiving node's leg to the backend node is node-to-node encapsulation, never attached to pods. With `dsrDispatch=opt` the fabric shows the client talking straight to the backend pod; when a client-tuple hand-off explains such a record, it is folded into the hand-off and the meta row warns (`dsrDispatch opt`), instead of a direct client→pod edge being drawn.
- With masquerading on, pod traffic to destinations outside `ipv4NativeRoutingCIDR` shows the node IP on the fabric; that node→destination leg is not attributed to the pod (the Isovalent or Hubble record of the pod's connection is shown instead).
- Not implemented: warnings for `Local` traffic landing on a node without a local endpoint, and for L2 announcements combined with `Local`.

### ACI topology

`adm_topology` adds ACI leaves, spines and controllers (`topSystem`: name, `role`, serial, OOB address, `aci_node` = `pod-N/node-N`), leaf↔spine links from `fabricLink` and fabric `lldpAdjEp` adjacencies (`link_source=aci`, both directions and both sources merged into one row), and host attachments from `lldpAdjEp` on leaf access ports (`link_source=lldp`, `a_device` = leaf, `a_interface` = port, `b_device` = the host's LLDP system name). Between two leaves the candidate path shows every equal-cost spine as one stage ("one of 2 spines"); no collected source gives the hop order. A warning appears when ACI leaves are present without `fabricLink` or `lldpAdjEp`.

### Contract annotation

`adm_graph_contracts` adds, for each `communicates_with` edge, the ACI policy that should apply, as intent, never claiming more than the collected policy supports:

- **Classification** (as ACI classifies traffic): a side whose IP is an ACI endpoint (`fvCEp`) during the conversation belongs to that EPG. A client pod or Envoy address belongs to its node's EPG, because ACI classifies by ingress port and encapsulation. Other addresses (VIPs, pod IPs as destinations, floating-SVI nodes, external addresses) use the longest-prefix external EPG subnet (`l3extSubnet` scope `import-security`) of the same tenant. Unresolved and ambiguous addresses are not classified, and `0.0.0.0/0` classifies only public addresses.
- **Match:** a contract applies when the client class consumes it (`fvRsCons`), the server class provides it (`fvRsProv`), its scope allows the pair (`application-profile` needs one AP), and a subject's filter (`vzRsSubjFiltAtt` → `vzEntry`) matches the transport (protocol names and numbers normalized, `icmpv6` = `ipv6-icmp`) and server port (`unspecified` matches any; APIC named ports are mapped).
- **`contract_basis`:**
  - `intra_epg`: both sides are in one EPG (`not_evaluated` if the EPG is collected with intra-EPG isolation, `pcEnfPref=enforced`).
  - `intent`: only permit entries match (fields `contract`, `contract_subject`, `contract_filter`, `contract_entry` such as `tcp 443`, `tcp 30080-30081`, `ip`).
  - `none`: only deny entries match and either `adm_aci_policy_complete` is 1 or a drop was logged; or nothing matches and `adm_aci_policy_complete` is 1.
  - `not_evaluated`: everything else: an unclassified side, sides in different tenants, a tenant with collected vzAny relations, taboos, ESGs, service graphs or an unenforced VRF (`fvCtx pcEnfPref=unenforced`), a preferred-group member, a matching entry with source ports or `tcpRules` or in a subject with `vzInTerm`/`vzOutTerm`, permit and deny entries matching together (precedence not evaluated), or no match while `adm_aci_policy_complete` is 0.
- No contract fields when the two sides are on the same Kubernetes node (the traffic never reaches the fabric) or when no ACI policy is collected.
- **ACL-log records** add `acl_action` (`drop` when any drop was logged, else `permit`), `acl_leaf`, `acl_permits` and `acl_drops`. Logging exists only where a subject uses `directives=log`. A conversation seen only in drop records is an edge with `acl_action=drop`. A flow that simply matches no contract is not logged, so the absence of a drop record proves nothing.

## Saved searches

All ship `disabled = 1` with `enableSched = 1` and `dispatchAs = owner`. Set the macros and `adm_observer_scope.csv`, backfill the identity builder, then enable them. `schedule_priority = higher` is honored only for owners with the `edit_search_schedule_priority` capability.

| Saved search | Schedule | Index time | Event time | Scheduling |
| --- | --- | --- | --- | --- |
| ADM - Identity builder | `1-56/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Service binding | `2-57/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Interface inventory | `7 * * * *` | `-2h@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Conversation rollup | `*/5 * * * *` | `-10m@5m` → `-5m@5m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Service backends | `3-58/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - ACI policy | `6-56/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Identity prune | `4 3 * * *` | — | — | — |
| ADM - Service binding prune | `9 3 * * *` | — | — | — |
| ADM - Service backends prune | `14 3 * * *` | — | — | — |
| ADM - Service routes prune | `19 3 * * *` | — | — | — |
| ADM - ACI policy prune | `24 3 * * *` | — | — | — |

## Validation

`tests/splunk/` runs a local Splunk 10.6 container with the TAs' search-time configuration only (no inputs or vendor scripts):

```sh
tests/splunk/lab.sh up && tests/splunk/lab.sh install
ADM_LAB=1 python3 -m unittest tests/splunk/test_data_layer.py tests/splunk/test_topology.py tests/splunk/test_aci.py -v
```

The test resets the lab indexes and collections, ingests `fixtures/raw/*.ndjson`, writes a scope mapping, runs the builders, runs the rollup over one index-time slice, ingests `fixtures/raw/late/` and rolls up a second slice, runs `adm_graph`, and compares the result with `tests/splunk/expected/graph.json`, which is derived from `fixtures/raw/scenario.json` (edge cases are labelled `ec-` or `edge_case`). It also checks argument validation, per-bucket resolution, hostNetwork exclusion, ACI/ND endpoint merging, node replacement, orientation reconciliation, the boundary prefilters, ICMP, IPv4-mapped addresses, exact-once counting, and the prune's complete and incomplete paged reads (with lab-only macro overrides of the page size).

`test_aci.py` does the same for the single-ACI-fabric pilot in three index-time batches: `fixtures/raw-aci/` (the demo scenario), then `fixtures/raw-aci/edge/` (edge cases from `fixtures/raw-aci/edge-cases.json` in the 12:15–12:30Z window, plus EndpointSlice updates at 12:10), then `fixtures/raw-aci/edge/late/` (pull-mode re-polls and ACL-log re-reports at 12:35–12:40). After each batch the builders and the rollup run over that batch's index-time slice only. It compares the demo window with `expected/aci_graph.json` and `expected/aci_topology.json` (before and after the later batches), and checks the edge cases against the expectations in `edge-cases.json`: per-connection hand-offs (two clients through one Gateway, a spoofed leftmost X-Forwarded-For, a request for a client without a conversation, three parallel SNAT connections, ambiguous SNAT pairing, NodePort on a node without application pods, each time-inference exclusion, a shared Gateway in another namespace with two receiving nodes), connection counts of a re-exported long flow, header validation, contract bases (intra-EPG, unresolved private address, source ports, `tcpRules`, no match with and without `adm_aci_policy_complete`), ACL-log re-reports, EndpointSlice interval stability, closure and reopening, builder idempotency, pull-mode objects, fabric-source independence, the connection cap (lab-only macro override) and, with test-only injected records, sampled NetFlow and DSR `opt` forwarding.
