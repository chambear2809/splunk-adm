# Splunk-native data layer (v1)

The app builds the dependency map inside Splunk from the installed TAs' events. Scheduled searches normalize flow records, roll them up into conversations, and maintain time-bounded identity in KV store. An on-demand graph macro joins them for the UI. No external projector, HEC token or hand-normalized input is required.

Everything in the data layer is SPL in `macros.conf`, `savedsearches.conf`, `collections.conf` and `transforms.conf`; the separately opt-in recovery action is the app's administrator-only Python alert action. The data layer targets Splunk Enterprise 10.6+ and Splunk Cloud. Recorded runtime qualification covers synthetic standalone Enterprise 10.6.0.5 and a bounded three-member SHC with a separate search peer on the same version, using synthetic containers on one host. This lab does not satisfy Splunk's separate-machine/VM production topology requirement. The SHC checks cover app functionality, not production capacity, independent host failures, version upgrades, or disaster recovery; see the repository record `docs/SHC_QUALIFICATION.md`. Cloud runtime and Cloud acceptance remain unverified. Automated assisted recovery has passed its [core milestone live tests](https://github.com/chambear2809/splunk-adm/blob/main/docs/benchmarks/2026-10-14-recovery-core.md) on standalone Splunk Enterprise 10.6.0.5; a separate disabled supervisor detects abandoned claims without taking over recovery. The accepted KV claim gate covers standalone KV Store only. SHC and failover recovery are not qualified. The app ships no `indexes.conf`; create the summary index through your normal process (ACS on Cloud). Summary events use the `stash` sourcetype and do not count against license.

## Sources

Optional on-demand DNS resolution evidence and standalone scoped-address investigations use separate versioned result contracts. They do not change application graphs, summary counters or ownership, and introduce no scheduled DNS writer. See [DNS operations](operators/dns-evidence.md) and the [candidate qualification record](DNS_EVIDENCE_QUALIFICATION.md). Existing traffic readers and settings persistence gates remain applicable.

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

Administrator-selected source expectations, freshness and required-job health
are described in [Deployment health](DEPLOYMENT_HEALTH.md). These shared settings
do not activate V2 or change source collection. Existing installations without
expectations retain their searches and show unknown deployment health.

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
| `adm_kv_max_rows` | `50000` | Must equal the effective platform `limits.conf [kvstore] max_rows_per_query` (not set by this app) |
| `adm_kv_page_size` | `10000` | Page size of `adm_kv_read_all`; requires `max_rows_per_query` of at least 10,000 |
| `adm_trace_limit` | `10000` | Boundary traces whose out-of-boundary spans are read; at most the effective platform `limits.conf [subsearch] maxout` (not set by this app) |
| `adm_network_history_cap` | `512` | Maximum VLAN/bridge-domain runs (consecutive identical polls) retained per identity row |

`adm_observer_scope` (KV collection and lookup, fields `observer_kind,observer,scope,cluster`) maps observers to a routing `scope`. Observer kinds: `exporter` (NetFlow `exporter_ip`), `fabric` (ND `fabricName`), `firewall` (FTD `DeviceIP`), `hec_source` (Isovalent HEC `source`, one token per cluster), `cluster` (`k8s.cluster.name`; also Hubble flows and Kubernetes Service frontends), `apic` (`apic_host`; also ACI ACL-log records), `nd_host` (`nd_host`). The collection starts empty. Unmapped observers receive a reserved `unmapped:<hash>` scope qualified by normalized observer kind and authority; they cannot borrow identities from another authority or an explicitly mapped `default` scope. Configure every observer of a routing domain explicitly before expecting cross-source correlation. Identity only joins within one scope. New summaries retain `scope_mapping_verified`; legacy `default` summaries without this proof are isolated by readers and require a separate-index rebuild before correlation. Public identity lookups also exclude legacy `default` rows without top-level `scope_mapping_verified=1`; new identity descriptors carry the same proof as `sm`. Verified generic `default` rows use a distinct key namespace, preserving quarantined legacy records. The administrator-only `adm_ip_identity_all` lookup exposes the unfiltered maintenance inventory so complete pruning does not discard quarantined rows. Reserve the `unmapped:` prefix for the app. ACI endpoint and VM-name aggregation includes `apic_host`, and Nexus Dashboard endpoint aggregation includes `nd_host`, before the scope lookup; identical object names on different controllers cannot merge before scope assignment.

Endpoint identity rows also carry optional network metadata. ACI `fvCEp` encapsulation supplies a decimal VLAN when it is in 1..4094. Relationship evidence is read in an independent subsearch, bounded by the dispatch event-time window plus one freshness lookback, while endpoint observations retain their original index-time slice. The child groups timestamped evidence by APIC/full EPG before returning results, disables child auto-finalization (`maxtime=0`), and reserves a completion footer within its 50,001-row limit. The builder requires the expected number of groups and exactly one footer; incomplete retrieval suppresses identity writes and returns a warning when endpoint observations are present. No raw-event return cap is applied. The endpoint's full EPG DN is joined to a time-qualified `fvRsBd` relation on the same APIC; the resolved target BD DN and tenant remain controller-scoped internally, while the graph exposes the BD name. Nexus Dashboard `displayBd` is used only when the resolved endpoint has no APIC value. Missing or malformed values remain absent and may carry `attr_vlan_status` or `attr_bridge_domain_status` (`incomplete`); a supported value that changes over an identity interval is represented as `varies`. The optional `network_history` identity field is a JSON array string; `desc.nh` embeds that array as JSON, not as an escaped string. Each entry is a run of consecutive polls with identical network state and carries `t` (first observation), `te` (last observation; absent in descriptors written before runs existed, meaning `te = t`), `v`, `b`, `bd_dn`, `bd_tenant`, `vs`, `bs`, `source`, and, from the run's first poll, `observer` and `epg_dn`; null metadata is retained as an explicit run so gaps are not extrapolated. A new run starts when the state changes or when more than two polling intervals pass between polls. The state is VLAN, bridge domain (name, DN, tenant), their statuses and `source`; the answering APIC/Nexus Dashboard host (`observer`) is not part of it, so a controller failover does not make the same bridge domain `varies`. Late replays merge into the run they belong to and are idempotent. A run is retained while its `te` is within normal identity retention, so a long stable run is never dropped for its old start. At most 512 runs are kept, newest first. `attr_network_history_capped` (`nhc`) is set only when a discarded run's state differs from every retained run's state; discarding only older runs of an already-retained state adds no uncertainty. The uncertainty ages out with retention: the descriptor also stores `nhc_te`, the end time of the newest discarded distinct-state run (the merge keeps the maximum of the stored value and any newly discarded run). `nhc` is derived on every merge and stays `1` (keeping VLAN and bridge domain `incomplete` unless the retained runs show `varies`) only while `nhc_te` is within identity retention of `last_seen`; afterwards both keys are dropped and the retained runs speak for themselves. Upgrade note: a row written before `nhc_te` existed that carries `nhc` is given `nhc_te` equal to its earliest retained run's start (everything discarded by the earlier count cap was older than that), or, when no history is retained, a value outside retention so it clears immediately. Legacy capped flags therefore clear within one retention period (7 days by default) of the first merge after upgrade, as active endpoints are rewritten on every observation. The graph reads the per-row `nhc` written by the merge and needs no `nhc_te`. Graph resolution treats a run as fresh until `te` plus two polling intervals.

## Observer scope storage and permissions

The live `adm_observer_scope` lookup uses KV Store. Its collection and lookup definition explicitly allow read to all roles and write only to `admin`/`sc_admin`. Collection ACLs enforce `outputlookup adm_observer_scope` and REST collection writes independently of the CSV `outputlookup_check_permission` setting. The app ships no `limits.conf` and requires no platform permission-switch override. Keep the recovery-state/audit lookup permission settings and their administrator-only ACLs unchanged.

The lookup name and four public fields are unchanged. Store `observer_kind` and `observer` in lowercase; the two readers normalize their matching inputs to preserve the former case-insensitive match behavior. `scope` and `cluster` retain their original values and case. Administrative upserts use `_key=sha256(json_array(observer_kind, observer))` after key normalization, then `outputlookup append=true key_field=_key adm_observer_scope`. The collection is replicated to indexers, preserving distributed lookup availability. The SHC qualification checks member KV convergence and the centralized V1 path through a separate peer; it does not establish peer-export timing for other distributable callers. Verify that timing in your deployment.

### Lookup execution placement

| Scope lookup site | Pipeline position / execution | Choice |
| --- | --- | --- |
| `adm_flow_enrich` | The initial `local=true` interface lookups run on the search head and centralize V1 enrichment before the rollup's transforming `stats`. The following scope lookup reads the live collection there. | Scope replication remains enabled for compatibility, but this V1 path no longer relies on a peer-side snapshot. Qualify the pre-aggregation transfer and search-head cost. |
| `adm_identity_observations` | After its observation-grouping `stats`, node `appendpipe`/`stats` and IP expansion. The scope lookup runs on the search head on the reduced identity rows. | Use the same KV definition; no additional remote lookup or forced locality change is needed. |
| `ADM - Migrate observer scope` | Administrator `inputlookup` of the retained CSV, followed by validation. | Explicit `lookup local=true` checks existing live KV rows on the search head before writes; never validate against a potentially older replicated snapshot. |

Both `adm_interfaces` lookups in `adm_flow_enrich` use `local=true` so an empty inventory works without a peer-side KV export file. Missing matches retain the `ifIndex` fallback. This centralizes V1 enrichment before aggregation: normalized candidates cross to the search head, so qualify raw candidate volume, search-head memory, network transfer and overlapping schedules at deployment scale. V2 already uses raw interface fields. Member KV replication and peer lookup exports are different mechanisms; neither should be inferred from standalone success.

Scope replication retains the former CSV's peer availability for callers that execute distributably. The current V1 flow path is centralized by its interface lookups and does not establish peer-export correctness or freshness. `collections.conf` declares the four string fields and an observer-key index; `transforms.conf fields_list` includes `_key, observer_kind, observer, scope, cluster`, so the mapping has all required match/output fields. Lookup/collection ACLs control the live data source, and only administrators update it. Replication uses Splunk's collection/knowledge-bundle mechanism; verify bundle refresh after administrative mapping changes in your distributed deployment. The bounded SHC regression validates member KV convergence and the centralized V1 interface path. It does not validate remote-peer export timing or production capacity. See [lookup command placement](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/lookup) and [KV collection replication](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.0-configuration-file-reference/collections.conf).

The old `adm_observer_scope.csv` remains readable only as a one-time migration source. It is not used by graph/builders after the update, and its CSV write ACL no longer controls live scope data. Do not continue updating that file as the scope configuration. Existing installations must complete the [administrator migration](UPGRADES.md#one-time-csv-to-kv-scope-migration) before resuming the pipeline; local transforms overrides must not leave the active lookup pointing at CSV. The administrator-only **ADM - Migrate observer scope** search ships disabled and unscheduled; it refuses invalid/conflicting rows or changes to existing mappings. No automatic or recurring CSV import runs.

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
| `adm_nat_observation` | Optional same-event Cisco FTD eStreamer evidence. It is emitted only when the reported and `NAT_*` tuples are complete, single-valued, valid, different, in a mapped scope and tied to device, event fingerprint, event time and receipt time. The reported tuple is not called original; `OriginalInitiatorIP` is retained as a separate field when valid. |
| `adm_acl` | `permit` or `drop` for ACI ACL-log records (`acllogPermitL3Pkt`, `acllogDropL3Pkt`) |
| `adm_xlate_ip`, `adm_xff`, `adm_trace_id` | Hubble: `IP.source_xlated` of SNAT forwarding traces; for L7 requests the rightmost `X-Forwarded-For` entry (the address Envoy appends for its immediate downstream peer; with `xff_num_trusted_hops` 0 earlier entries are client-supplied and never used), kept only when it is an IP literal (requests without one are dropped); the trace ID only as 32 lower-case hex digits. |
| `adm_ingress_vlan`, `adm_egress_vlan` | NetFlow VLAN fields accepted only as decimal values 1..4094. VLAN observations retain the original packet source and destination before conversation direction is resolved. |

Hubble records come from the open-source and Isovalent Enterprise exporters' JSON lines (`{"flow":{…},"node_name":"<cluster>/<node>","time":…}`, Cilium `flow.proto` field names) and rely on Splunk's automatic JSON field extraction; the base search keeps only events mentioning `TO_ENDPOINT`, `TO_NETWORK` or `REQUEST`. Only `L3_L4` `TO_ENDPOINT` forwarded flows in the original direction become flow records (the post-translation tuple at the backend pod); `TO_NETWORK` traces with `IP.source_xlated` and `L7` HTTP requests are evidence. Hubble flows carry no byte counts.

The real Hubble `1.19.5-cee.1` Enterprise sample in `fixtures/samples/hubble-enterprise/` is handled by `adm_flows_hubble`, already included in `adm_flows`; `adm_flows_hubble_enterprise` is an alias and must not be appended separately. Lab validation of all 1,589 events yields 557 conversations (600 forwarded TO_ENDPOINT flows minus 43 replies), no translation evidence (none of 453 TO_NETWORK traces has `IP.source_xlated`), and no retained L7 evidence (all 15 requests lack X-Forwarded-For and trace context). Observer is `k8s-01-wkr-02`, cluster scope observer is `k8s-01`, and nanosecond flow timestamps parse within 1 ms. Enterprise SNAT export and Envoy L7 IP/X-Forwarded-For behavior remain unconfirmed: the sample has no NodePort, SNAT, Gateway or Ingress traffic.

ACL-log records count logged packets at the enforcing leaf. A record stays in the leaf's buffer and is re-reported by later polls, so only the report from the first poll after its `timeStamp` (poll time minus `timeStamp` at most `adm_poll_interval` + 60 s) is counted.

### FTD NAT evidence

The inspected Cisco Security Cloud TA 3.6.5 and 3.7.2 ConnectionEvent builders request `DetailFieldSet`; Cisco's FQE lists `NAT_InitiatorIP`, `NAT_InitiatorPort`, `NAT_ResponderIP`, `NAT_ResponderPort` and the distinct `OriginalInitiatorIP` field in that set. It describes base `InitiatorIP` as the session initiator or responder address and notes that passthrough tunnel events can instead report tunnel endpoints. The TA has no explicit NAT aliases in its inspected `props.conf`, but Splunk's default `KV_MODE=auto` with `AUTO_KV_JSON=true` can extract JSON fields from the event. Field presence in a requested set does not prove a deployed FMC/FTD sends values, so the macro emits evidence only for complete explicit values. See the [Cisco Connection Event field definitions](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_available_fqe.html), [eStreamer OutputFieldSet protocol](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_estreamer_protocol.html), and [Splunk automatic JSON extraction behavior](https://help.splunk.com/en/splunk-cloud-platform/manage-knowledge-objects/knowledge-management-manual/10.4.2604/use-the-configuration-files-to-configure-field-extractions/configure-automatic-key-value-field-extraction).

The V1 FTD normalizer preserves that same-event tuple as `nat_observations` on its existing conversation summary. It requires every reported and translated IP/port, TCP/UDP/SCTP, mapped scope, device IP, stable indexed-event fingerprint, FirstPacketSecond and `_indextime`; it rejects unusable IPs, invalid ports, multivalue or incomplete tuple fields, and tuples with no semantic address or port change. IPv6 spellings are compared by address value. IP role fields use the existing `adm_ip` canonicalization (trimmed/lowercase literals and IPv4-mapped IPv6 unwrapped to dotted IPv4); they are normalized values, while the indexed event remains the raw source record. The normalized end uses `FirstPacketSecond` too (`adm_end=adm_start`); it does not retain a distinct close time. Cisco's FQE guide defines `FirstPacketSecond` for ConnectionEvents and describes `ConnectionDuration` as syslog-only, while `LastPacketSecond` is documented for syslog events. A distinct eStreamer end-time value has not been qualified. The reported tuple is not called original; `OriginalInitiatorIP` is retained as a separate field when valid. It does not infer that `InitiatorIP` is categorically the original address, join observations across events or observers, change traffic/counters, create a new conversation, or create a backend hand-off.

The graph filters each individual observation against the selected half-open event-time window before edge aggregation. When NAT evidence or truncation is present, the meta row also carries numeric `nat_window_start`/`nat_window_end` values from Splunk `addinfo`; the displayed graph window remains second-rounded. On the pinned local Splunk 10.6.0.5 image, `addinfo` preserved milliseconds but truncated a requested sub-millisecond latest bound: a request ending at `N+0.0005` returned an effective `info_max_time` of `N.000`, while `N+0.5` returned `N+0.500`. Thus an integer-second observation at `N` may be conservatively omitted for that sub-millisecond request. This is a tested-image result, not a claim about every Splunk release. The portable validator retains any fractional numeric bound it receives. Older portable graphs without exact fields fall back to the displayed bounds, so their fractional query-bound precision cannot be recovered. Up to 32 observations are carried per edge; truncation remains flagged if the source summary was capped before window filtering or the graph edge itself reaches the cap, so the flag means additional in-window evidence may have been omitted. V2 is staged and does not currently project this field; this task does not establish preservation during a V1-to-V2 cutover. V2 activation must wait for an equivalent schema path. The dedicated fixture/test is synthetic parser qualification, not evidence of live eStreamer emission. NAT-aware endpoint resolution is not complete: cross-event/native-key lifecycle correlation and load-balancer/backend attribution remain unresolved. NetFlow `flow_dir` is never used.

## Conversations

Saved search **ADM - Conversation rollup** (`` | `adm_conversation_rollup` | collect ``) runs every 5 minutes and selects flow records **by index time**: `dispatch.index_earliest = -10m@m`, `dispatch.index_latest = -5m@m`, with event-time bounds `-24h` to `+15m` (records older than 24 hours when indexed, or more than 15 minutes in the future, are not counted). Normal consecutive runs read disjoint index-time slices within those event-time limits. New summaries carry replay identities, so the graph deduplicates retries of an identical closed, immutable slice with unchanged configuration. Differently bounded overlapping slices and legacy summaries require a separate-index rebuild; see [Recovery and replay](RECOVERY.md). Continuous scheduling (`realtime_schedule = 0`) requests catch-up for delayed runs. Automatic native recovery after a container outage is **not qualified**: the exclusive local rehearsal resumed future jobs but left a missed slice unprocessed. The separately opt-in automated assisted recovery action can replay one verified closed, disjoint slice at a time on its qualified standalone deployment; see [scheduler evidence](https://github.com/chambear2809/splunk-adm/blob/main/docs/benchmarks/2026-10-13-pipeline.md) and [Recovery and replay](RECOVERY.md).

Records are bucketed by `adm_end` into 5-minute buckets. Each run writes `source="adm:conversation"`, `sourcetype=stash`, `adm_record=conversation`, `_time` = bucket start, one event per (`scope`, `client_ip`, `server_ip`, `server_port`, `transport`, bucket, `observer`):

`rollup_id` (identity of the contributing indexed-event set, absent when incomplete), `replay_protected` (1 when that identity is available), `flow_source`, `observer` (`source:observer`), `observations` (pipe-delimited `source:observer[:in_if>out_if]`, because `collect` flattens multivalue fields), `bytes_c2s`, `bytes_s2c`, `packets`, `records`, `client_ports` (distinct), `client_port_list` and `conns` (up to `adm_conn_cap` client ports and `client_port@start@end` triples, pipe-delimited), `conns_capped` (1 when there were more), `sampled` (1 when a NetFlow record was sampled at more than 1:1), `first_seen`, `last_seen`, `direction_basis`, `encapsulation`, `acl_permits`, `acl_drops`, `vlan_observations` (one JSON array string of at most 32 deduplicated VLAN/interface contexts) and `vlan_observations_truncated`, plus optional `nat_observations` (up to 32 complete FTD same-event JSON objects) and `nat_observations_truncated`. NAT evidence is metadata on the existing conversation row, not another record or traffic metric. Hubble SNAT traces are written as `adm_record=hubble_xlate` rows with `xlate_ip`; Hubble L7 requests as `adm_record=hubble_l7` rows grouped per X-Forwarded-For client (`xff`) with `trace_ids`. ACL-log records are also deduplicated by APIC object DN within a run.

Client and server are decided per record, in this order, and recorded in `direction_basis`:

1. `initiator`: the source names the initiator (FTD, Isovalent).
2. `port_rule`: one side uses a port below 1024 and the other does not, or one side uses an ephemeral port (≥ 32768) and the other does not; the other side is the server.
3. Reconciliation: a record with neither inherits the orientation of another record in the same run with the same address pair, transport and bucket whose server endpoint (IP and port) is one of its endpoints; it keeps that record's basis (`initiator` or `port_rule`). A gRPC server on port 50051 seen by NetFlow and by Isovalent therefore yields one conversation.
4. `unknown`: endpoints are ordered by IP so both directions merge; the UI shows the edge undirected.

UDP to port 8472 (VXLAN) or 6081 (Geneve) and IPIP (IP protocol 4) are merged regardless of direction (`direction_basis=unknown`, server port = tunnel port, `-` for IPIP). `encapsulation` is `vxlan`, `geneve` or `ipip` when both IPs are Kubernetes node identities. Reverse-direction NetFlow records of one conversation produce one conversation, never a reversed edge.

## Identity (KV store)

Collection `adm_ip_identity` (lookup `adm_ip_identity`, `max_matches = 1000`), one row per (source, entity, IP, scope):

`ip`, `scope`, `scope_mapping_verified` (explicit routing-mapping provenance), `entity_kind` (`pod`, `k8s_node`, `k8s_node_proxy`, `k8s_service`, `vm`, `endpoint`), `entity_id` (pod or Service UID, `<cluster>/<node>`, ACI endpoint DN, ND endpoint ID), `entity_name`, `cluster`, `namespace`, `owner_kind`, `owner_name`, `node`, `tenant`, `app_profile`, `epg`, `attach_device`, `attach_interface`, `mac`, `vm_name`, `valid_from`, `valid_to` (empty while present), `valid_end` (end used for resolution and pruning), `first_seen`, `last_seen`, `priority`, `source`, `ek` (entity key), `updated`, Service frontend fields (`port`, `transport`, `service`, `svc_type`, `traffic_policy`, `lb_mode`, `controller`, `owner_ref_kind`, `owner_ref_name`, `target_port`), and `desc` (JSON of these fields, returned by lookups). VRF is not stored: the collected ACI objects do not relate an endpoint to its VRF.

**ADM - Identity builder** (``| `adm_identity_build` ``, every 5 minutes, index time `-10m@m` to `@m`, event time `-24h` to `+15m`, continuous scheduling) reads new observations and upserts them:

- **Kubernetes pods** (`source=k8s_pods`, priority 1): watch events (`type` ADDED/MODIFIED/DELETED) or pull snapshots. `valid_from` is `status.startTime`, else the first ADDED, else the first observation; `valid_to` is the DELETED event time. Each `status.podIPs` entry is a row. Pods with `spec.hostNetwork: true`, or whose pod IP equals `status.hostIP`, are not IP owners. A ReplicaSet owner becomes a Deployment only when its name is `<deployment>-<pod-template-hash label>`. Events without `k8s.cluster.name` are stored with cluster `unknown` and reported in the builder's warnings.
- **Kubernetes nodes** (`source=k8s_nodes`, priority 2): `status.hostIP` and `spec.nodeName` of pod objects (including hostNetwork pods), and `status.addresses` (InternalIP, ExternalIP) of Node objects (`valid_from` = `metadata.creationTimestamp`); not created for cluster `unknown`.
- **Cilium ingress (Envoy) addresses** (`source=k8s_node_proxy`, `entity_kind=k8s_node_proxy`, priority 2): the Node annotations `network.cilium.io/ipv4-Ingress-ip` / `ipv6-Ingress-ip`, tied to the node (`node`).
- **Service frontends** (`source=k8s_services`, `entity_kind=k8s_service`, priority 0): one row per Service, frontend address, port and transport: each `status.loadBalancer.ingress[].ip` and `spec.externalIPs` with `spec.ports[].port`, and each `spec.ports[].nodePort` of NodePort and LoadBalancer Services under the pseudo-address `nodeport:<cluster>:<nodePort>/<transport>` (an exact lookup key; resolution builds it for any node IP and port). `port_name` is the Service port name, used to pick the EndpointSlice port (m3: a named `targetPort` is resolved through it). `lb_mode` is `service.cilium.io/forwarding-mode`, else `adm_cilium_lb_mode`; `controller` is `cilium_gateway` (owner Gateway or `io.cilium.gateway/owning-gateway` label) or `cilium_ingress` (owner Ingress or `cilium.io/ingress=true`). Complete per-UID snapshots close frontends removed from a living Service, including removed ports and NodePorts. Deletion closes every child; reappearance starts a separate interval. A later different UID taking the same address, port and transport also closes earlier ownership. Simultaneous owners remain overlapping evidence for ambiguous resolution. `adm_k8s_object_staleness` can bound watch gaps when configured.
- **hostNetwork pods** (`source=k8s_hostnet`, `entity_kind=k8s_hostnet_pod`, priority 9) on the node IP: they never resolve an address, but they mark nodes whose own processes could have opened a connection, which blocks time-inferred hand-offs from that node.
- **ACI endpoints** (`source=aci`, priority 3): `fvCEp` IPs (`ip` and child `fvIp addr`). Tenant, application profile and EPG come from the DN; `attach_device`/`attach_interface` from `fvRsCEpToPathEp tDn` (`pod-<n>/node-<id>`, `eth1/5`); `vm_name` through `fvRsVm`→`compVm`. Switch names are not resolved because the default inputs do not relate `topSystem` to paths. `valid_end` is the last report plus two polling intervals, so an endpoint that stops being reported expires.
- **Nexus Dashboard endpoints** (`source=nd_endpoints`, priority 3): the input collects endpoint changes incrementally from a checkpoint (`bin/cisco_dc_nd_collector.py:757-800`), so stable endpoints are not re-reported and no staleness applies. `valid_from` is `createTime`; `valid_to` is a `modType=deletion` record or the start of another endpoint with the same IP and scope.

The builder never reads the whole collection. Service snapshots use an accelerated `(entity_id, cluster, scope)` lookup and retain an internal `k8s_service_parent` anchor in `adm_ip_identity`. The anchor carries bounded timestamped frontend membership in `desc.sh`, so an empty or deleted snapshot still constrains an indexed-late presence. Retained presence participates in interval reconstruction; replay preserves interval keys, including subsecond boundaries. History retains one baseline before the retention horizon, at most 10,000 snapshots and 8 MiB per anchor, and materializes at most `adm_kv_max_rows` descriptor candidates per UID. Conflicting snapshots, capped lookups, incomplete expansions, missing retained payloads, or observations outside the retained horizon suppress affected writes and report incomplete evidence. Terminal anchors acquire a finite retention deadline. Installing this algorithm cannot reconstruct Service snapshots absent from raw retention.

For other identity observations the builder reads the stored rows of the same IP and scope through the lookup (at most `max_matches`), merges first/last seen and validity, keeps the newest non-empty attribute values, and closes an open pod, node, Envoy address, Service frontend (same port and transport) or ND endpoint interval at the `valid_from` of the next different entity with that IP. Changed rows are written with `outputlookup append=true key_field=_key override_if_empty=false`. When an IP returns `adm_identity_max_matches` stored rows, closing is skipped for it and the builder's summary row carries a warning. The builder returns one row: `rows_written`, `rows_observed`, `rows_closed`, `truncated_ips`, `rows_missing_cluster`, `warnings`. Overlapping index-time windows are harmless (merges are idempotent); automated assisted recovery still replays builder slots chronologically and one at a time. A paused builder can leave indexed data about 18 minutes stale during the bounded recovery invocation. Backfill by dispatching it once with `dispatch.index_earliest=-7d`.

**ADM - Identity prune** (manual maintenance only) reads the collection with `adm_kv_read_all`: 20 pages of 10,000 rows plus a probe at offset 1. It rewrites the collection without rows whose `valid_end` is older than `adm_identity_retention` only when the read is provably complete: pages contiguous, every page before the last full, the page after the last read and empty, and a short first page whose probe returned exactly one row fewer (otherwise the store capped the read). Otherwise it writes nothing and returns a warning. It never empties the collection (`override_if_empty=false`). **ADM - Service binding prune** (manual maintenance only) does the same for `adm_service_workload` by `last_seen`.

**Concurrency.** A saved search's single-instance limit does not serialize different searches or manual macro calls. A prune's full rewrite can discard a concurrent builder upsert. All prunes, including the additional Cisco client-history prune, therefore ship with `enableSched=0` and require `adm_prune_maintenance=1` before writing. The default `0` returns a read-only report and warning. The gate is an operator assertion, not a lock: pause and drain all writers, back up the collections, run one prune at a time, then reset the gate before resuming. Follow [Recovery and replay](RECOVERY.md#pruning-and-maintenance).

All prune searches retain the empty-write safeguard: when every stored row is expired, they report `rows_pruned=0` and warn that administrator cleanup is required. They do not silently report a successful deletion or clear a collection from an empty result.

**Client-history capacity.** `adm_network_client_history` adds a row whenever a client's change fingerprint differs; identical payloads collapse to one row that keeps the earliest `received_time`. The Catalyst fingerprint includes `lastUpdatedTime`, which the evidence describes as controller record-update time, not a per-poll value. If Catalyst Center advances it on every poll (not established), one client adds up to 24 rows per day at the default 3600-second client input interval and reaches 1000 rows in about 42 days; if it changes only when the client record changes, growth is much slower. Two limits apply:

- Context edges fail closed for a client whose stored rows reach `adm_identity_max_matches` (1000). The candidate check counts rows per scope and client IP across native IDs, so it can be reached sooner than one client's own rate suggests.
- **ADM - Network client history prune** rewrites the collection only after `adm_kv_read_all` reads it completely (20 pages of 10,000 rows). A collection that reaches 200,000 rows cannot be read completely, so the prune writes nothing and cannot recover on its own. The prune ships disabled and also requires `adm_prune_maintenance=1`.

Size the pilot as clients x rows per day x retention days (default 7, from `adm_identity_retention` = 604800 seconds) against 200,000. Run the prune report-only first (`adm_prune_maintenance=0`) and check `complete`, `rows_read` and `rows_expired`. If the read is incomplete, back up the collection and clean it up as administrator maintenance, following [Pruning and maintenance](RECOVERY.md#pruning-and-maintenance). Rows with a new `lastUpdatedTime` cannot be collapsed under the current contract: without a vendor poll ID, an unchanged poll cannot be told apart from a replay. Fixing that needs a coordinated change to the contract and the migration tool.

Collection `adm_service_workload` (**ADM - Service binding**, every 5 minutes, same windows) binds an OTel service (`service.name`, `deployment.environment.name`, `k8s.cluster.name`, `k8s.namespace.name`) to `k8s.pod.uid` with first/last seen (upsert by `_key`). Collection `adm_interfaces` (**ADM - Interface inventory**, hourly, index time `-2h@m`) maps (`device_ip`, `ifindex`) to `interface` and CDP neighbor (upsert; bounded by device ports, never pruned).

**ADM - Service backends** (`adm_k8s_service_build`, every 5 minutes, same windows) upserts two collections from Kubernetes objects:

- `adm_service_backends`: one row per EndpointSlice endpoint (`targetRef` pod), Service (`kubernetes.io/service-name`) and slice port: `cluster`, `namespace`, `service`, `slice_uid`, `pod_uid`, `pod_name`, `ip`, `node`, `target_port`, `protocol`, `port_name`, validity. Endpoints with `conditions.ready=false` and endpoints without `targetRef` (the placeholder endpoint Cilium adds to Gateway and Ingress Services) are not backends.
- `adm_service_routes`: one row per HTTPRoute rule backend × `parentRefs` (`parent_kind=Gateway`, `parent_namespace` = the parentRef's namespace or the route's) and per Ingress rule path (`parent_kind=Ingress`, or `IngressShared` when `ingress.cilium.io/loadbalancer-mode` or `adm_cilium_ingress_mode` is shared): `host`, `path`, `backend_namespace`, `backend_service`, `backend_port`, validity. A Gateway in another namespace (for example a shared Gateway in `gateway-system`) is matched through `parent_namespace`.

Each run merges with the stored rows of the same EndpointSlice or route (lookup by `slice_uid`/`route_uid` and cluster): a child present in the run continues its stored open interval (same `_key`, earliest `valid_from` and `first_seen` kept), so later MODIFIED events and pull re-polls never move `valid_from`. A child absent from a later listing of its parent (including a listing whose endpoints are all not ready) or from a DELETED event is closed at that listing; a child that reappears after being closed starts a new interval (new `_key`). When a parent returns `max_matches` stored rows the builder warns that intervals may not have been merged or closed. **ADM - Service backends prune** and **ADM - Service routes prune** (manual maintenance only) remove rows whose validity ended before `adm_identity_retention`, after a complete paged read.

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

- **Inputs:** summary rows (conversations and Hubble hand-off evidence) whose `client_ip` or `server_ip` is an IP of a boundary pod, of a node hosting one, or of a LoadBalancer frontend of the namespace's Services or of a Gateway its HTTPRoutes attach to (also in another namespace); conversations to any node of the cluster on a NodePort of those Services (also nodes without application pods); and conversations from the boundary's clients (other than Kubernetes nodes and Envoy addresses) to the boundary's dependencies, so that direct or blocked attempts to bypass the application show (at most `adm_scope_peer_limit` clients and dependencies; a meta warning reports more). The filter is built by the subsearch `adm_graph_scope_filter` over `adm_ip_identity`, `adm_service_routes` and the summary; only IP literals and port numbers are inserted into the search string, so very large namespaces are bounded by search-string size and the identity read cap, which is reported. A Splunk subsearch that hits its time or result limit is reported as a job message rather than an SPL meta field; the app surfaces these messages alongside graph warnings. Spans of the boundary (`k8s.cluster.name::` and `k8s.namespace.name::` indexed fields) plus all spans of at most `adm_trace_limit` boundary traces (subsearch), each with its parent's service found within the trace. Summary rows are summed per (conversation, bucket, observer) across rollup runs.
- **Resolution per bucket:** each (conversation, bucket) is resolved over that bucket's interval, so an IP reused inside the window resolves to the right pod in each bucket. Edges then aggregate by the resolved entity IDs.
- **Services and `calls`:** a service is `service:<cluster>/<namespace>/<service.name>/<environment>`. `calls` edges (`confidence=observed`) are cross-service parent/child spans whose parent service is in the boundary; `count` is the number of child spans; `evidence` lists `span:<trace>/<span>`.
- **`runs_on`:** service → `pod:<cluster>/<uid>` from `adm_service_workload` rows overlapping the window (`confidence=correlated`).
- **`communicates_with`:** conversations where either side resolves to a boundary pod or the server to a Service frontend of the namespace, and client-to-dependency conversations as above. The other side is a pod (any namespace, e.g. CoreDNS), `node:<cluster>/<node>`, `k8s_service:<cluster>/<namespace>/<service>/<frontend ip>:<port>`, `k8s_node_proxy:<cluster>/<node>` (Envoy), `vm:<scope>/<ip>` (ACI/ND endpoint with EPG/tenant/VM/leaf attributes), or `ip:<scope>/<ip>` with `endpoint_kind` `external` (public address), `unresolved` or `ambiguous`. V1 FTD edges may carry `nat_observations` / `nat_observations_truncated` describing complete translated tuple values from the same firewall event; these fields never create a hand-off or a new edge. Tunnel conversations (VXLAN, Geneve, IPIP) are included only between nodes that host boundary pods and only connect `node:` endpoints. Backend-side connections that a hand-off explains (a Hubble backend flow matched by client tuple; a receiving node's SNAT leg matched by a trace or by timing) are not shown separately. `confidence` is `correlated` when both sides resolve in every bucket, otherwise `unresolved`.
  - `bytes`: per observer, `bytes_c2s + bytes_s2c` summed across buckets and runs; the edge takes the largest observer total. Empty when no observer reports bytes (for example Isovalent only).
  - `count`: client connections: the `conns` of every observer row of the edge, merged per client port when a record starts within `adm_conn_gap` seconds of the previous record's end (return records, other observers, active-timeout re-exports); ACL-log-only conversations count logged records.
  - `evidence` (sources plus `span_peer`), `observers`, `sources`, `server_port` (empty for portless protocols), `transport`, `direction_basis`, `encapsulation` (`vxlan` or `geneve`; IPIP stays visible as `transport=ipip`), `span_ids`, `via_node` (receiving node, on conversations to a Service frontend), `acl_action` (`drop` when any drop was logged, else `permit`), `acl_leaf` (`pod-N/node-N`), `acl_permits`, `acl_drops`, and the contract fields below.
- **Span association (`span_peer`):** a CLIENT span is attached to a conversation when its `network.peer.address` and `server.port` equal the conversation's server IP and port, its `k8s.pod.uid` is the pod that owns the client IP, and the span overlaps the conversation interval within one second.
- **Nodes:** `id`, `label`, `kind` (`service`, `workload`, `endpoint`), `endpoint_kind`, `namespace`, `cluster`, `addresses` (union), `reason`, and `attr_*` (`attr_environment`, `attr_owner`, `attr_owner_kind`, `attr_node`, `attr_tenant`, `attr_app_profile`, `attr_epg`, `attr_vm_name`, `attr_mac`, `attr_attach_device`, `attr_attach_interface`, `attr_scope`; Service frontends: `attr_service`, `attr_frontend`, `attr_type`, `attr_traffic_policy`, `attr_lb_mode`, `attr_controller`, `attr_route`, and `attr_handoff=service_only` with `attr_candidates` when no backend could be determined; Envoy: `attr_node`). Pod and service facts from identity and spans win over edge-derived copies.
- **Meta row:** `window_start`, `window_end`, `spans`, `conversations`, `conversations_in_scope`, `matched_conversations`, `unresolved_conversations`, `ambiguous_conversations` (counts of (conversation, 5-minute bucket) pairs), `missing_parent_spans`, `root_present`, `nodes`, `edges`, `warnings`, `generated_at`. Warnings cover a missing entry service, missing parents, ambiguous identities, identity reads that reached `adm_identity_max_matches`, more boundary traces than `adm_trace_limit`, spans without `k8s.cluster.name`, a boundary pod, Service backend or ACI policy read that reached `adm_kv_max_rows`, summary rows whose connection list was capped at `adm_conn_cap`, fabric records folded into a client-tuple hand-off (DSR with `dsrDispatch=opt`), `Local`-policy connections attributed to a receiving node with no local backend pod, `Local`-policy Services inconsistent with the cluster's `` `adm_l2announcements_enabled` `` setting, a capped scope filter, and graphs over 500 nodes or 2,000 edges. `window_start` and `window_end` are integer epoch seconds.
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
| Isovalent Enterprise flow export | `cilium:hubble:flow` in `cilium_hubble` | Same JSON-lines envelope and Cilium `flow.proto` fields as the open-source exporter; normalized by `adm_flows_hubble` within `adm_flows`. `adm_flows_hubble_enterprise` is an alias. Real Hubble `1.19.5-cee.1` sample: 1,589 events → 557 conversations, no SNAT or retained L7 evidence; see `fixtures/samples/hubble-enterprise/README.md` and `tests/splunk/test_hubble_enterprise.py`. |
| Kubernetes objects (Helm `clusterReceiver.k8sObjects`) | `kube:object:services`, `kube:object:endpointslices`, `kube:object:ingresses`, `kube:object:httproutes`, `kube:object:nodes` (`kube:object:gateways` is not needed: Cilium's Gateway Service names its Gateway as owner) | Service frontends, backends, routes, Cilium per-node ingress IP. |
| ACI fabric (DC Networking `classInfo`) | `cisco:dc:aci:class` | `topSystem` (names, roles, OOB addresses), `fabricLink` and fabric `lldpAdjEp` (leaf↔spine), host `lldpAdjEp` (attachment by LLDP system name), contracts and external EPG subnets, ACL-log records. `fabricNode` and `vzFilter` are not used (the subject-filter relation carries the filter DN). |
| ACI NetFlow v9 via Stream, Nexus Dashboard flows for the ACI site | `stream:netflow`, `cisco:dc:nd:flows` | Fabric observations; either or both. ACI exports from each leaf's OOB address, so `exporter_ip` maps to `topSystem.oobMgmtAddr`; records carry the ingress interface only. |

### Identity

Service frontends, Envoy addresses and Node objects are identity rows (see Identity above); backends and routes are in `adm_service_backends` and `adm_service_routes`. The builder preserves separate membership intervals when a backend or route disappears and reappears within one input batch, including readiness changes and deletion snapshots. Replaying a batch keeps those intervals stable. Ingress backend ports retain either `backend_port` (numeric) or `backend_port_name`; named ports match the EndpointSlice port name for that backend Service. Conversation resolution checks the server side against port-qualified frontends first (priority 0): the server IP's own rows, and for a Kubernetes node IP also the `nodeport:<cluster>` rows; only frontends with the conversation's port and transport cover it. A frontend hit resolves the server to the Service, never directly to a pod. Pod IPs and VIPs are never ACI endpoints. Node attachment on ACI comes from the node's `fvCEp` path when nodes sit in an EPG/BD; for floating-SVI L3Out nodes, whose IPs are not endpoints, the topology's LLDP host links attach the node by name.

### Attribution from frontend to backend pod

`adm_graph_handoffs` links each client connection to a Service frontend with the backend pod that served it. A connection is a client port's records from all observers (forward and return NetFlow records, Nexus Dashboard copies, active-timeout re-exports) merged when a record starts within `adm_conn_gap` seconds of the previous one's end. Candidate backends are the EndpointSlice pods of the frontend's Service port (matched by port name) valid during the conversation; for Cilium Gateway and Ingress Services, the pods of the backend Services of the routes attached to that Gateway or Ingress (by namespace and name, so a shared Gateway in another namespace works). Backend candidates and hand-off evidence must match the conversation transport. Consumption of an explained backend connection is scoped by transport and connection time, so later source-port reuse remains visible. Rules, strongest first; times match within `adm_handoff_window` seconds:

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
- `Local` traffic landing on a node without a local endpoint: for a `hubble_client_tuple` hand-off on an `externalTrafficPolicy: Local` Service, when the resolved `via_node` has no candidate backend pod for that Service at the connection's time, the meta row warns with a count of affected connections (BGP/L2 advertisements may be wrong, or an endpoint may have moved).
- L2 announcements combined with `Local`: this is a static cluster/Service configuration inconsistency, not something derived from traffic. The operator-reported cluster default `` `adm_l2announcements_enabled` `` macro (0/1, like `` `adm_cilium_lb_mode` ``) is checked against every in-scope Service with `adm_etp=="Local"`; the meta row warns with a count of distinct affected Services when both are set, since Cilium does not support combining the two.

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

All ship `disabled = 1` and `dispatchAs = owner`. Builders and the rollup have `enableSched = 1`; prunes have `enableSched = 0` and must stay unscheduled. Set the macros and populate the `adm_observer_scope` KV lookup, backfill the identity builder, then enable the builders and rollup. The prune cron values below are inactive defaults, not concurrency protection. `schedule_priority = higher` is honored only for owners with the `edit_search_schedule_priority` capability.

| Saved search | Schedule | Index time | Event time | Scheduling |
| --- | --- | --- | --- | --- |
| ADM - Identity builder | `1-56/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Service binding | `2-57/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Interface inventory | `7 * * * *` | `-2h@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Conversation rollup | `*/5 * * * *` | `-10m@m` → `-5m@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - Service backends | `3-58/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous, priority higher |
| ADM - ACI policy | `6-56/5 * * * *` | `-10m@m` → `@m` | `-24h` → `+15m` | continuous |
| ADM - Identity prune | `4 3 * * *` | — | — | — |
| ADM - Service binding prune | `9 3 * * *` | — | — | — |
| ADM - Service backends prune | `14 3 * * *` | — | — | — |
| ADM - Service routes prune | `19 3 * * *` | — | — | — |
| ADM - ACI policy prune | `24 3 * * *` | — | — | — |

The Cisco contract adds the following separately staged searches. Their shipped
defaults are disabled; the public readers remain on V1. Follow the
[migration procedure](CISCO_CONTRACT_MIGRATION.md) and
[qualification gates](CISCO_NETWORKING_QUALIFICATION.md) before activation.

| Saved search | Schedule | Index time | Event time | Purpose |
| --- | --- | --- | --- | --- |
| ADM - Network client history builder | `1-56/5 * * * *` | `-10m@m` → `@m` | `0` → `+15m` | Source-qualified client and attachment history |
| ADM - Conversation rollup v2 | `*/5 * * * *` | `-10m@m` → `-5m@m` | `-24h` → `+15m` | V2 conversation rows in the separate summary index |
| ADM - Traffic observation rollup v2 | `*/5 * * * *` | `-10m@m` → `-5m@m` | `-24h` → `+15m` | Per-observer flow evidence with explicit counter limitations |
| ADM - Application catalog v2 | `15 * * * *` | — | `-1h@h` → `@h` | Separate V2 application catalog |
| ADM - Network client history prune | `5 3 * * *` | — | — | Unscheduled maintenance, shared prune gate required |

The history builder retains source event time separately from indexed receipt
time. Its unbounded event-time lower bound allows a newly received older
association event to be considered within the bounded index-time slice. It
does not backdate a Catalyst inventory snapshot into historical attachment.

### Automated assisted recovery

The `adm_recovery` custom administrator-only alert action is shipped
disabled through both `action.adm_recovery=0` and `[recovery] enabled=0` in
`default/adm_recovery.conf`; enable it only through local overrides. Enabling
the detector's notification does not enable recovery. The action is intended
for standalone Splunk Enterprise 10.6.0.5. The qualification gate accepts only
that exact release, the same set as the settings write gate; the [core milestone live tests](https://github.com/chambear2809/splunk-adm/blob/main/docs/benchmarks/2026-10-14-recovery-core.md)
passed on 10.6.0.5. Other patch releases are refused until qualified. The separately disabled abandoned-lease supervisor reports uncertain
recovery state for operator reconciliation; it does not take over a claim or
resume a writer. SHC and failover are outside the qualification. It requires the
target saved search to retain its shipped absolute windows and
`dispatchAs=owner`, and it refuses an enabled SHC, non-administrator owner,
configuration drift, or a backlog over four initial slots before pausing.

The action admits at most eight total slots, uses a 25-minute alert-action
`maxtime`, and budgets normal paused recovery work to 18 minutes. A crash or
uncertain writer can leave the schedule paused indefinitely for manual reconciliation. It records target and slot claims in the administrator-
only `adm_recovery_state` collection and audit events in
`adm_recovery_audit`. Recovered slots are omitted from missed-slot detection;
in-progress and uncertain claims remain visible and are never taken over or
re-dispatched. The action records durable pause state before changing
`is_scheduled`; restoration currently leaves a local `savedsearches.conf`
override. The separate `ADM - Recovery abandoned-lease alert` ships disabled
and creates tracked Splunk alerts for every expired target claim and every
expired slot claim except `recovered`. Even a target with state `restored`
blocks future recovery until its claim is deleted; normal success deletes it.
The supervisor reads claims in pages and raises an incident when the read is
incomplete. It never changes a claim or schedule, and it has no shipped paging
integration. See [Abandoned recovery claims](RECOVERY.md#abandoned-recovery-claims).

The explicit local opt-in is:

```ini
# local/savedsearches.conf
[ADM - Scheduler missed-slot alert]
action.adm_recovery = 1
disabled = 0

# local/adm_recovery.conf
[recovery]
enabled = 1
management_uri = https://localhost:8089
ca_file = /path/to/trusted/splunk-ca.pem
```

Use a trusted CA path appropriate to the deployment. TLS certificate and
hostname verification remain enabled; no verification bypass is supported.

For builder targets, replay is chronological and single-instance with
overlapping ten-minute bounds allowed. For the rollup, replay requires closed,
disjoint five-minute slices. The rollup's pre-replay manifest is a slice-
stability check. The post-replay summary-index comparison of every expected
`rollup_id` and its `records` count is the actual verification. See [Recovery
and replay](RECOVERY.md#automated-assisted-recovery-core-action) for the
manual fallback, claim behavior, and native catch-up qualification result.

## Application catalog and exact Find

`ADM - Application catalog` is disabled by default, runs hourly at minute 15,
and computes the preceding complete hour (`-1h@h` to `@h`). Like the other
writers, it dispatches as owner and is readable/dispatchable/editable only by
`admin`/`sc_admin`. Enable it through Splunk saved-search administration after
identity, service binding and conversation rollup are configured. The existing
application catalog is readable by viewers; both REST and `outputlookup` writes
remain administrator-only.

`adm_catalog_build` computes a read-only catalog from retained OTel service/pod
bindings and temporally resolved conversation summaries. Bound pods count
retained distinct `(cluster, namespace, pod_uid)` bindings, rather than asserting
that those pods are currently running. Conversations count distinct scoped
address/port/transport tuples directly touching those pods. Exporters, time
buckets and replay do not multiply the count. Peers count resolved identities or
scoped unknown addresses; public external peers do not count as unknown.
Blocked tuples require observed ACL drops. These are direct application counts,
not all edges in a dependency map. `window_start`/`window_end` record the actual
metric window; `updated` records the refresh time.

Keys are SHA-256 of a JSON array containing service, environment, cluster and
namespace. The array keeps dimension boundaries unambiguous even when a source
value contains a delimiter. Scope timestamps remain attached to their own
binding association when multiple services share a pod. Unsupported or missing
scope dimensions remain visible for repair and cannot open a map.

Inline paged KV reads reuse the existing completeness probes. Identity candidate
caps and multivalue expansion losses invalidate the computation. The single
catalog writer merges fresh rows with previous rows whose `updated` is within
`adm_identity_retention`; fresh keys win. It replaces storage only after both
computation and prior-catalog reads prove complete. `override_if_empty=false`
preserves the snapshot on an incomplete read. A complete snapshot with no
retained applications writes one internal bookkeeping row, `_key=adm-catalog-empty`
with `updated`, so every expired application can be removed without treating a
failed computation as an empty result. This reserved key is not application or
TA data and the UI ignores it. The writer uses inline reads and a final sort,
not capped subsearch result sets, and permits one concurrent dispatch.

The Applications page labels metrics as each row's last completed hour; its
Find/map time picker does not alter catalog metrics. Results over 5,000 rows
show an explicit message and can retry with an exact service prefilter.
Oversized results never silently fall back to metric-free scope rows. Other
catalog failures or an empty catalog can still show configured scopes with an
explanation that metrics are unavailable. An empty catalog alone does not prove
the job is disabled.

`adm_find(1)` accepts an exact IP, EPG (including ACI DN), or attached-device
value under a server-side single-line allowlist. It returns applications bound
to a matching pod or observed communicating with the matching endpoint during
the selected window. Resolution reuses temporal, scope-qualified graph identity
rules. Incomplete evidence returns an explicit warning instead of a false
no-match result. No owner is guessed. The frontend validates the value before
creating the search.

`fixtures/demo-catalog.json` and `fixtures/demo-find.json` are captured from real
ACI lab searches. Capture with `tools/capture_catalog_fixtures.py` under the lab
lock after `AciDataLayerTest.setUpClass()`, using the integer window and exact
queries recorded in each fixture. They include the source scenario, schema and
transitive macro definition hashes. Demo Find supports only those queries. Its
one-hour capture window is displayed separately from the captured map's
15-minute window; unavailable maps have disabled actions with explanations.

## Validation

`tests/splunk/` runs a local Splunk 10.6 container with the TAs' search-time configuration only (no inputs or vendor scripts):

```sh
tests/splunk/lab.sh up && tests/splunk/lab.sh install
ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk -v
```

The test resets the lab indexes and collections, ingests `fixtures/raw/*.ndjson`, writes a scope mapping, runs the builders, runs the rollup over one index-time slice, ingests `fixtures/raw/late/` and rolls up a second slice, runs `adm_graph`, and compares the result with `tests/splunk/expected/graph.json`, which is derived from `fixtures/raw/scenario.json` (edge cases are labelled `ec-` or `edge_case`). It also checks argument validation, per-bucket resolution, hostNetwork exclusion, ACI/ND endpoint merging, node replacement, orientation reconciliation, the boundary prefilters, ICMP, IPv4-mapped addresses, exact-once counting, and the prune's complete and incomplete paged reads (with lab-only macro overrides of the page size).

`test_aci.py` does the same for the single-ACI-fabric pilot in three index-time batches: `fixtures/raw-aci/` (the demo scenario), then `fixtures/raw-aci/edge/` (edge cases from `fixtures/raw-aci/edge-cases.json` in the 12:15–12:30Z window, plus EndpointSlice updates at 12:10), then `fixtures/raw-aci/edge/late/` (pull-mode re-polls and ACL-log re-reports at 12:35–12:40). After each batch the builders and the rollup run over that batch's index-time slice only. It compares the demo window with `expected/aci_graph.json` and `expected/aci_topology.json` (before and after the later batches), and checks the edge cases against the expectations in `edge-cases.json`: per-connection hand-offs (two clients through one Gateway, a spoofed leftmost X-Forwarded-For, a request for a client without a conversation, three parallel SNAT connections, ambiguous SNAT pairing, NodePort on a node without application pods, each time-inference exclusion, a shared Gateway in another namespace with two receiving nodes), connection counts of a re-exported long flow, header validation, contract bases (intra-EPG, unresolved private address, source ports, `tcpRules`, no match with and without `adm_aci_policy_complete`), ACL-log re-reports, EndpointSlice interval stability, closure and reopening, builder idempotency, pull-mode objects, fabric-source independence, the connection cap (lab-only macro override) and, with test-only injected records, sampled NetFlow and DSR `opt` forwarding.

The focused lab regressions in `tests/splunk/test_builder_regressions.py` and `tests/splunk/test_handoff_regressions.py` cover same-batch readiness gaps, indexed-late splits and replay, named Ingress ports, APIC scope isolation, transport-qualified hand-offs, and source-port reuse versus re-exported records. They run with the same `ADM_LAB=1` test command.

## Pipeline health and search completeness

The **Pipeline health** panel runs two read-only, on-demand searches independently of the map's filters. `adm_health_sources` summarizes the eight configured source index macros for events indexed in the last 24 hours, including empty sources. It reports event count, latest event time, latest index time, and the maximum per-event nonnegative ingestion delay. The panel calls out sources with no data received within 20 minutes; optional or quiet sources are not automatically considered failed. Counts use the configured indexes and supported source types (including the FTD connection-event predicate and configured trace/Hubble source types); they do not imply every event normalized successfully. The source probes override the map event-time window: event timestamps from epoch through ten years ahead are accepted, so late-arriving backlogs are included.

`adm_health_jobs` combines app-local saved-search configuration with visible `_internal` scheduler events for `ADM - *` searches in the same window. It reports disabled searches, latest run and successful-run times, outcome, failures, and skips. Overdue indications use the shipped schedules: 20 minutes for five-minute builders, two hours for interface inventory, and a legacy 26-hour threshold if an operator schedules pruning. Prunes are intentionally disabled during normal operation; their Disabled status does not mean they should be enabled. An unscheduled manual prune has no scheduler evidence. Operators who customize schedules must interpret these thresholds accordingly. Health is a snapshot; use **Check again** to refresh it. `adm_health_jobs` only shows the most recent scheduler status per search, so a missed slot hidden behind a later successful one is invisible to it; `adm_health_missed_slots` (used by the disabled-by-default `ADM - Scheduler missed-slot alert`) uses only scheduler.log successes with a `scheduler__` SID. It reports `reason=missed_slot` for unsatisfied five-minute writer slots and hourly V2 catalog slots strictly after each target's earliest visible success, subject to the ten-minute grace period. Slots before that checkpoint are not reported. With no successful checkpoint, a target produces exactly one `reason=no_successful_checkpoint` row without `scheduled_time`, rather than an invented backlog. Disabled and explicitly unscheduled targets are excluded; unknown schedule flags do not silently suppress reporting. The saved alert searches 24 hours plus a preceding hourly checkpoint (`-1500m@m`); extend that bound when increasing `adm_missed_slot_lookback`. After maintenance, a pre-pause checkpoint still anchors detection, so paused-period gaps remain visible and require absolute-slice replay. Manual successes neither establish a checkpoint nor clear scheduled gaps. See [Recovery and replay](RECOVERY.md#missed-runs-during-an-outage).

These searches run with the viewer's permissions. Missing index access can look like no visible data; absent saved-search configuration or scheduler history is explicitly unconfirmed. No additional privileges are granted by the app. An administrator can inspect health when an ordinary viewer lacks internal-log access. Partial search results and search failures remain visible in the panel. The checks do not enable searches, ingest events, or write collections.

The search provider waits for both results and job completion before presenting a graph or topology. Searches fail closed on job-level incompleteness (unfinished, early-finalized, truncated or event-dropping jobs) and on typed ERROR or FATAL job messages; this applies to the graph, topology, application catalog, Find, scope-option and health searches. WARN messages, for example from an unreachable distributed search peer, do not fail the search: they are shown as coverage warnings and may indicate partial results. DEBUG, INFO and NOTICE messages are ignored. Topology failures also produce a visible warning while allowing the application map to load. Warning text is bounded and rendered as plain text. Demo mode never represents synthetic fixtures as live pipeline health.

## Viewer permissions

Map searches run as the signed-in user. The local permission regression creates a dedicated role with only the `search` capability, no imported roles, and an explicit list of the fixture's source and summary indexes. It verifies the effective role and compares the restricted user's node IDs and edge endpoints with both the administrator's graph and the fixture expectations. Production roles need read access to the indexes configured by the app's macros; this app does not provision users or grant index access. Creating a role through Splunk REST can inherit capabilities from the platform's `[default]` stanza: explicitly update and verify its capability list rather than assuming a new role is read-only.

All shipped saved searches build derived data or perform maintenance, and use `dispatchAs=owner`. Their metadata read and write permissions are restricted to `admin` and `sc_admin`; allowing a viewer to read these saved searches also exposes owner-context dispatch. The map uses read-only macros and does not need that access. Ordinary viewers may therefore see unconfirmed saved-search configuration in Pipeline health; an administrator should perform the full scheduler check. Existing deployment-specific metadata overrides must be checked when upgrading because local permissions can override these defaults.

The scope collection and its lookup definition explicitly grant read to all roles and write only to `admin`/`sc_admin`. KV collection ACLs reject unauthorized `outputlookup adm_observer_scope` and REST collection writes; no `limits.conf` setting is required. The permission test verifies viewer reads, REST-write rejection and unchanged data, then temporarily grants `output_file` and `edit_own_objects` and requires scope/identity KV writes to be rejected. It confirms the effective CSV permission switch is false, imports an isolated legacy CSV as admin twice without duplicates, preserves mixed-case output values, and demonstrates that a viewer mutation of that retired CSV does not change the live KV mapping. A warning with a successful KV write is not accepted as denial. Existing CSVs must be migrated once as described in [Upgrades](UPGRADES.md#one-time-csv-to-kv-scope-migration).

Focused regressions, after installing the app in the disposable lab:

```sh
ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk -p 'test_identity_ownership.py' -v
ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk -p 'test_permissions.py' -v
```

The identity tests ingest pod observations and assert exact client and server UIDs, validity intervals, deletion gaps, delayed older ownership and replay, and overlapping IPs in separate scopes. The permission suite resets and seeds the lab itself, enables saved searches without scheduling them so a disabled search cannot masquerade as an authorization denial, and removes its generated user and role afterwards. Run these suites serially with other lab tests; purge the lab when finished. These checks validate server-side authorization, not browser login/SSO or a deployment's customized roles.

## Deployment qualification and visibility

| Deployment | Current evidence / operational boundary |
| --- | --- |
| Standalone Enterprise 10.6.0.5 | Historical synthetic lab qualification; every release candidate still requires its exact archive and live regression evidence. |
| Other 10.6.x patches | Not live qualified. Automated recovery, V2 migration and settings writes refuse them. |
| Distributed Enterprise / remote peers | Bounded synthetic SHC data-layer searches through a separate 10.6.0.5 peer passed; peer-export freshness, production load and other topologies remain unqualified. Automated recovery and V2 migration refuse remote peers. |
| Search head clustering | Bounded 10.6.0.5 checks cover graph/search, member KV convergence, permissions, browser access, configuration reapplication, scheduled execution during captain loss and unassisted member rejoin. An earlier assisted run is retained separately. Production availability, capacity and version upgrades remain unqualified. Automated recovery and V2 migration refuse SHC. |
| Splunk Cloud | Private-app vetting and runtime qualification outstanding; automated recovery and V2 migration refuse Cloud. |

Routing scopes are attribution boundaries, not user authorization. The shared KV and catalog ACLs assume all Atlas viewers are entitled to the entire configured dataset. Source-index permissions alone do not restrict administrator-derived lookup rows. Do not use one shared installation to serve viewers with different tenant entitlements without a separately designed and verified authorization boundary.

ACI contract evaluation requires exactly one explicitly mapped APIC authority per routing scope. Multiple controllers in a scope remain `not_evaluated`, rather than mixing identically named policy objects. Latest-state policy rows newer than the selected query boundary also force `not_evaluated`: this app does not retain a complete historical policy snapshot. Endpoint and traffic evidence remain available independently of policy evaluation. Filter actions come from the original ACI record rather than the add-on’s change-activity `action` field. Missing, conflicting, malformed, or legacy unverified actions cannot produce confident permit intent.
