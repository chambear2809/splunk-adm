# Kubernetes and Cilium source adapters

Status: offline source adapters and source-shaped synthetic tests. No live
Kubernetes or Cilium sample has been qualified. The Splunk OTel chart 0.161.0
is inspected as static package data only; this document does not enable a
collector, choose a kubeconfig, or grant cluster access.

## Inputs and collection identity

The functions in `tools/change_correlation/adapters/kubernetes.py` accept
decoded, versioned native Kubernetes JSON plus a separate `collection_metadata`
receipt. They never open a network connection. Snapshot input must use the
versioned native list kinds `v1/ServiceList`,
`discovery.k8s.io/v1/EndpointSliceList`, or `v1/PodList`. Cilium policy input is
restricted to `cilium.io/v2/CiliumNetworkPolicyList` and
`cilium.io/v2/CiliumClusterwideNetworkPolicyList`, and requires an explicit
`qualified_gvks` attestation for each native GVK seen. Cilium `spec`, annotations,
status and arbitrary labels are not projected.

Set `authority` to a stable native cluster identity, not the API server URL.
`partition` selects Kubernetes enumeration: it must equal the exact cluster
`authority` for a cluster-wide enumeration, or use the exact form
`namespace:<native namespace>` for a namespace-specific enumeration. The adapter
checks each namespaced object's `metadata.namespace` against a namespace
partition. Cluster-scoped `CiliumClusterwideNetworkPolicy` objects require the
cluster authority partition. For an empty namespaced list, the selected namespace
is carried by its explicit partition because there is no object namespace to
cross-check.

`scope` is the shared, verified cross-source routing scope. It is preserved
unchanged in the normalized receipt and is never interpreted as a Kubernetes
namespace or cluster selector; a value such as `change-a` is valid regardless of
the native enumeration partition. This corrects an earlier adapter version that
overloaded `scope` for cluster/namespace selection. This is an adapter metadata
compatibility boundary, not a Kubernetes API version change: keep
`source_version` set to the actual Kubernetes or Cilium version, and translate
legacy receipts upstream before combining them with corrected receipts. The
history partition includes both `partition` and `scope`; do not rewrite old
receipts in place or claim a continuous lineage across the metadata correction.

Each snapshot object's `object_id` is the Kubernetes UID and `revision` is the
native `metadata.resourceVersion` text. Resource versions remain opaque strings:
the adapter never parses or orders them numerically. The list-level
`metadata.resourceVersion` is required for a versioned list, but the normalized
contract has no collection cursor field, so a collector must retain list/watch
cursors separately when it resumes a watch.

The caller must attest the source version, permission fingerprint, page counts,
and whether the selected enumeration is full. A complete receipt needs every
page and a final list page without a continuation token. An incomplete list is
partial even when it contains zero items. A versioned Kubernetes `Status` error
becomes a failed receipt, except `410 Gone`, which becomes partial and requires
relist. Malformed errors/lists, unknown GVKs, missing items arrays, and
unsupported schemas raise a safe `ContractError`; none is converted to an
empty-complete collection.

## Snapshot fields

| Family | Projected information | Explicitly omitted |
| --- | --- | --- |
| `kubernetes/service_snapshot` | Service type, selector key names, SHA-256 digest of the complete selector map, canonical port tuples, compatibility port/protocol/target-port arrays, external and internal traffic policy | Raw selector values, annotations, arbitrary labels, full spec |
| `kubernetes/endpointslice_snapshot` | Service name label, address type, canonical port tuples and sorted port list, ready and not-ready Pod UID sets, their counts, unresolved endpoint count | Endpoint addresses, arbitrary labels, owner references and unqualified targetRefs |
| `kubernetes/pod_snapshot` | Pod name/namespace/node, controller owner kind/UID, ObjectMeta generation, status phase, digest of a fixed app/version label allowlist | Pod spec other than nodeName, image/container/status details, annotations, non-allowlisted labels |
| `cilium/policy_snapshot` | Exact API version/kind, namespace when namespaced, generation and hashes for selected metadata label values | Policy `spec`, annotations, status, arbitrary label keys/values, enforcement or application state |

Service port tuples use canonical JSON strings of
`[name-or-null, protocol, servicePort, targetPort-string]`; EndpointSlice port
tuples use `[name-or-null, protocol, port-or-null]`. Tuples are sorted as a
whole, and the compatibility arrays follow that same tuple ordering. This
preserves protocol/name/target associations without treating source array
reordering as a change. Selector values and the fixed Pod/Cilium label values
are hashed; the raw values are never emitted. Pod label hashing covers only
`app.kubernetes.io/component`, `instance`, `name`, `part-of`, and `version`.
Cilium metadata hashing covers only the adapter's fixed app/Cilium label-key
allowlist.

For EndpointSlices, a backend UID is accepted only from a `targetRef` with
`apiVersion: v1`, `kind: Pod`, a matching namespace, and a valid UID. Readiness
must be explicitly boolean before that UID enters a ready or not-ready set.
Missing or unqualified targetRefs, missing readiness, and conflicting readiness
for one UID increase `unresolved_endpoint_count`; the adapter does not infer
readiness from addresses, traffic or Pod state. Ready and not-ready counts are
distinct qualified UID counts; unresolved count is endpoint-record count.
Kubernetes documents nil
EndpointSlice readiness as true for consumers, but this adapter deliberately
leaves absent readiness unresolved rather than making an effective-routing
claim. [EndpointSlice API reference](https://kubernetes.io/docs/reference/kubernetes-api/discovery/endpoint-slice-v1/)

## Watch receipts and gaps

`adapt_services`, `adapt_endpointslices`, and `adapt_pods` dispatch native watch
events to the separate `kubernetes/object_watch` operational family. The
generic `adapt_kubernetes_watch` accepts `ADDED`, `MODIFIED`, `DELETED`,
`BOOKMARK`, and versioned `ERROR` events. ADDED is an observation; initial-state
ADDED events are not treated as proof of creation. DELETED retains a deterministic
event key, the native resource UID, event type and opaque resourceVersion. It is
not a snapshot removal.

A watch collection is complete only when the collector marks it contiguous and
ended and provides either an initial-state-complete attestation or a starting
resourceVersion. Otherwise it is partial. An API `410 Gone` / `Expired` event
always creates partial coverage with `kubernetes-watch:410-gone-relist-required`
in `source_reference`; the caller must relist and start a new watch. Watch
receipts are incremental and never authorize deletion claims. Bookmark and
watch-cursor state stays with the collector because the normalized envelope has
no cursor field. Kubernetes documents the list-then-watch pattern, opaque
resource-version semantics and relisting after `410 Gone` in [API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/).

Kubernetes API-server audit records are a distinct source for actor attribution;
the watch adapter does not claim actor or effective-time information. See
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).

## Source qualification and limits

The official Kubernetes API describes Service selectors, ports and traffic
policies in the [Service documentation](https://kubernetes.io/docs/concepts/services-networking/service/)
and the EndpointSlice grouping and readiness model in
[EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/).
Cilium documents namespaced `CiliumNetworkPolicy` and cluster-scoped
`CiliumClusterwideNetworkPolicy` in its [Kubernetes policy reference](https://docs.cilium.io/en/stable/network/kubernetes/policy/).
The adapter's GVK gate does not qualify the CRD's exact installed OpenAPI schema;
the caller's `qualified_gvks` is an attestation and remains subject to
version-matched CRD review and a sanitized source sample. `generation` means
desired-state generation advanced; it supplies no field-level rule diff and
does not establish policy enforcement.

The inspected Splunk OTel chart 0.161.0 defaults the cluster receiver to pull
Pods, NetworkPolicies and CRD definitions every six hours; its default object
list does not include Services or EndpointSlices. The chart's default ClusterRole
does not include EndpointSlice access. A CRD definition is not a Cilium policy
instance. The repository's Kubernetes operator configuration uses watch mode
with `include_initial_state: true` and separately requests EndpointSlice RBAC.
Those collection settings do not prove complete permissions, watch continuity,
or normalized change history. Hubble flow export is another independently
configured telemetry path; it does not establish policy intent or deployment
success. Package evidence is the statically inspected
`research/extracted/splunk-otel-collector-chart_01610/splunk-otel-collector`
tree (chart 0.161.0, SHA-256
`e3e02156e0b3ac2f733c8340d54b982d801c548aa48cfa6f89d598ab6188ecc3`, per
`research/package-manifest.json`).

Fixtures under `fixtures/change-correlation/kubernetes/` are synthetic,
source-shaped examples of native API payloads. They are not copied from a live
cluster and are not evidence of live qualification. Cilium policy status,
effective enforcement, Hubble verdicts, Gateway/route families, API audit actor
records and controller-managed policy application remain outside this adapter.

The adapter covers the candidate feature boundaries
`k8s_cilium.service_configuration`, `k8s_cilium.endpointslice_backends`,
`k8s_cilium.pod_lifecycle`, `k8s_cilium.policy_revision_application`, and
`k8s_cilium.watch_gaps_actor_audit` only to the extent described above. In
particular, actor audit, effective policy enforcement, Hubble verdicts, route
history and live completeness remain unqualified.
