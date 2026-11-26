# Atlas Kubernetes point-snapshot collector receiver

`atlas_k8s_snapshot` is an experimental, locally maintained Go logs receiver for
the Splunk OpenTelemetry Collector. It collects independent complete paginated
Node and Pod lists using the in-cluster service account token and Kubernetes CA.
It does not watch resources or emit historical ownership intervals. A complete
Node list and a complete Pod list are separate generations: their resource
versions and observation windows are not interchangeable, and a Pod's
`spec.nodeName` is not a Node UID. Do not use matching names or independent
snapshot windows as proof of an instantaneous or continuous Pod-to-Node binding.
The cluster, scope and producer ID are operator attestations.

The receiver performs one collection immediately and then on its configured
interval. Every page must have the same collection resourceVersion; invalid
continuations, duplicate UIDs/names, ambiguous Node addresses, invalid IPs,
expired lists, HTTP failures, timeout and configured limits reject the complete
collection before any events are passed to the downstream consumer. A Pod with
`hostNetwork=true` remains marked as such; no ownership is inferred from its IP.
The token is re-read from the projected file for each request; TLS validates
against the projected Kubernetes CA, proxies and redirects are disabled, and
errors do not include response bodies or credentials. The CA is loaded at
receiver creation, so a CA rotation requires collector restart/recreation.

Output is a structured map log body, translated to a JSON object by the pinned
Splunk HEC exporter. Each Node generation uses schema
`application_atlas.k8s_node_snapshot.v1` and sourcetype
`adm:k8s_node_snapshot:v1`; each Pod generation uses schema
`application_atlas.k8s_pod_node_snapshot.v1` and sourcetype
`adm:k8s_pod_node_snapshot:v1`. The sender sets resource attributes
`com.splunk.source`, `com.splunk.sourcetype`, and `com.splunk.index` for the
Splunk HEC exporter. A unique `generation_id` appears on each row and its
manifest. Every row has schema/version, cluster, scope, producer, UID/name and
LIST start/completion bounds; Node rows carry typed addresses and Pod rows carry
namespace, node name, host-network flag, IPs and phase. The row fingerprint is
SHA-256 of Go `encoding/json.Marshal` output for the row before adding
`record_fingerprint`. Rows are sorted by UID; `records_sha256` is SHA-256 of the
newline-joined canonical JSON rows *including* their fingerprints, with no final
newline. The empty-row digest is SHA-256 of empty bytes. The manifest gives
`resource_version`, `expected_count`, digest, `complete=true`, all-namespace
scope and `validity_basis=point_snapshot`; it does not acknowledge indexing.
Consumers must group by exact schema, source, scope, cluster, producer and
generation ID, verify every row/fingerprint/count/digest including zero,
reject duplicate/missing/conflicting rows and stale/unauthorized data, and
qualify both sender clock uncertainty and indexed time/receipt. A source
manifest proves completed API collection, not atomic or successful HEC delivery.
The exporter may split or partially deliver a batch; consumer validation is
mandatory and this repository does not yet supply an accepting consumer.

Example configuration (merge into the *existing* reviewed collector deployment;
use an existing authenticated Splunk HEC exporter and restricted index):

```yaml
receivers:
  atlas_k8s_snapshot:
    cluster: cluster-name
    scope: routing-scope
    producer_id: collector-instance
    source: atlas_k8s_snapshot
    index: atlas_identity
    interval: 1m
    timeout: 30s
    page_size: 200
    max_pages: 100
    max_records: 10000
    max_bytes: 16777216        # normalized output per Node or Pod generation
    max_page_bytes: 33554432   # one raw LIST response page
service:
  pipelines:
    logs/atlas_k8s_snapshot:
      receivers: [atlas_k8s_snapshot]
      exporters: [splunk_hec/platform]
```

Sizing: `max_page_bytes` (64 KiB to 256 MiB, default 32 MiB) caps one raw LIST
response. Each page is decoded into the few fields the receiver keeps and then
discarded, so total cluster size is limited by `max_pages × page_size` and
`max_records`, not by this value. Budget transient memory of up to about twice
`max_page_bytes` for the read buffer and decode, plus roughly three copies of
the normalized output (rows, canonical strings and log records). Bytes read per
cycle are bounded by the timeout and by `max_pages × max_page_bytes` per
resource, not by a cumulative cap. Full Pod objects with large `managedFields`, env lists or
annotations are commonly 10–40 KiB each; at the default `page_size: 200` a
32 MiB page allows roughly 160 KiB per Pod. Lower `page_size` before raising
`max_page_bytes`. `max_bytes` (1 KiB to 64 MiB, default 16 MiB) caps the
normalized JSON rows plus manifest of one generation; normalized Pod rows are
typically under 1 KiB, so the default covers `max_records: 10000`.

Each failed cycle logs `atlas kubernetes snapshot failed` with a fixed
`reason` field, the `resource` (`nodes` or `pods`), and `http_status` when the
API server replied with a non-200 status. Reasons are `page_byte_limit`,
`page_limit`, `record_limit`, `output_limit`, `http_status`, `timeout`,
`request_failed`, `read_failed`, `malformed_response`, `inconsistent_list`,
`invalid_object`, `clock_discontinuity`, `credential_unavailable`,
`credential_invalid`, `encoding`, `delivery_failed`, `generation` (random
generation ID unavailable), `invalid_resource`, `invalid_request` and `internal`
(an unclassified error). No response bodies,
tokens or exporter error text are logged.

This fragment is illustrative: the exporter name, HEC token/index authorization,
parser settings and all existing pipelines must be reconciled against the target
configuration. Do not publish secrets in config or logs. The receiver assumes
one active replica per producer identity; replicas or exporter retries can
produce overlapping/duplicate generations. It intentionally has no leader
election, watch state, persistence or Kubernetes object patching. Existing Pod
interval producers and normal `k8s_objects` streams are unaffected. LIST/watch
permissions and effective least privilege must be independently checked; this
receiver needs only LIST on nodes and pods, no mutation and no RBAC expansion.

The `build-manifest.yaml` pins the upstream collector source release and
identifies the registration point. Add this module's `NewFactory()` to the
existing `b.AddReceivers` in `internal/components/components.go`, with an
appropriate local module replacement, and retain all existing factories,
feature gates and config providers. Build the upstream `./cmd/otelcol` and
package a separately reviewed image. This is a custom distribution, not a
vendor-signed TA or claim of vendor support. Pin and verify source/image digests,
review licensing and dependencies, qualify compatibility and resource limits,
and verify the resulting binary and HEC ingestion before an authorized rollout.
No image, binary, deployment, index or RBAC change is produced by this module.
