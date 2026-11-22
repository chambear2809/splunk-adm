# Application owners (OpenTelemetry)

**Purpose:** make each service's traces identify the service, its environment and its pod, and record the network peer of each outgoing call. With that, the map can draw service-to-service calls and tie each call to the network conversation that carried it.

For source selection and release limits, see [deployment options](deployment-options.md). Trace instrumentation is optional for network-derived conversations. Without spans, the app has no trace-derived calls or service bindings; do not treat that absence as proof that the application made no calls. Follow only the trace setup selected for your deployment.

## What we need from you

- [ ] Each service exports OpenTelemetry traces to the node-local Splunk OTel Collector agent.
- [ ] Each service sets `service.name` and `deployment.environment.name`.
- [ ] Outgoing calls produce CLIENT spans with the peer address and port; incoming requests produce SERVER spans.
- [ ] W3C trace context (`traceparent`) passes through the ingress or gateway.
- [ ] Send us the service inventory listed at the end.

## Resource attributes

| Attribute                                                                                | Set by                                                                  | Notes                                                                                                               |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `service.name`                                                                           | You (`OTEL_SERVICE_NAME`)                                               | Stable and unique within the namespace                                                                              |
| `deployment.environment.name`                                                            | You (`OTEL_RESOURCE_ATTRIBUTES`) or the collector's `environment` value | Same value for all services of one environment                                                                      |
| `k8s.cluster.name`, `k8s.namespace.name`, `k8s.pod.name`, `k8s.pod.uid`, `k8s.node.name` | The collector                                                           | Requires configured Kubernetes enrichment and successful pod association; verify these attributes in exported spans |

Send spans to the agent on the pod's own node so the collector can associate them with the right pod:

```yaml
env:
  - name: K8S_NODE_IP
    valueFrom:
      fieldRef:
        fieldPath: status.hostIP
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: "http://$(K8S_NODE_IP):4317"
  - name: OTEL_SERVICE_NAME
    value: "<service-name>"
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: "deployment.environment.name=<environment>"
```

## Span attributes the map uses

The implemented network association uses **CLIENT** spans with a valid peer IP in `attributes.network.peer.address` and a numeric destination port in `attributes.server.port`, plus the originating pod UID and overlapping time interval. Verify the emitted fields; a hostname in `server.address` alone cannot establish an IP conversation match.

| Evidence                           | Fields used by Atlas                                                                                              | Limit                                                                                                                                                                           |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CLIENT span → network conversation | `kind=SPAN_KIND_CLIENT`, `attributes.network.peer.address`, `attributes.server.port`, pod identity and span times | Requires the same pod/peer/port and compatible time. Missing peer IP leaves the network association unresolved.                                                                 |
| Trace service calls                | `trace_id`, `span_id`, `parent_span_id`, `service.name` and workload/resource attributes                          | Requires the relevant spans and resolvable service context; a missing parent remains incomplete evidence.                                                                       |
| Other semantic attributes          | `server.address`, `client.address`, `http.route`, `db.system.name`                                                | May be useful raw span context, but the current graph does not use these as substitutes for the peer-IP association or automatically name an uninstrumented database from them. |

## Trace context through ingress

Preserve W3C trace context through the ingress/gateway when your instrumentation supports it, then inspect exported spans and Hubble events. Do not assume forwarding `traceparent` automatically populates Hubble's `flow.trace_context.parent.trace_id`. The parser retains that field only when a valid trace ID is actually present. Ingress/Gateway backend attribution separately requires the supported L7/hand-off evidence described in the [data contract](../DATA_LAYER.md#attribution-from-frontend-to-backend-pod); a span's `client.address` alone is not that evidence.

When a proxy and an application lack shared trace context, send one tagged read request and compare the tag and response in both access logs. Match each observed TCP connection independently. Database handshakes in the same window help verify transport. A per-query trace or database audit record is needed to tie a particular statement to the request.

## How to verify

```spl
index=otel_traces sourcetype="otel:traces" | stats count by "service.name", "deployment.environment.name", "k8s.namespace.name"
index=otel_traces sourcetype="otel:traces" "SPAN_KIND_CLIENT" | spath | search kind="SPAN_KIND_CLIENT" | table "service.name" name "attributes.server.address" "attributes.server.port" "attributes.network.peer.address" | head 20
```

Each instrumented service should appear with its configured environment and namespace. CLIENT spans used for network association must carry the actual peer IP and destination port; `server.address` is useful context but does not replace the peer IP. Verify pod UID and span timestamps as well.

## Recorded VM application evidence

Use the Services view with an explicit `vm_scope`, service and environment, and an absolute observation window of at most five minutes. An administrator enables the scoped reader through the app-local `adm_vm_application_graph_rows(3)` macro. The shipped reader reports unqualified evidence until a deployment supplies that mapping.

The reader must verify the source authority, VM identity, trace and span IDs, and complete observation window before emitting graph rows. Use the root ID `service:vm/<scope>/<service>/<environment>`. Keep the caller's index permissions and return one metadata row, even when a scope or window has no qualifying evidence. When the span lacks a peer address, only a separately matched socket can support a correlated endpoint. A proxy listener and its upstream database require a paired socket observation. Keep VM telemetry under its actual resource identity.

For a write canary, first verify that a form read exports a server span and related database client spans through the same collector and filter. Raw OTLP JSON can encode span kinds as integers (`2` for server and `3` for client), so check the raw capture before filtering by span kind. Qualify the write using the Save span and its own database child spans, then check the database commit independently.

For a browser entry in a Save replay, capture the actual browser submit and
response. If the action uses an existing WebSocket, qualify context carried
by that submit message. Verify that the indexed browser and server spans
share a trace ID and that the server's parent span ID matches the browser
span ID. Verify the database child spans and commit in the same run. Scope
the replay to the entry path the browser used. A shared proxy needs its own
same-request evidence before it appears in that graph. [W3C Trace Context](https://www.w3.org/TR/trace-context/#traceparent-header)

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Use the vendored commit rather than assuming upstream `main` matches it. Check the exact skill/package release status and guardrails in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying.

- [splunk-observability-k8s-auto-instrumentation-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-k8s-auto-instrumentation-setup): zero-code instrumentation for Java, Node.js, Python, .NET, Go and Apache workloads in Kubernetes.
- [splunk-observability-otel-collector-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-otel-collector-setup): the collector your spans are sent to (operated by the Kubernetes platform team).

## What to send back

- Service list per namespace: entry services, ports, protocols, and dependencies outside the cluster (databases, APIs, VMs).
- Instrumentation per service (language, agent or SDK, version).
- Which services sit behind Cilium Gateway/Ingress, a LoadBalancer Service or a NodePort.

## Open questions

- Any services that cannot be instrumented? They still appear from network evidence, but without call-level detail.
- Do any calls go through a service mesh or sidecar proxy? That changes which IP the network sees.

## Sources

OpenTelemetry semantic conventions (HTTP, database, general attributes: `server.*`, `client.*`, `network.peer.*`, `deployment.environment.name`). Collector-added Kubernetes attributes and environment value: Splunk OTel Collector chart 0.161.0 `values.yaml:262-270` and its `k8s_attributes` processor configuration. How the map uses spans: `docs/DATA_LAYER.md` (span association and access paths).
