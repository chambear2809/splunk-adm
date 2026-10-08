# Application owners (OpenTelemetry)

**Purpose:** make each service's traces identify the service, its environment and its pod, and record the network peer of each outgoing call. With that, the map can draw service-to-service calls and tie each call to the network conversation that carried it.

## What we need from you

- [ ] Each service exports OpenTelemetry traces to the node-local Splunk OTel Collector agent.
- [ ] Each service sets `service.name` and `deployment.environment.name`.
- [ ] Outgoing calls produce CLIENT spans with the peer address and port; incoming requests produce SERVER spans.
- [ ] W3C trace context (`traceparent`) passes through the ingress or gateway.
- [ ] Send us the service inventory listed at the end.

## Resource attributes

| Attribute | Set by | Notes |
| --- | --- | --- |
| `service.name` | You (`OTEL_SERVICE_NAME`) | Stable and unique within the namespace |
| `deployment.environment.name` | You (`OTEL_RESOURCE_ATTRIBUTES`) or the collector's `environment` value | Same value for all services of one environment |
| `k8s.cluster.name`, `k8s.namespace.name`, `k8s.pod.name`, `k8s.pod.uid`, `k8s.node.name` | The collector | Added automatically when spans are sent to the agent on the same node |

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

Use the current OpenTelemetry semantic conventions; most instrumentation libraries set these automatically.

| Span kind | Attributes | Use |
| --- | --- | --- |
| CLIENT (HTTP, gRPC, database, messaging) | `server.address`, `server.port`, `network.peer.address` | Links the call to the network conversation from this pod to that IP and port |
| SERVER | `client.address`, `network.peer.address`, `http.route` | Identifies the caller; behind a proxy, `client.address` carries the original client from `X-Forwarded-For` |
| Database CLIENT | `db.system.name`, `server.address`, `server.port` | Names uninstrumented databases (for example a VM in ACI) |

`network.peer.address` must be the IP actually connected to. If your library only records a hostname, enable the option that records the peer IP, or tell us the service so we can mark its calls as name-only.

## Trace context through ingress

- **Cilium Ingress / Gateway API:** forward the `traceparent` header unchanged (the default). Hubble's L7 flows then carry the trace ID and link the gateway hop to your server spans.

## How to verify

```spl
index=otel_traces sourcetype="otel:traces" | stats count by "service.name", "deployment.environment.name", "k8s.namespace.name"
index=otel_traces sourcetype="otel:traces" "SPAN_KIND_CLIENT" | spath | search kind="SPAN_KIND_CLIENT" | table "service.name" name "attributes.server.address" "attributes.server.port" "attributes.network.peer.address" | head 20
```

Each service should appear with its environment and namespace, and client spans should show the three peer attributes.

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Their `main` branch is verified on Splunk Enterprise 10.4; review plans against 10.6 for this pilot.

- [splunk-observability-k8s-auto-instrumentation-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-k8s-auto-instrumentation-setup): zero-code instrumentation for Java, Node.js, Python, .NET, Go and Apache workloads in Kubernetes.
- [splunk-observability-otel-collector-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-otel-collector-setup): the collector your spans are sent to (operated by the Kubernetes platform team).

## What to send back

- Service list per namespace: entry services, ports, protocols, and dependencies outside the cluster (databases, APIs, VMs).
- Instrumentation per service (language, agent or SDK, version).
- Which services sit behind Cilium Gateway/Ingress, a LoadBalancer Service or a NodePort.

## Open questions

- Any services that cannot be instrumented? They still appear from network evidence, but without call-level detail.
- Do any calls go through a service mesh or sidecar proxy? That changes which IP the network sees.

## Sources

OpenTelemetry semantic conventions (HTTP, database, general attributes: `server.*`, `client.*`, `network.peer.*`, `deployment.environment.name`). Collector-added Kubernetes attributes and environment value: Splunk OTel Collector chart 0.161.0 `values.yaml:262-270` and its `k8s_attributes` processor configuration. How the map uses spans: `docs/DATA_LAYER.md` (span association and access paths).
