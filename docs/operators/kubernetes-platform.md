# Kubernetes platform team

**Purpose:** send Kubernetes object history, application spans and Hubble flow logs to Splunk through the Splunk OpenTelemetry Collector for Kubernetes, so the map can tell which pod, Service, Ingress or Gateway owned an address at a given time.

## What we need from you

- [ ] Deploy (or update) the Splunk OTel Collector Helm chart with the values below.
- [ ] Grant the extra RBAC rules for EndpointSlices, Ingresses, Gateways and HTTPRoutes.
- [ ] Mount the Hubble flow log directory into the collector agent and tail it.
- [ ] Run an LLDP agent on every node that advertises the Kubernetes node name.
- [ ] Send back the cluster details listed at the end.

## Helm values

Validated against chart 0.161.0. Keep your existing values; merge these in.

```yaml
clusterName: <cluster-name>          # becomes k8s.cluster.name on every event
environment: <environment>           # optional; becomes deployment.environment.name

splunkPlatform:
  endpoint: https://<hec-host>:8088/services/collector/event
  token: <HEC token "otel-k8s">      # or provide it as a Kubernetes secret
  index: k8s                         # Kubernetes objects (and container logs, see below)
  tracesEnabled: true
  tracesIndex: otel_traces
  sourcetype: otel:traces            # default sourcetype for traces; objects keep kube:object:<resource>

clusterReceiver:
  k8sObjects:                        # this list replaces the chart default
    - name: pods
      mode: watch
    - name: services
      mode: watch
    - name: endpointslices
      group: discovery.k8s.io
      mode: watch
    - name: ingresses
      group: networking.k8s.io
      mode: watch
    - name: gateways
      group: gateway.networking.k8s.io
      mode: watch
    - name: httproutes
      group: gateway.networking.k8s.io
      mode: watch
    - name: nodes
      mode: watch
  config:                            # merged over the chart's receiver config
    receivers:
      k8s_objects:
        include_initial_state: true  # also send objects that already exist at start-up

rbac:
  customRules:                       # pods, services and nodes are already granted by the chart
    - apiGroups: ["discovery.k8s.io"]
      resources: ["endpointslices"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["networking.k8s.io"]
      resources: ["ingresses"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["gateway.networking.k8s.io"]
      resources: ["gateways", "httproutes"]
      verbs: ["get", "list", "watch"]

logsCollection:
  extraFileLogs:
    file_log/hubble-flows:
      include: [/var/run/cilium/hubble/events.log]
      start_at: end
      include_file_path: true
      include_file_name: false
      resource:
        com.splunk.source: /var/run/cilium/hubble/events.log
        com.splunk.sourcetype: cilium:hubble:flow
        com.splunk.index: cilium_hubble
        host.name: 'EXPR(env("K8S_NODE_NAME"))'

agent:
  extraVolumes:
    - name: hubble-flows
      hostPath:
        path: /var/run/cilium/hubble
  extraVolumeMounts:
    - name: hubble-flows
      mountPath: /var/run/cilium/hubble
      readOnly: true
```

Notes:

- **Pull vs watch:** the chart's default pod collection is a pull every 6 hours, which is too coarse to know which pod owned an IP at a given minute. Watch mode sends each change as it happens.
- **Watch-mode start-up (required):** in the collector shipped with chart 0.161.0, watch mode sends only changes. Without `include_initial_state: true`, Pods, Services and Nodes that already exist when the collector starts are never reported, and their IPs stay unknown in the map. The chart doesn't expose this option under `k8sObjects`, so it is set through `clusterReceiver.config` as above (receiver `k8s_objects`, merged over the chart defaults). After a collector restart, existing objects are sent once as `ADDED` events.
- **Required objects:** pods, services, endpointslices, ingresses, httproutes and nodes. Gateways are optional; the map uses HTTPRoutes and the Gateway's Service.
- **Container logs:** they also go to `splunkPlatform.index` by default. Route them elsewhere with the `splunk.com/index` pod or namespace annotation, or set `logsCollection.containers.enabled: false` if this pilot does not need them.
- **Gateway API:** collect `gateways` and `httproutes` only if the Gateway API CRDs are installed; otherwise remove those two entries (and their RBAC rule).
- **Hubble export:** the file is written by Cilium only when the Hubble exporter is enabled (see [cilium-isovalent.md](cilium-isovalent.md)). Cilium rotates it; the include pattern matches only the active file.

## LLDP on nodes

Run an LLDP agent (for example `lldpd`) on every node, advertising a system name equal to the Kubernetes node name (`kubectl get nodes`). If kubelet uses `--hostname-override`, set the LLDP system name to that value. The ACI team enables LLDP receive on the matching leaf ports.

## How to verify

```spl
index=k8s sourcetype IN ("kube:object:pods", "kube:object:services", "kube:object:endpointslices", "kube:object:ingresses", "kube:object:gateways", "kube:object:httproutes", "kube:object:nodes") | stats count by sourcetype
index=otel_traces sourcetype="otel:traces" | stats count by "service.name", "k8s.namespace.name"
index=cilium_hubble sourcetype="cilium:hubble:flow" | stats count by host
```

Every node should appear as a `host` in the last search.

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Their `main` branch is verified on Splunk Enterprise 10.4; review plans against 10.6 for this pilot.

- [splunk-observability-otel-collector-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-otel-collector-setup): renders, preflights, applies and validates the Splunk OTel Collector Helm chart, including `splunkPlatform`, `tracesEnabled`, `clusterReceiver.k8sObjects` and `logsCollection.extraFileLogs`.
- [splunk-observability-k8s-auto-instrumentation-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-k8s-auto-instrumentation-setup): zero-code instrumentation for application pods (used with the application teams).

## What to send back

- Cluster name, Kubernetes version, chart version, the final values file (without the token).
- Node names, node IPs and node subnets; pod CIDR per node; NodePort range.
- The Cilium Ingress/Gateway resources in use and their LoadBalancer Services.
- One hour of sample events for each sourcetype above.

## Open questions

- Is the Kubernetes node name identical to the host name advertised by LLDP?
- Does any Service use `externalIPs`, or `hostNetwork` pods that serve application traffic?

## Sources

Chart 0.161.0 `values.yaml:28,36-60,130-134,548-640,683-800,893-897`; `templates/clusterRole.yaml:31-52,124-130`; `templates/config/_otel-k8s-cluster-receiver-config.tpl:209-213` (`kube:object:<resource>` sourcetype), `:50-53` (receiver `k8s_objects` renders only `auth_type` and `objects`); `templates/configmap-cluster-receiver.yaml:21` (`clusterReceiver.config` merged over defaults); `include_initial_state`: opentelemetry-collector-contrib v0.161.0 `receiver/k8sobjectsreceiver/README.md:61-62`; `templates/config/_otel-agent.tpl:745-755` (extra file logs); `templates/config/_common.tpl:227-231` (`splunk.com/index` annotation). Hubble export path: Cilium 1.20.2 Helm `values.yaml:2209-2238`.
