# Cilium and Isovalent team

**Purpose:** export Hubble flow logs and Isovalent Runtime Security connection events, and tell us how Cilium load-balances, so the map can say which backend pod served a client that came in through a LoadBalancer VIP, NodePort, Ingress or Gateway.

## What we need from you

- [ ] Enable Hubble's static flow exporter, limited to the application's traffic and the fields below.
- [ ] Send us the load-balancing settings in effect (table below).
- [ ] Keep Isovalent Runtime Security `processConnect` events flowing to the Splunk HEC token `isovalent`.
- [ ] If you use Isovalent Enterprise's own flow exporter, send one real sample event before we model it.

## Hubble flow export (Cilium Helm values)

Validated against Cilium 1.20.2. The Kubernetes team tails the file with the Splunk OTel Collector (see [kubernetes-platform.md](kubernetes-platform.md)).

```yaml
hubble:
  enabled: true
  export:
    static:
      enabled: true
      filePath: /var/run/cilium/hubble/events.log
      # Each entry is a Hubble flow filter (JSON); entries are OR'ed.
      allowList:
        - '{"source_pod":["<app-namespace>/"]}'
        - '{"destination_pod":["<app-namespace>/"]}'
        - '{"destination_ip":["<LoadBalancer pool CIDR>"]}'
      fieldMask:
        - time
        - verdict
        - IP
        - l4
        - source
        - destination
        - Type
        - node_name
        - event_type
        - traffic_direction
        - trace_observation_point
        - is_reply
        - destination_service
        - l7
        - trace_context
      fileMaxSizeMb: 10
      fileMaxBackups: 5
```

- Add one `source_pod`/`destination_pod` pair per application namespace. Cilium's Envoy (Ingress/Gateway) upstream connections and SNAT forwarding traces are kept by the `destination_pod` filter because their destination is an application pod.
- The map needs, from these flows: backend arrivals (`TO_ENDPOINT`), SNAT forwarding traces (`TO_NETWORK` with `IP.source_xlated`), and L7 HTTP requests (`l7.http.headers` with `X-Forwarded-For`, and `trace_context`). Keep every field in the mask above.
- `IP` includes `source_xlated`, which the map uses to follow SNAT.
- `l7` carries HTTP headers. Ingress and Gateway attribution relies on `X-Forwarded-For`. Consider `hubble.redact` (`enabled`, `http.urlQuery`, `http.userInfo`) so query strings and credentials are not exported.

### Monitor aggregation

The default `bpf.monitorAggregation: medium` suppresses Hubble's pre-translation and some forwarding traces. Flows still appear at the backend pod after translation, which is enough for `externalTrafficPolicy: Local`, DSR and NodePort `Local`. For `Cluster` with SNAT to a pod on another node, the map then marks the client-to-pod link "inferred" instead of "observed". Lowering aggregation adds events and CPU; do not change it for the pilot without measuring.

## Load-balancing facts we need

| Setting (Cilium Helm) | Why it matters |
| --- | --- |
| `kubeProxyReplacement` | Service translation happens in Cilium, so Service ClusterIPs never appear on the network |
| `routingMode`, `autoDirectNodeRoutes`, `ipv4NativeRoutingCIDR` | Native routing makes pod IPs visible to the fabric; tunnel mode hides them inside node-to-node VXLAN/Geneve |
| `loadBalancer.mode` (`snat`, `dsr`, `hybrid`) and `loadBalancer.algorithm` | SNAT hides the client IP from remote backends; DSR keeps it and returns traffic directly from the backend node |
| `loadBalancer.dsrDispatch` | How DSR carries the service address (`opt`, `ipip`, `geneve`). Use `ipip` if DSR is used: the fabric then shows the receiving-node → backend-node hop as IPIP, which the map uses to tie the client to the backend. With `opt`, that hop is indistinguishable from a direct client → pod connection, and the map reports a warning instead of guessing. Per-Service DSR also needs `bpf.lbModeAnnotation: true`. |
| `bgpControlPlane.enabled` and your BGP advertisements | Which nodes attract VIP traffic. With `externalTrafficPolicy: Local`, only nodes with a local backend advertise |
| `l2announcements.enabled` | L2 announcements cannot be combined with `externalTrafficPolicy: Local` |
| `ingressController.enabled`, `gatewayAPI.enabled` | Cilium's Envoy terminates client connections and opens new ones to backends from the node's ingress IP, and adds `X-Forwarded-For` |

Also send the LB IPAM pools (`CiliumLoadBalancerIPPool`) and BGP advertisement objects in use.

## Isovalent Runtime Security

Isovalent Runtime Security (Tetragon) must emit `process_connect` events, exported to Splunk HEC using the `isovalent` token (index `cisco_isovalent`, sourcetype `cisco:isovalent`). The Cisco Security Cloud add-on splits them into `cisco:isovalent:processConnect` at index time.

Verify with your Isovalent version that connect events are enabled. In open-source Tetragon they require a TracingPolicy on TCP connect.

## Isovalent Enterprise flow export

If Isovalent Enterprise exports flows instead of, or alongside, Hubble's built-in file export, send us one real exported event per event type: a forwarded flow, an L7 HTTP flow and a dropped flow. We will not model the Enterprise format before we have seen it.

## How to verify

```spl
index=cilium_hubble sourcetype="cilium:hubble:flow" | spath path=flow.trace_observation_point output=top | stats count by top
index=cilium_hubble sourcetype="cilium:hubble:flow" "X-Forwarded-For" | spath path=flow.l7.http.headers{}.key output=header | search header="X-Forwarded-For" | head 5
index=cisco_isovalent sourcetype="cisco:isovalent:processConnect" | head 5
```

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Their `main` branch is verified on Splunk Enterprise 10.4; review plans against 10.6 for this pilot.

- [cisco-isovalent-platform-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-isovalent-platform-setup): install and validate Cilium, Tetragon and Hubble.
- [splunk-observability-isovalent-integration](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-isovalent-integration): ships Tetragon logs to Splunk Platform (collector file tail and HEC) and Hubble metrics to Splunk Observability Cloud.
- [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-security-cloud-setup): the Cisco Security Cloud Isovalent HEC input (configured by the Splunk team).
- Gap: no skill configures Hubble **flow** export (`hubble.export.static`). Use the values in this handout; the collector side is in [kubernetes-platform.md](kubernetes-platform.md).

## What to send back

- Cilium, Hubble and Isovalent versions; the Cilium Helm values (redacted) for the settings above.
- LB IPAM pools, BGP advertisements, CiliumNode ingress IPs (`spec.ingress.ipv4`).
- One hour of Hubble and `processConnect` sample events; the Enterprise export sample if applicable.

## Open questions

- Which Services use `externalTrafficPolicy: Local` and which use `Cluster`?
- Is DSR or hybrid mode enabled, and with which dispatch?
- Is TLS passthrough used on any Gateway? With passthrough, Envoy cannot add `X-Forwarded-For`, so attribution through it is time-correlated only.

## Sources

Cilium 1.20.2 Helm `values.yaml` (`hubble.export.static` 2209-2238, `hubble.redact` 1606, `bpf.monitorAggregation` 678, `loadBalancer` 2554-2571, `bgpControlPlane` 515, `l2announcements` 499, `ingressController` 984, `gatewayAPI` 1094). Hubble `flow.proto` v1.20.2 (Flow fields, `IP.source_xlated`, FlowFilter syntax). Kube-proxy-free, BGP, L2 announcement and Ingress behavior: docs.cilium.io stable (1.20.2). Isovalent sourcetypes: Cisco Security Cloud 3.7.2 `default/props.conf:2282-2303`, `default/inputs.conf:120-125`.
