# Cilium and Isovalent team

**Purpose:** export Hubble flow logs and Isovalent Runtime Security connection events, and tell us how Cilium load-balances, so the map can say which backend pod served a client that came in through a LoadBalancer VIP, NodePort, Ingress or Gateway.

For source selection and release limits, see [deployment options](deployment-options.md). Hubble and Isovalent Runtime Security are separate optional feeds. Configure the ones selected for your deployment. Without compatible handoff evidence, a Service frontend may remain visible while its backend or receiving node stays unresolved; do not infer that path from aggregate backend traffic.

## What we need from you

- [ ] Enable Hubble's static flow exporter, limited to the application's traffic and the fields below.
- [ ] Send us the load-balancing settings in effect (table below).
- [ ] Keep Isovalent Runtime Security `processConnect` events flowing to the Splunk HEC token `isovalent`.
- [ ] If you use Isovalent Enterprise's own flow exporter, verify that its events use the supported Hubble JSON-lines envelope; send a redacted sample for an unrecognized format.

## Hubble flow export (Cilium Helm values)

Validated against Cilium 1.20.2. The Kubernetes team tails the file with the Splunk OTel Collector (see [kubernetes-platform.md](kubernetes-platform.md)).

The `cisco-isovalent-platform-setup` skill renders this for you (OSS Cilium chart only; see below) from a `hubble_flow_export` spec block:

```yaml
# spec.yaml (skill input), not a Helm values file
hubble_flow_export:
  enabled: true
  namespaces: ["<app-namespace>"]
  allow_list: ['{"destination_ip":["<LoadBalancer pool CIDR>"]}']
  field_mask:
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
  file_max_size_mb: 10
  file_max_backups: 5
```

```sh
cd vendor/splunk-cisco-skills
bash skills/cisco-isovalent-platform-setup/scripts/setup.sh --spec /path/to/spec.yaml --dry-run
# review helm/cilium-values.yaml, then rerun without --dry-run to apply
```

This coordinates automatically with `splunk-observability-isovalent-integration`'s collector file tail (same file path, index `cilium_hubble`, sourcetype `cilium:hubble:flow`), which the Kubernetes team runs with the same tool. The equivalent raw Helm values, if you configure Cilium directly instead:

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

The default `bpf.monitorAggregation: medium` suppresses Hubble's pre-translation and some forwarding traces. Flows still appear at the backend pod after translation, which is enough for `externalTrafficPolicy: Local`, DSR and NodePort `Local`. For `Cluster` with SNAT to a pod on another node, the map can use timing inference only when the data contract's uniqueness and exclusion rules pass; otherwise the backend stays unresolved. Lowering aggregation adds events and CPU; do not change it for the pilot without measuring.

## Load-balancing facts we need

| Setting (Cilium Helm)                                                      | Why it matters                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kubeProxyReplacement`                                                     | Service translation happens in Cilium, so Service ClusterIPs never appear on the network                                                                                                                                                                                                                                                                                                                         |
| `routingMode`, `autoDirectNodeRoutes`, `ipv4NativeRoutingCIDR`             | Native routing makes pod IPs visible to the fabric; tunnel mode hides them inside node-to-node VXLAN/Geneve                                                                                                                                                                                                                                                                                                      |
| `loadBalancer.mode` (`snat`, `dsr`, `hybrid`) and `loadBalancer.algorithm` | SNAT hides the client IP from remote backends; DSR keeps it and returns traffic directly from the backend node                                                                                                                                                                                                                                                                                                   |
| `loadBalancer.dsrDispatch`                                                 | How DSR carries the service address (`opt`, `ipip`, `geneve`). Use `ipip` if DSR is used: the fabric then shows the receiving-node → backend-node hop as IPIP, which the map uses to tie the client to the backend. With `opt`, that hop is indistinguishable from a direct client → pod connection, and the map reports a warning instead of guessing. Per-Service DSR also needs `bpf.lbModeAnnotation: true`. |
| `bgpControlPlane.enabled` and your BGP advertisements                      | Which nodes attract VIP traffic. With `externalTrafficPolicy: Local`, only nodes with a local backend advertise                                                                                                                                                                                                                                                                                                  |
| `l2announcements.enabled`                                                  | L2 announcements cannot be combined with `externalTrafficPolicy: Local`. Reported here as the `` `adm_l2announcements_enabled` `` macro (0/1, operator-set, next to `` `adm_cilium_lb_mode` ``); the map warns when it is 1 and a `Local`-policy Service is in scope.                                                                                                                                            |
| `ingressController.enabled`, `gatewayAPI.enabled`                          | Cilium's Envoy terminates client connections and opens new ones to backends from the node's ingress IP, and adds `X-Forwarded-For`                                                                                                                                                                                                                                                                               |

Also send the LB IPAM pools (`CiliumLoadBalancerIPPool`) and BGP advertisement objects in use.

## Isovalent Runtime Security

Isovalent Runtime Security (Tetragon) must emit `process_connect` events, exported to Splunk HEC using the `isovalent` token (index `cisco_isovalent`, sourcetype `cisco:isovalent`). The Cisco Security Cloud add-on splits them into `cisco:isovalent:processConnect` at index time.

Verify with your Isovalent version that connect events are enabled. In open-source Tetragon they require a TracingPolicy on TCP connect.

## Isovalent Enterprise flow export

The shared parser supports open-source and Isovalent Enterprise Hubble JSON-lines with the `flow`, `node_name` and `time` envelope and documented Cilium flow fields. The checked-in [Enterprise samples](../../fixtures/samples/hubble-enterprise/README.md) and `tests/splunk/test_hubble_enterprise.py` cover the inspected 1.19.5-cee.1 export. This does not qualify every Enterprise version or a different export schema. Verify actual event fields, and provide redacted forwarded/L7/dropped samples when the target differs. Do not ingest the same export twice under separate OSS and Enterprise aliases.

## How to verify

```spl
index=cilium_hubble sourcetype="cilium:hubble:flow" | spath path=flow.trace_observation_point output=top | stats count by top
index=cilium_hubble sourcetype="cilium:hubble:flow" "X-Forwarded-For" | spath path=flow.l7.http.headers{}.key output=header | search header="X-Forwarded-For" | head 5
index=cisco_isovalent sourcetype="cisco:isovalent:processConnect" | head 5
```

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Use the vendored commit rather than assuming upstream `main` matches it. Check the exact skill/package release status and guardrails in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying.

- [cisco-isovalent-platform-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-isovalent-platform-setup): install and validate Cilium, Tetragon and Hubble, including the `hubble_flow_export` spec block used above (OSS Cilium chart only; the Isovalent Enterprise chart's flow-export values aren't verified, so the skill fails closed if you point it there — verify the supported values for your Enterprise chart and use its approved configuration procedure; the raw values above are the OSS example).
- [splunk-observability-isovalent-integration](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-isovalent-integration): ships Tetragon logs to Splunk Platform (collector file tail and HEC), tails the Hubble flow export file into `cilium_hubble` (coordinates automatically with the block above), and ships Hubble metrics to Splunk Observability Cloud.
- [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-security-cloud-setup): the Cisco Security Cloud Isovalent HEC input (configured by the Splunk team).

## What to send back

- Cilium, Hubble and Isovalent versions; the Cilium Helm values (redacted) for the settings above.
- LB IPAM pools, BGP advertisements, CiliumNode ingress IPs (`spec.ingress.ipv4`).
- One hour of Hubble and `processConnect` sample events; the Enterprise export sample if applicable.

## Open questions

- Which Services use `externalTrafficPolicy: Local` and which use `Cluster`?
- Is DSR or hybrid mode enabled, and with which dispatch?
- Is TLS passthrough used on any Gateway? With passthrough, HTTP header evidence may be unavailable; do not assume the remaining evidence resolves a backend. Check the supported handoff rules and preserve unresolved boundaries.

## Sources

Cilium 1.20.2 Helm `values.yaml` (`hubble.export.static` 2209-2238, `hubble.redact` 1606, `bpf.monitorAggregation` 678, `loadBalancer` 2554-2571, `bgpControlPlane` 515, `l2announcements` 499, `ingressController` 984, `gatewayAPI` 1094). Hubble `flow.proto` v1.20.2 (Flow fields, `IP.source_xlated`, FlowFilter syntax). Kube-proxy-free, BGP, L2 announcement and Ingress behavior: docs.cilium.io stable (1.20.2). Isovalent sourcetypes: Cisco Security Cloud 3.7.2 `default/props.conf:2282-2303`, `default/inputs.conf:120-125`.
