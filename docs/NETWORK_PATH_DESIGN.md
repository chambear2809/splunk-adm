# Network path evidence

## What the path view shows

Selecting a network conversation shows a *candidate path*: the client, its attachment (pod → Kubernetes node → leaf and port, or VM → ACI leaf and port), the shortest CDP path between the two attachment switches, the server's attachment and the server. Each hop is marked observed when a collected record names that device (NetFlow exporter, Nexus Dashboard fabric/leaf, FTD device, Isovalent node), or not observed otherwise. Where no collected link connects two segments, for example between the NX-OS fabric and ACI or to the internet edge, the path shows an explicit gap. See the topology contract in [DATA_LAYER.md](DATA_LAYER.md).

A candidate path comes from inventory. Observations at several hops don't prove that one packet traversed them in that order: ECMP, overlays, asymmetric return paths and sampling all break that inference. Forward and reverse directions need their own observations.

A load balancer or proxy can terminate the client connection and open another. Treat a request across such a device as connected transport legs, not one unchanged flow. [Kubernetes source IP guidance](https://kubernetes.io/docs/tutorials/services/source-ip/).

## Evidence by stage

| Stage | Evidence | Role and limitation |
| --- | --- | --- |
| Firewall / edge | FTD connection tuple, device, zones/interfaces, time; pre/post-NAT tuple | Policy and connection observation. The inspected Security Cloud TA extracts no translated tuple, so a public VIP is not yet linked to its backend. |
| Physical fabric | Stream NetFlow tuple, exporter, ingress/egress interfaces, sampling; NX-OS CDP neighbors | Observations plus inventory topology. Exporters don't prove hop order. Host-facing ifIndex names need `show interface snmp-ifindex`. |
| ACI attachment | Endpoint IP/MAC, attachment path DN, tenant, EPG, VM, validity history | Endpoint attachment, not packet forwarding proof. |
| Nexus Dashboard | Fabric flow records with leaf and interface; endpoint change events | Fabric-level observations and attachment changes. |
| Kubernetes node / CNI | Pod placement and IP history from pod watch events; Isovalent `processConnect` for pod-initiated connections | With Cilium native routing, pod IPs appear on the fabric. In tunnel mode the fabric sees only node-to-node VXLAN/Geneve. |
| Service → pod | Cilium kube-proxy replacement translates ClusterIPs at connect time | ClusterIPs never appear on the wire; connections show backend pod IPs. |
| Application | OTel parent/child spans, service identity, `k8s.pod.uid`; client span `network.peer.address` + `server.port` | Trace calls establish application dependency. A client span matched to a conversation by peer address, port, owning pod and time links that call to that connection. |

## Matching rules

Identities join only within one routing scope (`adm_observer_scope.csv`); observation domain IDs are not VRFs. An IP resolves only when exactly one identity covers the interval. Conversations without that stay visible as unknown or multiple-owner endpoints. Unobserved hops stay marked as not observed, and missing links stay gaps; nothing is filled in by guesswork.
