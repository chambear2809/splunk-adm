# Segmentation policy workbench (draft only)

For security and segmentation teams. Open a map, then choose **More actions → Segmentation policy (draft)**. The workbench answers three questions about the map's scope:

1. How much observed traffic do the collected policies already permit?
2. If a proposed rule set were enforced, what observed traffic would it block?
3. What would that rule set look like as Kubernetes, Cilium, ACI or firewall configuration?

Atlas **never applies policy**. It does not call Kubernetes, Cilium, APIC, firewall or SaaS APIs and does not write to any external system. Each export is a local file marked `DRAFT`, for review in your normal change process.

## Evidence and permissions

The workbench reads only the conversations (`communicates_with` edges) already on the map. It runs no searches of its own.

- **Map window**: the default. Uses the map that is already loaded, with its truncation, read coverage and warnings.
- **Another window** (live Splunk data only): **Read window** re-runs the same bounded map search for the same scope and an absolute UTC window of 1 minute to 7 days. It reads five-minute summaries and ranks the top N edges when the result is large. The search runs as you, with your Splunk role; Atlas never elevates permissions. Demo data has only one captured window.

The workbench reports the read as **incomplete** when the map is truncated, read coverage is below 100%, summaries are still pending, or a search warned that it hit a cap. When the read is incomplete, every count is a lower bound. Unresolved and ambiguous endpoints are counted and listed.

## Coverage by collected policy

Each observed conversation is counted once, by conversations and by connections, as one of the following:

| Result | Meaning | Source field |
| --- | --- | --- |
| Covered | A collected ACI contract permits it (`contract_basis=intent`), or both ends are in the same EPG (`intra_epg`). | ACI `vzBrCP`/`vzSubj`/`vzRsSubjFiltAtt`/`vzEntry`, `fvRsProv`/`fvRsCons` (see [aci-network](aci-network.md)) |
| Not covered | Collected ACI policy is complete and has no permit (`contract_basis=none`), or a drop was logged. | Same, plus `adm_aci_policy_complete=1` |
| Unknown | No policy data, or policy that Atlas does not evaluate (`not_evaluated` or no contract fields). | — |

Rules:

- Atlas never calls traffic "allowed" without policy evidence. "Covered" means the configured ACI intent permits the conversation. It does not prove enforcement.
- **Cilium and Kubernetes policy rules are not collected.** Atlas keeps only Hubble flow verdicts (forwarded flows on the map). The pod side of a conversation therefore stays unknown unless ACI evidence covers it, and the workbench says how many pod conversations this affects.
- `vzAny`, taboos, ESG membership, unenforced VRFs and cross-tenant contracts are `not_evaluated` and count as unknown. "Not covered" requires the optional `classInfo_adm_policy` input (`adm_aci_policy_complete=1`).
- The absence of an ACL drop record proves nothing. Conversations that a collected contract permits but that also logged drops are flagged as conflicts.

## Proposed rules

The rule set is a strict JSON document, `atlas.segmentation.ruleset/v1`, limited to 200 rules and 512 KiB. Each rule has an `id`, an `action` (`allow` or `deny`), a `source` and `destination` selector, a `protocol` (`tcp`, `udp` or `sctp`) and `ports` (`from`/`to`, 1–65535). These are destination (server) ports.

| Selector | Fields | Matches |
| --- | --- | --- |
| `application` | `service`, `environment` | Pods linked to the OpenTelemetry service by `runs_on` |
| `endpoint` | `nodeId` | Exactly one map node |
| `epg` | `tenant`, `appProfile`, `epg` | ACI endpoints with all three attributes |
| `esg` | `tenant`, `esg` | Accepted for drafts, **never resolved** (ESG membership is not collected), so always unknown |
| `k8s` | `cluster`, `namespace`, optional `workload` (controller name) | Pods in that namespace, or that controller |
| `cidr` | IPv4 CIDR, host bits zero | Endpoints whose every IPv4 address is inside |

Parsing fails closed: unknown fields, duplicate IDs, invalid names, IPv6, non-canonical CIDRs and reversed port ranges are rejected with a message, and the previous rule set stays active. Kubernetes label selectors are rejected because Atlas does not collect pod labels.

**Seed from observed traffic** writes one exact `allow` rule per distinct observed source, destination, protocol and port, ordered by connections. It never widens a rule. It skips conversations with no port, an ACL drop, an unknown direction, or an endpoint it cannot name with a selector, and it lists what it skipped.

## Replay semantics

Matching is three-valued (match, no match, unknown):

1. A conversation with no protocol or port is **unknown**.
2. A matching `deny` rule **blocks** it. Deny rules take precedence. A `deny` rule that might match makes the result **unknown**.
3. Otherwise a matching `allow` rule **allows** it. An `allow` rule that might match makes the result **unknown**.
4. Otherwise it is **blocked by default deny**.

"Might match" covers an unresolved, ambiguous or ESG endpoint, a pod without `runs_on` or owner data, a Kubernetes Service address, partial EPG attributes, an endpoint only partly inside a CIDR, and a conversation whose direction Atlas could not establish (`direction_basis=unknown`).

Results show allowed, blocked and unknown counts; why conversations are unknown; rules that matched nothing; and the 25 top would-be-blocked conversations by connections (then bytes). Each listed conversation shows its evidence sources, a **Show on map** link (map window only) and a **Trace** link for the same window. When more conversations would be blocked than are listed, the table says so.

## Draft exports

Each file starts with a `DRAFT … NOT APPLIED` header and lists the rules it could not represent, with the reason.

| File | Contents | Limits |
| --- | --- | --- |
| `…-networkpolicy.yaml` | `networking.k8s.io/v1` NetworkPolicy, one per namespace or workload: ingress on the destination, egress on the source. Peers use `namespaceSelector` (`kubernetes.io/metadata.name`), `podSelector` and `ipBlock`. Ranges use `endPort` (stable since Kubernetes 1.25). | No deny rules in NetworkPolicy, so those are skipped. Workloads map to `app.kubernetes.io/name: <controller>` and are marked `# VERIFY label`, because Atlas has no pod labels. Peers must be Kubernetes in the same cluster or a CIDR. |
| `…-ciliumnetworkpolicy.yaml` | `cilium.io/v2` CiliumNetworkPolicy with `ingress`/`ingressDeny`/`egress`/`egressDeny`, `fromEndpoints`/`toEndpoints` or `fromCIDR`/`toCIDR`, and `toPorts` with `port`, `endPort` and `protocol`. | SCTP is skipped. `fromCIDR`/`toCIDR` do not select cluster-managed endpoints. The same label caveat applies. Consider per-endpoint audit mode before enforcing. |
| `…-aci-contracts.json` | `atlasDraft` notice plus an `apicPayload` of `fvTenant` → `vzFilter`/`vzEntry`, `vzBrCP` → `vzSubj` → `vzRsSubjFiltAtt` (`action` permit/deny), and `fvAp` → `fvAEPg` → `fvRsCons`/`fvRsProv`. | EPG to EPG in the same tenant only. ESG, cross-tenant and conflicting rules are skipped. Contract scope `context`. Check names against existing objects before any manual import. |
| `…-firewall-rules.csv` | One row per rule: status `DRAFT`, action, protocol, ports, selectors, and the addresses observed for each selector in the evidence window. | The address lists show what was seen in the window, not complete membership. CSV cells are protected against formula injection. |

Grounding:

- APIC object model: [Cisco APIC REST API Configuration Guide 4.1(x), Tenant Policies](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/4-x/rest-api-config/Cisco-APIC-REST-API-Configuration-Guide-411/Cisco-APIC-REST-API-Configuration-Guide-411_chapter_01010.html). The class attributes match the DC Networking TA 1.2.2 records in `fixtures/raw-aci/FIELDS.md`.
- Kubernetes: [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
- Cilium: [Layer 4](https://docs.cilium.io/en/stable/security/policy/layer4/), [Deny policies](https://docs.cilium.io/en/stable/security/policy/deny/), [Layer 3](https://docs.cilium.io/en/stable/security/policy/layer3/).

## Limits

- Only conversations on the map are evaluated. Edges outside the map's ranked top N, and traffic without a flow source, are not seen. An incomplete read is reported, never hidden.
- Ports are destination ports from the map's direction inference. ICMP and other portless traffic is always unknown.
- Coverage reads ACI contract evidence only. Cilium/Kubernetes policy, firewall rule bases and ESG membership are not collected.
- Rule sets are not saved. Copy the JSON from **Edit rules as JSON** to keep one.
- The workbench is a client-side view over existing searches. It adds no saved searches, KV collections or REST endpoints, and ships in its own optional asset (`pages/segmentation.js`) loaded only when opened.
