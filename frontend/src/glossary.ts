import type {
  DirectionBasis,
  EndpointKind,
  GraphEdge,
  GraphNode,
  HandoffBasis,
  Relationship,
} from "./graph";

/** Plain-language names used everywhere in the UI. */
export const relationshipLabel: Record<Relationship, string> = {
  calls: "Traced call",
  communicates_with: "Network conversation",
  runs_on: "Runs on",
  forwards_to: "Forwarded to backend",
};

export const confidenceLabel: Record<GraphEdge["confidence"], string> = {
  observed: "Traced",
  correlated: "Identified",
  unresolved: "Unknown IP",
  inferred: "Inferred",
};

export const endpointKindLabel: Record<EndpointKind, string> = {
  k8s_node: "Kubernetes node",
  vm: "VM",
  external: "External",
  unresolved: "Unknown IP",
  ambiguous: "Multiple owners",
  k8s_service: "Kubernetes Service",
  k8s_node_proxy: "Cilium Envoy",
};

export const sourceLabel = (source: string): string =>
  ({
    netflow: "Stream NetFlow",
    nd: "Nexus Dashboard",
    ftd: "Cisco FTD",
    isovalent: "Isovalent",
    span_peer: "OTel client span",
    cdp: "CDP",
    hubble: "Hubble",
    aci: "ACI",
    aci_acllog: "ACI ACL log",
    lldp: "LLDP",
  })[source] ?? source;

/** Short name of a node's kind, e.g. "Service", "Pod", "VM". */
export function kindLabel(node: GraphNode): string {
  if (node.kind === "service") return "Service";
  if (node.kind === "workload") return "Pod";
  return node.endpoint_kind
    ? endpointKindLabel[node.endpoint_kind]
    : "Endpoint";
}

/** True when the node's identity could not be established uniquely. */
export const isUnknown = (node: GraphNode) =>
  node.endpoint_kind === "unresolved" || node.endpoint_kind === "ambiguous";

export function directionLabel(edge: GraphEdge): string | undefined {
  const basis: DirectionBasis | undefined = edge.direction_basis;
  if (basis === "initiator") {
    const reporters = (edge.sources ?? [])
      .filter((s) => s === "isovalent" || s === "ftd" || s === "hubble")
      .map(sourceLabel);
    return `Initiator reported by ${reporters.join(" and ") || "the source"}`;
  }
  if (basis === "port_rule")
    return "Inferred from ports (the server side uses the service port)";
  if (basis === "unknown") return "Direction unknown";
  return undefined;
}

export const attributeLabels: [string, string][] = [
  ["vm_name", "VM name"],
  ["tenant", "Tenant"],
  ["app_profile", "App profile"],
  ["epg", "EPG"],
  ["attach_device", "Attached to"],
  ["attach_interface", "Port"],
  ["owner", "Deployment"],
  ["node", "Kubernetes node"],
  ["mac", "MAC"],
  ["scope", "Routing scope"],
  ["environment", "Environment"],
  ["frontend", "Frontend"],
  ["type", "Service type"],
  ["traffic_policy", "External traffic policy"],
  ["lb_mode", "Cilium load balancing"],
  ["controller", "Ingress controller"],
  ["route", "Route"],
];

/** Readable values for coded Service attributes. */
export function attributeValue(key: string, value: string): string {
  if (key === "lb_mode")
    return (
      { snat: "SNAT", dsr: "DSR", hybrid: "Hybrid (DSR for TCP)" }[value] ??
      value
    );
  if (key === "controller")
    return (
      {
        cilium_gateway: "Cilium Gateway API (Envoy)",
        cilium_ingress: "Cilium Ingress (Envoy)",
      }[value] ?? value
    );
  return value;
}

export interface HandoffContext {
  /** Service name, e.g. "catalog-api". */
  service?: string;
  /** Client addresses that reached the frontend. */
  clients: string[];
  /** Node that received the frontend traffic. */
  node?: string;
}
const clientText = (c: HandoffContext) =>
  c.clients.length ? c.clients.join(", ") : "the client";
/** Plain-language answer to "how was the backend determined?". */
export function handoffExplanation(
  basis: HandoffBasis,
  ctx: HandoffContext,
): string {
  switch (basis) {
    case "hubble_client_tuple":
      return "Hubble saw the same client address and port arrive at this pod";
    case "hubble_xlate":
      return `Hubble recorded the SNAT translation on ${ctx.node ?? "the receiving node"}`;
    case "time_inferred":
      return `Inferred: the only connection from ${ctx.node ?? "the receiving node"} to a ${ctx.service ?? "backend"} pod within 1 s`;
    case "l7_forwarded_for":
      return `Envoy forwarded with X-Forwarded-For ${clientText(ctx)}`;
  }
}
/** Hand-off confidence: evidence picked the backend, or timing did. */
export const handoffConfidence = (c: GraphEdge["confidence"]) =>
  c === "inferred" ? "Inferred" : "Observed";
export const handoffShort: Record<HandoffBasis, string> = {
  hubble_client_tuple: "Hubble: same client tuple",
  hubble_xlate: "Hubble: SNAT translation",
  time_inferred: "Inferred from timing",
  l7_forwarded_for: "Envoy X-Forwarded-For",
};

/** Policy intent for a conversation, or undefined when not collected. */
export function contractSummary(edge: GraphEdge): string | undefined {
  if (edge.contract_basis === "intent" && edge.contract)
    return `Permitted by contract ${edge.contract}${edge.contract_entry ? ` · ${edge.contract_entry}` : ""} (intent)`;
  if (edge.contract_basis === "intra_epg") return "Same EPG (intra-EPG)";
  if (edge.contract_basis === "not_evaluated") return "Policy not evaluated";
  if (edge.contract_basis === "none")
    return edge.contract
      ? `Denied by contract ${edge.contract}${edge.contract_entry ? ` · ${edge.contract_entry}` : ""}`
      : "No permitting contract found in the collected policy";
  return undefined;
}
/** Short contract cell for tables and exports. */
export function contractCell(edge: GraphEdge): string {
  switch (edge.contract_basis) {
    case "intent":
      return `${edge.contract}${edge.contract_entry ? ` · ${edge.contract_entry}` : ""}`;
    case "intra_epg":
      return "Same EPG";
    case "not_evaluated":
      return "Not evaluated";
    case "none":
      return edge.contract ? `Denied by ${edge.contract}` : "None found";
    default:
      return "—";
  }
}
/** Why a conversation's policy was not evaluated, in plain words. */
export function policyReason(edge: GraphEdge): string | undefined {
  if (edge.contract_basis === "intra_epg")
    return "Both sides are in one EPG. ACI permits traffic inside an EPG unless intra-EPG isolation is enforced.";
  if (edge.contract_basis !== "not_evaluated") return undefined;
  return (
    edge.contract_reason ??
    "The collected ACI policy can't settle this conversation: a side is unclassified or in another tenant, the VRF uses vzAny, taboos, ESGs, service graphs, preferred groups or is unenforced, or policy collection is incomplete."
  );
}
/** "node-a", or "one of node-a, node-b" when several nodes received traffic. */
export function receivedOn(nodes?: string[]): string | undefined {
  if (!nodes?.length) return undefined;
  return nodes.length === 1 ? nodes[0] : `one of ${nodes.join(", ")}`;
}
export const isBlocked = (edge: GraphEdge) => edge.acl_action === "drop";
/** ACL-log observation, e.g. "ACL log: permit at leaf-103". */
export function aclSummary(edge: GraphEdge, leaf?: string): string | undefined {
  if (!edge.acl_action) return undefined;
  const at = leaf ?? edge.acl_leaf;
  const counts = [
    edge.acl_permits ? plural(edge.acl_permits, "permit") : "",
    edge.acl_drops ? plural(edge.acl_drops, "drop") : "",
  ]
    .filter(Boolean)
    .join(", ");
  return `ACL log: ${edge.acl_action}${at ? ` at ${at}` : ""}${counts ? ` (${counts})` : ""}${edge.acl_action === "drop" ? " · blocked by the fabric" : ""}`;
}

export function prettyBytes(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`;
  if (bytes < 1e6) return `${(bytes / 1000).toFixed(1)} KB`;
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${(bytes / 1e9).toFixed(1)} GB`;
}

export const portLabel = (edge: GraphEdge) =>
  edge.server_port !== undefined
    ? `${edge.server_port}/${edge.transport ?? "?"}`
    : edge.transport?.toLowerCase() === "ipip"
      ? "IPIP"
      : (edge.transport ?? "—");

/** How well both ends of a network conversation are identified. */
export type IdentityState = "identified" | "external" | "unknown" | "multiple";
export const identityLabel: Record<IdentityState, string> = {
  identified: "Identified",
  external: "External",
  unknown: "Unknown IP",
  multiple: "Multiple owners",
};
export function edgeIdentity(
  edge: GraphEdge,
  node: (id: string) => GraphNode | undefined,
): IdentityState {
  const kinds = [node(edge.source), node(edge.target)].map(
    (n) => n?.endpoint_kind,
  );
  if (kinds.includes("ambiguous")) return "multiple";
  if (kinds.includes("unresolved")) return "unknown";
  if (kinds.includes("external")) return "external";
  return edge.confidence === "unresolved" ? "unknown" : "identified";
}

export interface MapSummary {
  services: number;
  conversations: number;
  identified: number;
  external: number;
  unknown: number;
  multiple: number;
  /** Conversations the fabric dropped (ACL log). */
  blocked: number;
  /** Endpoint nodes by identity, split by whether they only call in. */
  unknownSources: number;
  unknownOther: number;
  externalNodes: number;
}
/** One count used by the header, inspector and exports. */
export function summarize(
  nodes: GraphNode[],
  edges: GraphEdge[],
  node: (id: string) => GraphNode | undefined,
): MapSummary {
  const conv = edges.filter((e) => e.relationship === "communicates_with");
  const states = conv.map((e) => edgeIdentity(e, node));
  const count = (s: IdentityState) => states.filter((x) => x === s).length;
  let unknownSources = 0,
    unknownOther = 0;
  for (const n of nodes) {
    if (!isUnknown(n)) continue;
    const mine = conv.filter((e) => e.source === n.id || e.target === n.id);
    const source =
      mine.length > 0 &&
      mine.every((e) => e.source === n.id && e.direction_basis !== "unknown");
    if (source) unknownSources++;
    else unknownOther++;
  }
  return {
    services: nodes.filter((n) => n.kind === "service").length,
    conversations: conv.length,
    blocked: conv.filter(isBlocked).length,
    identified: count("identified"),
    external: count("external"),
    unknown: count("unknown"),
    multiple: count("multiple"),
    unknownSources,
    unknownOther,
    externalNodes: nodes.filter((n) => n.endpoint_kind === "external").length,
  };
}
export const plural = (n: number, one: string, many = `${one}s`) =>
  `${n} ${n === 1 ? one : many}`;

/** Plain-language title for a search warning; the full text stays as detail. */
const WARNING_TITLES: [RegExp, string][] = [
  [/no spans in .* the graph is empty/i, "Entry service not found"],
  [/^Graph exceeds/i, "Map too large"],
  [/listed only the first .* connections/i, "Connection list capped"],
  [
    /dsrDispatch opt|folded into the hand-off/i,
    "DSR legs folded into hand-offs",
  ],
  [/boundary clients or dependencies/i, "Scope limit reached"],
  [/boundary traces/i, "Trace limit reached"],
  [/ACI policy read|adm_aci_policy/i, "Contract policy read incompletely"],
  [
    /max_rows_per_query|could not be read completely/i,
    "Inventory read incompletely",
  ],
  [
    /adm_identity_max_matches|several identities|ambiguous/i,
    "Address with many owners",
  ],
  [/k8s\.cluster\.name|clusterName/i, "Cluster name missing"],
  [/parent outside the window|missing parent/i, "Traces cut by the time range"],
  [/No identity record/i, "Unknown address"],
];
export function warningTitle(text: string): string {
  return WARNING_TITLES.find(([re]) => re.test(text))?.[1] ?? "Search warning";
}
