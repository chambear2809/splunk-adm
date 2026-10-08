import { isoTime } from "./time";
export type NodeKind = "service" | "workload" | "endpoint";
export type Relationship =
  "calls" | "communicates_with" | "runs_on" | "forwards_to";
export type EndpointKind =
  | "k8s_node"
  | "vm"
  | "external"
  | "unresolved"
  | "ambiguous"
  | "k8s_service"
  | "k8s_node_proxy";
/** How a Service frontend was linked to the backend pod that served it. */
export type HandoffBasis =
  "hubble_client_tuple" | "hubble_xlate" | "time_inferred" | "l7_forwarded_for";
export const HANDOFF_BASES: readonly HandoffBasis[] = [
  "hubble_client_tuple",
  "hubble_xlate",
  "time_inferred",
  "l7_forwarded_for",
];
export type ContractBasis = "intent" | "intra_epg" | "not_evaluated" | "none";
export const CONTRACT_BASES: readonly ContractBasis[] = [
  "intent",
  "intra_epg",
  "not_evaluated",
  "none",
];
export type AclAction = "permit" | "drop";
export type DirectionBasis = "initiator" | "port_rule" | "unknown";
export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  endpoint_kind?: EndpointKind;
  namespace?: string;
  cluster?: string;
  addresses?: string[];
  reason?: string;
  attributes?: Record<string, string>;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: Relationship;
  evidence: string[];
  confidence: "observed" | "correlated" | "unresolved" | "inferred";
  count: number;
  bytes?: number;
  reason?: string;
  observers?: string[];
  sources?: string[];
  span_ids?: string[];
  server_port?: number;
  transport?: string;
  direction_basis?: DirectionBasis;
  encapsulation?: string;
  evidence_truncated?: boolean;
  /** forwards_to only. */
  handoff_basis?: HandoffBasis;
  /** Kubernetes node that received the frontend traffic, when known. */
  /** Kubernetes nodes that received the frontend traffic (one or several). */
  via_node?: string[];
  /** Why the collected ACI policy was not evaluated, when the search says. */
  contract_reason?: string;
  contract?: string;
  contract_subject?: string;
  contract_filter?: string;
  /** e.g. "tcp 443". */
  contract_entry?: string;
  contract_basis?: ContractBasis;
  acl_action?: AclAction;
  acl_leaf?: string;
  acl_permits?: number;
  acl_drops?: number;
}
export interface Graph {
  schema_version: 1;
  snapshot_id: string;
  generated_at: string;
  demo: boolean;
  window: { start: string; end: string };
  boundary: {
    id: string;
    service: string;
    environment: string;
    cluster: string;
    namespace: string;
    root_node_id: string;
  };
  nodes: GraphNode[];
  edges: GraphEdge[];
  coverage: {
    spans: number;
    conversations: number;
    matched_conversations: number;
    unresolved_conversations: number;
    ambiguous_conversations: number;
    warnings: string[];
  };
}
const COVERAGE_COUNTS = [
  "spans",
  "conversations",
  "matched_conversations",
  "unresolved_conversations",
  "ambiguous_conversations",
] as const;
export const ENDPOINT_KINDS: readonly EndpointKind[] = [
  "k8s_node",
  "vm",
  "external",
  "unresolved",
  "ambiguous",
  "k8s_service",
  "k8s_node_proxy",
];
export const RELATIONSHIPS: readonly Relationship[] = [
  "calls",
  "communicates_with",
  "runs_on",
  "forwards_to",
];
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const strings = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");
const number = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0;
const id = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= 4096;
const date = isoTime;
const allowedEdges: Record<Relationship, [NodeKind[], NodeKind[]]> = {
  calls: [["service"], ["service"]],
  runs_on: [["service"], ["workload"]],
  communicates_with: [
    ["workload", "endpoint"],
    ["workload", "endpoint"],
  ],
  forwards_to: [["endpoint"], ["workload"]],
};
const optionalText = (v: unknown) => v === undefined || typeof v === "string";
const optionalCount = (v: unknown) => v === undefined || number(v);
/**
 * Node-to-node tunnel of a conversation. Cilium DSR forwards to remote
 * backends over IPIP, which flow records report as transport `ipip`.
 */
export function tunnelOf(e: GraphEdge): string | undefined {
  return (
    e.encapsulation ??
    (e.transport?.toLowerCase() === "ipip" ? "ipip" : undefined)
  );
}
export const tunnelLabel = (t: string) =>
  t === "ipip" ? "IPIP (DSR)" : t.toUpperCase();
/** Reject malformed snapshots before using untrusted indexed content in the UI. */
export function parseGraph(value: unknown): Graph {
  if (
    !object(value) ||
    value.schema_version !== 1 ||
    typeof value.demo !== "boolean" ||
    !id(value.snapshot_id) ||
    !date(value.generated_at)
  )
    throw new Error("Unsupported or invalid graph snapshot.");
  const b = value.boundary,
    w = value.window,
    c = value.coverage;
  if (
    !object(b) ||
    ![
      "id",
      "service",
      "environment",
      "cluster",
      "namespace",
      "root_node_id",
    ].every((k) => id(b[k])) ||
    !object(w) ||
    !date(w.start) ||
    !date(w.end) ||
    Date.parse(w.start) >= Date.parse(w.end)
  )
    throw new Error("Snapshot boundary or time window is invalid.");
  if (
    !object(c) ||
    !COVERAGE_COUNTS.every((k) => number(c[k])) ||
    !strings(c.warnings)
  )
    throw new Error("Snapshot coverage is invalid.");
  if (
    !Array.isArray(value.nodes) ||
    value.nodes.length > 500 ||
    !Array.isArray(value.edges) ||
    value.edges.length > 2000
  )
    throw new Error(
      "Graph exceeds the pilot limit (500 nodes / 2,000 edges). Narrow the time range or namespace.",
    );
  const kinds = new Map<string, NodeKind>();
  const endpointKinds = new Map<string, unknown>();
  for (const n of value.nodes) {
    if (
      !object(n) ||
      !id(n.id) ||
      typeof n.label !== "string" ||
      typeof n.kind !== "string" ||
      !["service", "workload", "endpoint"].includes(n.kind) ||
      (n.addresses !== undefined && !strings(n.addresses)) ||
      kinds.has(n.id)
    )
      throw new Error("Snapshot contains invalid or duplicate nodes.");
    for (const k of ["namespace", "cluster", "reason"])
      if (n[k] !== undefined && typeof n[k] !== "string")
        throw new Error("Invalid node metadata.");
    if (
      (n.endpoint_kind !== undefined &&
        (n.kind !== "endpoint" ||
          !ENDPOINT_KINDS.includes(n.endpoint_kind as EndpointKind))) ||
      (n.attributes !== undefined &&
        (!object(n.attributes) ||
          !Object.values(n.attributes).every((v) => typeof v === "string")))
    )
      throw new Error("Invalid node metadata.");
    kinds.set(n.id, n.kind as NodeKind);
    endpointKinds.set(n.id, n.endpoint_kind);
  }
  if (value.nodes.length && kinds.get(String(b.root_node_id)) !== "service")
    throw new Error("Snapshot root is missing or is not a service.");
  const edgeIds = new Set<string>();
  for (const e of value.edges) {
    if (
      !object(e) ||
      !id(e.id) ||
      edgeIds.has(e.id) ||
      typeof e.source !== "string" ||
      typeof e.target !== "string" ||
      !kinds.has(e.source) ||
      !kinds.has(e.target) ||
      typeof e.relationship !== "string" ||
      typeof e.confidence !== "string" ||
      !RELATIONSHIPS.includes(e.relationship as Relationship) ||
      !["observed", "correlated", "unresolved", "inferred"].includes(
        e.confidence,
      ) ||
      !strings(e.evidence) ||
      !number(e.count) ||
      (e.bytes !== undefined && !number(e.bytes)) ||
      (e.observers !== undefined && !strings(e.observers)) ||
      (e.sources !== undefined && !strings(e.sources)) ||
      (e.span_ids !== undefined && !strings(e.span_ids)) ||
      (e.server_port !== undefined &&
        !(
          Number.isInteger(e.server_port) &&
          (e.server_port as number) >= 0 &&
          (e.server_port as number) <= 65535
        )) ||
      (e.transport !== undefined && typeof e.transport !== "string") ||
      (e.direction_basis !== undefined &&
        !["initiator", "port_rule", "unknown"].includes(
          String(e.direction_basis),
        )) ||
      (e.encapsulation !== undefined && typeof e.encapsulation !== "string") ||
      (e.reason !== undefined && typeof e.reason !== "string") ||
      (e.evidence_truncated !== undefined &&
        typeof e.evidence_truncated !== "boolean") ||
      (e.via_node !== undefined && !strings(e.via_node)) ||
      !optionalText(e.contract_reason) ||
      !optionalText(e.contract) ||
      !optionalText(e.contract_subject) ||
      !optionalText(e.contract_filter) ||
      !optionalText(e.contract_entry) ||
      !optionalText(e.acl_leaf) ||
      !optionalCount(e.acl_permits) ||
      !optionalCount(e.acl_drops) ||
      (e.contract_basis !== undefined &&
        !CONTRACT_BASES.includes(e.contract_basis as ContractBasis)) ||
      (e.acl_action !== undefined &&
        e.acl_action !== "permit" &&
        e.acl_action !== "drop")
    )
      throw new Error("Snapshot contains invalid relationships.");
    const forward = e.relationship === "forwards_to";
    if (
      forward !== (e.handoff_basis !== undefined) ||
      (forward &&
        (!HANDOFF_BASES.includes(e.handoff_basis as HandoffBasis) ||
          !["observed", "inferred"].includes(e.confidence) ||
          endpointKinds.get(e.source) !== "k8s_service")) ||
      (!forward && e.confidence === "inferred") ||
      // Contract and ACL-log annotations describe network conversations only.
      (e.relationship !== "communicates_with" &&
        [
          "contract",
          "contract_basis",
          "acl_action",
          "acl_leaf",
          "acl_permits",
          "acl_drops",
        ].some((k) => e[k] !== undefined)) ||
      // A contract is named for intent (permit) or, with basis none, a deny.
      (e.contract !== undefined &&
        e.contract_basis !== "intent" &&
        e.contract_basis !== "none") ||
      (e.contract_basis === "intent" && e.contract === undefined)
    )
      throw new Error("Snapshot contains an invalid handoff or policy field.");
    const [sources, targets] = allowedEdges[e.relationship as Relationship];
    if (
      !sources.includes(kinds.get(e.source)!) ||
      !targets.includes(kinds.get(e.target)!)
    )
      throw new Error(
        "Snapshot relationship connects incompatible node kinds.",
      );
    edgeIds.add(e.id);
  }
  return value as unknown as Graph;
}
export interface GraphIndex {
  node: Map<string, GraphNode>;
  edge: Map<string, GraphEdge>;
  incident: Map<string, GraphEdge[]>;
  outgoing: Map<string, GraphEdge[]>;
}
export function indexGraph(graph: Graph): GraphIndex {
  const node = new Map(graph.nodes.map((n) => [n.id, n]));
  const edge = new Map(graph.edges.map((e) => [e.id, e]));
  const incident = new Map<string, GraphEdge[]>(),
    outgoing = new Map<string, GraphEdge[]>();
  const push = (m: Map<string, GraphEdge[]>, k: string, e: GraphEdge) => {
    const list = m.get(k);
    if (list) list.push(e);
    else m.set(k, [e]);
  };
  for (const e of graph.edges) {
    push(outgoing, e.source, e);
    push(incident, e.source, e);
    if (e.target !== e.source) push(incident, e.target, e);
  }
  return { node, edge, incident, outgoing };
}
/** Case-insensitive match on label, address or attribute; empty query matches all. */
export function matchesQuery(node: GraphNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  return (
    !q ||
    [
      node.label,
      ...(node.addresses ?? []),
      ...Object.values(node.attributes ?? {}),
    ]
      .join(" ")
      .toLowerCase()
      .includes(q)
  );
}
