export type NodeKind = "service" | "workload" | "endpoint";
export type Relationship = "calls" | "communicates_with" | "runs_on";
export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  namespace?: string;
  cluster?: string;
  addresses?: string[];
  reason?: string;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: Relationship;
  evidence: string[];
  confidence: "observed" | "correlated" | "unresolved";
  count: number;
  bytes?: number;
  reason?: string;
  observers?: string[];
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
    flows: number;
    matched_flows: number;
    unresolved_flows: number;
    warnings: string[];
  };
}
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const strings = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");
const number = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0;
const date = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
/** Reject malformed snapshots before using untrusted indexed content in the UI. */
export function parseGraph(value: unknown): Graph {
  if (
    !object(value) ||
    value.schema_version !== 1 ||
    typeof value.demo !== "boolean" ||
    typeof value.snapshot_id !== "string" ||
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
    ].every((k) => typeof b[k] === "string") ||
    !object(w) ||
    !date(w.start) ||
    !date(w.end) ||
    Date.parse(w.start) >= Date.parse(w.end)
  )
    throw new Error("Snapshot boundary or time window is invalid.");
  if (
    !object(c) ||
    !["spans", "flows", "matched_flows", "unresolved_flows"].every((k) =>
      number(c[k]),
    ) ||
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
      "Graph exceeds the pilot limit (500 nodes / 2,000 edges). Narrow the boundary.",
    );
  const ids = new Set<string>();
  for (const n of value.nodes) {
    if (
      !object(n) ||
      typeof n.id !== "string" ||
      typeof n.label !== "string" ||
      typeof n.kind !== "string" ||
      !["service", "workload", "endpoint"].includes(n.kind) ||
      (n.addresses !== undefined && !strings(n.addresses)) ||
      ids.has(n.id)
    )
      throw new Error("Snapshot contains invalid or duplicate nodes.");
    for (const k of ["namespace", "cluster", "reason"])
      if (n[k] !== undefined && typeof n[k] !== "string")
        throw new Error("Invalid node metadata.");
    ids.add(n.id);
  }
  if (value.nodes.length && !ids.has(String(b.root_node_id)))
    throw new Error("Snapshot root is missing.");
  const edgeIds = new Set<string>();
  for (const e of value.edges) {
    if (
      !object(e) ||
      typeof e.id !== "string" ||
      edgeIds.has(e.id) ||
      typeof e.source !== "string" ||
      typeof e.target !== "string" ||
      !ids.has(e.source) ||
      !ids.has(e.target) ||
      typeof e.relationship !== "string" ||
      typeof e.confidence !== "string" ||
      !["calls", "communicates_with", "runs_on"].includes(e.relationship) ||
      !["observed", "correlated", "unresolved"].includes(e.confidence) ||
      !strings(e.evidence) ||
      !number(e.count) ||
      (e.bytes !== undefined && !number(e.bytes)) ||
      (e.observers !== undefined && !strings(e.observers)) ||
      (e.reason !== undefined && typeof e.reason !== "string")
    )
      throw new Error("Snapshot contains invalid relationships.");
    edgeIds.add(e.id);
  }
  return value as unknown as Graph;
}
export const relationshipLabel = {
  calls: "Observed call",
  communicates_with: "Network communication",
  runs_on: "Workload binding",
};
export function prettyBytes(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`;
  if (bytes < 1e6) return `${(bytes / 1000).toFixed(1)} KB`;
  return `${(bytes / 1e6).toFixed(1)} MB`;
}
