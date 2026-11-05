import type { GraphEdge, GraphNode, GraphTruncation } from "../graph";
import { MAX_GRAPH_EDGES, MAX_GRAPH_NODES } from "./limits";
import { edgeVolume } from "./weight";

/** Structure (traces, hosting, hand-offs) outranks traffic of any volume. */
const PRIORITY: Record<GraphEdge["relationship"], number> = {
  calls: 0,
  runs_on: 1,
  forwards_to: 2,
  communicates_with: 3,
  traffic_observation: 4,
};
export const TRUNCATION_RANKING = "relationship, then bytes, then connections";

export function rankEdges(edges: readonly GraphEdge[]): GraphEdge[] {
  return [...edges].sort(
    (a, b) =>
      PRIORITY[a.relationship] - PRIORITY[b.relationship] ||
      edgeVolume(b) - edgeVolume(a) ||
      b.count - a.count ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
}

/**
 * Keeps the heaviest relationships that fit the display limits, plus every
 * node they need. The result references only kept nodes, so it passes the
 * same validation as an untruncated graph. Runs in O(E log E).
 */
export function truncateGraph(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  rootId: string,
  totals: { nodes: number; edges: number },
  limits = { nodes: MAX_GRAPH_NODES, edges: MAX_GRAPH_EDGES },
): { nodes: GraphNode[]; edges: GraphEdge[]; truncation?: GraphTruncation } {
  const totalNodes = Math.max(totals.nodes, nodes.length);
  const totalEdges = Math.max(totals.edges, edges.length);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const complete =
    totalNodes === nodes.length &&
    totalEdges === edges.length &&
    nodes.length <= limits.nodes &&
    edges.length <= limits.edges;
  if (complete) return { nodes: [...nodes], edges: [...edges] };
  const keepNodes = new Set<string>();
  if (byId.has(rootId)) keepNodes.add(rootId);
  const keepEdges = new Set<string>();
  for (const e of rankEdges(edges)) {
    if (keepEdges.size >= limits.edges) break;
    const needed = [e.source, e.target];
    for (const r of e.client_handoffs ?? []) needed.push(r.target);
    // A relationship whose endpoints the server did not return is unusable.
    if (!needed.every((id) => byId.has(id))) continue;
    const added = new Set(needed.filter((id) => !keepNodes.has(id)));
    if (keepNodes.size + added.size > limits.nodes) continue;
    for (const id of added) keepNodes.add(id);
    keepEdges.add(e.id);
  }
  // Remaining capacity: isolated nodes (hosts, services) in their given order.
  for (const kind of ["service", "workload", "endpoint", "client"] as const)
    for (const n of nodes) {
      if (keepNodes.size >= limits.nodes) break;
      if (n.kind === kind) keepNodes.add(n.id);
    }
  const keptNodes = nodes.filter((n) => keepNodes.has(n.id));
  const keptEdges = edges.filter((e) => keepEdges.has(e.id));
  return {
    nodes: keptNodes,
    edges: keptEdges,
    truncation: {
      truncated: true,
      shown: { nodes: keptNodes.length, edges: keptEdges.length },
      total: { nodes: totalNodes, edges: totalEdges },
      ranking: TRUNCATION_RANKING,
    },
  };
}

export const truncationWarning = (t: GraphTruncation) =>
  `Map shows the top ${t.shown.edges.toLocaleString("en-US")} of ${t.total.edges.toLocaleString("en-US")} relationships and ${t.shown.nodes.toLocaleString("en-US")} of ${t.total.nodes.toLocaleString("en-US")} nodes, ranked by ${t.ranking}. Narrow the scope to see the rest.`;

/** "Top 10,000 of 48,213" for the map/table chip. */
export const truncationChip = (t: GraphTruncation) =>
  `Top ${t.shown.edges.toLocaleString("en-US")} of ${t.total.edges.toLocaleString("en-US")} connections`;
