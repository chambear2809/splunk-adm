import type { Graph, GraphEdge, GraphNode } from "./graph";

export interface EdgeChange {
  id: string;
  previous: GraphEdge;
  current: GraphEdge;
}

/** A node group is useful because a Deployment may have several pod UIDs. */
export interface NodeChange {
  key: string;
  previous: GraphNode[];
  current: GraphNode[];
}

export interface GraphDiff {
  addedEdges: GraphEdge[];
  removedEdges: GraphEdge[];
  changedEdges: EdgeChange[];
  addedNodes: GraphNode[];
  removedNodes: GraphNode[];
  changedNodes: NodeChange[];
}

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

/** Stable equality for graph records, without depending on property order. */
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (object(value))
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stable(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

/**
 * Evidence IDs are observations inside an already identified edge, rather
 * than edge identity. Span IDs in particular rotate as a window is refreshed.
 * Treat the other evidence lists as sets so collector ordering is immaterial.
 */
function edgeComparable(edge: GraphEdge): unknown {
  const { evidence, sources, observers } = edge;
  const rest = { ...edge };
  delete rest.span_ids;
  return {
    ...rest,
    evidence: [
      ...new Set(
        evidence.map((value) => (value.startsWith("span:") ? "span" : value)),
      ),
    ].sort(),
    sources: sources ? [...sources].sort() : undefined,
    observers: observers ? [...observers].sort() : undefined,
  };
}

const workloadKey = (node: GraphNode) =>
  [
    node.cluster ?? "",
    node.namespace ?? "",
    node.attributes?.owner ?? node.attributes?.service ?? node.label,
  ]
    .map((part) => encodeURIComponent(part))
    .join("/");

function nodeKey(node: GraphNode): string {
  if (node.kind === "workload") return `workload:${workloadKey(node)}`;
  if (node.kind === "service") return `service:${node.id}`;
  // Endpoint IDs identify the actual address/attachment and must remain distinct.
  return `endpoint:${node.id}`;
}

/** Fields that identify a pod instance, rather than its owning service. */
function nodeComparable(node: GraphNode): unknown {
  if (node.kind !== "workload") return node;
  const stableNode: Record<string, unknown> = { ...node };
  delete stableNode.id;
  delete stableNode.label;
  delete stableNode.addresses;
  return stableNode;
}

/**
 * Compare two graph snapshots. Edge IDs are the contract for edge identity.
 * Workload nodes are grouped by cluster/namespace/owner (or service), so a
 * Kubernetes pod UID, generated pod label, or replacement IP does not appear
 * as graph churn.
 */
export function diffGraphs(previous: Graph, current: Graph): GraphDiff {
  const oldEdges = new Map(previous.edges.map((edge) => [edge.id, edge]));
  const newEdges = new Map(current.edges.map((edge) => [edge.id, edge]));
  const addedEdges: GraphEdge[] = [];
  const removedEdges: GraphEdge[] = [];
  const changedEdges: EdgeChange[] = [];
  for (const [id, edge] of newEdges) {
    const old = oldEdges.get(id);
    if (!old) addedEdges.push(edge);
    else if (stable(edgeComparable(old)) !== stable(edgeComparable(edge)))
      changedEdges.push({ id, previous: old, current: edge });
  }
  for (const [id, edge] of oldEdges)
    if (!newEdges.has(id)) removedEdges.push(edge);

  const group = (nodes: GraphNode[]) => {
    const result = new Map<string, GraphNode[]>();
    for (const node of nodes) {
      const list = result.get(nodeKey(node));
      if (list) list.push(node);
      else result.set(nodeKey(node), [node]);
    }
    return result;
  };
  const oldNodes = group(previous.nodes);
  const newNodes = group(current.nodes);
  const addedNodes: GraphNode[] = [];
  const removedNodes: GraphNode[] = [];
  const changedNodes: NodeChange[] = [];
  for (const [key, nodes] of newNodes) {
    const old = oldNodes.get(key);
    if (!old) addedNodes.push(...nodes);
    else if (
      stable(
        old
          .map(nodeComparable)
          .sort((a, b) => stable(a).localeCompare(stable(b))),
      ) !==
      stable(
        nodes
          .map(nodeComparable)
          .sort((a, b) => stable(a).localeCompare(stable(b))),
      )
    )
      changedNodes.push({ key, previous: old, current: nodes });
  }
  for (const [key, nodes] of oldNodes)
    if (!newNodes.has(key)) removedNodes.push(...nodes);
  return {
    addedEdges,
    removedEdges,
    changedEdges,
    addedNodes,
    removedNodes,
    changedNodes,
  };
}
