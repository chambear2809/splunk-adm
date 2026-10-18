import { edgeIdentity, isBlocked, type IdentityState } from "./glossary";
import { indexGraph, tunnelOf, type Graph, type GraphIndex } from "./graph";

export interface Facets {
  identity?: "identified" | "external" | "unknown";
  port?: number;
  source?: string;
  blocked?: boolean;
  hideInfrastructure?: boolean;
}

const edgeFacetsActive = (facets: Facets) =>
  facets.identity !== undefined ||
  facets.port !== undefined ||
  (facets.source !== undefined && facets.source.length > 0) ||
  facets.blocked === true;
const active = (facets: Facets) =>
  edgeFacetsActive(facets) || facets.hideInfrastructure === true;

const identityMatches = (state: IdentityState, wanted: Facets["identity"]) =>
  wanted === undefined ||
  (wanted === "unknown"
    ? state === "unknown" || state === "multiple"
    : state === wanted);

/** Filter edge facets while retaining enough ownership context for layout. */
export function filterGraph(graph: Graph, facets: Facets): Graph {
  if (!active(facets)) return graph;
  const index = indexGraph(graph);
  const matched = graph.edges.filter((edge) => {
    if (!edgeFacetsActive(facets)) return true;
    const conversation = edge.relationship === "communicates_with";
    const observation = edge.relationship === "traffic_observation";
    return (
      (conversation || observation) &&
      identityMatches(
        edgeIdentity(edge, (id) => index.node.get(id)),
        facets.identity,
      ) &&
      (facets.port === undefined || edge.server_port === facets.port) &&
      (facets.source === undefined ||
        facets.source.length === 0 ||
        edge.sources?.includes(facets.source) === true) &&
      (facets.blocked !== true || (conversation && isBlocked(edge)))
    );
  });
  const keptEdges = new Map(matched.map((edge) => [edge.id, edge]));
  const keptNodes = edgeFacetsActive(facets)
    ? new Set(matched.flatMap((edge) => [edge.source, edge.target]))
    : new Set(graph.nodes.map((node) => node.id));
  let changed = true;
  while (changed) {
    changed = false;
    for (const edge of graph.edges) {
      if (
        edge.relationship !== "runs_on" ||
        !keptNodes.has(edge.target) ||
        index.node.get(edge.target)?.kind !== "workload"
      )
        continue;
      if (!keptEdges.has(edge.id)) {
        keptEdges.set(edge.id, edge);
        changed = true;
      }
      for (const node of [edge.source, edge.target]) {
        if (!keptNodes.has(node)) {
          keptNodes.add(node);
          changed = true;
        }
      }
    }
  }
  if (facets.hideInfrastructure) {
    for (const node of graph.nodes) {
      if (node.endpoint_kind !== "k8s_node") continue;
      const conversations = (index.incident.get(node.id) ?? []).filter(
        (edge) => edge.relationship === "communicates_with",
      );
      // Match layout's Infrastructure lane: hosts with no application traffic.
      if (conversations.every((edge) => !!tunnelOf(edge)))
        keptNodes.delete(node.id);
    }
  }
  const edges = [...keptEdges.values()].filter(
    (edge) => keptNodes.has(edge.source) && keptNodes.has(edge.target),
  );
  const nodes = graph.nodes.filter((node) => keptNodes.has(node.id));
  return { ...graph, nodes, edges };
}

/** Return the bounded undirected neighborhood around a node. */
export function focusHops(
  index: GraphIndex,
  id: string,
  hops: number,
): ReadonlySet<string> {
  if (
    !Number.isInteger(hops) ||
    hops < 0 ||
    !Number.isFinite(hops) ||
    !index.node.has(id)
  )
    return new Set();
  const result = new Set([id]);
  let frontier = [id];
  for (let depth = 0; depth < hops; depth += 1) {
    const next: string[] = [];
    for (const current of frontier) {
      for (const edge of index.incident.get(current) ?? []) {
        const other = edge.source === current ? edge.target : edge.source;
        if (!result.has(other)) {
          result.add(other);
          next.push(other);
        }
      }
    }
    frontier = next;
    if (!frontier.length) break;
  }
  return result;
}
