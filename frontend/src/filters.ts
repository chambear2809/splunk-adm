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

export type FocusDirection = "any" | "callers" | "dependencies";

const serviceMembers = (index: GraphIndex, id: string): string[] =>
  index.node.get(id)?.kind === "service"
    ? (index.outgoing.get(id) ?? [])
        .filter((edge) => edge.relationship === "runs_on")
        .map((edge) => edge.target)
    : [];

/**
 * Return the bounded neighborhood around a node. A service card stands for its
 * pods, so focusing a service includes their conversations. With a direction,
 * only observed call/conversation edges are followed: "callers" walks from
 * server to client (observed callers), "dependencies" from client
 * to server. Conversations whose direction is unknown are followed both ways,
 * and forwards_to hand-offs cost no hop because the client reached the Service
 * IP, not a second application. Blocked conversations are not followed: a
 * dropped attempt does not show that the server depended on that client.
 */
export function focusHops(
  index: GraphIndex,
  id: string,
  hops: number,
  direction: FocusDirection = "any",
): ReadonlySet<string> {
  return focusTrace(index, id, hops, direction).nodes;
}

export interface FocusTrace {
  nodes: ReadonlySet<string>;
  /** Directed focus only: conversations and calls the walk actually followed. */
  followed: ReadonlySet<string>;
}

export function focusTrace(
  index: GraphIndex,
  id: string,
  hops: number,
  direction: FocusDirection = "any",
): FocusTrace {
  const followed = new Set<string>();
  if (
    !Number.isInteger(hops) ||
    hops < 0 ||
    !Number.isFinite(hops) ||
    !index.node.has(id)
  )
    return { nodes: new Set(), followed };
  if (direction === "any") {
    const result = new Set([id, ...serviceMembers(index, id)]);
    let frontier = [...result];
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
    return { nodes: result, followed };
  }
  const distance = new Map<string, number>();
  const layers: string[][] = Array.from({ length: hops + 1 }, () => []);
  const reach = (node: string, depth: number) => {
    const known = distance.get(node);
    if (known !== undefined && known <= depth) return;
    distance.set(node, depth);
    layers[depth].push(node);
    for (const member of serviceMembers(index, node)) reach(member, depth);
  };
  reach(id, 0);
  const upstream = direction === "callers";
  for (let depth = 0; depth <= hops; depth += 1) {
    for (let at = 0; at < layers[depth].length; at += 1) {
      const current = layers[depth][at];
      if (distance.get(current) !== depth) continue;
      for (const edge of index.incident.get(current) ?? []) {
        if (edge.source === edge.target || isBlocked(edge)) continue;
        const passThrough = edge.relationship === "forwards_to";
        if (
          edge.relationship !== "communicates_with" &&
          edge.relationship !== "calls" &&
          !passThrough
        )
          continue;
        const reverseOk = edge.target === current;
        const forwardOk = edge.source === current;
        const bothWays =
          edge.relationship === "communicates_with" &&
          edge.direction_basis === "unknown";
        const follows = upstream ? reverseOk : forwardOk;
        if (!follows && !bothWays) continue;
        const next = edge.source === current ? edge.target : edge.source;
        const cost = passThrough ? 0 : 1;
        if (depth + cost <= hops) {
          followed.add(edge.id);
          reach(next, depth + cost);
        }
      }
    }
  }
  const result = new Set(distance.keys());
  for (const edge of index.edge.values()) {
    if (edge.relationship === "runs_on" && result.has(edge.target))
      result.add(edge.source);
  }
  return { nodes: result, followed };
}
