import {
  edgeIdentity,
  isBlocked,
  observedPort,
  type IdentityState,
} from "./glossary";
import {
  indexGraph,
  tunnelOf,
  type Graph,
  type GraphEdge,
  type GraphIndex,
  type TrafficObservation,
} from "./graph";

export interface Facets {
  identity?: "identified" | "external" | "unknown";
  port?: number;
  source?: string;
  blocked?: boolean;
  hideInfrastructure?: boolean;
  /** Omit inferred relationships (drawn dashed by default). */
  hideInferred?: boolean;
}

const edgeFacetsActive = (facets: Facets) =>
  facets.identity !== undefined ||
  facets.port !== undefined ||
  (facets.source !== undefined && facets.source.length > 0) ||
  facets.blocked === true;
const active = (facets: Facets) =>
  edgeFacetsActive(facets) || facets.hideInfrastructure === true;

const flowFacetActive = (facets: Facets) =>
  facets.identity !== undefined ||
  facets.port !== undefined ||
  facets.blocked === true;

const identityMatches = (state: IdentityState, wanted: Facets["identity"]) =>
  wanted === undefined ||
  (wanted === "unknown"
    ? state === "unknown" || state === "multiple"
    : state === wanted);

const observationPortMatches = (
  observation: TrafficObservation,
  wanted: number,
) =>
  observation.source_port === wanted ||
  observation.destination_port === wanted ||
  (observation.source_port === undefined &&
    observation.destination_port === undefined &&
    observation.server_port === wanted);

const oneObservationValue = <K extends keyof TrafficObservation>(
  observations: TrafficObservation[],
  key: K,
): TrafficObservation[K] | undefined => {
  const values = observations.map((observation) => observation[key]);
  if (values.length === 0 || values.some((value) => value === undefined))
    return undefined;
  const defined = values as TrafficObservation[K][];
  return defined.every((value) => value === defined[0])
    ? defined[0]
    : undefined;
};

/**
 * Keep a native observation edge's ownership/context, but remove tuples that
 * failed the port facet. Aggregate counters are intentionally dropped because
 * their original values may describe observations that are no longer shown.
 */
const portFilteredObservation = (
  edge: GraphEdge,
  wanted: number,
): GraphEdge | undefined => {
  const observations = edge.traffic_observations;
  if (!observations?.length) return edge;
  const retained = observations.filter((observation) =>
    observationPortMatches(observation, wanted),
  );
  if (!retained.length) return undefined;
  const retainedCount = retained.reduce(
    (total, observation) => total + (observation.records ?? 1),
    0,
  );
  const context = { ...edge };
  delete context.bytes;
  delete context.raw_bytes;
  delete context.raw_packets;
  delete context.records;
  delete context.counter_semantics;
  delete context.metrics_authoritative;
  delete context.source_port;
  delete context.destination_port;
  delete context.server_port;
  delete context.transport;
  return {
    ...context,
    count: retainedCount,
    metrics_authoritative: false,
    traffic_observations: retained,
    ...(oneObservationValue(retained, "source_port") !== undefined
      ? { source_port: oneObservationValue(retained, "source_port") }
      : {}),
    ...(oneObservationValue(retained, "destination_port") !== undefined
      ? {
          destination_port: oneObservationValue(retained, "destination_port"),
        }
      : {}),
    ...(oneObservationValue(retained, "server_port") !== undefined
      ? { server_port: oneObservationValue(retained, "server_port") }
      : {}),
    ...(oneObservationValue(retained, "transport") !== undefined
      ? { transport: oneObservationValue(retained, "transport") }
      : {}),
  };
};

/** Filter edge facets while retaining enough ownership context for layout. */
export function filterGraph(graph: Graph, facets: Facets): Graph {
  if (!active(facets)) return graph;
  const index = indexGraph(graph);
  const matched = graph.edges.filter((edge) => {
    if (!edgeFacetsActive(facets)) return true;
    if (edge.relationship === "calls") {
      // Calls carry declared source provenance, but not flow-level facts such
      // as identity, port, or blocked state to which those facets can apply.
      return (
        facets.source !== undefined &&
        facets.source.length > 0 &&
        !flowFacetActive(facets) &&
        edge.sources?.includes(facets.source) === true
      );
    }
    const conversation = edge.relationship === "communicates_with";
    const observation = edge.relationship === "traffic_observation";
    const nativeObservations = edge.traffic_observations;
    const portMatches =
      facets.port === undefined ||
      (observation && nativeObservations?.length
        ? nativeObservations.some((item) =>
            observationPortMatches(item, facets.port!),
          )
        : observation
          ? edge.source_port === facets.port ||
            edge.destination_port === facets.port ||
            (edge.source_port === undefined &&
              edge.destination_port === undefined &&
              observedPort(edge) === facets.port)
          : observedPort(edge) === facets.port);
    return (
      (conversation || observation) &&
      identityMatches(
        edgeIdentity(edge, (id) => index.node.get(id)),
        facets.identity,
      ) &&
      portMatches &&
      (facets.source === undefined ||
        facets.source.length === 0 ||
        edge.sources?.includes(facets.source) === true) &&
      (facets.blocked !== true || (conversation && isBlocked(edge)))
    );
  });
  const keptEdges = new Map<string, GraphEdge>();
  for (const edge of matched) {
    const filtered =
      facets.port !== undefined && edge.relationship === "traffic_observation"
        ? portFilteredObservation(edge, facets.port)
        : edge;
    if (filtered) keptEdges.set(edge.id, filtered);
  }
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
