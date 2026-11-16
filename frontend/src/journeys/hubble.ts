import type { GraphIndex, HandoffBasis } from "../graph";
import { handoffShort } from "../glossary";
import { clientHandoffResolution } from "../topology";

/** One qualified client-specific handoff record. Candidates are not packet hops. */
export interface HubbleJourneyCandidate {
  backendId: string;
  backendLabel: string;
  basis: HandoffBasis;
  basisLabel: string;
  relation: "correlated" | "inferred";
  connections: number;
  receivingNodes: string[];
  observers: string[];
}

export interface HubbleJourney {
  clientId: string;
  serviceId: string;
  edgeId: string;
  status: "complete" | "unavailable";
  message?: string;
  candidates: HubbleJourneyCandidate[];
}

/**
 * Project only the handoff attached to the selected client-to-Service edge.
 * Aggregate Service forwarding and edge-level observers cannot establish that
 * client's backend. Distinct records remain distinct; they are not ordered hops.
 */
export function buildHubbleJourney(
  selectedEdgeId: string,
  index: GraphIndex,
): HubbleJourney | undefined {
  const edge = index.edge.get(selectedEdgeId);
  if (!edge || edge.relationship !== "communicates_with") return undefined;
  const client = index.node.get(edge.source);
  const service = index.node.get(edge.target);
  if (!client || service?.endpoint_kind !== "k8s_service") return undefined;

  const resolution = clientHandoffResolution(edge, service, index);
  const base = { clientId: client.id, serviceId: service.id, edgeId: edge.id };
  if (!resolution.complete) {
    return {
      ...base,
      status: "unavailable",
      message:
        resolution.message ??
        "Client-specific handoff evidence is unavailable or invalid.",
      candidates: [],
    };
  }
  // Explicit contradictory scopes or clusters cannot be reconciled by a
  // matching display name or a pod ID alone. Missing values remain unknown.
  const conflicts = (values: (string | undefined)[]) =>
    new Set(values.filter((value) => value !== undefined && value !== ""))
      .size > 1;
  const backends = resolution.records.map((record) =>
    index.node.get(record.target)!,
  );
  if (
    conflicts([
      edge.scope,
      client.attributes?.scope,
      service.attributes?.scope,
      ...backends.map((node) => node.attributes?.scope),
    ]) ||
    conflicts([
      edge.cluster,
      service.cluster,
      ...backends.map((node) => node.cluster),
    ])
  ) {
    return {
      ...base,
      status: "unavailable",
      message:
        "Client handoff evidence has conflicting scope or cluster metadata.",
      candidates: [],
    };
  }
  return {
    ...base,
    status: "complete",
    candidates: resolution.records.map((record) => ({
      backendId: record.target,
      backendLabel: index.node.get(record.target)!.label,
      basis: record.basis,
      basisLabel: handoffShort[record.basis],
      relation: record.basis === "time_inferred" ? "inferred" : "correlated",
      connections: record.connections,
      receivingNodes: [...record.receiving_nodes],
      observers: [...record.observers],
    })),
  };
}
