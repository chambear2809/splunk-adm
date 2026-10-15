import {
  contractSummary,
  edgeIdentity,
  handoffConfidence,
  isBlocked,
} from "./glossary";
import { sourceStatus, type HealthReport } from "./health";
import type { Graph, GraphIndex } from "./graph";

export type FindingKind =
  | "blocked_conversation"
  | "unknown_identity"
  | "ambiguous_identity"
  | "missing_contract"
  | "inferred_backend"
  | "stale_source";

export interface Finding {
  id: string;
  kind: FindingKind;
  title: string;
  detail: string;
  edgeId?: string;
}

export function deriveFindings(
  graph: Graph,
  index: GraphIndex,
  health?: HealthReport,
): Finding[] {
  const findings: Finding[] = [];
  const node = (id: string) => index.node.get(id);
  for (const edge of graph.edges) {
    if (edge.relationship === "communicates_with") {
      if (isBlocked(edge)) {
        findings.push({
          id: `blocked:${edge.id}`,
          kind: "blocked_conversation",
          title: "Blocked conversation",
          detail: `The fabric recorded a drop${edge.acl_leaf ? ` at ${edge.acl_leaf}` : ""}.`,
          edgeId: edge.id,
        });
      }
      const identity = edgeIdentity(edge, node);
      if (identity === "unknown" || identity === "multiple") {
        findings.push({
          id: `${identity}:${edge.id}`,
          kind:
            identity === "unknown" ? "unknown_identity" : "ambiguous_identity",
          title:
            identity === "unknown"
              ? "Unknown endpoint identity"
              : "Ambiguous endpoint identity",
          detail:
            identity === "unknown"
              ? "An endpoint address could not be mapped to an owner."
              : "An endpoint address matched multiple owners.",
          edgeId: edge.id,
        });
      }
      if (edge.contract_basis === "none" && !edge.contract) {
        findings.push({
          id: `contract:${edge.id}`,
          kind: "missing_contract",
          title: "No permitting contract",
          detail:
            contractSummary(edge) ??
            "No permitting contract was found in the collected policy.",
          edgeId: edge.id,
        });
      }
    }
    if (edge.relationship === "forwards_to" && edge.confidence === "inferred") {
      findings.push({
        id: `inferred:${edge.id}`,
        kind: "inferred_backend",
        title: "Backend inferred",
        detail: `The backend was selected with ${handoffConfidence(edge.confidence).toLowerCase()} confidence.`,
        edgeId: edge.id,
      });
    }
  }
  if (health) {
    for (const source of health.sources) {
      const status = sourceStatus(source, health.checkedAt);
      if (status === "Data received within 20 minutes") continue;
      findings.push({
        id: `source:${source.name}`,
        kind: "stale_source",
        title: `${source.name} source evidence needs review`,
        detail: status,
      });
    }
  }
  return findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
