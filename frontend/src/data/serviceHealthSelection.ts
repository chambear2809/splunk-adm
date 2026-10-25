import type { Graph } from "../graph";
import {
  configuredDetectorIds,
  type EvidenceConfiguration,
  type ObserverMapping,
} from "./evidenceConfig";
import {
  routingScope,
  validateServiceHealthSelection,
  type ServiceHealthSelection,
} from "./evidence";

function eligibleMapping(mapping: ObserverMapping, cluster: string): boolean {
  if (
    !mapping.organization_id ||
    !mapping.realm ||
    mapping.mapping_status !== "verified" ||
    mapping.cluster !== cluster
  )
    return false;
  if (mapping.observer_kind === "o11y_export") return true;
  if (mapping.observer_kind !== "o11y_detector") return false;
  try {
    configuredDetectorIds(mapping.detector_ids ?? "");
    return true;
  } catch {
    return false;
  }
}

/** Detector context can be selected independently of measured-health collection. */
export function serviceEvidenceScopes(
  config: EvidenceConfiguration,
  cluster: string,
): string[] {
  return [
    ...new Set(
      config.mappings
        .filter((mapping) => eligibleMapping(mapping, cluster))
        .map((mapping) => mapping.scope),
    ),
  ].sort();
}

/** Only the graph boundary carries all four qualified service dimensions. */
export function serviceHealthSelection(
  graph: Graph,
  selectedNodeId: string,
  scope: string,
  config: EvidenceConfiguration,
  window = {
    start: Date.parse(graph.window.start) / 1000,
    end: Date.parse(graph.window.end) / 1000,
  },
): ServiceHealthSelection {
  routingScope(scope);
  const root = graph.nodes.find(
    (node) => node.id === graph.boundary.root_node_id,
  );
  if (
    selectedNodeId !== graph.boundary.root_node_id ||
    root?.kind !== "service" ||
    !config.mappings.some(
      (mapping) =>
        eligibleMapping(mapping, graph.boundary.cluster) &&
        mapping.scope === scope,
    )
  )
    throw new Error(
      "A verified service and configured Observability evidence authority are required.",
    );
  return validateServiceHealthSelection({
    schemaVersion: 1,
    workflow: "service",
    selectionId: `${graph.snapshot_id}:${selectedNodeId}`,
    scope,
    window,
    service: {
      name: graph.boundary.service,
      environment: graph.boundary.environment,
      cluster: graph.boundary.cluster,
      namespace: graph.boundary.namespace,
    },
    identityBasis:
      "Exact graph-boundary service name, environment, cluster and Kubernetes namespace; metric health and configured detector context remain source-specific.",
    configurationFingerprint: config.fingerprint,
  });
}
