import type { Graph } from "../graph";
import type { EvidenceConfiguration } from "./evidenceConfig";
import {
  routingScope,
  validateServiceHealthSelection,
  type ServiceHealthSelection,
} from "./evidence";

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
        mapping.observer_kind === "o11y_export" &&
        mapping.mapping_status === "verified" &&
        mapping.scope === scope &&
        mapping.cluster === graph.boundary.cluster,
    )
  )
    throw new Error("A verified service and health authority are required.");
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
      "Exact graph-boundary service name, environment, cluster and Kubernetes namespace; health remains source-specific.",
    configurationFingerprint: config.fingerprint,
  });
}
