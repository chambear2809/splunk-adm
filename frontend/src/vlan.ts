import type { GraphEdge, GraphIndex, VlanObservation } from "./graph";
import { deviceName } from "./topology";
import type { TopologyIndex } from "./topology";

export interface VlanContext extends VlanObservation {
  edgeId: string;
}

/** Flatten, deduplicate, and cap NetFlow contexts for an edge or endpoint. */
export function vlanContexts(edges: GraphEdge[]): {
  contexts: VlanContext[];
  truncated: boolean;
} {
  const map = new Map<string, VlanContext>();
  let truncated = false;
  for (const edge of edges) {
    if (edge.vlan_observations_truncated) truncated = true;
    for (const observation of edge.vlan_observations ?? []) {
      const key = [
        observation.vlan,
        observation.position,
        observation.exporter,
        observation.interface_index ?? "",
        observation.interface ?? "",
        observation.src_ip,
        observation.dest_ip,
      ].join("\u001f");
      const previous = map.get(key);
      if (previous) {
        previous.first_seen = Math.min(
          previous.first_seen,
          observation.first_seen,
        );
        previous.last_seen = Math.max(
          previous.last_seen,
          observation.last_seen,
        );
      } else map.set(key, { ...observation, edgeId: edge.id });
    }
  }
  const all = [...map.values()].sort(
    (a, b) =>
      a.vlan - b.vlan ||
      a.first_seen - b.first_seen ||
      a.edgeId.localeCompare(b.edgeId),
  );
  if (all.length > 32) truncated = true;
  return { contexts: all.slice(0, 32), truncated };
}

export function vlanEdges(index: GraphIndex, nodeId: string): GraphEdge[] {
  return (index.incident.get(nodeId) ?? []).filter(
    (edge) =>
      edge.relationship === "communicates_with" &&
      (edge.vlan_observations?.length ?? 0) > 0,
  );
}

export function vlanExporter(
  observation: VlanObservation,
  topo: TopologyIndex,
): string {
  return deviceName(observation.exporter, topo).name;
}

export function vlanInterface(
  observation: VlanObservation,
  topo: TopologyIndex,
): string | undefined {
  if (observation.interface) return observation.interface;
  if (observation.interface_index) {
    const resolved = topo.ifName.get(
      `${observation.exporter.trim().toLowerCase()}|${observation.interface_index}`,
    );
    return resolved ?? `ifIndex ${observation.interface_index}`;
  }
  return undefined;
}

export function vlanTime(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString([], {
    dateStyle: "short",
    timeStyle: "short",
  });
}
