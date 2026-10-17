import type {
  AttachmentEvidence,
  Graph,
  GraphEdge,
  GraphIndex,
  GraphNode,
  TrafficObservation,
} from "./graph";
import {
  edgeIdentity,
  handoffShort,
  identityLabel,
  kindLabel,
} from "./glossary";
import {
  backendChoices,
  backendChoiceSummary,
  clientBackendChoices,
  clientHandoffBasisSummary,
  clientHandoffResolution,
  deviceName,
  edgeDeviceContext,
  handoffCoverageMessage,
  observationsByDevice,
  type TopologyIndex,
} from "./topology";

/**
 * One CSV cell. Values that a spreadsheet would evaluate as a formula
 * (leading = + - @ tab or CR) are prefixed with a single quote.
 */
export function csvCell(value: unknown): string {
  let s = value === undefined || value === null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
export const csvRow = (cells: unknown[]) => cells.map(csvCell).join(",");

export const FLOW_COLUMNS = [
  "client_name",
  "client_kind",
  "client_ip",
  "client_epg",
  "client_namespace",
  "server_name",
  "server_kind",
  "server_ip",
  "server_epg",
  "server_namespace",
  "port",
  "transport",
  "direction_basis",
  "identity",
  "seen_by",
  "contract",
  "contract_entry",
  "contract_basis",
  "acl_action",
  "acl_leaf",
  "service",
  "backend",
  "handoff",
  "vlan_observations",
  "vlan_observations_truncated",
  "client_attachment_source",
  "client_attachment_authority",
  "client_routing_domain",
  "client_attachment_status",
  "client_attachment_basis",
  "client_attachment_event_time",
  "client_attachment_received_time",
  "client_attachment_collected_time",
  "client_attachment_device_id",
  "client_attachment_device_name",
  "client_attachment_device_mac",
  "client_ssid_number",
  "traffic_observations",
] as const;

const side = (n: GraphNode | undefined, id: string) => [
  n?.label ?? id,
  n ? kindLabel(n) : "",
  n?.addresses?.join(" ") ?? (n?.kind === "endpoint" ? n.label : ""),
  n?.attributes?.epg ?? "",
  n?.namespace ?? "",
];

/** Required network flows for firewall rule or ACI contract requests. */
export function requiredFlowsCsv(
  graph: Graph,
  index: GraphIndex,
  topo: TopologyIndex,
): string {
  const node = (id: string) => index.node.get(id);
  const leaf = (raw?: string, context = {}) => {
    if (!raw) return "";
    const n = deviceName(raw, topo, context);
    return n.secondary ? `${n.name} (${n.secondary})` : n.name;
  };
  const rows = graph.edges
    .filter((e) => e.relationship === "communicates_with")
    .map((e) => {
      const context = edgeDeviceContext(e, index);
      const target = node(e.target);
      const clientHandoff =
        target?.endpoint_kind === "k8s_service"
          ? clientHandoffResolution(e, target, index)
          : undefined;
      const clientHandoffCoverage = clientHandoff?.version2
        ? clientHandoff.message
        : target?.endpoint_kind === "k8s_service"
          ? handoffCoverageMessage(target)
          : undefined;
      const choices =
        target?.endpoint_kind === "k8s_service" && !clientHandoffCoverage
          ? clientHandoff?.version2
            ? clientBackendChoices(index, clientHandoff.records)
            : backendChoices(index, target.id)
          : [];
      const forwards = choices.flatMap((c) => c.edges);
      const handoffBasis = clientHandoff?.version2
        ? clientHandoffBasisSummary(clientHandoff.records)
        : [
            ...new Set(forwards.map((f) => handoffShort[f.handoff_basis!])),
          ].join("; ");
      return csvRow([
        ...side(node(e.source), e.source),
        ...side(node(e.target), e.target),
        e.server_port ?? "",
        e.transport ?? "",
        e.direction_basis ?? "",
        identityLabel[edgeIdentity(e, node)],
        observationsByDevice(e, topo, [], context)
          .map((d) => {
            const n = deviceName(d.key, topo, context);
            return n.secondary ? `${n.name} (${n.secondary})` : n.name;
          })
          .join("; "),
        e.contract ?? "",
        e.contract_entry ?? "",
        e.contract_basis ?? "",
        e.acl_action ?? "",
        leaf(e.acl_leaf, context),
        target?.endpoint_kind === "k8s_service"
          ? (target.attributes?.service ?? target.label)
          : "",
        clientHandoffCoverage ??
          (choices.map(backendChoiceSummary).join("; ") ||
            (target?.attributes?.handoff === "service_only"
              ? "not determined"
              : "")),
        clientHandoffCoverage
          ? "unavailable for individual client"
          : handoffBasis,
        e.vlan_observations?.length ? JSON.stringify(e.vlan_observations) : "",
        e.vlan_observations_truncated ? "1" : "",
        node(e.source)?.attributes?.access_platform ?? "",
        node(e.source)?.attributes?.source_authority ?? "",
        node(e.source)?.attributes?.routing_domain ?? "",
        node(e.source)?.attributes?.attachment_status ?? "",
        node(e.source)?.attributes?.attachment_basis ?? "",
        node(e.source)?.attributes?.attachment_event_time ?? "",
        node(e.source)?.attributes?.attachment_received_time ?? "",
        node(e.source)?.attributes?.attachment_collected_time ?? "",
        node(e.source)?.attributes?.attachment_device_id ?? "",
        node(e.source)?.attributes?.attachment_device_name ?? "",
        node(e.source)?.attributes?.attachment_device_mac ?? "",
        node(e.source)?.attributes?.ssid_number ?? "",
        e.traffic_observations?.length
          ? JSON.stringify(e.traffic_observations)
          : "",
      ]);
    });
  return [csvRow([...FLOW_COLUMNS]), ...rows].join("\r\n") + "\r\n";
}

export const CONTEXT_EVIDENCE_COLUMNS = [
  "edge_id",
  "edge_relationship",
  "source_id",
  "target_id",
  "evidence_kind",
  "source",
  "source_authority",
  "client_source",
  "client_authority",
  "scope",
  "cluster",
  "mapping_status",
  "evidence_json",
] as const;

/** Export the original per-edge context records without merging node summaries. */
export function contextEvidenceCsv(graph: Graph): string {
  const rows: string[] = [];
  const append = (
    edge: GraphEdge,
    evidenceKind: "attachment_evidence" | "traffic_observation",
    value: AttachmentEvidence | TrafficObservation,
  ) => {
    const observation = evidenceKind === "traffic_observation";
    const item = value as AttachmentEvidence & TrafficObservation;
    rows.push(
      csvRow([
        edge.id,
        edge.relationship,
        edge.source,
        edge.target,
        evidenceKind,
        observation ? item.source : undefined,
        observation ? item.source_authority : undefined,
        observation ? undefined : item.client_source,
        observation ? undefined : item.client_authority,
        observation ? item.scope : undefined,
        observation ? item.cluster : undefined,
        observation ? item.mapping_status : undefined,
        JSON.stringify(value),
      ]),
    );
  };
  for (const edge of graph.edges) {
    for (const attachment of edge.attachment_evidence ?? [])
      append(edge, "attachment_evidence", attachment);
    for (const observation of edge.traffic_observations ?? [])
      append(edge, "traffic_observation", observation);
  }
  return [csvRow([...CONTEXT_EVIDENCE_COLUMNS]), ...rows].join("\r\n") + "\r\n";
}
