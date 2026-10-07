import type { Graph, GraphIndex, GraphNode } from "./graph";
import {
  edgeIdentity,
  handoffShort,
  identityLabel,
  kindLabel,
} from "./glossary";
import {
  deviceName,
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
  const leaf = (raw?: string) => {
    if (!raw) return "";
    const n = deviceName(raw, topo);
    return n.secondary ? `${n.name} (${n.secondary})` : n.name;
  };
  const rows = graph.edges
    .filter((e) => e.relationship === "communicates_with")
    .map((e) => {
      const target = node(e.target);
      const forwards =
        target?.endpoint_kind === "k8s_service"
          ? (index.outgoing.get(target.id) ?? []).filter(
              (f) => f.relationship === "forwards_to",
            )
          : [];
      return csvRow([
        ...side(node(e.source), e.source),
        ...side(node(e.target), e.target),
        e.server_port ?? "",
        e.transport ?? "",
        e.direction_basis ?? "",
        identityLabel[edgeIdentity(e, node)],
        observationsByDevice(e, topo)
          .map((d) => {
            const n = deviceName(d.label, topo);
            return n.secondary ? `${n.name} (${n.secondary})` : n.name;
          })
          .join("; "),
        e.contract ?? "",
        e.contract_entry ?? "",
        e.contract_basis ?? "",
        e.acl_action ?? "",
        leaf(e.acl_leaf),
        target?.endpoint_kind === "k8s_service"
          ? (target.attributes?.service ?? target.label)
          : "",
        forwards
          .map(
            (f) =>
              `${node(f.target)?.label ?? f.target}${f.confidence === "inferred" ? " (inferred)" : ""}`,
          )
          .join("; ") ||
          (target?.attributes?.handoff === "service_only"
            ? "not determined"
            : ""),
        [...new Set(forwards.map((f) => handoffShort[f.handoff_basis!]))].join(
          "; ",
        ),
      ]);
    });
  return [csvRow([...FLOW_COLUMNS]), ...rows].join("\r\n") + "\r\n";
}
