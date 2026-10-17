import { ArrowRight } from "lucide-react";
import type { Graph, GraphIndex, GraphNode } from "../graph";
import { IdentityBadge } from "../Inspector";
import {
  contractCell,
  edgeIdentity,
  portLabel,
  prettyBytes,
  relationshipLabel,
} from "../glossary";
import {
  edgeDeviceContext,
  observationsByDevice,
  type indexTopology,
} from "../topology";
export function TableView({
  graph,
  label,
  selected,
  onSelect,
  topo,
  index,
  node,
}: {
  graph: Graph;
  label: (id: string) => string;
  selected?: string;
  onSelect: (id: string) => void;
  topo: ReturnType<typeof indexTopology>;
  index: GraphIndex;
  node: (id: string) => GraphNode | undefined;
}) {
  const conv = graph.edges.filter(
    (e) => e.relationship === "communicates_with",
  );
  const calls = graph.edges.filter((e) => e.relationship === "calls");
  return (
    <div className="table-view">
      <table>
        <caption>Network conversations</caption>
        <thead>
          <tr>
            <th scope="col">Client → Server</th>
            <th scope="col">Port</th>
            <th scope="col">Seen at</th>
            <th scope="col">Contract</th>
            <th scope="col" className="num">
              Bytes
            </th>
            <th scope="col">Identity</th>
          </tr>
        </thead>
        <tbody>
          {conv.map((e) => (
            <tr key={e.id} className={selected === e.id ? "selected" : ""}>
              <td>
                <button className="link" onClick={() => onSelect(e.id)}>
                  {label(e.source)}
                  {e.direction_basis === "unknown" ? (
                    " ↔ "
                  ) : (
                    <ArrowRight size={13} aria-label="to" />
                  )}
                  {label(e.target)}
                </button>
              </td>
              <td>{portLabel(e)}</td>
              <td>
                {observationsByDevice(e, topo, [], edgeDeviceContext(e, index))
                  .map((d) => d.label)
                  .join(", ") || "—"}
              </td>
              <td>{contractCell(e)}</td>
              <td className="num">
                {e.traffic_observations?.length
                  ? "See observations"
                  : e.bytes !== undefined
                    ? prettyBytes(e.bytes)
                    : "—"}
              </td>
              <td>
                {e.acl_action === "drop" ? (
                  <span className="status blocked">Blocked</span>
                ) : (
                  <IdentityBadge state={edgeIdentity(e, node)} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <table>
        <caption>Traced calls</caption>
        <thead>
          <tr>
            <th scope="col">Caller → Callee</th>
            <th scope="col" className="num">
              Spans
            </th>
          </tr>
        </thead>
        <tbody>
          {calls.map((e) => (
            <tr key={e.id} className={selected === e.id ? "selected" : ""}>
              <td>
                <button className="link" onClick={() => onSelect(e.id)}>
                  {label(e.source)} <ArrowRight size={13} aria-label="to" />{" "}
                  {label(e.target)}
                </button>
              </td>
              <td className="num">{e.count.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        {relationshipLabel.communicates_with} rows include every conversation
        that touches the namespace in the selected time range.
      </p>
    </div>
  );
}
