import { useMemo } from "react";
import {
  ArrowRight,
  BrickWall,
  Network,
  Server,
  Waypoints,
} from "lucide-react";
import type { Graph, GraphEdge, GraphIndex } from "./graph";
import { edgeIdentity, plural, portLabel, prettyBytes } from "./glossary";
import { IdentityBadge } from "./Inspector";
import {
  deviceSummaries,
  fabricLabel,
  type DeviceSummary,
  type TopologyIndex,
} from "./topology";

const ROLE_LABEL: Record<DeviceSummary["role"], string> = {
  firewall: "Firewall",
  switch: "Switch",
  fabric: "Fabric (Nexus Dashboard)",
  host: "Kubernetes node (Isovalent)",
};

function RoleIcon({ role }: { role: DeviceSummary["role"] }) {
  const p = { size: 16, "aria-hidden": true } as const;
  if (role === "firewall") return <BrickWall {...p} />;
  if (role === "host") return <Server {...p} />;
  if (role === "fabric") return <Waypoints {...p} />;
  return <Network {...p} />;
}

function Conversations({
  edges,
  index,
  selected,
  onSelect,
}: {
  edges: GraphEdge[];
  index: GraphIndex;
  selected?: string;
  onSelect: (id: string) => void;
}) {
  const node = (id: string) => index.node.get(id);
  const sorted = [...edges].sort(
    (a, b) => (b.bytes ?? -1) - (a.bytes ?? -1) || a.id.localeCompare(b.id),
  );
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Client → Server</th>
          <th scope="col">Port</th>
          <th scope="col">Contract</th>
          <th scope="col" className="num">
            Bytes
          </th>
          <th scope="col">Identity</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((e) => (
          <tr key={e.id} className={selected === e.id ? "selected" : ""}>
            <td>
              <button className="link" onClick={() => onSelect(e.id)}>
                {node(e.source)?.label}
                {e.direction_basis === "unknown" ? (
                  " ↔ "
                ) : (
                  <ArrowRight size={13} aria-label="to" />
                )}
                {node(e.target)?.label}
              </button>
            </td>
            <td>{portLabel(e)}</td>
            <td>
              {e.contract_basis === "intent"
                ? `${e.contract}${e.contract_entry ? ` · ${e.contract_entry}` : ""}`
                : e.contract_basis === "not_evaluated"
                  ? "Not fully evaluated"
                  : e.contract_basis === "none"
                    ? "None found"
                    : "—"}
            </td>
            <td className="num">
              {e.bytes !== undefined ? prettyBytes(e.bytes) : "—"}
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
  );
}

export function DevicesView({
  graph,
  index,
  topo,
  selected,
  onSelect,
}: {
  graph: Graph;
  index: GraphIndex;
  topo: TopologyIndex;
  selected?: string;
  onSelect: (id: string) => void;
}) {
  const { devices, unseenByFabric, idle } = useMemo(
    () => deviceSummaries(graph.edges, topo),
    [graph, topo],
  );
  return (
    <div className="devices-view">
      <p className="muted">
        Every device that reported one of this map's conversations, with the
        interfaces it saw them on.
      </p>
      {devices.map((d) => (
        <section key={d.key} className="device-card" aria-label={d.label}>
          <header>
            <RoleIcon role={d.role} />
            <div>
              <h3>{d.label}</h3>
              <p className="muted small">
                {[
                  d.device?.role ? `ACI ${d.device.role}` : ROLE_LABEL[d.role],
                  d.device?.platform,
                  d.device?.mgmt_ip,
                  fabricLabel(d.device?.fabric),
                  d.device?.aci_node?.split("/").at(-1),
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            </div>
            <span className="chip">
              {plural(d.edges.length, "conversation")}
            </span>
          </header>
          <p className="device-meta">
            <span className="muted">Reported by</span> {d.sources.join(", ")}
            {d.edges.some(
              (e) =>
                e.acl_action === "drop" &&
                d.device &&
                [d.device.id, d.device.aci_node, d.device.name]
                  .filter(Boolean)
                  .map((x) => x!.toLowerCase())
                  .includes((e.acl_leaf ?? "").toLowerCase()),
            ) && (
              <>
                {" "}
                <span className="status blocked">Drops logged here</span>
              </>
            )}
            {d.interfaces.length > 0 && (
              <>
                {" "}
                <span className="muted">· Interfaces</span>{" "}
                {d.interfaces.map((i) => (
                  <code key={i} className="if-chip">
                    {i}
                  </code>
                ))}
              </>
            )}
          </p>
          <Conversations
            edges={d.edges}
            index={index}
            selected={selected}
            onSelect={onSelect}
          />
        </section>
      ))}
      <section className="device-card quiet">
        <header>
          <Waypoints size={16} aria-hidden />
          <div>
            <h3>
              {plural(unseenByFabric.length, "conversation")} not seen by any
              fabric device
            </h3>
            <p className="muted small">
              Only a Kubernetes node (Isovalent) reported these, so no switch,
              firewall or Nexus Dashboard record covers them.
            </p>
          </div>
        </header>
        {unseenByFabric.length > 0 && (
          <Conversations
            edges={unseenByFabric}
            index={index}
            selected={selected}
            onSelect={onSelect}
          />
        )}
      </section>
      {idle.length > 0 && (
        <p className="muted small">
          In inventory but not reporting these conversations:{" "}
          {idle.map((d) => d.name).join(", ")}.
        </p>
      )}
    </div>
  );
}
