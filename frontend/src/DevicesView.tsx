import { useMemo } from "react";
import {
  ArrowRight,
  BrickWall,
  Network,
  Server,
  Waypoints,
} from "lucide-react";
import type { Graph, GraphEdge, GraphIndex } from "./graph";
import {
  contractCell,
  edgeIdentity,
  plural,
  portLabel,
  prettyBytes,
} from "./glossary";
import { IdentityBadge } from "./Inspector";
import {
  deviceSummaries,
  deviceKindLabel,
  fabricLabel,
  type DeviceSummary,
  type TopologyIndex,
} from "./topology";

export const MAX_ATTACHMENT_REFERENCES = 32;

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

function inventoryDetails(
  device: NonNullable<DeviceSummary["device"]>,
): string {
  const fields = [
    device.sources.length ? `Source ${device.sources.join(", ")}` : undefined,
    device.mapping_status ? `Mapping ${device.mapping_status}` : undefined,
    device.scope ? `Scope ${device.scope}` : undefined,
    device.routing_domain
      ? `Routing domain ${device.routing_domain}`
      : undefined,
    device.access_platform ? `Access ${device.access_platform}` : undefined,
    device.client_mac ? `Client MAC ${device.client_mac}` : undefined,
    device.client_ip ? `Client IP ${device.client_ip}` : undefined,
    device.attachment_status
      ? `Attachment ${device.attachment_status}`
      : undefined,
    device.evidence_kind ? `Evidence ${device.evidence_kind}` : undefined,
    device.attachment_basis ? `Basis ${device.attachment_basis}` : undefined,
    device.source_time
      ? `Source time/freshness ${device.source_time}`
      : undefined,
    device.received_time ? `Received ${device.received_time}` : undefined,
    device.latest_received_time
      ? `Latest received ${device.latest_received_time}`
      : undefined,
    device.collected_time
      ? `Collector time ${device.collected_time}`
      : undefined,
    device.attachment_event_time
      ? `Attachment event ${device.attachment_event_time}`
      : undefined,
    device.attachment_received_time
      ? `Attachment received ${device.attachment_received_time}`
      : undefined,
    device.attachment_collected_time
      ? `Attachment collector time ${device.attachment_collected_time}`
      : undefined,
    device.attachment_device_name
      ? `Attached device ${device.attachment_device_name}`
      : undefined,
    device.attachment_interface
      ? `Attachment interface ${device.attachment_interface}`
      : undefined,
    device.ssid_number ? `SSID number ${device.ssid_number}` : undefined,
    device.overlay_peer_system_ip
      ? `Overlay peer ${device.overlay_peer_system_ip}${device.overlay_peer_color ? ` (${device.overlay_peer_color})` : ""}`
      : undefined,
    device.overlay_protocol ? `Tunnel ${device.overlay_protocol}` : undefined,
  ].filter((value): value is string => Boolean(value));
  return fields.join(" · ");
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
    (a, b) =>
      (a.traffic_observations?.length || b.traffic_observations?.length
        ? 0
        : (b.bytes ?? -1) - (a.bytes ?? -1)) || a.id.localeCompare(b.id),
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
  const { devices, unseenByFabric, idle, attachmentReferences } = useMemo(
    () => deviceSummaries(graph.edges, topo, index),
    [graph, index, topo],
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
      {attachmentReferences.length > 0 && (
        <section
          className="device-card attachment-references"
          aria-label="Client attachment devices"
        >
          <header>
            <Waypoints size={16} aria-hidden />
            <div>
              <h3>Client attachment devices</h3>
              <p className="muted small">
                Source-qualified client evidence is shown alongside compatible
                flow observations. It does not prove a packet route.
              </p>
            </div>
          </header>
          <ul className="seen-list">
            {attachmentReferences
              .slice(0, MAX_ATTACHMENT_REFERENCES)
              .map((reference) => (
                <li key={reference.key}>
                  <b>
                    {reference.device
                      ? `${reference.device.name} (${deviceKindLabel(
                          reference.device.kind,
                          reference.device.cluster,
                        )})`
                      : "Unresolved attachment device"}
                  </b>
                  <small>
                    {reference.device
                      ? [
                          reference.device.id,
                          reference.device.device_authority,
                          reference.device.scope,
                          reference.device.cluster,
                        ]
                          .filter(Boolean)
                          .join(" · ")
                      : [
                          reference.unresolvedReason,
                          reference.evidence.device_id,
                          reference.evidence.device_name,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                    <br />
                    {[
                      reference.client
                        ? `Client ${reference.client}`
                        : undefined,
                      reference.evidence.status,
                      reference.evidence.basis,
                      reference.evidence.device_serial,
                      reference.evidence.ssid_number
                        ? `SSID ${reference.evidence.ssid_number}`
                        : undefined,
                      ...reference.exporterContext,
                      `${reference.flowEdges.length} correlated flow ${
                        reference.flowEdges.length === 1
                          ? "observation"
                          : "observations"
                      }`,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </small>
                </li>
              ))}
          </ul>
          {attachmentReferences.length > MAX_ATTACHMENT_REFERENCES && (
            <p className="muted small">
              {plural(
                attachmentReferences.length - MAX_ATTACHMENT_REFERENCES,
                "additional attachment reference",
              )}{" "}
              {attachmentReferences.length - MAX_ATTACHMENT_REFERENCES === 1
                ? "was"
                : "were"}{" "}
              omitted because the list is capped at {MAX_ATTACHMENT_REFERENCES}.
            </p>
          )}
        </section>
      )}
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
          {idle
            .map((d) => {
              const details = inventoryDetails(d);
              return `${d.name} (${deviceKindLabel(d.kind, d.cluster)})${details ? ` — ${details}` : ""}`;
            })
            .join(", ")}
          .
        </p>
      )}
    </div>
  );
}
