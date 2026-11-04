import { useMemo } from "react";
import {
  ArrowRight,
  BrickWall,
  Network,
  Server,
  Waypoints,
} from "lucide-react";
import type { Graph, GraphEdge, GraphIndex, TrafficObservation } from "./graph";
import {
  contractCell,
  edgeIdentity,
  plural,
  portLabel,
  prettyBytes,
} from "./glossary";
import { IdentityBadge } from "./Inspector";
import { AciFabricPanel } from "./AciFabricPanel";
import type { SearchClient } from "./data/searchClient";
import {
  deviceSummaries,
  deviceKindLabel,
  fabricLabel,
  type DeviceSummary,
  type TopologyIndex,
} from "./topology";

export const MAX_ATTACHMENT_REFERENCES = 32;
export const MAX_OBSERVER_GROUPS = 256;
export const MAX_OBSERVER_ENTRIES = 50;

export interface TrafficObserverGroup {
  key: string;
  source: string;
  authority: string;
  observer: string;
  profile?: string;
  scope?: string;
  cluster?: string;
  observation_domain_id?: string;
  observation_domain_present?: string;
  version?: string;
  records: number;
  entries: { edge: GraphEdge; observation: TrafficObservation }[];
}

const field = (value: string | undefined) => value?.trim() || "unknown";
const optionalField = (value: unknown) =>
  value === undefined || value === null ? "absent" : String(value);

/** Groups source records by their attested observer context, never by route. */
export function trafficObserverGroups(graph: Graph): TrafficObserverGroup[] {
  const groups = new Map<string, TrafficObserverGroup>();
  for (const edge of graph.edges) {
    if (edge.relationship !== "traffic_observation") continue;
    for (const observation of edge.traffic_observations ?? []) {
      const authority = field(observation.source_authority);
      const profile = field(observation.profile);
      const scope = field(observation.scope);
      const cluster = field(observation.cluster);
      const exporter = field(observation.exporter_ip);
      const point = field(observation.observation_point);
      const source = field(observation.source);
      const domainId = optionalField(observation.observation_domain_id);
      const domainPresent = optionalField(
        observation.observation_domain_present,
      );
      const extra = observation as TrafficObservation & {
        version?: unknown;
        exporter_version?: unknown;
      };
      const version = optionalField(extra.version ?? extra.exporter_version);
      const unresolved =
        authority === "unknown" ||
        (point === "unknown" && exporter === "unknown");
      const key = [
        source,
        authority,
        profile,
        scope,
        cluster,
        exporter,
        point,
        domainId,
        domainPresent,
        version,
        ...(unresolved
          ? [edge.id, String(edge.traffic_observations?.indexOf(observation))]
          : []),
      ].join("\u001f");
      const group = groups.get(key) ?? {
        key,
        source,
        authority,
        observer:
          observation.observation_point ?? observation.exporter_ip ?? "unknown",
        ...(observation.profile ? { profile: observation.profile } : {}),
        ...(observation.scope ? { scope: observation.scope } : {}),
        ...(observation.cluster ? { cluster: observation.cluster } : {}),
        ...(observation.observation_domain_id
          ? { observation_domain_id: observation.observation_domain_id }
          : {}),
        observation_domain_present: domainPresent,
        ...(version !== "absent" ? { version } : {}),
        records: 0,
        entries: [],
      };
      group.records += observation.records ?? 1;
      group.entries.push({ edge, observation });
      groups.set(key, group);
    }
  }
  return [...groups.values()].sort((a, b) => a.key.localeCompare(b.key));
}

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
    device.source_time_status
      ? `Source time status ${device.source_time_status}`
      : undefined,
    device.history_coverage === "unconfirmed"
      ? "Retained history coverage unconfirmed"
      : device.history_coverage === "retained_evidence"
        ? "Retained evidence only"
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

const observationTuple = (observation: TrafficObservation) => (
  <span className="observation-tuple">
    <span>Source {observation.source_ip ?? "unknown"}</span>
    {observation.source_port !== undefined && (
      <span>:{observation.source_port}</span>
    )}
    <span> → Destination {observation.destination_ip ?? "unknown"}</span>
    {observation.destination_port !== undefined && (
      <span>:{observation.destination_port}</span>
    )}
    {observation.transport && <span> · {observation.transport}</span>}
    {observation.is_reply !== undefined && (
      <span> · Reply {String(observation.is_reply)}</span>
    )}
  </span>
);

function TrafficObservers({
  groups,
  selected,
  onSelect,
}: {
  groups: TrafficObserverGroup[];
  selected?: string;
  onSelect: (id: string) => void;
}) {
  if (!groups.length) return null;
  return (
    <section className="device-card" aria-label="Flow exporters and observers">
      <header>
        <Waypoints size={16} aria-hidden />
        <div>
          <h3>Flow exporters and observers</h3>
          <p className="muted small">
            Source observations are grouped by their reported authority and
            observer context. They are not devices, routes, or packet hops.
          </p>
        </div>
      </header>
      <table>
        <thead>
          <tr>
            <th scope="col">Reported observer</th>
            <th scope="col">Context</th>
            <th scope="col">Observed tuple</th>
            <th scope="col" className="num">
              Flow records
            </th>
          </tr>
        </thead>
        <tbody>
          {groups.slice(0, MAX_OBSERVER_GROUPS).map((group) => (
            <tr key={group.key}>
              <td>
                <b>{group.observer}</b>
                <div className="muted small">
                  {group.source} · Authority {group.authority}
                </div>
              </td>
              <td>
                {[group.profile, group.scope, group.cluster]
                  .concat(
                    [
                      group.observation_domain_id &&
                        `Domain ${group.observation_domain_id}`,
                      group.observation_domain_present &&
                        `Domain present ${group.observation_domain_present}`,
                      group.version && `Version ${group.version}`,
                    ].filter((value): value is string => Boolean(value)),
                  )
                  .filter(Boolean)
                  .join(" · ") || "—"}
              </td>
              <td>
                {group.entries
                  .slice(0, MAX_OBSERVER_ENTRIES)
                  .map(({ edge, observation }, index) => (
                    <div key={`${edge.id}-${index}`}>
                      <button
                        className="link"
                        aria-pressed={selected === edge.id}
                        onClick={() => onSelect(edge.id)}
                      >
                        {observationTuple(observation)}
                      </button>
                    </div>
                  ))}
                {group.entries.length > MAX_OBSERVER_ENTRIES && (
                  <div className="muted small">
                    {group.entries.length - MAX_OBSERVER_ENTRIES} additional
                    source records omitted from display; total flow records
                    remains {group.records.toLocaleString()}.
                  </div>
                )}
              </td>
              <td className="num">{group.records.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        Flow record counts are source-reported records, not connection or byte
        totals.
      </p>
      {groups.length > MAX_OBSERVER_GROUPS && (
        <p className="muted small">
          {groups.length - MAX_OBSERVER_GROUPS} additional observer contexts
          omitted from display; source records remain in the snapshot.
        </p>
      )}
    </section>
  );
}

export function DevicesView({
  graph,
  index,
  topo,
  selected,
  onSelect,
  client,
  live = false,
  earliest,
  latest,
}: {
  graph: Graph;
  index: GraphIndex;
  topo: TopologyIndex;
  selected?: string;
  onSelect: (id: string) => void;
  client?: SearchClient;
  live?: boolean;
  earliest?: string;
  latest?: string;
}) {
  const { devices, unseenByFabric, idle, attachmentReferences } = useMemo(
    () => deviceSummaries(graph.edges, topo, index),
    [graph, index, topo],
  );
  const observerGroups = useMemo(() => trafficObserverGroups(graph), [graph]);
  return (
    <div className="devices-view">
      <p className="muted">
        Source observations and separate device context for this map. Legacy
        device cards below list only devices associated with reported
        conversations.
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
      <TrafficObservers
        groups={observerGroups}
        selected={selected}
        onSelect={onSelect}
      />
      {earliest && (
        <AciFabricPanel
          client={client}
          live={live}
          earliest={earliest}
          latest={latest}
        />
      )}
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
