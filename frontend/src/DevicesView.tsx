import { useMemo, useState, type ReactNode } from "react";
import {
  Boxes,
  BrickWall,
  Cable,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Network,
  Server,
  Waypoints,
} from "lucide-react";
import type { Graph, GraphEdge, GraphIndex, TrafficObservation } from "./graph";
import { plural, prettyBytes } from "./glossary";
import { AciFabricPanel } from "./AciFabricPanel";
import "./devicesTab.css";
import type { SearchClient } from "./data/searchClient";
import { pageURL, type Page } from "./app/urlState";
import { VirtualTable, type VirtualColumn } from "./scale/VirtualTable";
import {
  deviceSummaries,
  deviceKindLabel,
  fabricLabel,
  type Device,
  type TopologyIndex,
} from "./topology";
import {
  TOP_CONVERSATIONS,
  VIRTUALIZE_DEVICES_ABOVE,
  conversationDetail,
  formatLastSeen,
  groupDeviceRows,
  ipNames,
  observerRow,
  summaryRow,
  unseenRow,
  windowByHeights,
  type Conversation,
  type DeviceGroup,
  type DeviceRowModel,
} from "./devicesTab";

export const MAX_ATTACHMENT_REFERENCES = 32;

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

function inventoryDetails(device: Device): string {
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

const currentParams = () =>
  typeof location === "undefined"
    ? new URLSearchParams()
    : new URLSearchParams(location.search);

/** Same-mode link to an Atlas page, e.g. /device?id=… */
function atlasHref(page: string, key: string, value: string): string {
  const next = new URLSearchParams();
  const mode = currentParams().get("mode");
  if (mode) next.set("mode", mode);
  next.set(key, value);
  // The impact page is registered separately; pageURL only joins the path.
  return pageURL(page as Page, next);
}
export const deviceHref = (id: string) => atlasHref("device", "id", id);
export const impactHref = (element: string) =>
  atlasHref("impact", "element", element);

function GroupIcon({ group }: { group: DeviceGroup }) {
  const p = { size: 16, "aria-hidden": true } as const;
  if (group === "Leaf") return <Network {...p} />;
  if (group === "Spine") return <Waypoints {...p} />;
  if (group === "FI") return <Cable {...p} />;
  if (group === "Host/VDS") return <Server {...p} />;
  if (group === "K8s node/Cilium") return <Boxes {...p} />;
  if (group === "Firewall") return <BrickWall {...p} />;
  return <CircleDot {...p} />;
}

const endpointCell = (
  endpoint: Conversation["source"],
  edgeId: string,
  onSelect: (id: string) => void,
) => (
  <button
    type="button"
    className="link device-conv-endpoint"
    title={endpoint.ip}
    onClick={() => onSelect(edgeId)}
  >
    {endpoint.label}
  </button>
);

function useConversationColumns(
  onSelect: (id: string) => void,
): VirtualColumn<Conversation>[] {
  return useMemo(
    () => [
      {
        key: "source",
        header: "Source",
        width: 1.4,
        render: (c) => endpointCell(c.source, c.edgeId, onSelect),
        sortValue: (c) => c.source.label,
        filterText: (c) => `${c.source.label} ${c.source.ip ?? ""}`,
      },
      {
        key: "destination",
        header: "Destination",
        width: 1.4,
        render: (c) => endpointCell(c.destination, c.edgeId, onSelect),
        sortValue: (c) => c.destination.label,
        filterText: (c) => `${c.destination.label} ${c.destination.ip ?? ""}`,
      },
      {
        key: "service",
        header: "Service",
        headerTitle: "Listener port/protocol",
        render: (c) => (
          <span
            className="device-conv-service"
            title={conversationDetail(c)}
            tabIndex={0}
          >
            {c.service}
            {c.blocked && <span className="status blocked">Blocked</span>}
          </span>
        ),
        sortValue: (c) => c.port ?? Number.MAX_SAFE_INTEGER,
        filterText: (c) => `${c.service}${c.blocked ? " blocked" : ""}`,
      },
      {
        key: "flows",
        header: "Flows",
        num: true,
        render: (c) => c.flows.toLocaleString(),
        sortValue: (c) => c.flows,
      },
      {
        key: "replies",
        header: "Replies",
        num: true,
        render: (c) => (c.replies ? c.replies.toLocaleString() : "—"),
        sortValue: (c) => c.replies,
      },
      {
        key: "bytes",
        header: "Bytes",
        num: true,
        render: (c) => (c.bytes !== undefined ? prettyBytes(c.bytes) : "—"),
        sortValue: (c) => c.bytes ?? -1,
      },
      {
        key: "last",
        header: "Last seen",
        width: 1.1,
        render: (c) => formatLastSeen(c.lastSeen),
        sortValue: (c) => c.lastSeen ?? 0,
      },
    ],
    [onSelect],
  );
}

const ROW_HEIGHT = 56;
const GROUP_HEIGHT = 38;
const PANEL_HEIGHT = 420;
const PANEL_TABLE_HEIGHT = 300;
const LIST_VIEWPORT = 640;

function ConversationPanel({
  row,
  selected,
  columns,
  fixedHeight,
}: {
  row: DeviceRowModel;
  selected?: string;
  columns: VirtualColumn<Conversation>[];
  fixedHeight: boolean;
}) {
  const [showAll, setShowAll] = useState(false);
  const all = row.conversations;
  const shown = useMemo(
    () => (showAll ? all : all.slice(0, TOP_CONVERSATIONS)),
    [all, showAll],
  );
  const selectedKey = selected
    ? all.find((c) => c.edgeId === selected)?.key
    : undefined;
  return (
    <div className="device-conv-panel">
      <VirtualTable
        caption="Conversations"
        rows={shown}
        columns={columns}
        rowKey={(c) => c.key}
        selected={selectedKey}
        viewportHeight={fixedHeight ? PANEL_TABLE_HEIGHT : 360}
        empty="No conversations."
      />
      {all.length > shown.length && (
        <p className="device-conv-more muted small">
          Top {shown.length.toLocaleString()} of {all.length.toLocaleString()}
          {" · "}
          {row.deviceId ? (
            <a href={deviceHref(row.deviceId)}>Show all</a>
          ) : (
            <button
              type="button"
              className="link"
              onClick={() => setShowAll(true)}
            >
              Show all
            </button>
          )}
        </p>
      )}
    </div>
  );
}

function DeviceRow({
  row,
  open,
  onToggle,
  onOpenDevice,
  children,
}: {
  row: DeviceRowModel;
  open: boolean;
  onToggle: () => void;
  onOpenDevice?: (deviceId: string) => void;
  children?: ReactNode;
}) {
  const openDevice = row.deviceId
    ? () =>
        onOpenDevice
          ? onOpenDevice(row.deviceId!)
          : location.assign(deviceHref(row.deviceId!))
    : undefined;
  return (
    <section
      className="device-card device-row"
      aria-label={row.name}
      data-device-row={row.key}
    >
      <header onDoubleClick={openDevice}>
        <button
          type="button"
          className="devices-row-toggle"
          aria-expanded={open}
          title={row.details}
          onClick={onToggle}
        >
          {open ? (
            <ChevronDown size={14} aria-hidden />
          ) : (
            <ChevronRight size={14} aria-hidden />
          )}
          <GroupIcon group={row.group} />
          <span className="device-row-name">
            <b>{row.name}</b>
            {row.subtitle && (
              <span className="muted small">{row.subtitle}</span>
            )}
          </span>
        </button>
        <span className="device-row-chips">
          <span className="chip" title="Conversations">
            {plural(row.conversations.length, "conversation")}
          </span>
          <span className="chip" title="Distinct endpoints">
            {plural(row.peers, "peer")}
          </span>
          {row.bytes !== undefined && (
            <span className="chip" title="Bytes">
              {prettyBytes(row.bytes)}
            </span>
          )}
          {row.blocked > 0 && (
            <span className="chip blocked" title="Blocked conversations">
              {row.blocked} blocked
            </span>
          )}
        </span>
        <span className="device-row-actions">
          {row.deviceId && (
            <a href={deviceHref(row.deviceId)} className="device-row-action">
              Open device
            </a>
          )}
          {row.element && (
            <a href={impactHref(row.element)} className="device-row-action">
              Impact
            </a>
          )}
        </span>
      </header>
      {open && children}
    </section>
  );
}

type ListItem =
  | { type: "group"; group: DeviceGroup; count: number; open: boolean }
  | { type: "row"; row: DeviceRowModel; open: boolean };

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
  onOpenDevice,
}: {
  graph: Graph;
  index: GraphIndex;
  topo: TopologyIndex;
  /** Double-click a device row to open its page. */
  onOpenDevice?: (deviceId: string) => void;
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
  const rows = useMemo(() => {
    const names = ipNames(graph);
    return [
      ...devices.map((d) => summaryRow(d, index)),
      ...trafficObserverGroups(graph).map((g) => observerRow(g, topo, names)),
      ...(unseenByFabric.length ? [unseenRow(unseenByFabric, index)] : []),
    ];
  }, [devices, unseenByFabric, graph, index, topo]);
  const [query, setQuery] = useState("");
  const [groupOpen, setGroupOpen] = useState<
    Partial<Record<DeviceGroup, boolean>>
  >({});
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [scrollTop, setScrollTop] = useState(0);
  const groups = useMemo(() => groupDeviceRows(rows, query), [rows, query]);
  const shownDevices = groups.reduce((sum, g) => sum + g.rows.length, 0);
  const virtual = shownDevices > VIRTUALIZE_DEVICES_ABOVE;
  const items: ListItem[] = [];
  for (const g of groups) {
    const open = groupOpen[g.group] ?? g.defaultOpen;
    items.push({ type: "group", group: g.group, count: g.rows.length, open });
    if (open)
      for (const row of g.rows)
        items.push({ type: "row", row, open: expanded.has(row.key) });
  }
  const columns = useConversationColumns(onSelect);
  const heights = items.map((item) =>
    item.type === "group"
      ? GROUP_HEIGHT
      : ROW_HEIGHT + (item.open ? PANEL_HEIGHT : 0),
  );
  const range = virtual
    ? windowByHeights(heights, scrollTop, LIST_VIEWPORT)
    : { first: 0, last: items.length, before: 0, after: 0 };
  const toggleRow = (key: string) =>
    setExpanded((cur) => {
      const next = new Set(cur);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const renderItem = (item: ListItem, i: number) => {
    const style = virtual ? { height: heights[i] } : undefined;
    if (item.type === "group")
      return (
        <h3 key={`g:${item.group}`} className="devices-group" style={style}>
          <button
            type="button"
            aria-expanded={item.open}
            onClick={() =>
              setGroupOpen((cur) => ({ ...cur, [item.group]: !item.open }))
            }
          >
            {item.open ? (
              <ChevronDown size={14} aria-hidden />
            ) : (
              <ChevronRight size={14} aria-hidden />
            )}
            <GroupIcon group={item.group} />
            {item.group}
            <span className="chip">{item.count}</span>
          </button>
        </h3>
      );
    return (
      <div
        key={item.row.key}
        className="devices-item"
        style={style}
        data-virtual={virtual || undefined}
      >
        <DeviceRow
          row={item.row}
          open={item.open}
          onToggle={() => toggleRow(item.row.key)}
          onOpenDevice={onOpenDevice}
        >
          <ConversationPanel
            row={item.row}
            selected={selected}
            columns={columns}
            fixedHeight={virtual}
          />
        </DeviceRow>
      </div>
    );
  };
  return (
    <div className="devices-view">
      <div className="devices-toolbar">
        <label className="sr-only" htmlFor="devices-filter">
          Filter devices
        </label>
        <input
          id="devices-filter"
          type="search"
          placeholder="Filter devices"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setScrollTop(0);
          }}
        />
        <span className="muted small" aria-live="polite">
          {shownDevices === rows.length
            ? plural(rows.length, "device")
            : `${shownDevices} of ${plural(rows.length, "device")}`}
        </span>
      </div>
      <div
        className={virtual ? "devices-list virtual" : "devices-list"}
        style={virtual ? { height: LIST_VIEWPORT } : undefined}
        data-scroll-region={virtual || undefined}
        onScroll={
          virtual ? (e) => setScrollTop(e.currentTarget.scrollTop) : undefined
        }
      >
        {range.before > 0 && (
          <div aria-hidden="true" style={{ height: range.before }} />
        )}
        {items
          .slice(range.first, range.last)
          .map((item, i) => renderItem(item, range.first + i))}
        {range.after > 0 && (
          <div aria-hidden="true" style={{ height: range.after }} />
        )}
        {!items.length && (
          <p className="muted small">
            {rows.length ? "No devices match." : "No devices."}
          </p>
        )}
      </div>
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
            </div>
          </header>
          <ul className="seen-list">
            {attachmentReferences
              .slice(0, MAX_ATTACHMENT_REFERENCES)
              .map((reference) => (
                <li
                  key={reference.key}
                  data-device-id={
                    reference.device?.id ?? reference.evidence.device_id
                  }
                  title={[
                    ...(reference.device
                      ? [
                          reference.device.id,
                          reference.device.device_authority,
                          reference.device.scope,
                          reference.device.cluster,
                        ]
                      : [
                          reference.unresolvedReason,
                          reference.evidence.device_id,
                          reference.evidence.device_name,
                        ]),
                    reference.client ? `Client ${reference.client}` : undefined,
                    reference.evidence.status,
                    reference.evidence.basis,
                    reference.evidence.device_serial,
                    reference.evidence.ssid_number
                      ? `SSID ${reference.evidence.ssid_number}`
                      : undefined,
                    ...reference.exporterContext,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                >
                  <b>
                    {reference.device
                      ? `${reference.device.name} (${deviceKindLabel(
                          reference.device.kind,
                          reference.device.cluster,
                        )})`
                      : "Unresolved attachment device"}
                  </b>
                  <small>
                    {[
                      reference.client,
                      plural(reference.flowEdges.length, "flow"),
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </small>
                </li>
              ))}
          </ul>
          {attachmentReferences.length > MAX_ATTACHMENT_REFERENCES && (
            <p className="muted small">
              Showing {MAX_ATTACHMENT_REFERENCES} of{" "}
              {attachmentReferences.length}
            </p>
          )}
        </section>
      )}
      {idle.length > 0 && (
        <details className="devices-idle">
          <summary className="muted small">
            Idle inventory · {idle.length}
          </summary>
          <ul className="devices-idle-list">
            {idle.map((d) => (
              <li key={d.id} title={inventoryDetails(d) || undefined}>
                {d.name}{" "}
                <span className="muted small">
                  {[deviceKindLabel(d.kind, d.cluster), fabricLabel(d.fabric)]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
