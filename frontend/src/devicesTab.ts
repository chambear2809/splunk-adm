/**
 * Map → Devices tab model: one compact row per device or flow observer, each
 * with its conversations aggregated to endpoint pair + service port, so raw
 * 5-tuples (and their ephemeral client ports) never become rows.
 */
import type { Graph, GraphEdge, GraphIndex, TrafficObservation } from "./graph";
import { portLabel } from "./glossary";
import {
  deviceKindLabel,
  fabricLabel,
  observationExporterDevice,
  type Device,
  type DeviceSummary,
  type TopologyIndex,
} from "./topology";

/** Conversations shown per device before "Show all". */
export const TOP_CONVERSATIONS = 50;
/** Device groups expanded by default hold the busiest devices. */
export const DEFAULT_EXPANDED_DEVICES = 5;
/** The device list windows its rows above this many devices. */
export const VIRTUALIZE_DEVICES_ABOVE = 50;
/** Client ports kept per conversation for the drill-down. */
export const MAX_CLIENT_PORTS = 16;
/** Ports at or above this are treated as ephemeral client ports. */
export const EPHEMERAL_PORT_MIN = 32768;

export const DEVICE_GROUPS = [
  "Leaf",
  "Spine",
  "FI",
  "Host/VDS",
  "K8s node/Cilium",
  "Firewall",
  "Other",
] as const;
export type DeviceGroup = (typeof DEVICE_GROUPS)[number];

export interface ConversationEndpoint {
  /** Graph node ID or IP address. */
  id: string;
  label: string;
  ip?: string;
}
export type ServiceBasis =
  | "reply_flag"
  | "server_port"
  | "well_known"
  | "ephemeral"
  | "lower_port"
  | "single_port"
  | "edge"
  | "none";
export interface Conversation {
  key: string;
  /** Graph edge selected when the row is opened. */
  edgeId: string;
  /** Client (initiator) side. */
  source: ConversationEndpoint;
  /** Listener (service) side. */
  destination: ConversationEndpoint;
  service: string;
  port?: number;
  transport?: string;
  flows: number;
  replies: number;
  bytes?: number;
  /** Epoch milliseconds. */
  lastSeen?: number;
  clientPorts: number[];
  clientPortCount: number;
  replyFlags: string[];
  basis: ServiceBasis;
  blocked: boolean;
}

export interface DeviceRowModel {
  key: string;
  name: string;
  subtitle?: string;
  /** Raw source metadata, shown only as a tooltip. */
  details: string;
  group: DeviceGroup;
  /** Inventory ID, when the row is an inventory device. */
  deviceId?: string;
  /** Impact element key. */
  element?: string;
  conversations: Conversation[];
  peers: number;
  bytes?: number;
  blocked: number;
}

interface Side {
  ip?: string;
  port?: number;
}

/**
 * Which side of an observed flow is the listener. A reply flag decides it
 * (a reply's source is the server); otherwise a reported server port, a
 * well-known port, the non-ephemeral port, and finally the lower port.
 */
export function orientObservation(o: TrafficObservation): {
  client: Side;
  server: Side;
  basis: ServiceBasis;
} {
  const src: Side = { ip: o.source_ip, port: o.source_port };
  const dst: Side = { ip: o.destination_ip, port: o.destination_port };
  const forward = (basis: ServiceBasis) => ({
    client: src,
    server: dst,
    basis,
  });
  const reverse = (basis: ServiceBasis) => ({
    client: dst,
    server: src,
    basis,
  });
  if (o.is_reply === true) return reverse("reply_flag");
  if (o.is_reply === false) return forward("reply_flag");
  const sp = src.port;
  const dp = dst.port;
  if (o.server_port !== undefined) {
    if (dp === o.server_port) return forward("server_port");
    if (sp === o.server_port) return reverse("server_port");
  }
  if (sp === undefined && dp === undefined) return forward("none");
  if (sp === undefined) return forward("single_port");
  if (dp === undefined) return reverse("single_port");
  const wellKnown = (p: number) => p < 1024;
  if (wellKnown(dp) !== wellKnown(sp))
    return wellKnown(dp) ? forward("well_known") : reverse("well_known");
  const ephemeral = (p: number) => p >= EPHEMERAL_PORT_MIN;
  if (ephemeral(dp) !== ephemeral(sp))
    return ephemeral(sp) ? forward("ephemeral") : reverse("ephemeral");
  return dp <= sp ? forward("lower_port") : reverse("lower_port");
}

/** Bytes an observation reports, or undefined when it reports none. */
export function observationBytes(o: TrafficObservation): number | undefined {
  if (o.bytes_in !== undefined || o.bytes_out !== undefined)
    return (o.bytes_in ?? 0) + (o.bytes_out ?? 0);
  if (o.raw_bytes !== undefined) return o.raw_bytes;
  if (o.raw_bytes_in !== undefined || o.raw_bytes_out !== undefined)
    return (o.raw_bytes_in ?? 0) + (o.raw_bytes_out ?? 0);
  return undefined;
}

/** Epoch seconds or milliseconds → milliseconds. */
const epochMs = (value: number | undefined) =>
  value === undefined || !Number.isFinite(value) || value <= 0
    ? undefined
    : value < 1e12
      ? value * 1000
      : value;

const blockedVerdict = (verdict?: string) =>
  !!verdict && /drop|deny|denied|block|reject/i.test(verdict);

const addNumber = (a: number | undefined, b: number | undefined) =>
  a === undefined ? b : b === undefined ? a : a + b;

function serviceLabel(port?: number, transport?: string) {
  const t = transport?.toLowerCase();
  if (port !== undefined) return `${port}/${t ?? "?"}`;
  return t ?? "—";
}

/** IP → map name, for addresses exactly one graph node claims. */
export function ipNames(graph: Graph): Map<string, string> {
  const names = new Map<string, string>();
  const ambiguous = new Set<string>();
  for (const node of graph.nodes)
    for (const ip of node.addresses ?? []) {
      const known = names.get(ip);
      if (known !== undefined && known !== node.label) ambiguous.add(ip);
      else names.set(ip, node.label);
    }
  for (const ip of ambiguous) names.delete(ip);
  return names;
}

const endpointFor = (
  ip: string | undefined,
  names: Map<string, string>,
): ConversationEndpoint => ({
  id: ip ?? "unknown",
  label: (ip && names.get(ip)) ?? ip ?? "Unknown",
  ...(ip ? { ip } : {}),
});

function mergeObservation(
  conversation: Conversation,
  o: TrafficObservation,
  clientPort: number | undefined,
) {
  const records = o.records ?? 1;
  conversation.flows += records;
  if (o.is_reply === true) conversation.replies += records;
  conversation.bytes = addNumber(conversation.bytes, observationBytes(o));
  const seen = epochMs(o.last_seen ?? o.first_seen);
  if (seen !== undefined)
    conversation.lastSeen = Math.max(conversation.lastSeen ?? 0, seen);
  if (
    clientPort !== undefined &&
    !conversation.clientPorts.includes(clientPort)
  ) {
    conversation.clientPortCount += 1;
    if (conversation.clientPorts.length < MAX_CLIENT_PORTS)
      conversation.clientPorts.push(clientPort);
  }
  const flag = o.is_reply === undefined ? "absent" : String(o.is_reply);
  if (!conversation.replyFlags.includes(flag))
    conversation.replyFlags.push(flag);
  if (blockedVerdict(o.verdict)) conversation.blocked = true;
}

/** Aggregates raw flow observations to client/server pair + service port. */
export function aggregateObservations(
  entries: readonly { edge: GraphEdge; observation: TrafficObservation }[],
  names: Map<string, string>,
): Conversation[] {
  const byKey = new Map<string, Conversation>();
  for (const { edge, observation: o } of entries) {
    const { client, server, basis } = orientObservation(o);
    const transport = o.transport?.toLowerCase();
    const key = JSON.stringify([
      client.ip ?? edge.source,
      server.ip ?? edge.target,
      server.port ?? null,
      transport ?? null,
    ]);
    let conversation = byKey.get(key);
    if (!conversation) {
      conversation = {
        key,
        edgeId: edge.id,
        source: endpointFor(client.ip, names),
        destination: endpointFor(server.ip, names),
        service: serviceLabel(server.port, transport),
        ...(server.port !== undefined ? { port: server.port } : {}),
        ...(transport ? { transport } : {}),
        flows: 0,
        replies: 0,
        clientPorts: [],
        clientPortCount: 0,
        replyFlags: [],
        basis,
        blocked: false,
      };
      byKey.set(key, conversation);
    }
    mergeObservation(conversation, o, client.port);
  }
  return sortConversations([...byKey.values()]);
}

/** Map conversation edges (already client → server) keyed by pair + service. */
export function edgeConversations(
  edges: readonly GraphEdge[],
  index: GraphIndex,
): Conversation[] {
  const byKey = new Map<string, Conversation>();
  const endpoint = (id: string): ConversationEndpoint => {
    const node = index.node.get(id);
    return {
      id,
      label: node?.label ?? id,
      ...(node?.addresses?.[0] ? { ip: node.addresses[0] } : {}),
    };
  };
  for (const e of edges) {
    const transport = e.transport?.toLowerCase();
    const key = JSON.stringify([
      e.source,
      e.target,
      e.server_port ?? null,
      transport ?? null,
    ]);
    let conversation = byKey.get(key);
    if (!conversation) {
      conversation = {
        key,
        edgeId: e.id,
        source: endpoint(e.source),
        destination: endpoint(e.target),
        service: portLabel(e).toLowerCase(),
        ...(e.server_port !== undefined ? { port: e.server_port } : {}),
        ...(transport ? { transport } : {}),
        flows: 0,
        replies: 0,
        clientPorts: [],
        clientPortCount: 0,
        replyFlags: [],
        basis: "edge",
        blocked: false,
      };
      byKey.set(key, conversation);
    }
    conversation.flows += e.records ?? e.count ?? 0;
    if (e.bytes !== undefined)
      conversation.bytes = addNumber(conversation.bytes, e.bytes);
    if (e.acl_action === "drop") conversation.blocked = true;
    const observedBytes = e.bytes === undefined;
    for (const o of e.traffic_observations ?? []) {
      const { client } = orientObservation(o);
      const flows = conversation.flows;
      const bytes = conversation.bytes;
      mergeObservation(conversation, o, client.port);
      // Edge totals are authoritative; observations add detail only.
      conversation.flows = flows;
      if (!observedBytes) conversation.bytes = bytes;
    }
    for (const v of e.vlan_observations ?? []) {
      const seen = epochMs(v.last_seen);
      if (seen !== undefined)
        conversation.lastSeen = Math.max(conversation.lastSeen ?? 0, seen);
    }
  }
  return sortConversations([...byKey.values()]);
}

/** Busiest first: flows, then bytes, then a stable key. */
export function sortConversations(rows: Conversation[]): Conversation[] {
  return rows.sort(
    (a, b) =>
      b.flows - a.flows ||
      (b.bytes ?? -1) - (a.bytes ?? -1) ||
      a.key.localeCompare(b.key),
  );
}

function totals(conversations: readonly Conversation[]) {
  const peers = new Set<string>();
  let bytes: number | undefined;
  let blocked = 0;
  for (const c of conversations) {
    peers.add(c.source.id);
    peers.add(c.destination.id);
    bytes = addNumber(bytes, c.bytes);
    if (c.blocked) blocked += 1;
  }
  return {
    peers: peers.size,
    ...(bytes !== undefined ? { bytes } : {}),
    blocked,
  };
}

/** Which header a device sits under. */
export function deviceGroup(
  device: Device | undefined,
  role?: DeviceSummary["role"],
  name = device?.name ?? "",
): DeviceGroup {
  if (role === "firewall" || device?.kind === "firewall") return "Firewall";
  const aciRole = device?.role?.toLowerCase();
  if (aciRole === "spine" || /\bspine\b/i.test(name)) return "Spine";
  if (aciRole === "leaf" || /\bleaf\b/i.test(name)) return "Leaf";
  if (
    device?.kind === "network_device" ||
    /fabric interconnect|\bFI\b/i.test(`${device?.platform ?? ""} ${name}`)
  )
    return "FI";
  if (
    role === "host" &&
    (!device || device.sources.includes("kubernetes_node"))
  )
    return "K8s node/Cilium";
  if (
    device?.kind === "hypervisor" ||
    device?.kind === "virtual_switch" ||
    device?.kind === "host"
  )
    return "Host/VDS";
  if (role === "host") return "K8s node/Cilium";
  return "Other";
}

const SOURCE_LABEL: Record<string, string> = {
  hubble: "Cilium",
  isovalent: "Cilium",
  stream_ipfix: "IPFIX",
  ipfix: "IPFIX",
  netflow: "NetFlow",
};
export const sourceLabel = (source: string) =>
  SOURCE_LABEL[source.toLowerCase()] ?? source;

/** "TO_ENDPOINT" → "to endpoint". */
const pointLabel = (point: string) =>
  point.replace(/[_-]+/g, " ").trim().toLowerCase();

/**
 * Human name for a flow observer: "appd-k8-2/TO_ENDPOINT" from Hubble reads
 * "appd-k8-2 · Cilium (to endpoint)"; an exporter reads its inventory name.
 */
export function observerName(
  source: string,
  observer: string,
  exporter?: Device,
): string {
  const kind = sourceLabel(source);
  if (exporter) return `${exporter.name} · ${kind}`;
  const slash = observer.lastIndexOf("/");
  if (slash > 0 && /^[A-Z][A-Z_]+$/.test(observer.slice(slash + 1)))
    return `${observer.slice(0, slash)} · ${kind} (${pointLabel(observer.slice(slash + 1))})`;
  if (/^[A-Z][A-Z_]+$/.test(observer))
    return `${kind} (${pointLabel(observer)})`;
  return `${observer} · ${kind}`;
}

export interface ObserverGroupInput {
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

export function observerRow(
  group: ObserverGroupInput,
  topo: TopologyIndex,
  names: Map<string, string>,
): DeviceRowModel {
  const first = group.entries[0]?.observation;
  const exporter = first ? observationExporterDevice(first, topo) : undefined;
  const conversations = aggregateObservations(group.entries, names);
  const details = [
    `Source ${group.source}`,
    `Authority ${group.authority}`,
    `Observer ${group.observer}`,
    group.profile && `Profile ${group.profile}`,
    group.scope && `Scope ${group.scope}`,
    group.cluster && `Cluster ${group.cluster}`,
    group.observation_domain_id && `Domain ${group.observation_domain_id}`,
    group.observation_domain_present &&
      `Domain present ${group.observation_domain_present}`,
    group.version && `Version ${group.version}`,
    `Flow records ${group.records.toLocaleString()}`,
    exporter && `Exporter ${exporter.name} (${exporter.id})`,
  ]
    .filter(Boolean)
    .join(" · ");
  const sourceKind = sourceLabel(group.source);
  return {
    key: `observer:${group.key}`,
    name: observerName(group.source, group.observer, exporter),
    // The name already carries the source kind.
    subtitle: group.cluster ?? group.scope,
    details,
    group: exporter
      ? deviceGroup(exporter)
      : sourceKind === "Cilium"
        ? "K8s node/Cilium"
        : "Other",
    ...(exporter ? { deviceId: exporter.id } : {}),
    element: exporter?.id ?? group.observer,
    conversations,
    ...totals(conversations),
  };
}

export function summaryRow(
  d: DeviceSummary,
  index: GraphIndex,
): DeviceRowModel {
  const conversations = edgeConversations(d.edges, index);
  const device = d.device;
  const kind = device?.role
    ? `ACI ${device.role}`
    : d.role === "host"
      ? "Kubernetes node"
      : d.role === "fabric"
        ? "Nexus Dashboard"
        : device
          ? deviceKindLabel(device.kind, device.cluster, device.sources)
          : d.role === "firewall"
            ? "Firewall"
            : "Switch";
  const details = [
    device?.platform && `Platform ${device.platform}`,
    device?.mgmt_ip && `Mgmt ${device.mgmt_ip}`,
    device?.fabric && `Fabric ${fabricLabel(device.fabric)}`,
    device?.aci_node && `Node ${device.aci_node}`,
    d.sources.length ? `Reported by ${d.sources.join(", ")}` : undefined,
    d.interfaces.length ? `Interfaces ${d.interfaces.join(", ")}` : undefined,
  ]
    .filter(Boolean)
    .join(" · ");
  return {
    key: `device:${d.key}`,
    name: d.label,
    subtitle: [kind, device?.aci_node?.split("/").at(-1) ?? device?.mgmt_ip]
      .filter(Boolean)
      .join(" · "),
    details,
    group: deviceGroup(device, d.role, d.label),
    ...(device ? { deviceId: device.id } : {}),
    element: device?.id ?? d.key,
    conversations,
    ...totals(conversations),
  };
}

export function unseenRow(
  edges: readonly GraphEdge[],
  index: GraphIndex,
): DeviceRowModel {
  const conversations = edgeConversations(edges, index);
  return {
    key: "unseen-by-fabric",
    name: "Not seen by fabric",
    subtitle: "Isovalent only",
    details: "Conversations no fabric device reported",
    group: "Other",
    conversations,
    ...totals(conversations),
  };
}

/** Busiest first, then by name. */
export function sortDeviceRows(rows: DeviceRowModel[]): DeviceRowModel[] {
  return rows.sort(
    (a, b) =>
      b.conversations.length - a.conversations.length ||
      a.name.localeCompare(b.name, undefined, { numeric: true }) ||
      a.key.localeCompare(b.key),
  );
}

export const rowMatches = (row: DeviceRowModel, query: string) =>
  !query ||
  [row.name, row.subtitle, row.details, row.group]
    .join(" ")
    .toLowerCase()
    .includes(query);

export interface DeviceGroupModel {
  group: DeviceGroup;
  rows: DeviceRowModel[];
  /** Expanded unless the user collapses it. */
  defaultOpen: boolean;
}

/** Rows bucketed by kind, in fixed group order; empty groups are dropped. */
export function groupDeviceRows(
  rows: readonly DeviceRowModel[],
  query = "",
): DeviceGroupModel[] {
  const q = query.trim().toLowerCase();
  const sorted = sortDeviceRows(rows.filter((row) => rowMatches(row, q)));
  const top = new Set(
    sorted.slice(0, DEFAULT_EXPANDED_DEVICES).map((row) => row.group),
  );
  return DEVICE_GROUPS.map((group) => ({
    group,
    rows: sorted.filter((row) => row.group === group),
    defaultOpen: q !== "" || top.has(group),
  })).filter((g) => g.rows.length > 0);
}

/** Items [first, last) intersecting the viewport, for variable item heights. */
export function windowByHeights(
  heights: readonly number[],
  scrollTop: number,
  viewport: number,
  overscan = 400,
): { first: number; last: number; before: number; after: number } {
  let offset = 0;
  let first = heights.length;
  let last = heights.length;
  let before = 0;
  const top = scrollTop - overscan;
  const bottom = scrollTop + viewport + overscan;
  for (let i = 0; i < heights.length; i++) {
    const end = offset + heights[i];
    if (first === heights.length && end > top) {
      first = i;
      before = offset;
    }
    if (offset >= bottom) {
      last = i;
      break;
    }
    offset = end;
  }
  if (first === heights.length) before = offset;
  const total = heights.reduce((sum, h) => sum + h, 0);
  let renderedEnd = before;
  for (let i = first; i < last; i++) renderedEnd += heights[i];
  return {
    first,
    last: Math.max(first, last),
    before,
    after: total - renderedEnd,
  };
}

export function formatLastSeen(ms?: number): string {
  if (ms === undefined) return "—";
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ");
}

/** Drill-down text for a conversation row: client ports and reply flags. */
export function conversationDetail(c: Conversation): string {
  return [
    c.source.ip && `Client ${c.source.ip}`,
    c.destination.ip && `Server ${c.destination.ip}`,
    c.clientPortCount
      ? `Client ports ${c.clientPorts.join(", ")}${c.clientPortCount > c.clientPorts.length ? ` +${c.clientPortCount - c.clientPorts.length}` : ""}`
      : undefined,
    c.replyFlags.length ? `Reply ${c.replyFlags.join("/")}` : undefined,
    `Service basis ${c.basis.replace(/_/g, " ")}`,
  ]
    .filter(Boolean)
    .join(" · ");
}
