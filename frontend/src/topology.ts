import {
  validClientHandoffMetadata,
  type ClientHandoffRecord,
  type Graph,
  type GraphEdge,
  type GraphIndex,
  type GraphNode,
} from "./graph";
import type { AttachmentEvidence } from "./graph";
import {
  aclSummary,
  attributeValue,
  contractSummary,
  endpointKindLabel,
  handoffExplanation,
  handoffShort,
  receivedOn,
  sourceLabel,
} from "./glossary";
import { count, many, one, type Row } from "./rows";

export type DeviceKind =
  | "switch"
  | "firewall"
  | "controller"
  | "access_point"
  | "router"
  | "host"
  | "network_client"
  | "network_device";
export interface Device {
  id: string;
  name: string;
  kind: DeviceKind;
  mgmt_ip?: string;
  platform?: string;
  os_version?: string;
  serial?: string;
  fabric?: string;
  /** ACI `pod-N/node-N` key, matching graph attachment attributes. */
  aci_node?: string;
  /** ACI fabric role (`leaf`, `spine`, `controller`) when collected. */
  role?: string;
  device_authority?: string;
  native_device_id?: string;
  cluster?: string;
  aliases?: string[];
  scope?: string;
  routing_domain?: string;
  access_platform?: string;
  client_mac?: string;
  client_ip?: string;
  mapping_status?: string;
  evidence_kind?: string;
  source_time?: string;
  received_time?: string;
  latest_received_time?: string;
  collected_time?: string;
  attachment_status?: string;
  attachment_basis?: string;
  attachment_event_time?: string;
  attachment_received_time?: string;
  attachment_collected_time?: string;
  attachment_device_id?: string;
  attachment_device_name?: string;
  attachment_interface?: string;
  ssid_number?: string;
  overlay_peer_system_ip?: string;
  overlay_peer_color?: string;
  overlay_protocol?: string;
  sources: string[];
}
export interface Link {
  a_device: string;
  a_interface?: string;
  b_device: string;
  b_interface?: string;
  source: string;
  kind?:
    | "physical"
    | "wireless_association"
    | "overlay_context"
    | "traffic_observation";
  scope?: string;
  cluster?: string;
  mapping_status?: string;
}
export interface Interface {
  device_id: string;
  interface: string;
  ifindex?: number;
  description?: string;
  state?: string;
}
export interface Topology {
  devices: Device[];
  links: Link[];
  interfaces: Interface[];
  warnings: string[];
}
export const emptyTopology = (): Topology => ({
  devices: [],
  links: [],
  interfaces: [],
  warnings: [],
});

const DEVICE_KINDS: DeviceKind[] = [
  "switch",
  "firewall",
  "controller",
  "access_point",
  "router",
  "host",
  "network_client",
  "network_device",
];
const LINK_KINDS: Link["kind"][] = [
  "physical",
  "wireless_association",
  "overlay_context",
  "traffic_observation",
];
export const MAX_TOPOLOGY_ROWS = 20000;

/** Assembles `adm_topology` rows (device, link, interface, meta). Rows are untrusted. */
export function rowsToTopology(rows: unknown): Topology {
  if (!Array.isArray(rows)) throw new Error("Topology rows must be an array.");
  if (rows.length > MAX_TOPOLOGY_ROWS)
    throw new Error("Topology exceeds the pilot limit.");
  const topo = emptyTopology();
  const need = (row: Row, key: string) => {
    const v = one(row, key);
    if (v === undefined)
      throw new Error(`Invalid topology row: missing ${key}.`);
    return v;
  };
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error("Invalid topology row.");
    const row = raw as Row;
    const type = one(row, "row_type");
    if (type === "device") {
      const kind = one(row, "device_kind") ?? "switch";
      if (!DEVICE_KINDS.includes(kind as DeviceKind))
        throw new Error(`Invalid topology device kind ${kind}.`);
      const device: Device = {
        id: need(row, "device_id"),
        name: one(row, "name") ?? need(row, "device_id"),
        kind: kind as DeviceKind,
        sources: many(row, "sources") ?? [],
      };
      for (const k of [
        "mgmt_ip",
        "platform",
        "os_version",
        "serial",
        "fabric",
        "aci_node",
        "role",
      ] as const) {
        const v = one(row, k);
        if (v !== undefined) device[k] = v;
      }
      for (const k of [
        "device_authority",
        "native_device_id",
        "cluster",
        "scope",
        "routing_domain",
        "access_platform",
        "client_mac",
        "client_ip",
        "mapping_status",
        "evidence_kind",
        "source_time",
        "received_time",
        "latest_received_time",
        "collected_time",
        "attachment_status",
        "attachment_basis",
        "attachment_event_time",
        "attachment_received_time",
        "attachment_collected_time",
        "attachment_device_id",
        "attachment_device_name",
        "attachment_interface",
        "ssid_number",
        "overlay_peer_system_ip",
        "overlay_peer_color",
        "overlay_protocol",
      ] as const) {
        const v = one(row, k);
        if (v !== undefined) device[k] = v;
      }
      device.aliases = many(row, "aliases") ?? [];
      topo.devices.push(device);
    } else if (type === "link") {
      const source = one(row, "link_source") ?? "cdp";
      const rawKind = one(row, "link_kind");
      const kind =
        rawKind ??
        (source === "lldp" || source === "cdp" || source === "aci"
          ? "physical"
          : undefined);
      if (!kind || !LINK_KINDS.includes(kind as Link["kind"]))
        throw new Error(`Invalid topology link kind ${String(kind)}.`);
      topo.links.push({
        a_device: need(row, "a_device"),
        a_interface: one(row, "a_interface"),
        b_device: need(row, "b_device"),
        b_interface: one(row, "b_interface"),
        source,
        kind: kind as Link["kind"],
        scope: one(row, "scope"),
        cluster: one(row, "cluster"),
        mapping_status: one(row, "mapping_status"),
      });
    } else if (type === "interface") {
      const iface: Interface = {
        device_id: need(row, "device_id"),
        interface: need(row, "interface"),
      };
      const ifindex = count(row, "ifindex");
      if (ifindex !== undefined) iface.ifindex = ifindex;
      for (const k of ["description", "state"] as const) {
        const v = one(row, k);
        if (v !== undefined) iface[k] = v;
      }
      topo.interfaces.push(iface);
    } else if (type === "meta") {
      topo.warnings.push(...(many(row, "warnings") ?? []));
    } else throw new Error(`Invalid topology row type ${String(type)}.`);
  }
  return topo;
}

const ETHERNET = /^(?:ethernet|eth|e)\s*(\d+(?:\/\d+)+)$/i;
/** Comparison key: ethX/Y, EthX/Y and EthernetX/Y become one form. */
export function interfaceKey(name: string): string {
  const t = name.trim();
  const m = ETHERNET.exec(t);
  return m ? `ethernet${m[1]}` : t.toLowerCase();
}
/** Compact display form, e.g. "Eth1/49". */
export function interfaceLabel(name: string): string {
  const t = name.trim();
  const m = ETHERNET.exec(t);
  return m ? `Eth${m[1]}` : t;
}

export interface TopologyIndex {
  /** Exact canonical identity index. */
  byId: Map<string, Device>;
  /** Candidate indexes; aliases are never globally authoritative for V2. */
  aliasCandidates: Map<string, Device[]>;
  ipCandidates: Map<string, Device[]>;
  ambiguousCanonicalIds: Set<string>;
  containsV2Devices: boolean;
  byKey: Map<string, Device>;
  byIp: Map<string, Device>;
  ambiguousKeys: Set<string>;
  ifName: Map<string, string>;
  /** Switch-to-switch adjacency (CDP, ACI fabric links); hosts excluded. */
  adjacency: Map<string, { to: string; out?: string; in?: string }[]>;
  /** Host attachment from LLDP: qualified canonical host ID → leaf and port. */
  lldpHost: Map<string, { device: string; port?: string }>;
  ambiguousIfName: Set<string>;
}
const key = (s: string) => s.trim().toLowerCase();
const SOURCE_ID =
  /^(?:aci|nxos|meraki|host|network_client|catalyst|sdwan_router):[a-f0-9]{64}$/;
const isV2Device = (d: Device) =>
  d.mapping_status !== undefined || SOURCE_ID.test(d.id);

export interface DeviceResolutionContext {
  conflict?: boolean;
  scope?: string;
  cluster?: string;
  authority?: string;
  families?: string[];
}

/** Summarize aggregate frontend coverage; client-specific evidence is validated separately. */
export function handoffCoverageMessage(
  service: GraphNode | undefined,
): string | undefined {
  const attrs = service?.attributes;
  const coverage = attrs?.handoff_coverage;
  if (coverage === undefined || coverage === "complete") return undefined;
  const connections = attrs?.handoff_connections ?? "unknown";
  const determined = attrs?.handoff_determined ?? "unknown";
  const unresolved = attrs?.handoff_unresolved ?? "unknown";
  return `Aggregate frontend handoff coverage is ${coverage} (${determined} of ${connections} connections determined; ${unresolved} unresolved). Each client path requires its own complete handoff evidence.`;
}

export interface ClientHandoffResolution {
  version2: boolean;
  complete: boolean;
  records: ClientHandoffRecord[];
  message?: string;
}

/** Read only the handoff attached to this exact client → Service edge. */
export function clientHandoffResolution(
  edge: GraphEdge,
  service: GraphNode | undefined,
  index?: GraphIndex,
): ClientHandoffResolution {
  const fields = [
    edge.client_handoff_coverage,
    edge.client_handoff_connections,
    edge.client_handoff_determined,
    edge.client_handoff_unresolved,
    edge.client_handoffs,
  ];
  const version2 =
    service?.attributes?.handoff_coverage !== undefined ||
    fields.some((value) => value !== undefined);
  if (!version2) return { version2: false, complete: false, records: [] };
  const valid = validClientHandoffMetadata(
    edge,
    index
      ? (id) =>
          index.node.get(id)?.kind === "workload" &&
          id.startsWith(`pod:${service?.cluster ?? ""}/`)
      : undefined,
  );
  if (
    !valid ||
    edge.relationship !== "communicates_with" ||
    edge.target !== service?.id ||
    service?.endpoint_kind !== "k8s_service"
  ) {
    return {
      version2: true,
      complete: false,
      records: [],
      message: "Client-specific handoff evidence is unavailable or invalid.",
    };
  }
  if (edge.client_handoff_coverage !== "complete") {
    const coverage = edge.client_handoff_coverage;
    return {
      version2: true,
      complete: false,
      records: [],
      message: `Client handoff coverage is ${coverage} (${edge.client_handoff_determined} of ${edge.client_handoff_connections} connections determined; ${edge.client_handoff_unresolved} unresolved). Backend and receiving-node assignments are unavailable.`,
    };
  }
  return {
    version2: true,
    complete: true,
    records: edge.client_handoffs,
  };
}

export function clientHandoffReceivingNodes(
  records: ClientHandoffRecord[],
): string[] {
  return [...new Set(records.flatMap((record) => record.receiving_nodes))];
}

export function clientHandoffBasisSummary(
  records: ClientHandoffRecord[],
): string {
  const counts = new Map<string, number>();
  for (const record of records)
    counts.set(
      record.basis,
      (counts.get(record.basis) ?? 0) + record.connections,
    );
  return [...counts]
    .map(
      ([basis, connections]) =>
        `${handoffShort[basis as keyof typeof handoffShort]} (${connections})`,
    )
    .join("; ");
}

export function backendChoiceSummary(choice: BackendChoice): string {
  if (!choice.clientHandoffs)
    return `${choice.label}${choice.state === "inferred" ? " (inferred)" : ""}`;
  const connections = choice.clientHandoffs.reduce(
    (sum, item) => sum + item.connections,
    0,
  );
  return `${choice.label} (${connections} connections; ${clientHandoffBasisSummary(choice.clientHandoffs)})`;
}

/** Resolve an exact V2 identity or a uniquely qualified alias/IP. */
export function resolveDevice(
  raw: string | undefined,
  topo: TopologyIndex,
  context: DeviceResolutionContext = {},
): Device | undefined {
  if (context.conflict) return undefined;
  if (!raw?.trim()) return undefined;
  const exactId = raw.trim();
  const normalized = key(raw);
  const exact = topo.byId.get(exactId);
  if (topo.ambiguousCanonicalIds.has(exactId)) return undefined;
  const hasV2Devices = topo.containsV2Devices;
  const contextMatches = (d: Device) => {
    if (!isV2Device(d)) return context.scope === undefined || !hasV2Devices;
    if (context.scope !== undefined && d.scope !== context.scope) return false;
    if (context.cluster !== undefined && d.cluster !== context.cluster)
      return false;
    if (
      context.authority !== undefined &&
      d.device_authority !== context.authority
    )
      return false;
    if (context.families?.length) {
      const families = new Set(context.families);
      const prefix = d.id.split(":", 1)[0];
      if (
        !families.has(prefix) &&
        !d.sources.some((source) => families.has(source))
      )
        return false;
    }
    return true;
  };
  if (exact)
    return (!hasV2Devices || isV2Device(exact)) && contextMatches(exact)
      ? exact
      : undefined;

  const candidates = [
    ...(topo.aliasCandidates.get(normalized) ?? []),
    ...(topo.ipCandidates.get(normalized) ?? []),
  ];
  const unique = [...new Map(candidates.map((d) => [d.id, d])).values()].filter(
    (d) => !topo.ambiguousCanonicalIds.has(d.id),
  );
  if (context.scope !== undefined) {
    const scoped = unique.filter(
      (d) =>
        isV2Device(d) && d.mapping_status === "mapped" && contextMatches(d),
    );
    if (scoped.length)
      return new Set(scoped.map((d) => d.id)).size === 1
        ? scoped[0]
        : undefined;
    if (hasV2Devices) return undefined;
  }
  // Unqualified aliases are retained only for the original V1 topology rows.
  if (hasV2Devices) return undefined;
  const legacy = unique.filter((d) => !isV2Device(d));
  return legacy.length === 1 ? legacy[0] : undefined;
}

export function indexTopology(topo: Topology): TopologyIndex {
  const byKey = new Map<string, Device>(),
    byIp = new Map<string, Device>(),
    byId = new Map<string, Device>(),
    aliasCandidates = new Map<string, Device[]>(),
    ipCandidates = new Map<string, Device[]>(),
    ifName = new Map<string, string>(),
    adjacency = new Map<string, { to: string; out?: string; in?: string }[]>(),
    lldpHost = new Map<string, { device: string; port?: string }>();
  const ambiguousHosts = new Set<string>();
  const ambiguousIds = new Set<string>();
  const ambiguousKeys = new Set<string>();
  const ambiguousIps = new Set<string>();
  const ambiguousIfName = new Set<string>();
  const addCandidate = (
    map: Map<string, Device[]>,
    alias: string,
    d: Device,
  ) => {
    const normalized = key(alias);
    if (!normalized) return;
    const list = map.get(normalized) ?? [];
    if (!list.some((candidate) => candidate.id === d.id)) list.push(d);
    map.set(normalized, list);
  };
  const addAlias = (
    map: Map<string, Device>,
    ambiguous: Set<string>,
    alias: string,
    d: Device,
  ) => {
    const normalized = key(alias);
    if (!normalized || ambiguous.has(normalized)) return;
    const previous = map.get(normalized);
    if (previous && previous.id !== d.id) {
      map.delete(normalized);
      ambiguous.add(normalized);
    } else map.set(normalized, d);
  };
  for (const d of topo.devices) {
    const id = d.id;
    if (ambiguousIds.has(id)) {
      // Keep a duplicate canonical ID unavailable regardless of input order.
    } else if (!byId.has(id)) byId.set(id, d);
    else {
      byId.delete(id);
      ambiguousIds.add(id);
    }
    addCandidate(aliasCandidates, d.id, d);
    addCandidate(aliasCandidates, d.name, d);
    if (d.native_device_id)
      addCandidate(aliasCandidates, d.native_device_id, d);
    if (d.aci_node) addCandidate(aliasCandidates, d.aci_node, d);
    for (const alias of d.aliases ?? [])
      addCandidate(aliasCandidates, alias, d);
    addAlias(byKey, ambiguousKeys, d.id, d);
    if (!isV2Device(d)) {
      addAlias(byKey, ambiguousKeys, d.name, d);
      if (d.aci_node) addAlias(byKey, ambiguousKeys, d.aci_node, d);
      for (const alias of d.aliases ?? [])
        addAlias(byKey, ambiguousKeys, alias, d);
    }
    if (d.mgmt_ip) {
      addCandidate(ipCandidates, d.mgmt_ip, d);
      if (!isV2Device(d)) addAlias(byIp, ambiguousIps, d.mgmt_ip, d);
    }
  }
  for (const i of topo.interfaces)
    if (i.ifindex !== undefined) {
      const canonical = byId.get(i.device_id)?.id ?? i.device_id;
      const nameKey = `${key(canonical)}|${i.ifindex}`;
      const previous = ifName.get(nameKey);
      if (previous && interfaceKey(previous) !== interfaceKey(i.interface)) {
        ifName.delete(nameKey);
        ambiguousIfName.add(nameKey);
      } else if (!ambiguousIfName.has(nameKey))
        ifName.set(nameKey, i.interface);
    }
  const add = (a: string, b: string, out?: string, inn?: string) => {
    const list = adjacency.get(a) ?? [];
    const existing = list.find((x) => x.to === b);
    if (!existing) list.push({ to: b, out, in: inn });
    else {
      if (existing.out !== out) existing.out = undefined;
      if (existing.in !== inn) existing.in = undefined;
    }
    adjacency.set(a, list);
  };
  const partialIndex = {
    byId,
    aliasCandidates,
    ipCandidates,
    ambiguousCanonicalIds: ambiguousIds,
    containsV2Devices: topo.devices.some(isV2Device),
    byKey,
    byIp,
    ambiguousKeys,
    ifName,
    adjacency,
    lldpHost,
    ambiguousIfName,
  } as TopologyIndex;
  for (const l of topo.links) {
    const kind =
      l.kind ??
      (["lldp", "cdp", "aci"].includes(l.source) ? "physical" : undefined);
    if (
      kind === "wireless_association" ||
      kind === "overlay_context" ||
      kind === "traffic_observation"
    )
      continue;
    const linkContext = { scope: l.scope, cluster: l.cluster };
    const endpointA = resolveDevice(l.a_device, partialIndex, linkContext);
    const endpointB = resolveDevice(l.b_device, partialIndex, linkContext);
    // Client-to-switch attachment is point evidence, not switch adjacency.
    if (
      endpointA?.kind === "network_client" ||
      endpointB?.kind === "network_client"
    )
      continue;
    if (l.source === "lldp" && kind === "physical") {
      // LLDP from a leaf names the attached server by its system name.
      const resolvedLeaf = endpointA;
      const resolvedHost = endpointB;
      if (!resolvedLeaf) continue;
      if (!resolvedHost && isV2Device(resolvedLeaf)) continue;
      if (
        (isV2Device(resolvedLeaf) ||
          (resolvedHost && isV2Device(resolvedHost))) &&
        (l.mapping_status !== "mapped" ||
          !l.scope ||
          !l.cluster ||
          resolvedLeaf.scope !== l.scope ||
          resolvedHost?.scope !== l.scope ||
          resolvedLeaf.cluster !== l.cluster ||
          resolvedHost?.cluster !== l.cluster)
      )
        continue;
      const leaf = resolvedLeaf.id;
      const host = resolvedHost ? key(resolvedHost.id) : key(l.b_device);
      const previous = lldpHost.get(host);
      if (
        previous &&
        (previous.device !== leaf || previous.port !== l.a_interface)
      ) {
        ambiguousHosts.add(host);
        lldpHost.delete(host);
      }
      if (!ambiguousHosts.has(host))
        lldpHost.set(host, { device: leaf, port: l.a_interface });
      continue;
    }
    if (kind !== "physical") continue;
    const resolvedA = endpointA;
    const resolvedB = endpointB;
    if (!resolvedA || !resolvedB) continue;
    const a = resolvedA.id;
    const b = resolvedB.id;
    if (isV2Device(resolvedA) || isV2Device(resolvedB)) {
      if (
        l.mapping_status !== "mapped" ||
        !l.scope ||
        !l.cluster ||
        resolvedA.scope !== l.scope ||
        resolvedB.scope !== l.scope ||
        resolvedA.cluster !== l.cluster ||
        resolvedB.cluster !== l.cluster
      )
        continue;
    }
    if (key(a) === key(b)) continue;
    add(key(a), key(b), l.a_interface, l.b_interface);
    add(key(b), key(a), l.b_interface, l.a_interface);
  }
  for (const list of adjacency.values())
    list.sort((x, y) => x.to.localeCompare(y.to));
  return {
    byId,
    aliasCandidates,
    ipCandidates,
    ambiguousCanonicalIds: ambiguousIds,
    containsV2Devices: topo.devices.some(isV2Device),
    byKey,
    byIp,
    ambiguousKeys,
    ifName,
    adjacency,
    lldpHost,
    ambiguousIfName,
  };
}

/** One place where a conversation was seen, resolved to a device when possible. */
export interface ObservationPoint {
  source: string;
  /** Lower-case device or host key used to match path stages. */
  key: string;
  label: string;
  /** True only when the observer resolved to an inventory identity. */
  resolved: boolean;
  role: "switch" | "firewall" | "host" | "fabric";
  in?: string;
  out?: string;
}

function resolveIf(
  topo: TopologyIndex,
  device: string,
  raw?: string,
): string | undefined {
  if (!raw || raw === "?") return undefined;
  const m = /^ifIndex\s+(\d+)$/i.exec(raw.trim());
  if (m) {
    const nameKey = `${key(device)}|${m[1]}`;
    if (topo.ambiguousIfName.has(nameKey)) return `ifIndex ${m[1]}`;
    const name = topo.ifName.get(nameKey);
    return name ? interfaceLabel(name) : `ifIndex ${m[1]}`;
  }
  return interfaceLabel(raw);
}

/**
 * Parses `<source>:<observer>[:<in>><out>]` from the graph search into
 * observation points. Nexus Dashboard reports ingress and egress leaves
 * (`<fabric>:<leaf>:<if>><leaf>:<if>`), so it yields up to two points.
 */
export function parseObserver(
  observer: string,
  topo: TopologyIndex,
  context: DeviceResolutionContext = {},
): ObservationPoint[] {
  if (context.conflict) return [];
  const at = observer.indexOf(":");
  if (at < 0) return [];
  const source = observer.slice(0, at);
  const rest = observer.slice(at + 1);
  if (source === "isovalent" || source === "hubble") {
    const device = resolveDevice(rest, topo, {
      ...context,
      families: ["kubernetes_node"],
    });
    return [
      {
        source,
        key: key(device?.id ?? rest),
        label: device?.name ?? rest,
        resolved: !!device,
        role: "host",
      },
    ];
  }
  const sourceContext = {
    ...context,
    ...(source === "nd"
      ? { families: ["nxos", "nxos_cdp", "aci_topSystem"] }
      : {}),
  };
  if (source === "aci_acllog") {
    const device = resolveDevice(rest, topo, {
      ...sourceContext,
      families: ["aci_topSystem"],
    });
    return [
      {
        source,
        key: key(device?.id ?? rest),
        label: device?.name ?? rest,
        resolved: !!device,
        role: "switch",
      },
    ];
  }
  if (source === "nd") {
    const first = rest.indexOf(":");
    const fabric = first < 0 ? rest : rest.slice(0, first);
    const sides = first < 0 ? [] : rest.slice(first + 1).split(">");
    const points: ObservationPoint[] = [];
    sides.forEach((side, i) => {
      if (!side || side === "?") return;
      const [leaf, iface] = side.split(":");
      const device = resolveDevice(leaf, topo, sourceContext);
      points.push({
        source,
        key: key(device?.id ?? leaf),
        label: device?.name ?? leaf,
        resolved: !!device,
        role: "switch",
        ...(i === 0
          ? { in: iface ? interfaceLabel(iface) : undefined }
          : { out: iface ? interfaceLabel(iface) : undefined }),
      });
    });
    return points.length
      ? points
      : [
          {
            source,
            key: key(fabric),
            label: fabric,
            resolved: false,
            role: "fabric",
          },
        ];
  }
  const m = /^(.*):([^:>]*)>([^:>]*)$/.exec(rest);
  const ip = m ? m[1] : rest;
  const device = resolveDevice(ip, topo, sourceContext);
  const name = device?.id ?? ip;
  return [
    {
      source,
      key: key(name),
      label:
        device?.name ??
        (source === "ftd" ? `Firewall ${ip}` : `Exporter ${ip}`),
      resolved: !!device,
      role: source === "ftd" ? "firewall" : "switch",
      in: m ? resolveIf(topo, name, m[2]) : undefined,
      out: m ? resolveIf(topo, name, m[3]) : undefined,
    },
  ];
}

/** Observer strings of an edge, plus its ACL-log enforcing leaf. */
export function edgeObservers(edge: GraphEdge): string[] {
  const list = [...(edge.observers ?? [])];
  const acl = edge.acl_leaf && `aci_acllog:${edge.acl_leaf}`;
  if (acl && !list.includes(acl)) list.push(acl);
  return list;
}

export interface DeviceObservation {
  key: string;
  label: string;
  role: ObservationPoint["role"];
  resolved: boolean;
  sources: string[];
  interfaces: string[];
}
function parseEdgeObserver(
  observer: string,
  edge: GraphEdge,
  topo: TopologyIndex,
  context: DeviceResolutionContext,
): ObservationPoint[] {
  if (context.conflict) return [];
  const at = observer.indexOf(":");
  const rest = at < 0 ? "" : observer.slice(at + 1);
  const ip = rest.split(":", 1)[0];
  const observations =
    edge.traffic_observations?.filter(
      (item) => !!item.exporter_ip && item.exporter_ip === ip,
    ) ?? [];
  const compatibleObservations = observations.filter(
    (item) =>
      (context.scope === undefined ||
        item.scope === undefined ||
        item.scope === context.scope) &&
      (context.cluster === undefined ||
        item.cluster === undefined ||
        item.cluster === context.cluster) &&
      (context.authority === undefined ||
        item.source_authority === undefined ||
        item.source_authority === context.authority),
  );
  if (observations.length && !compatibleObservations.length) return [];
  const contextKeys = new Set(
    compatibleObservations.map((item) =>
      JSON.stringify([
        item.scope ?? null,
        item.cluster ?? null,
        item.source_authority ?? null,
      ]),
    ),
  );
  if (contextKeys.size > 1) return [];
  const observation =
    contextKeys.size === 1 ? compatibleObservations[0] : undefined;
  const scopeConflict =
    !!observation &&
    !!context.scope &&
    !!observation.scope &&
    context.scope !== observation.scope;
  const clusterConflict =
    !!observation &&
    !!context.cluster &&
    !!observation.cluster &&
    context.cluster !== observation.cluster;
  const authorityConflict =
    !!observation &&
    !!context.authority &&
    !!observation.source_authority &&
    context.authority !== observation.source_authority;
  if (scopeConflict || clusterConflict || authorityConflict) return [];
  const scopedContext = observation
    ? {
        scope: observation.scope,
        cluster: observation.cluster,
        authority: observation.source_authority,
        ...context,
      }
    : context;
  return parseObserver(observer, topo, scopedContext);
}
/** Observation points grouped by device, for "Seen by" lists. */
export function observationsByDevice(
  edge: GraphEdge,
  topo: TopologyIndex,
  extra: string[] = [],
  context: DeviceResolutionContext = {},
): DeviceObservation[] {
  const groups = new Map<string, DeviceObservation>();
  for (const o of new Set([...edgeObservers(edge), ...extra])) {
    for (const p of parseEdgeObserver(o, edge, topo, context)) {
      const g = groups.get(p.key) ?? {
        key: p.key,
        label: p.label,
        role: p.role,
        resolved: p.resolved,
        sources: [],
        interfaces: [],
      };
      const src = sourceLabel(p.source);
      g.resolved ||= p.resolved;
      if (!g.sources.includes(src)) g.sources.push(src);
      for (const i of [p.in, p.out])
        if (i && !g.interfaces.includes(i)) g.interfaces.push(i);
      groups.set(p.key, g);
    }
  }
  return [...groups.values()];
}

export type StageKind =
  "entity" | "host" | "switch" | "firewall" | "handoff" | "gap";
export interface Stage {
  kind: StageKind;
  title: string;
  subtitle?: string;
  /** Equal-cost devices this stage may be any one of (ECMP). */
  alternatives?: string[];
  /** Service handoff: how the backend was determined. */
  handoff?: {
    state: "observed" | "inferred" | "undetermined";
    text: string;
  };
  /** Interfaces in path order (toward the server). */
  ports?: { in?: string; out?: string };
  observed?: boolean;
  observedBy: string[];
  seenInterfaces: string[];
  nodeId?: string;
}
export interface CandidatePath {
  stages: Stage[];
  unplaced: DeviceObservation[];
  sameHost: boolean;
  /** Explanations of the path, e.g. DSR return traffic. */
  notes: string[];
  /** Backends of a Service frontend, for choosing which leg to show. */
  backends: { id: string; label: string; state: "observed" | "inferred" }[];
  backend?: string;
  /** Contract intent and ACL-log observation, in display order. */
  policy: {
    text: string;
    tone: "intent" | "observed" | "blocked" | "neutral";
  }[];
}

interface Attachment {
  stages: Stage[];
  device?: string;
  port?: string;
  host?: string;
}
const stage = (s: Omit<Stage, "observedBy" | "seenInterfaces">): Stage => ({
  ...s,
  observedBy: [],
  seenInterfaces: [],
});

/** Leaf and port of a Kubernetes node: its ACI/ND endpoint, else LLDP. */
function hostAttachment(
  hostName: string,
  hostNode: GraphNode | undefined,
  topo: TopologyIndex,
): { device?: string; port?: string } {
  const attrs = hostNode?.attributes ?? {};
  const context: DeviceResolutionContext = {
    scope: attrs.scope,
    cluster: hostNode?.cluster,
    families: ["aci_topSystem", "nxos", "kubernetes_node"],
  };
  if (attrs.attach_device) {
    const device = resolveDevice(attrs.attach_device, topo, context);
    if (device) return { device: device.id, port: attrs.attach_interface };
    if (!topo.containsV2Devices)
      return { device: attrs.attach_device, port: attrs.attach_interface };
    return {};
  }
  const host = resolveDevice(hostName, topo, {
    ...context,
    families: ["kubernetes_node"],
  });
  if (host) return topo.lldpHost.get(key(host.id)) ?? {};
  // V1 graph fixtures predate qualified topology host inventory.
  if (!topo.containsV2Devices) return topo.lldpHost.get(key(hostName)) ?? {};
  return {};
}

function findHost(
  graph: Graph,
  index: GraphIndex,
  cluster: string | undefined,
  hostName: string,
): GraphNode | undefined {
  if (cluster === "unknown") return undefined;
  if (cluster) return index.node.get(`node:${cluster}/${hostName}`);
  const matches = graph.nodes.filter(
    (n) => n.endpoint_kind === "k8s_node" && n.label === hostName,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

const hostIdentity = (cluster: string | undefined, name: string) =>
  cluster && cluster !== "unknown" ? `node:${cluster}/${name}` : undefined;

const podCluster = (node: GraphNode) =>
  node.id.startsWith("pod:") ? node.id.slice(4).split("/")[0] : node.cluster;

export function nodeDeviceContext(
  node: GraphNode | undefined,
): DeviceResolutionContext {
  if (!node) return {};
  return {
    scope: node.attributes?.scope,
    cluster: node.cluster,
  };
}

/** Context is available only from agreeing endpoints or explicit edge fields. */
export function edgeDeviceContext(
  edge: GraphEdge,
  index: GraphIndex,
): DeviceResolutionContext {
  const explicit = edge as GraphEdge & {
    scope?: string;
    cluster?: string;
    source_authority?: string;
  };
  const source = index.node.get(edge.source);
  const target = index.node.get(edge.target);
  const valuesAgree = (values: Array<string | undefined>) => {
    const present = values.filter(
      (value): value is string => value !== undefined && value !== "",
    );
    return {
      value: new Set(present).size <= 1 ? present[0] : undefined,
      count: present.length,
      conflict: new Set(present).size > 1,
    };
  };
  const endpointScopes = [source?.attributes?.scope, target?.attributes?.scope];
  const scopeAgreement = valuesAgree([...endpointScopes, explicit.scope]);
  if (scopeAgreement.conflict) return { conflict: true };
  if (!scopeAgreement.value) return {};
  const scope = scopeAgreement.value;

  const endpointClusters = [source?.cluster, target?.cluster];
  const clusterAgreement = valuesAgree([...endpointClusters, explicit.cluster]);
  if (clusterAgreement.conflict) return { conflict: true };
  const cluster =
    explicit.cluster ||
    (endpointClusters.every((value) => value !== undefined && value !== "")
      ? clusterAgreement.value
      : undefined);
  const endpointAuthorities = [
    source?.attributes?.source_authority,
    target?.attributes?.source_authority,
  ];
  const authorityAgreement = valuesAgree([
    ...endpointAuthorities,
    explicit.source_authority,
  ]);
  if (authorityAgreement.conflict) return { conflict: true };
  const authority =
    explicit.source_authority ||
    (endpointAuthorities.every((value) => value !== undefined && value !== "")
      ? authorityAgreement.value
      : undefined);
  return {
    scope,
    ...(cluster ? { cluster } : {}),
    ...(authority ? { authority } : {}),
  };
}

/** Entity → host → access switch, from the graph's identity attributes. */
function attachment(
  node: GraphNode | undefined,
  graph: Graph,
  index: GraphIndex,
  topo: TopologyIndex,
): Attachment {
  if (!node) return { stages: [] };
  const attrs = node.attributes ?? {};
  const entity = stage({
    kind: node.endpoint_kind === "k8s_node" ? "host" : "entity",
    title: node.label,
    subtitle:
      node.kind === "workload"
        ? `Pod${node.namespace ? ` · ${node.namespace}` : ""}`
        : node.kind === "service"
          ? "Service"
          : node.endpoint_kind === "vm" && attrs.epg
            ? `VM · EPG ${attrs.epg}`
            : node.endpoint_kind
              ? endpointKindLabel[node.endpoint_kind]
              : "Endpoint",
    nodeId: node.id,
  });
  if (node.kind === "workload") {
    const hostName = attrs.node;
    if (!hostName) return { stages: [entity] };
    const hostNode = findHost(graph, index, podCluster(node), hostName);
    const host = stage({
      kind: "host",
      title: hostName,
      subtitle: "Kubernetes node",
      nodeId: hostNode?.id,
    });
    const at = hostAttachment(hostName, hostNode, topo);
    return {
      stages: [entity, host],
      host: hostNode?.id ?? hostIdentity(podCluster(node), hostName),
      device: at.device,
      port: at.port,
    };
  }
  if (node.endpoint_kind === "k8s_node_proxy" && attrs.node) {
    // Cilium Envoy runs on its node; it attaches to the fabric through it.
    const hostNode = findHost(graph, index, node.cluster, attrs.node);
    const at = hostAttachment(attrs.node, hostNode, topo);
    return {
      stages: [
        { ...entity, subtitle: `Cilium Envoy · ${node.addresses?.[0] ?? ""}` },
        stage({
          kind: "host",
          title: attrs.node,
          subtitle: "Kubernetes node",
          nodeId: hostNode?.id,
        }),
      ],
      host: hostNode?.id ?? hostIdentity(node.cluster, attrs.node),
      device: at.device,
      port: at.port,
    };
  }
  if (node.endpoint_kind === "k8s_node") {
    const at = hostAttachment(node.label, node, topo);
    return {
      stages: [entity],
      host: node.id,
      device: at.device,
      port: at.port,
    };
  }
  const context = nodeDeviceContext(node);
  const attached = attrs.attach_device
    ? resolveDevice(attrs.attach_device, topo, context)
    : undefined;
  if (attached)
    return {
      stages: [entity],
      device: attached.id,
      port: attrs.attach_interface,
    };
  if (attrs.attach_device && !topo.containsV2Devices)
    return {
      stages: [entity],
      device: attrs.attach_device,
      port: attrs.attach_interface,
    };
  return {
    stages: [entity],
  };
}

interface Layer {
  ids: string[];
  in?: string;
  out?: string;
}
function distances(topo: TopologyIndex, from: string): Map<string, number> {
  const dist = new Map([[from, 0]]);
  const queue = [from];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const next of topo.adjacency.get(cur) ?? [])
      if (!dist.has(next.to)) {
        dist.set(next.to, dist.get(cur)! + 1);
        queue.push(next.to);
      }
  }
  return dist;
}
/**
 * Every shortest path between two switches, layer by layer. A layer with
 * several devices is an equal-cost choice (e.g. leaf → one of N spines → leaf).
 */
export function fabricLayers(
  topo: TopologyIndex,
  from: string,
  to: string,
  context: DeviceResolutionContext = {},
): Layer[] | undefined {
  const a = resolveDevice(from, topo, context);
  const b = resolveDevice(to, topo, context);
  if (!a || !b) return undefined;
  const start = key(a.id),
    goal = key(b.id);
  if (start === goal) return [{ ids: [start] }];
  const ds = distances(topo, start);
  const total = ds.get(goal);
  if (total === undefined) return undefined;
  const dg = distances(topo, goal);
  const layers: Layer[] = [];
  for (let d = 0; d <= total; d++)
    layers.push({
      ids: [...ds]
        .filter(([id, n]) => n === d && dg.get(id) === total - d)
        .map(([id]) => id)
        .sort(),
    });
  // Ports are only certain between two single-device layers.
  for (let i = 0; i + 1 < layers.length; i++) {
    const a = layers[i],
      b = layers[i + 1];
    if (a.ids.length !== 1 || b.ids.length !== 1) continue;
    const link = topo.adjacency.get(a.ids[0])?.find((x) => x.to === b.ids[0]);
    a.out = link?.out;
    b.in = link?.in;
  }
  return layers;
}

const gap = (title: string): Stage => stage({ kind: "gap", title });
/** "apic:192.0.2.50" → "ACI (APIC 192.0.2.50)"; NX-OS fabric names pass through. */
export const fabricLabel = (fabric?: string) =>
  fabric?.startsWith("apic:") ? `ACI (APIC ${fabric.slice(5)})` : fabric;

export function deviceKindLabel(kind: DeviceKind, cluster?: string): string {
  if (kind === "host")
    return `Kubernetes host${cluster ? ` · ${cluster}` : ""}`;
  if (kind === "access_point") return "Access point";
  if (kind === "router") return "Router";
  if (kind === "network_client") return "Network client";
  if (kind === "network_device") return "Network device";
  if (kind === "firewall") return "Firewall";
  if (kind === "controller") return "Controller";
  return "Switch";
}

function deviceStage(
  topo: TopologyIndex,
  id: string,
  raw?: Stage["ports"],
): Stage {
  const d = resolveDevice(id, topo);
  const ports = raw && {
    in: raw.in && interfaceLabel(raw.in),
    out: raw.out && interfaceLabel(raw.out),
  };
  return stage({
    kind:
      d?.kind === "firewall"
        ? "firewall"
        : d?.kind === "host"
          ? "host"
          : d?.kind === "switch" || d?.kind === "controller"
            ? "switch"
            : "entity",
    title: d?.name ?? id,
    ...(d ? { nodeId: d.id } : {}),
    subtitle:
      d?.kind === "access_point"
        ? "Access point · inventory identity"
        : d?.kind === "router"
          ? "Router · inventory identity"
          : d?.kind === "network_client"
            ? `Network client · ${d.attachment_status ?? d.mapping_status ?? "observed evidence"}`
            : d?.kind === "host"
              ? `${deviceKindLabel(d.kind, d.cluster)} · inventory identity`
              : d
                ? d.aci_node
                  ? `ACI ${d.role ?? "switch"} · ${d.aci_node.split("/").at(-1)}`
                  : [d.platform, fabricLabel(d.fabric)]
                      .filter(Boolean)
                      .join(" · ") || "Switch"
                : /^pod-\d+\/node-\d+$/i.test(id)
                  ? "ACI leaf"
                  : "Switch",
    ports,
  });
}

/** Switch stages from one attachment to another, or an explicit gap. */
function fabricSegment(
  topo: TopologyIndex,
  from: { device?: string; port?: string },
  to: { device?: string; port?: string },
  names: { from: string; to: string },
): Stage[] {
  if (from.device && to.device) {
    const layers = fabricLayers(topo, from.device, to.device);
    if (layers && layers.length === 1)
      return [deviceStage(topo, from.device, { in: from.port, out: to.port })];
    if (layers)
      return layers.map((layer, i) => {
        const ports = {
          in: i === 0 ? from.port : layer.in,
          out: i === layers.length - 1 ? to.port : layer.out,
        };
        if (layer.ids.length === 1)
          return deviceStage(topo, layer.ids[0], ports);
        const devices = layer.ids.map((id) => topo.byId.get(id));
        const spines = devices.every((d) => d?.role === "spine");
        return stage({
          kind: "switch",
          title: `One of ${layer.ids.length} ${spines ? "spines" : "switches"}`,
          subtitle: `${devices.map((d, j) => d?.name ?? layer.ids[j]).join(", ")} · ECMP`,
          alternatives: layer.ids,
        });
      });
    return [
      deviceStage(topo, from.device, { in: from.port }),
      gap(
        topo.adjacency.size
          ? "No collected link between these switches"
          : "Topology not loaded",
      ),
      deviceStage(topo, to.device, { out: to.port }),
    ];
  }
  if (from.device)
    return [
      deviceStage(topo, from.device, { in: from.port }),
      gap(`Attachment of ${names.to} unknown`),
    ];
  if (to.device)
    return [
      gap(`Attachment of ${names.from} unknown`),
      deviceStage(topo, to.device, { out: to.port }),
    ];
  return [gap("No attachment data for either side")];
}

/**
 * Several nodes received a frontend's traffic: one stage naming all of them.
 * Their shared leaf is kept only when every candidate attaches to it.
 */
function candidateNodes(
  names: string[],
  graph: Graph,
  index: GraphIndex,
  cluster: string | undefined,
  topo: TopologyIndex,
): Attachment {
  const at = names.map((n) =>
    hostAttachment(n, findHost(graph, index, cluster, n), topo),
  );
  const leaves = new Set(at.map((x) => x.device && key(x.device)));
  const shared = leaves.size === 1 && at[0].device ? at[0] : undefined;
  return {
    stages: [
      stage({
        kind: "host",
        title: `One of ${names.length} nodes`,
        subtitle: `${names.join(", ")} · received the traffic`,
        alternatives: names,
      }),
    ],
    device: shared?.device,
    port:
      shared && new Set(at.map((x) => x.port)).size === 1
        ? shared.port
        : undefined,
  };
}

/** Clients that reached a Service frontend, by address. */
function frontendClients(index: GraphIndex, serviceId: string): string[] {
  const out: string[] = [];
  for (const e of index.incident.get(serviceId) ?? [])
    if (e.relationship === "communicates_with" && e.target === serviceId) {
      const n = index.node.get(e.source);
      for (const a of n?.addresses ?? [n?.label ?? e.source])
        if (!out.includes(a)) out.push(a);
    }
  return out;
}

/** The Service hand-off stage plus the leg to the backend pod. */
function serviceLeg(
  edge: GraphEdge,
  service: GraphNode,
  graph: Graph,
  index: GraphIndex,
  topo: TopologyIndex,
  backendId?: string,
): {
  recv: Attachment;
  stages: Stage[];
  notes: string[];
  choices: BackendChoice[];
  backend?: string;
  observers: string[];
} {
  const a = service.attributes ?? {};
  const forwards = (index.outgoing.get(service.id) ?? []).filter(
    (e) => e.relationship === "forwards_to",
  );
  const handoff = clientHandoffResolution(edge, service, index);
  const coverageMessage = handoff.version2
    ? handoff.message
    : handoffCoverageMessage(service);
  const choices = handoff.version2
    ? handoff.complete
      ? clientBackendChoices(index, handoff.records)
      : []
    : coverageMessage
      ? []
      : backendChoices(index, service.id);
  const choice = choices.find((c) => c.id === backendId) ?? choices[0];
  const selectedRecords = choice?.clientHandoffs ?? [];
  const observedHost = handoff.version2
    ? undefined
    : (edge.observers ?? [])
        .map((o) => /^(?:hubble|isovalent):(.+)$/.exec(o)?.[1])
        .find(Boolean);
  const recvNames = [
    ...new Set(
      handoff.version2
        ? clientHandoffReceivingNodes(selectedRecords)
        : coverageMessage
          ? []
          : (edge.via_node ??
            forwards.find((f) => f.via_node?.length)?.via_node ??
            (observedHost ? [observedHost] : [])),
    ),
  ];
  // One receiving node is a fact; several are a set of candidates.
  const recvName = recvNames.length === 1 ? recvNames[0] : undefined;
  const recvNode = recvName
    ? findHost(graph, index, service.cluster, recvName)
    : undefined;
  const recv: Attachment =
    recvNames.length > 1
      ? candidateNodes(recvNames, graph, index, service.cluster, topo)
      : recvName
        ? {
            stages: [
              stage({
                kind: "host",
                title: recvName,
                subtitle: "Kubernetes node · received the traffic",
                nodeId: recvNode?.id,
              }),
            ],
            host: recvNode?.id ?? hostIdentity(service.cluster, recvName),
            ...hostAttachment(recvName, recvNode, topo),
          }
        : { stages: [gap("Receiving node unknown")] };

  const proxy = graph.nodes.find(
    (n) =>
      n.endpoint_kind === "k8s_node_proxy" &&
      recvName &&
      key(n.attributes?.node ?? "") === key(recvName),
  );
  const controller = a.controller
    ? ({ cilium_gateway: "Cilium Gateway", cilium_ingress: "Cilium Ingress" }[
        a.controller
      ] ?? attributeValue("controller", a.controller))
    : undefined;
  const frontend = a.frontend ?? service.addresses?.[0] ?? service.label;
  const title =
    controller ??
    (a.type === "NodePort"
      ? `NodePort ${frontend.split(":").at(-1)}`
      : `${a.type ?? "Service"} VIP`);
  const subtitle = [
    controller && "Envoy",
    a.type === "LoadBalancer" || controller ? `VIP ${frontend}` : frontend,
    // Only Gateway/Ingress traffic is re-originated by the node's Envoy.
    controller &&
      proxy?.addresses?.[0] &&
      `upstream from ${proxy.addresses[0]}`,
    !controller && a.traffic_policy,
    !controller && a.lb_mode && attributeValue("lb_mode", a.lb_mode),
  ]
    .filter(Boolean)
    .join(" · ");
  const ctx = {
    service: a.service ?? service.label,
    clients: frontendClients(index, service.id),
    node: receivedOn(recvNames),
  };
  const handoffStage = stage({
    kind: "handoff",
    title,
    subtitle,
    nodeId: service.id,
    handoff: choice
      ? { state: choice.state, text: choiceExplanation(choice, ctx) }
      : {
          state: "undetermined",
          text:
            coverageMessage ??
            `Backend not determined (${a.candidates ?? "unknown number of"} candidates)`,
        },
  });
  const stages: Stage[] = [handoffStage];
  const notes: string[] = [];
  const observers: string[] = [];
  const leg = { recv, stages, notes, choices, backend: choice?.id, observers };
  if (!choice) return leg;
  const pod = index.node.get(choice.id);
  const backend = attachment(pod, graph, index, topo);
  if (choice.clientHandoffs)
    observers.push(
      ...choice.clientHandoffs.flatMap((record) => record.observers),
    );
  else for (const f of choice.edges) observers.push(...edgeObservers(f));
  // The connection from the receiving node (or its Envoy) to the backend,
  // including Cilium DSR's IPIP leg between the two nodes.
  const fromIds = new Set(
    [recvNode?.id, proxy?.id].filter((x): x is string => !!x),
  );
  const toIds = new Set(
    [choice.id, backend.stages[1]?.nodeId].filter((x): x is string => !!x),
  );
  if (!handoff.version2)
    for (const e of graph.edges)
      if (
        e.relationship === "communicates_with" &&
        fromIds.has(e.source) &&
        toIds.has(e.target)
      )
        observers.push(...edgeObservers(e));
  if (choices.length > 1)
    backend.stages[0] = {
      ...backend.stages[0],
      subtitle: `${backend.stages[0].subtitle} · 1 of ${choices.length} backends`,
    };
  if (backend.host && backend.host === recv.host) {
    // Served by a pod on the receiving node: no second fabric crossing.
    stages.push(backend.stages[0]);
  } else {
    stages.push(
      ...fabricSegment(topo, recv, backend, {
        from: recvName ?? "the receiving node",
        to: pod?.label ?? "the backend",
      }),
      ...[...backend.stages].reverse(),
    );
    const backendHost = backend.stages[1]?.title;
    if (a.lb_mode === "dsr" && !controller && recvName && backendHost)
      notes.push(
        `Cilium DSR: ${recvName} forwards to ${backendHost} over IPIP; replies leave ${backendHost} directly with the VIP as source, so return traffic appears at a different leaf.`,
      );
  }
  return leg;
}

/** One backend pod chosen for a Service, with every hand-off edge to it. */
export interface BackendChoice {
  id: string;
  label: string;
  edges: GraphEdge[];
  state: "observed" | "inferred";
  clientHandoffs?: ClientHandoffRecord[];
}
/** Backends of a Service frontend: observed first, then by name. */
export function backendChoices(
  index: GraphIndex,
  serviceId: string,
): BackendChoice[] {
  const by = new Map<string, BackendChoice>();
  for (const f of index.outgoing.get(serviceId) ?? []) {
    if (f.relationship !== "forwards_to") continue;
    const c = by.get(f.target) ?? {
      id: f.target,
      label: index.node.get(f.target)?.label ?? f.target,
      edges: [],
      state: "inferred" as const,
    };
    c.edges.push(f);
    if (f.confidence === "observed") c.state = "observed";
    by.set(f.target, c);
  }
  return [...by.values()].sort(
    (x, y) =>
      Number(x.state !== "observed") - Number(y.state !== "observed") ||
      x.label.localeCompare(y.label),
  );
}
export function clientBackendChoices(
  index: GraphIndex,
  records: ClientHandoffRecord[],
): BackendChoice[] {
  const by = new Map<string, BackendChoice>();
  for (const record of records) {
    const node = index.node.get(record.target);
    if (!node || node.kind !== "workload") continue;
    const choice: BackendChoice = by.get(record.target) ?? {
      id: record.target,
      label: node.label,
      edges: [],
      state: "observed" as const,
      clientHandoffs: [],
    };
    choice.clientHandoffs!.push(record);
    if (record.basis === "time_inferred") choice.state = "inferred";
    by.set(record.target, choice);
  }
  return [...by.values()].sort(
    (a, b) =>
      Number(a.state !== "observed") - Number(b.state !== "observed") ||
      a.label.localeCompare(b.label),
  );
}
/** Plain-language summary of a backend's hand-off evidence. */
export function choiceExplanation(
  choice: BackendChoice,
  ctx: Parameters<typeof handoffExplanation>[1],
): string {
  if (choice.clientHandoffs)
    return choice.clientHandoffs
      .map(
        (record) =>
          `${handoffShort[record.basis]} · ${record.connections} ${record.connections === 1 ? "connection" : "connections"}`,
      )
      .join("; ");
  const ordered = [...choice.edges].sort(
    (x, y) =>
      Number(x.confidence !== "observed") - Number(y.confidence !== "observed"),
  );
  const text = handoffExplanation(ordered[0].handoff_basis!, ctx);
  const inferred = ordered
    .filter((e) => e.confidence === "inferred")
    .reduce((sum, e) => sum + e.count, 0);
  if (choice.state === "observed" && inferred)
    return `${text}; ${inferred === 1 ? "1 more connection" : `${inferred} more connections`} inferred from timing`;
  return text;
}

/**
 * Candidate path for a network conversation, from collected inventory only:
 * client → host → access switch → shortest fabric path (every equal-cost spine)
 * → access switch → host → server. A Service frontend adds the node that
 * received the traffic, the hand-off, and the leg to the chosen backend pod.
 * Missing links are explicit gaps; observations mark stages but never prove
 * packet order.
 */
export function buildPath(
  edge: GraphEdge,
  graph: Graph,
  index: GraphIndex,
  topo: TopologyIndex,
  options: { backend?: string } = {},
): CandidatePath {
  const notes: string[] = [];
  const resolutionContext = edgeDeviceContext(edge, index);
  const legObservers: string[] = [];
  let backends: CandidatePath["backends"] = [];
  let backend: string | undefined;
  const client = attachment(index.node.get(edge.source), graph, index, topo);
  const target = index.node.get(edge.target);
  const nameOf = (n?: GraphNode) => n?.label ?? "this endpoint";
  const stages: Stage[] = [...client.stages];
  let sameHost = false;
  if (target?.endpoint_kind === "k8s_service") {
    const leg = serviceLeg(edge, target, graph, index, topo, options.backend);
    notes.push(...leg.notes);
    backends = leg.choices.map((c) => ({
      id: c.id,
      label: c.label,
      state: c.state,
    }));
    backend = leg.backend;
    legObservers.push(...leg.observers);
    if (leg.recv.host && leg.recv.host === client.host) {
      stages.push(...leg.recv.stages.slice(client.stages.length ? 1 : 0));
    } else {
      stages.push(
        ...fabricSegment(topo, client, leg.recv, {
          from: nameOf(index.node.get(edge.source)),
          to: leg.recv.stages[0]?.title ?? "the receiving node",
        }),
        ...leg.recv.stages,
      );
    }
    stages.push(...leg.stages);
  } else {
    const server = attachment(target, graph, index, topo);
    sameHost = !!client.host && client.host === server.host;
    if (sameHost) {
      // Pod-to-pod on one node never reaches the fabric.
      if (server.stages[0]?.kind === "entity") stages.push(server.stages[0]);
    } else
      stages.push(
        ...fabricSegment(topo, client, server, {
          from: nameOf(index.node.get(edge.source)),
          to: nameOf(target),
        }),
        ...[...server.stages].reverse(),
      );
  }

  const observations = edgeObservers(edge).flatMap((o) =>
    parseEdgeObserver(o, edge, topo, resolutionContext),
  );
  // A firewall is placed next to the side that leaves the fabric.
  const firewalls = observations.filter((o) => o.role === "firewall");
  const outside = (n?: GraphNode) =>
    n?.endpoint_kind === "external" || n?.endpoint_kind === "unresolved";
  for (const fw of dedupe(firewalls)) {
    const fwStage = stage({
      kind: "firewall",
      title: fw.label,
      subtitle: "Firewall",
    });
    if (outside(index.node.get(edge.target))) {
      const at = stages.length - 1;
      stages.splice(at, 0, gap("No collected link to the firewall"), fwStage);
    } else if (outside(index.node.get(edge.source))) {
      stages.splice(1, 0, fwStage, gap("No collected link from the firewall"));
    }
  }
  collapseGaps(stages);

  // Behind a Service hand-off, the backend leg is marked from its own
  // evidence: the hand-off edges and the upstream conversation.
  const split = stages.findIndex((st) => st.kind === "handoff");
  const legObservations = legObservers.flatMap((o) =>
    parseEdgeObserver(o, edge, topo, resolutionContext),
  );
  const placed = new Set<string>();
  stages.forEach((s, i) => {
    if (s.kind === "gap" || s.kind === "entity" || s.kind === "handoff") return;
    const pool =
      split < 0
        ? observations
        : i < split
          ? [...observations, ...recvObservations(legObservations, s)]
          : legObservations;
    const keys = new Set<string>();
    const ids = s.alternatives ?? (s.nodeId ? [s.nodeId] : []);
    for (const id of ids) {
      const d = resolveDevice(id, topo, resolutionContext);
      if (d) keys.add(key(d.id));
    }
    if (s.kind === "host") {
      const graphHost = s.nodeId ? index.node.get(s.nodeId) : undefined;
      const host = resolveDevice(s.title, topo, {
        scope: graphHost?.attributes?.scope ?? resolutionContext.scope,
        cluster: graphHost?.cluster ?? resolutionContext.cluster,
        families: ["kubernetes_node"],
      });
      if (host) keys.add(key(host.id));
    }
    // Display-name matching is limited to V1 rows; V2 evidence matches a
    // source-qualified canonical ID only.
    if (!topo.containsV2Devices) {
      keys.add(key(s.title));
      for (const id of s.alternatives ?? []) keys.add(key(id));
      for (const id of ids) {
        const d = topo.byId.get(id);
        if (d) keys.add(key(d.name));
      }
    }
    for (const o of pool) {
      if (!keys.has(o.key)) continue;
      placed.add(o.key);
      const src = sourceLabel(o.source);
      if (!s.observedBy.includes(src)) s.observedBy.push(src);
      const ifs = [o.in, o.out].filter(Boolean).join(" → ");
      if (ifs && !s.seenInterfaces.includes(ifs)) s.seenInterfaces.push(ifs);
    }
    s.observed = s.observedBy.length > 0;
  });
  const unplaced = observationsByDevice(
    edge,
    topo,
    legObservers,
    resolutionContext,
  ).filter((d) => !placed.has(d.key));
  const aclLeaf = edge.acl_leaf
    ? deviceName(edge.acl_leaf, topo, resolutionContext).name
    : undefined;
  const policy: CandidatePath["policy"] = [];
  const contract = contractSummary(edge);
  if (contract)
    policy.push({
      text: contract,
      tone:
        edge.contract_basis === "intent" || edge.contract_basis === "intra_epg"
          ? "intent"
          : edge.contract_basis === "none" && edge.contract
            ? "blocked"
            : "neutral",
    });
  const acl = aclSummary(edge, aclLeaf);
  if (acl)
    policy.push({
      text: acl,
      tone: edge.acl_action === "drop" ? "blocked" : "observed",
    });
  return { stages, unplaced, sameHost, policy, notes, backends, backend };
}

/** The receiving node is marked seen by host sensors on the hand-off. */
function recvObservations(
  points: ObservationPoint[],
  s: Stage,
): ObservationPoint[] {
  return s.kind === "host" ? points.filter((p) => p.role === "host") : [];
}

function dedupe(points: ObservationPoint[]) {
  const seen = new Set<string>();
  return points.filter((p) => !seen.has(p.key) && seen.add(p.key));
}
function collapseGaps(stages: Stage[]) {
  for (let i = stages.length - 1; i > 0; i--)
    if (stages[i].kind === "gap" && stages[i - 1].kind === "gap")
      stages.splice(i, 1);
}

/** Search over a conversation's port and the devices and interfaces that saw it. */
export function edgeMatches(
  edge: GraphEdge,
  query: string,
  topo: TopologyIndex,
  index?: GraphIndex,
): boolean {
  const q = query.trim().toLowerCase();
  if (!q || edge.relationship !== "communicates_with") return false;
  const context = index ? edgeDeviceContext(edge, index) : {};
  const hay: string[] = topo.containsV2Devices ? [] : [...edgeObservers(edge)];
  for (const v of [edge.contract, edge.contract_entry]) if (v) hay.push(v);
  if (edge.server_port !== undefined)
    hay.push(`${edge.server_port}/${edge.transport ?? ""}`);
  for (const d of observationsByDevice(edge, topo, [], context)) {
    if (topo.containsV2Devices) {
      if (!d.resolved) continue;
      const device = resolveDevice(d.key, topo, context);
      if (!device) continue;
      hay.push(
        d.label,
        device.name,
        device.native_device_id ?? "",
        device.aci_node ?? "",
        ...(device.aliases ?? []),
        ...d.interfaces,
        ...d.interfaces.map(interfaceKey),
      );
    } else {
      hay.push(d.label, ...d.interfaces, ...d.interfaces.map(interfaceKey));
    }
  }
  if (topo.containsV2Devices && edge.acl_leaf) {
    const aclDevice = resolveDevice(edge.acl_leaf, topo, {
      ...context,
      families: ["aci_topSystem"],
    });
    if (aclDevice)
      hay.push(
        aclDevice.name,
        aclDevice.native_device_id ?? "",
        aclDevice.aci_node ?? "",
        ...(aclDevice.aliases ?? []),
      );
  }
  const qk = interfaceKey(q);
  return hay.some((h) => {
    const l = h.toLowerCase();
    return l.includes(q) || l.includes(qk);
  });
}

/** Hostname first; ACI `pod-1/node-201` resolves to its leaf via topology. */
export function deviceName(
  raw: string,
  topo: TopologyIndex,
  context: DeviceResolutionContext = {},
): { name: string; secondary?: string } {
  const d = resolveDevice(raw, topo, context);
  if (!d) {
    const candidates = [
      ...(topo.aliasCandidates.get(key(raw)) ?? []),
      ...(topo.ipCandidates.get(key(raw)) ?? []),
    ];
    return topo.ambiguousKeys.has(key(raw)) || candidates.length > 1
      ? { name: raw, secondary: "Ambiguous alias" }
      : { name: raw };
  }
  if (d.aci_node && d.aci_node === raw.trim())
    return { name: d.name, secondary: d.aci_node.split("/").at(-1) };
  return { name: d.name };
}

export interface DeviceSummary {
  key: string;
  label: string;
  role: ObservationPoint["role"];
  device?: Device;
  sources: string[];
  interfaces: string[];
  edges: GraphEdge[];
}
export interface AttachmentDeviceReference {
  key: string;
  device?: Device;
  evidence: AttachmentEvidence;
  client?: string;
  flowEdges: GraphEdge[];
  exporterContext: string[];
  unresolvedReason?: string;
}
const ROLE_ORDER: ObservationPoint["role"][] = [
  "firewall",
  "switch",
  "fabric",
  "host",
];
/** Every observer, the interfaces it reported and the conversations it saw. */
export function deviceSummaries(
  edges: GraphEdge[],
  topo: TopologyIndex,
  index?: GraphIndex,
): {
  devices: DeviceSummary[];
  unseenByFabric: GraphEdge[];
  idle: Device[];
  attachmentReferences: AttachmentDeviceReference[];
} {
  const byKey = new Map<string, DeviceSummary>();
  const attachmentByKey = new Map<string, AttachmentDeviceReference>();
  const unseenByFabric: GraphEdge[] = [];
  for (const e of edges) {
    if (
      e.relationship === "traffic_observation" &&
      e.confidence === "correlated"
    ) {
      const sourceNode = index?.node.get(e.source);
      const targetNode = index?.node.get(e.target);
      const clientNode =
        sourceNode?.kind === "client"
          ? sourceNode
          : targetNode?.kind === "client"
            ? targetNode
            : undefined;
      for (const [i, evidence] of (e.attachment_evidence ?? []).entries()) {
        const evidenceId =
          typeof evidence.device_id === "string"
            ? evidence.device_id.trim()
            : undefined;
        const alias = evidenceId ? resolveDevice(evidenceId, topo) : undefined;
        // Attachment IDs are source-qualified identities. Names and aliases
        // help navigation elsewhere, but cannot resolve attachment evidence.
        const inventory =
          alias && evidenceId && key(alias.id) === key(evidenceId)
            ? alias
            : undefined;
        const clientScope = clientNode?.attributes?.scope;
        const unresolvedReason = !evidenceId
          ? "The attachment record has no source-qualified device ID."
          : topo.ambiguousKeys.has(key(evidenceId))
            ? "The source-qualified device ID is ambiguous in inventory."
            : !inventory
              ? alias
                ? "The attachment ID matches an inventory alias, not the source-qualified device ID."
                : "No exact source-qualified device ID matches inventory."
              : !inventory.scope ||
                  !clientScope ||
                  inventory.scope !== clientScope
                ? "The inventory device scope does not exactly match the client evidence scope."
                : !inventory.cluster ||
                    !clientNode?.cluster ||
                    inventory.cluster !== clientNode.cluster
                  ? "The inventory device cluster does not exactly match the client evidence cluster."
                  : !inventory.device_authority ||
                      !evidence.client_authority ||
                      inventory.device_authority !== evidence.client_authority
                    ? "The inventory device authority does not exactly match the attachment record."
                    : undefined;
        const device = unresolvedReason ? undefined : inventory;
        const id = device?.id ?? evidenceId ?? `${e.id}:${i}`;
        const groupKey = `${device ? "device" : "unresolved"}:${key(id)}`;
        const reference = attachmentByKey.get(groupKey) ?? {
          key: groupKey,
          device,
          evidence,
          client: clientNode?.label,
          flowEdges: [],
          exporterContext: [],
          ...(unresolvedReason ? { unresolvedReason } : {}),
        };
        if (!reference.flowEdges.includes(e)) reference.flowEdges.push(e);
        for (const observation of e.traffic_observations ?? []) {
          if (!observation.exporter_ip) continue;
          const exporter = resolveDevice(observation.exporter_ip, topo, {
            scope: observation.scope,
            cluster: observation.cluster,
            authority: observation.source_authority,
          });
          const resolved =
            exporter &&
            exporter.cluster === observation.cluster &&
            exporter.scope === observation.scope;
          const context = resolved
            ? `Exporter ${exporter.name} (${exporter.id})`
            : [
                `Exporter IP ${observation.exporter_ip}`,
                observation.profile,
                observation.scope,
                observation.cluster,
              ]
                .filter(Boolean)
                .join(" · ");
          if (!reference.exporterContext.includes(context))
            reference.exporterContext.push(context);
        }
        attachmentByKey.set(groupKey, reference);
      }
    }
    if (e.relationship !== "communicates_with") continue;
    const seen = observationsByDevice(
      e,
      topo,
      [],
      index ? edgeDeviceContext(e, index) : {},
    );
    if (!seen.some((d) => d.role !== "host")) unseenByFabric.push(e);
    for (const d of seen) {
      const s = byKey.get(d.key) ?? {
        key: d.key,
        label: d.label,
        role: d.role,
        device: resolveDevice(d.key, topo),
        sources: [],
        interfaces: [],
        edges: [],
      };
      for (const x of d.sources) if (!s.sources.includes(x)) s.sources.push(x);
      for (const x of d.interfaces)
        if (!s.interfaces.includes(x)) s.interfaces.push(x);
      s.edges.push(e);
      byKey.set(d.key, s);
    }
  }
  const devices = [...byKey.values()].sort(
    (a, b) =>
      ROLE_ORDER.indexOf(a.role) - ROLE_ORDER.indexOf(b.role) ||
      a.label.localeCompare(b.label),
  );
  for (const d of devices)
    d.interfaces.sort((a, b) =>
      a.localeCompare(b, undefined, { numeric: true }),
    );
  const seenIds = new Set(devices.map((d) => d.device?.id).filter(Boolean));
  const idle = [...new Set(topo.byId.values())]
    .filter((d) => !seenIds.has(d.id))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    devices,
    unseenByFabric,
    idle,
    attachmentReferences: [...attachmentByKey.values()].sort((a, b) =>
      (a.device?.name ?? a.evidence.device_id ?? "").localeCompare(
        b.device?.name ?? b.evidence.device_id ?? "",
      ),
    ),
  };
}
