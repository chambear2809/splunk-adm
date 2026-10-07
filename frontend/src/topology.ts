import type { Graph, GraphEdge, GraphIndex, GraphNode } from "./graph";
import {
  aclSummary,
  attributeValue,
  contractSummary,
  endpointKindLabel,
  handoffExplanation,
  sourceLabel,
} from "./glossary";
import { count, many, one, type Row } from "./rows";

export type DeviceKind = "switch" | "firewall" | "controller";
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
  sources: string[];
}
export interface Link {
  a_device: string;
  a_interface?: string;
  b_device: string;
  b_interface?: string;
  source: string;
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

const DEVICE_KINDS: DeviceKind[] = ["switch", "firewall", "controller"];
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
      topo.devices.push(device);
    } else if (type === "link") {
      topo.links.push({
        a_device: need(row, "a_device"),
        a_interface: one(row, "a_interface"),
        b_device: need(row, "b_device"),
        b_interface: one(row, "b_interface"),
        source: one(row, "link_source") ?? "cdp",
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
  byKey: Map<string, Device>;
  byIp: Map<string, Device>;
  ifName: Map<string, string>;
  /** Switch-to-switch adjacency (CDP, ACI fabric links); hosts excluded. */
  adjacency: Map<string, { to: string; out?: string; in?: string }[]>;
  /** Host attachment from LLDP: lower-case host name → leaf and port. */
  lldpHost: Map<string, { device: string; port?: string }>;
}
const key = (s: string) => s.trim().toLowerCase();
export function indexTopology(topo: Topology): TopologyIndex {
  const byKey = new Map<string, Device>(),
    byIp = new Map<string, Device>(),
    ifName = new Map<string, string>(),
    adjacency = new Map<string, { to: string; out?: string; in?: string }[]>(),
    lldpHost = new Map<string, { device: string; port?: string }>();
  for (const d of topo.devices) {
    byKey.set(key(d.id), d);
    byKey.set(key(d.name), d);
    if (d.aci_node) byKey.set(key(d.aci_node), d);
    if (d.mgmt_ip) byIp.set(d.mgmt_ip, d);
  }
  for (const i of topo.interfaces)
    if (i.ifindex !== undefined)
      ifName.set(`${key(i.device_id)}|${i.ifindex}`, i.interface);
  const add = (a: string, b: string, out?: string, inn?: string) => {
    const list = adjacency.get(a) ?? [];
    if (!list.some((x) => x.to === b)) list.push({ to: b, out, in: inn });
    adjacency.set(a, list);
  };
  for (const l of topo.links) {
    if (l.source === "lldp") {
      // LLDP from a leaf names the attached server by its system name.
      const leaf = byKey.get(key(l.a_device))?.id ?? l.a_device;
      lldpHost.set(key(l.b_device), { device: leaf, port: l.a_interface });
      continue;
    }
    const a = byKey.get(key(l.a_device))?.id ?? l.a_device;
    const b = byKey.get(key(l.b_device))?.id ?? l.b_device;
    if (key(a) === key(b)) continue;
    add(key(a), key(b), l.a_interface, l.b_interface);
    add(key(b), key(a), l.b_interface, l.a_interface);
  }
  for (const list of adjacency.values())
    list.sort((x, y) => x.to.localeCompare(y.to));
  return { byKey, byIp, ifName, adjacency, lldpHost };
}

/** One place where a conversation was seen, resolved to a device when possible. */
export interface ObservationPoint {
  source: string;
  /** Lower-case device or host key used to match path stages. */
  key: string;
  label: string;
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
    const name = topo.ifName.get(`${key(device)}|${m[1]}`);
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
): ObservationPoint[] {
  const at = observer.indexOf(":");
  if (at < 0) return [];
  const source = observer.slice(0, at);
  const rest = observer.slice(at + 1);
  if (source === "isovalent" || source === "hubble")
    return [{ source, key: key(rest), label: rest, role: "host" }];
  if (source === "aci_acllog") {
    const device = topo.byKey.get(key(rest));
    return [
      {
        source,
        key: key(device?.id ?? rest),
        label: device?.name ?? rest,
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
      const device = topo.byKey.get(key(leaf));
      points.push({
        source,
        key: key(device?.id ?? leaf),
        label: device?.name ?? leaf,
        role: "switch",
        ...(i === 0
          ? { in: iface ? interfaceLabel(iface) : undefined }
          : { out: iface ? interfaceLabel(iface) : undefined }),
      });
    });
    return points.length
      ? points
      : [{ source, key: key(fabric), label: fabric, role: "fabric" }];
  }
  const m = /^(.*):([^:>]*)>([^:>]*)$/.exec(rest);
  const ip = m ? m[1] : rest;
  const device = topo.byIp.get(ip) ?? topo.byKey.get(key(ip));
  const name = device?.id ?? ip;
  return [
    {
      source,
      key: key(name),
      label:
        device?.name ??
        (source === "ftd" ? `Firewall ${ip}` : `Exporter ${ip}`),
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
  sources: string[];
  interfaces: string[];
}
/** Observation points grouped by device, for "Seen by" lists. */
export function observationsByDevice(
  edge: GraphEdge,
  topo: TopologyIndex,
): DeviceObservation[] {
  const groups = new Map<string, DeviceObservation>();
  for (const o of edgeObservers(edge))
    for (const p of parseObserver(o, topo)) {
      const g = groups.get(p.key) ?? {
        key: p.key,
        label: p.label,
        role: p.role,
        sources: [],
        interfaces: [],
      };
      const src = sourceLabel(p.source);
      if (!g.sources.includes(src)) g.sources.push(src);
      for (const i of [p.in, p.out])
        if (i && !g.interfaces.includes(i)) g.interfaces.push(i);
      groups.set(p.key, g);
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
  if (attrs.attach_device)
    return { device: attrs.attach_device, port: attrs.attach_interface };
  return topo.lldpHost.get(key(hostName)) ?? {};
}

function findHost(
  graph: Graph,
  index: GraphIndex,
  cluster: string | undefined,
  hostName: string,
): GraphNode | undefined {
  return (
    index.node.get(`node:${cluster}/${hostName}`) ??
    graph.nodes.find(
      (n) => n.endpoint_kind === "k8s_node" && n.label === hostName,
    )
  );
}

const podCluster = (node: GraphNode) =>
  node.id.startsWith("pod:") ? node.id.slice(4).split("/")[0] : node.cluster;

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
      host: key(hostName),
      device: at.device,
      port: at.port,
    };
  }
  if (node.endpoint_kind === "k8s_node") {
    const at = hostAttachment(node.label, node, topo);
    return {
      stages: [entity],
      host: key(node.label),
      device: at.device,
      port: at.port,
    };
  }
  return {
    stages: [entity],
    device: attrs.attach_device,
    port: attrs.attach_interface,
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
): Layer[] | undefined {
  const resolve = (x: string) => key(topo.byKey.get(key(x))?.id ?? x);
  const start = resolve(from),
    goal = resolve(to);
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

function deviceStage(
  topo: TopologyIndex,
  id: string,
  raw?: Stage["ports"],
): Stage {
  const d = topo.byKey.get(key(id));
  const ports = raw && {
    in: raw.in && interfaceLabel(raw.in),
    out: raw.out && interfaceLabel(raw.out),
  };
  return stage({
    kind: d?.kind === "firewall" ? "firewall" : "switch",
    title: d?.name ?? id,
    subtitle: d
      ? d.aci_node
        ? `ACI ${d.role ?? "switch"} · ${d.aci_node.split("/").at(-1)}`
        : [d.platform, fabricLabel(d.fabric)].filter(Boolean).join(" · ") ||
          "Switch"
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
        const devices = layer.ids.map((id) => topo.byKey.get(id));
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
): { recv: Attachment; stages: Stage[] } {
  const a = service.attributes ?? {};
  const forwards = (index.outgoing.get(service.id) ?? []).filter(
    (e) => e.relationship === "forwards_to",
  );
  const observedHost = (edge.observers ?? [])
    .map((o) => /^(?:hubble|isovalent):(.+)$/.exec(o)?.[1])
    .find(Boolean);
  const recvName =
    edge.via_node ?? forwards.find((f) => f.via_node)?.via_node ?? observedHost;
  const recvNode = recvName
    ? findHost(graph, index, service.cluster, recvName)
    : undefined;
  const recv: Attachment = recvName
    ? {
        stages: [
          stage({
            kind: "host",
            title: recvName,
            subtitle: "Kubernetes node · received the traffic",
            nodeId: recvNode?.id,
          }),
        ],
        host: key(recvName),
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
  const chosen =
    forwards.length === 1
      ? forwards[0]
      : (forwards.find((f) => f.confidence === "observed") ?? forwards[0]);
  const ctx = {
    service: a.service ?? service.label,
    clients: frontendClients(index, service.id),
    node: recvName,
  };
  const handoffStage = stage({
    kind: "handoff",
    title,
    subtitle,
    nodeId: service.id,
    handoff: chosen
      ? {
          state: chosen.confidence === "inferred" ? "inferred" : "observed",
          text: handoffExplanation(chosen.handoff_basis!, ctx),
        }
      : {
          state: "undetermined",
          text: `Backend not determined (${a.candidates ?? "unknown number of"} candidates)`,
        },
  });
  const stages: Stage[] = [handoffStage];
  if (!chosen) return { recv, stages };
  const pod = index.node.get(chosen.target);
  const backend = attachment(pod, graph, index, topo);
  if (forwards.length > 1)
    backend.stages[0] = {
      ...backend.stages[0],
      subtitle: `${backend.stages[0].subtitle} · 1 of ${forwards.length} backends`,
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
  }
  return { recv, stages };
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
): CandidatePath {
  const client = attachment(index.node.get(edge.source), graph, index, topo);
  const target = index.node.get(edge.target);
  const nameOf = (n?: GraphNode) => n?.label ?? "this endpoint";
  const stages: Stage[] = [...client.stages];
  let sameHost = false;
  if (target?.endpoint_kind === "k8s_service") {
    const leg = serviceLeg(edge, target, graph, index, topo);
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
    parseObserver(o, topo),
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

  const placed = new Set<string>();
  for (const s of stages) {
    if (s.kind === "gap" || s.kind === "entity" || s.kind === "handoff")
      continue;
    const titles = s.alternatives ?? [s.title];
    const keys = new Set<string>();
    for (const t of titles) {
      keys.add(key(t));
      const d = topo.byKey.get(key(t));
      if (d) {
        keys.add(key(d.id));
        keys.add(key(d.name));
      }
    }
    for (const o of observations) {
      if (!keys.has(o.key) && !keys.has(key(o.label))) continue;
      placed.add(o.key);
      const src = sourceLabel(o.source);
      if (!s.observedBy.includes(src)) s.observedBy.push(src);
      const ifs = [o.in, o.out].filter(Boolean).join(" → ");
      if (ifs && !s.seenInterfaces.includes(ifs)) s.seenInterfaces.push(ifs);
    }
    s.observed = s.observedBy.length > 0;
  }
  const unplaced = observationsByDevice(edge, topo).filter(
    (d) => !placed.has(d.key),
  );
  const aclLeaf = edge.acl_leaf
    ? deviceName(edge.acl_leaf, topo).name
    : undefined;
  const policy: CandidatePath["policy"] = [];
  const contract = contractSummary(edge);
  if (contract)
    policy.push({
      text: contract,
      tone: edge.contract_basis === "intent" ? "intent" : "neutral",
    });
  const acl = aclSummary(edge, aclLeaf);
  if (acl)
    policy.push({
      text: acl,
      tone: edge.acl_action === "drop" ? "blocked" : "observed",
    });
  return { stages, unplaced, sameHost, policy };
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
): boolean {
  const q = query.trim().toLowerCase();
  if (!q || edge.relationship !== "communicates_with") return false;
  const hay: string[] = [...edgeObservers(edge)];
  for (const v of [edge.contract, edge.contract_entry]) if (v) hay.push(v);
  if (edge.server_port !== undefined)
    hay.push(`${edge.server_port}/${edge.transport ?? ""}`);
  for (const d of observationsByDevice(edge, topo))
    hay.push(d.label, ...d.interfaces, ...d.interfaces.map(interfaceKey));
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
): { name: string; secondary?: string } {
  const d = topo.byKey.get(raw.trim().toLowerCase());
  if (!d) return { name: raw };
  if (d.aci_node && d.aci_node.toLowerCase() === raw.trim().toLowerCase())
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
): { devices: DeviceSummary[]; unseenByFabric: GraphEdge[]; idle: Device[] } {
  const byKey = new Map<string, DeviceSummary>();
  const unseenByFabric: GraphEdge[] = [];
  for (const e of edges) {
    if (e.relationship !== "communicates_with") continue;
    const seen = observationsByDevice(e, topo);
    if (!seen.some((d) => d.role !== "host")) unseenByFabric.push(e);
    for (const d of seen) {
      const s = byKey.get(d.key) ?? {
        key: d.key,
        label: d.label,
        role: d.role,
        device: topo.byKey.get(d.key),
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
  const idle = [...new Set(topo.byKey.values())]
    .filter((d) => !seenIds.has(d.id))
    .sort((a, b) => a.name.localeCompare(b.name));
  return { devices, unseenByFabric, idle };
}
