import type { Graph, GraphNode } from "../graph";
import {
  fabricLayersMulti,
  resolveDevice,
  virtualPortFor,
  type Device,
  type TopologyIndex,
  type VirtualPort,
} from "../topology";
import { deviceTier, isIp, normIface, shortName, type Tier } from "./elements";

/** A conversation end: a graph card (demo/map) or an identity-enriched address (live). */
export interface ImpactEndpoint {
  /** Graph card ID, else `ip:<address>`. */
  key: string;
  ip?: string;
  name?: string;
  /** adm_ip_identity entity_kind or graph endpoint kind. */
  kind?: string;
  app?: string;
  /** Kubernetes node of a pod. */
  node?: string;
  cluster?: string;
  epg?: string;
  graph?: GraphNode;
}

export interface PathNode {
  id: string;
  label: string;
  tier: Tier;
  /** Identities whose failure takes this node down (device IDs, card IDs, `ip:` keys). */
  refs: string[];
  depth: number;
}
export interface PathEdge {
  a: string;
  b: string;
  /** Interfaces carrying this edge, as `<device>|<interface>` (both lower case). */
  ports: string[];
  basis: string;
}
/** Endpoint → host → virtual switch → uplinks (FI) → fabric attachment. */
export interface Access {
  start: string;
  nodes: Map<string, PathNode>;
  edges: PathEdge[];
  /** Fabric attachment switches (lower-case device IDs). */
  exits: string[];
  /** Attachment collected; false means the fabric side is unknown. */
  known: boolean;
  basis: string[];
  /** Local switching domains (node ID, key): a shared key is switched without the fabric. */
  segments: { node: string; key: string }[];
}

export interface PathContext {
  topo: TopologyIndex;
  graph?: Graph;
  /** Kubernetes node name (lower case) → node address, from identity rows. */
  k8sNodes: Map<string, string>;
  devByKey: Map<string, Device>;
  cache: Map<string, Access>;
}

const lower = (s?: string) => s?.trim().toLowerCase() ?? "";

export function pathContext(
  topo: TopologyIndex,
  graph?: Graph,
  k8sNodes: Map<string, string> = new Map(),
): PathContext {
  const devByKey = new Map<string, Device>();
  for (const d of topo.byId.values()) devByKey.set(lower(d.id), d);
  return { topo, graph, k8sNodes, devByKey, cache: new Map() };
}

export const deviceLabel = (ctx: PathContext, id: string) =>
  shortName(ctx.devByKey.get(lower(id))?.name) || id;

const port = (device: string | undefined, name: string | undefined) =>
  device && name ? [`${lower(device)}|${normIface(name)}`] : [];

function uniquePort(ctx: PathContext, ip?: string, mac?: string) {
  const pick = (k?: string) => {
    if (!k) return undefined;
    const list = ctx.topo.virtualPorts.get(lower(k)) ?? [];
    const unique = new Map(list.map((p) => [`${p.switch}|${p.vm}`, p]));
    return unique.size === 1 ? [...unique.values()][0] : undefined;
  };
  return pick(mac) ?? (mac ? undefined : pick(ip));
}

function graphNodeFor(ctx: PathContext, ip?: string): GraphNode | undefined {
  if (!ip || !ctx.graph) return undefined;
  const hits = ctx.graph.nodes.filter(
    (n) =>
      n.kind === "endpoint" &&
      (n.addresses ?? []).some((a) => lower(a) === lower(ip)),
  );
  return hits.length === 1 ? hits[0] : undefined;
}

class Builder {
  nodes = new Map<string, PathNode>();
  edges: PathEdge[] = [];
  exits = new Set<string>();
  basis = new Set<string>();
  known = true;
  segments: { node: string; key: string }[] = [];
  constructor(private ctx: PathContext) {}
  node(id: string, label: string, tier: Tier, refs: string[], depth: number) {
    const cur = this.nodes.get(id);
    if (cur) cur.depth = Math.min(cur.depth, depth);
    else
      this.nodes.set(id, { id, label, tier, refs: [...new Set(refs)], depth });
    return id;
  }
  device(id: string, depth: number) {
    const k = lower(id);
    const d = this.ctx.devByKey.get(k);
    return this.node(
      k,
      deviceLabel(this.ctx, k),
      deviceTier(d, this.ctx.topo),
      [k],
      depth,
    );
  }
  edge(a: string, b: string, ports: string[], basis: string) {
    this.edges.push({ a, b, ports, basis });
  }
}

/** VM vNIC → VDS on its host → host uplinks (vmnics) → FI → leaves, or its ACI attachment. */
function virtualAccess(
  b: Builder,
  ctx: PathContext,
  from: string,
  depth: number,
  p: VirtualPort,
) {
  const sw = lower(p.switch);
  const hv = p.hypervisor ? lower(p.hypervisor) : "";
  const swName = deviceLabel(ctx, sw);
  const hvName = hv ? deviceLabel(ctx, hv) : "";
  // The per-host switch instance fails with either the host or the switch.
  const inst = b.node(
    `vds:${sw}@${hv}`,
    hv ? hvName : swName,
    hv ? "hypervisor" : "vswitch",
    [sw, ...(hv ? [hv] : [])],
    depth + 1,
  );
  b.edge(from, inst, [], "VMM vNIC");
  // Same host, switch and VLAN (or portgroup): switched in the VDS.
  const seg = p.vlan ?? p.portgroup;
  if (seg) b.segments.push({ node: inst, key: `${inst}|${seg}` });
  if (p.overlay) {
    b.known = false;
    b.basis.add(`overlay ${p.overlay}`);
    return;
  }
  const uplinks = ctx.topo.uplinks.get(`${sw}|${hv}`) ?? [];
  if (uplinks.length) {
    b.basis.add("host uplinks (hvsAdj)");
    for (const u of uplinks) {
      const peer = lower(u.device);
      const second = ctx.topo.uplinks.get(`${peer}|`) ?? [];
      b.device(peer, depth + 2);
      b.edge(
        inst,
        peer,
        [...port(hv, u.uplink), ...port(peer, u.port)],
        "hvsAdj",
      );
      if (!second.length) {
        b.exits.add(peer);
        continue;
      }
      b.basis.add("FI uplinks (lldpAdjEp)");
      for (const s of second) {
        const leaf = lower(s.device);
        b.device(leaf, depth + 3);
        b.edge(
          peer,
          leaf,
          [...port(peer, s.uplink), ...port(leaf, s.port)],
          "lldpAdjEp",
        );
        b.exits.add(leaf);
      }
    }
    return;
  }
  const leaves = (p.attach_nodes ?? [])
    .map((n) => resolveDevice(n, ctx.topo)?.id)
    .filter((x): x is string => !!x)
    .map(lower);
  if (!leaves.length) {
    b.known = false;
    return;
  }
  b.basis.add(leaves.length > 1 ? "vPC (fvRsCEpToPathEp)" : "fvRsCEpToPathEp");
  for (const leaf of new Set(leaves)) {
    b.device(leaf, depth + 2);
    b.edge(inst, leaf, port(leaf, p.attach_interface), "fvRsCEpToPathEp");
    b.exits.add(leaf);
  }
}

/** A host (bare metal or VM) reached from `from`. */
function hostAccess(
  b: Builder,
  ctx: PathContext,
  from: string,
  depth: number,
  host: { name?: string; ip?: string; graph?: GraphNode },
) {
  const attrs = host.graph?.attributes ?? {};
  const vport =
    (host.graph && virtualPortFor(host.graph, ctx.topo)) ??
    uniquePort(ctx, host.ip, attrs.mac);
  if (vport) return virtualAccess(b, ctx, from, depth, vport);
  const attach = attrs.attach_device
    ? resolveDevice(attrs.attach_device, ctx.topo)
    : undefined;
  if (attach) {
    const leaf = b.device(attach.id, depth + 1);
    b.edge(
      from,
      leaf,
      port(attach.id, attrs.attach_interface),
      "attach_device",
    );
    b.exits.add(leaf);
    b.basis.add("endpoint attachment");
    return;
  }
  const names = [host.name, host.graph?.label].filter((x): x is string => !!x);
  for (const name of names) {
    const dev = resolveDevice(name, ctx.topo, {
      families: ["kubernetes_node"],
    });
    const lldp =
      (dev && ctx.topo.lldpHost.get(lower(dev.id))) ??
      (!ctx.topo.containsV2Devices
        ? ctx.topo.lldpHost.get(lower(name))
        : undefined);
    if (lldp) {
      const leaf = b.device(lldp.device, depth + 1);
      b.edge(from, leaf, port(lldp.device, lldp.port), "LLDP");
      b.exits.add(leaf);
      b.basis.add("host LLDP");
      return;
    }
  }
  b.known = false;
}

/** Infrastructure an endpoint needs to reach the fabric, from collected inventory only. */
export function accessFor(ep: ImpactEndpoint, ctx: PathContext): Access {
  const cached = ctx.cache.get(ep.key);
  if (cached) return cached;
  const b = new Builder(ctx);
  const g = ep.graph ?? (ep.ip ? graphNodeFor(ctx, ep.ip) : undefined);
  const refs = [
    ep.key,
    ...(ep.ip ? [`ip:${lower(ep.ip)}`] : []),
    ...(g ? [g.id] : []),
  ];
  const start = b.node(
    `ep:${ep.key}`,
    ep.name ?? g?.label ?? ep.ip ?? ep.key,
    "endpoint",
    refs,
    0,
  );
  const hostName =
    g?.kind === "workload" || g?.endpoint_kind === "k8s_node_proxy"
      ? g.attributes?.node
      : ep.kind === "pod" || ep.kind === "k8s_hostnet_pod"
        ? ep.node
        : undefined;
  const kind = g?.endpoint_kind ?? ep.kind;
  if (hostName) {
    const cluster =
      g?.cluster ??
      (g?.id.startsWith("pod:") ? g.id.slice(4).split("/")[0] : ep.cluster);
    const hostGraph =
      ctx.graph?.nodes.find((n) => n.id === `node:${cluster}/${hostName}`) ??
      ctx.graph?.nodes.find(
        (n) => n.endpoint_kind === "k8s_node" && n.label === hostName,
      );
    const hostIp =
      hostGraph?.addresses?.[0] ?? ctx.k8sNodes.get(lower(hostName));
    const hostRefs = [
      `host:${lower(hostName)}`,
      ...(hostGraph ? [hostGraph.id] : []),
      ...(hostIp ? [`ip:${lower(hostIp)}`] : []),
    ];
    const h = b.node(`host:${lower(hostName)}`, hostName, "host", hostRefs, 1);
    b.edge(start, h, [], "pod on node");
    b.segments.push({ node: h, key: h });
    hostAccess(b, ctx, h, 1, { name: hostName, ip: hostIp, graph: hostGraph });
  } else if (
    kind === "k8s_service" ||
    kind === "external" ||
    kind === "unresolved"
  ) {
    b.known = false;
  } else {
    hostAccess(b, ctx, start, 0, { name: ep.name, ip: ep.ip, graph: g });
  }
  const access: Access = {
    start,
    nodes: b.nodes,
    edges: b.edges,
    exits: [...b.exits],
    known: b.known && b.exits.size > 0,
    basis: [...b.basis],
    segments: b.segments,
  };
  ctx.cache.set(ep.key, access);
  return access;
}

/** Switches that may forward between fabric attachments (never controllers or FIs). */
const transit = (ctx: PathContext, id: string) => {
  const d = ctx.devByKey.get(id);
  return !!d && d.kind === "switch" && d.role !== "controller";
};

export interface FabricPath {
  /** Equal-cost layers between the two attachments; one layer means a shared (vPC) switch set. */
  layers: string[][];
  /** Spines a fabric-crossing conversation may use when one side is unknown. */
  core: string[];
}

export function fabricBetween(
  ctx: PathContext,
  from: string[],
  to: string[],
): FabricPath {
  if (!from.length) return { layers: [], core: [] };
  if (!to.length) {
    const core = new Set<string>();
    for (const f of from)
      for (const n of ctx.topo.adjacency.get(f) ?? [])
        if (transit(ctx, n.to) && ctx.devByKey.get(n.to)?.role === "spine")
          core.add(n.to);
    return { layers: [], core: [...core].sort() };
  }
  const layers =
    fabricLayersMulti(ctx.topo, from, to)?.map((l) => l.ids.map(lower)) ?? [];
  return { layers, core: [] };
}

/** Undirected BFS over the conversation's candidate graph minus failed nodes and edges. */
export function reachable(
  adj: Map<string, string[]>,
  from: string,
  goal: (id: string) => boolean,
  dead: (id: string) => boolean,
): boolean {
  if (dead(from)) return false;
  const seen = new Set([from]);
  const queue = [from];
  for (let i = 0; i < queue.length; i++) {
    const cur = queue[i];
    if (goal(cur)) return true;
    for (const next of adj.get(cur) ?? [])
      if (!seen.has(next) && !dead(next)) {
        seen.add(next);
        queue.push(next);
      }
  }
  return false;
}

export function fabricAdjacency(ctx: PathContext): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const [a, list] of ctx.topo.adjacency) {
    if (!transit(ctx, a)) continue;
    adj.set(
      a,
      list.filter((n) => transit(ctx, n.to)).map((n) => n.to),
    );
  }
  return adj;
}

export const isPublic = (ip?: string) => {
  if (!ip || !isIp(ip) || ip.includes(":")) return false;
  const [a, b] = ip.split(".").map(Number);
  return !(
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b < 32) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b < 128) ||
    (a === 169 && b === 254)
  );
};
