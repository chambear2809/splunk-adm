import { parseObserver } from "../topology";
import { inSubnet, normIface, type ImpactElement, type Tier } from "./elements";
import {
  accessFor,
  deviceLabel,
  fabricAdjacency,
  fabricBetween,
  reachable,
  type Access,
  type ImpactEndpoint,
  type PathContext,
  type PathNode,
} from "./paths";

export type Severity = "outage" | "degraded" | "unknown" | "unaffected";
export const SEVERITY_RANK: Record<Severity, number> = {
  unaffected: 0,
  degraded: 1,
  unknown: 2,
  outage: 3,
};
export type Evidence = "observed" | "inferred";

export interface ImpactConversation {
  /** Graph edge ID (map/demo) or src|dst|port|protocol (live). */
  id: string;
  src: ImpactEndpoint;
  dst: ImpactEndpoint;
  port?: number;
  protocol: string;
  bytes?: number;
  flows: number;
  /** Observer strings `<source>:<device>[:<in>><out>]`. */
  observers: string[];
  app?: string;
  /** Service frontend: backend pods it forwards to (replicas). */
  backends?: ImpactEndpoint[];
  /** Direction detail of a merged conversation (client → listener, listener → client). */
  bytesFwd?: number;
  bytesRev?: number;
  directions?: "both" | "forward" | "reverse";
  firstSeen?: number;
  lastSeen?: number;
  /** Applications on node-address traffic: Hubble-observed or hosted-on (inferred). */
  apps?: { name: string; basis: "hubble" | "hosted" }[];
}

export interface Classified {
  conv: ImpactConversation;
  severity: Severity;
  /** observed: a collector at a failed element exported this conversation. */
  traversal: Evidence;
  alternate: string[];
  alternateEvidence?: Evidence;
  /** Terse reason, e.g. "single-homed", "vPC peer", "ECMP", "endpoint down". */
  reason: string;
  /** Failed elements on the candidate path. */
  failedAt: string[];
}

/** A set of failed elements compiled for fast matching. */
export interface Failure {
  elements: ImpactElement[];
  devices: Set<string>;
  refs: Set<string>;
  ifaces: { device?: string; name: string }[];
  endpoint: (ep: ImpactEndpoint) => boolean;
  ref: (ref: string) => boolean;
  port: (port: string) => boolean;
}

const lower = (s?: string) => s?.trim().toLowerCase() ?? "";

export function compileFailure(elements: ImpactElement[]): Failure {
  const devices = new Set<string>();
  const refs = new Set<string>();
  const ifaces: Failure["ifaces"] = [];
  for (const e of elements) {
    for (const p of e.ports ?? []) {
      const at = p.lastIndexOf("|");
      ifaces.push({ device: p.slice(0, at), name: p.slice(at + 1) });
    }
    if (e.kind === "interface") {
      const name = normIface(e.iface);
      if (e.devices.size)
        for (const d of e.devices) ifaces.push({ device: d, name });
      else ifaces.push({ name });
      continue;
    }
    for (const d of e.devices) devices.add(d);
    for (const r of e.endpoints)
      refs.add(lower(r).startsWith("ip:") ? lower(r) : r);
  }
  const apps = elements.filter((e) => e.app).map((e) => lower(e.app));
  const epgs = elements.filter((e) => e.epg).map((e) => lower(e.epg));
  const subnets = elements.flatMap((e) => (e.subnet ? [e.subnet] : []));
  const ref = (r: string) =>
    devices.has(r) ||
    refs.has(r) ||
    (r.startsWith("ip:") && subnets.some((s) => inSubnet(r.slice(3), s)));
  const endpoint = (ep: ImpactEndpoint) => {
    if (ref(ep.key) || (ep.ip && ref(`ip:${lower(ep.ip)}`))) return true;
    if (ep.graph && refs.has(ep.graph.id)) return true;
    const app = lower(ep.app ?? ep.graph?.attributes?.owner);
    if (app && apps.includes(app)) return true;
    const a = ep.graph?.attributes;
    const epg = lower(ep.epg ?? a?.epg);
    const full = a ? lower([a.tenant, a.app_profile, a.epg].join("|")) : "";
    return !!epg && (epgs.includes(epg) || epgs.includes(full));
  };
  const port = (p: string) => {
    const [device, name] = [
      p.slice(0, p.lastIndexOf("|")),
      p.slice(p.lastIndexOf("|") + 1),
    ];
    return ifaces.some(
      (i) => i.name === name && (!i.device || i.device === device),
    );
  };
  return { elements, devices, refs, ifaces, endpoint, ref, port };
}

/** Candidate path of one endpoint pair, independent of what fails. */
export interface PairPath {
  a: Access;
  b: Access;
  nodes: Map<string, PathNode>;
  /** Live (non-failed) edge list: [a, b, ports]. */
  edges: { a: string; b: string; ports: string[] }[];
  /** Node IDs that may carry the conversation. */
  cand: Set<string>;
  /** Equal-choice groups among candidates (same side and depth, or one fabric layer). */
  groups: string[][];
  /** Locally switched on one host segment. */
  local: boolean;
  core: string[];
}

const sideGroups = (acc: Access, limit: number) => {
  const by = new Map<number, string[]>();
  for (const n of acc.nodes.values())
    if (n.depth <= limit) by.set(n.depth, [...(by.get(n.depth) ?? []), n.id]);
  return [...by.values()];
};

export function pairPath(
  src: ImpactEndpoint,
  dst: ImpactEndpoint,
  ctx: PathContext,
): PairPath {
  const a = accessFor(src, ctx);
  const b = accessFor(dst, ctx);
  const nodes = new Map<string, PathNode>(a.nodes);
  for (const [id, n] of b.nodes) if (!nodes.has(id)) nodes.set(id, n);
  const edges = [...a.edges, ...b.edges].map((e) => ({
    a: e.a,
    b: e.b,
    ports: e.ports,
  }));
  const shared = [...a.nodes.keys()].filter((id) => b.nodes.has(id));
  // One Kubernetes node, or one host's VDS on one VLAN: switched locally.
  const seg = a.segments.find((s) => b.segments.some((t) => t.key === s.key));
  const local = !!seg;
  const cand = new Set<string>();
  const groups: string[][] = [];
  let core: string[] = [];
  if (seg) {
    const cutA = a.nodes.get(seg.node)!.depth;
    const cutB = b.nodes.get(seg.node)!.depth;
    for (const n of a.nodes.values()) if (n.depth <= cutA) cand.add(n.id);
    for (const n of b.nodes.values()) if (n.depth <= cutB) cand.add(n.id);
  } else if (shared.length) {
    const cutA = Math.max(...shared.map((id) => a.nodes.get(id)!.depth));
    const cutB = Math.max(...shared.map((id) => b.nodes.get(id)!.depth));
    for (const n of a.nodes.values()) if (n.depth <= cutA) cand.add(n.id);
    for (const n of b.nodes.values()) if (n.depth <= cutB) cand.add(n.id);
    groups.push(...sideGroups(a, cutA), ...sideGroups(b, cutB));
  } else {
    for (const id of a.nodes.keys()) cand.add(id);
    for (const id of b.nodes.keys()) cand.add(id);
    groups.push(...sideGroups(a, Infinity), ...sideGroups(b, Infinity));
    const known = a.known ? a : b.known ? b : undefined;
    const fabric =
      a.known && b.known
        ? fabricBetween(ctx, a.exits, b.exits)
        : known
          ? fabricBetween(ctx, known.exits, [])
          : { layers: [], core: [] };
    for (const layer of fabric.layers) {
      groups.push(layer);
      for (const id of layer) {
        cand.add(id);
        if (!nodes.has(id))
          nodes.set(id, {
            id,
            label: deviceLabel(ctx, id),
            tier: tierOfId(ctx, id),
            refs: [id],
            depth: 99,
          });
      }
    }
    core = fabric.core;
    if (core.length) groups.push(core);
    for (const id of core) {
      cand.add(id);
      if (!nodes.has(id))
        nodes.set(id, {
          id,
          label: deviceLabel(ctx, id),
          tier: "spine",
          refs: [id],
          depth: 99,
        });
    }
  }
  return { a, b, nodes, edges, cand, groups, local, core };
}

const tierOfId = (ctx: PathContext, id: string): Tier => {
  const d = ctx.devByKey.get(id);
  return d?.role === "spine" ? "spine" : d?.role === "leaf" ? "leaf" : "switch";
};

/** Lower-case device keys that exported or logged this conversation. */
export function observedKeys(
  conv: ImpactConversation,
  ctx: PathContext,
): Set<string> {
  const out = new Set<string>();
  for (const o of conv.observers)
    for (const p of parseObserver(o, ctx.topo)) {
      const k = lower(p.key);
      out.add(k);
      // A VDS instance key is `<switch>@<host>`: the host exported it.
      if (k.includes("@")) for (const part of k.split("@")) out.add(part);
    }
  return out;
}

interface PairResult {
  severity: Severity;
  alternate: string[];
  reason: string;
  failedAt: string[];
}

function classifyPair(
  p: PairPath,
  src: ImpactEndpoint,
  dst: ImpactEndpoint,
  f: Failure,
  ctx: PathContext,
  fabAdj: Map<string, string[]>,
  observedAt: boolean,
): PairResult {
  const dead = (id: string) => {
    const n = p.nodes.get(id);
    const refs = n?.refs ?? [id];
    if (refs.some(f.ref)) return true;
    if (id === p.a.start && f.endpoint(src)) return true;
    if (id === p.b.start && f.endpoint(dst)) return true;
    return false;
  };
  const deadEdges = p.edges.filter((e) => e.ports.some(f.port));
  const failedAt = [
    ...new Set([
      ...[...p.cand].filter(dead).map((id) => p.nodes.get(id)?.label ?? id),
      ...deadEdges
        .filter((e) => p.cand.has(e.a) && p.cand.has(e.b))
        .flatMap((e) => e.ports.filter(f.port).map((x) => x.split("|")[1])),
    ]),
  ];
  if (dead(p.a.start) || dead(p.b.start))
    return {
      severity: "outage",
      alternate: [],
      reason: "endpoint down",
      failedAt,
    };
  if (!failedAt.length && !observedAt)
    return { severity: "unaffected", alternate: [], reason: "", failedAt };
  // Live adjacency: access edges that did not fail, plus fabric transit.
  const adj = new Map<string, string[]>();
  const link = (x: string, y: string) => {
    adj.set(x, [...(adj.get(x) ?? []), y]);
    adj.set(y, [...(adj.get(y) ?? []), x]);
  };
  for (const e of p.edges) if (!e.ports.some(f.port)) link(e.a, e.b);
  for (const [x, list] of fabAdj) adj.set(x, [...(adj.get(x) ?? []), ...list]);
  const alternates = () => {
    const out = new Set<string>();
    for (const g of p.groups) {
      if (!g.some(dead)) continue;
      for (const id of g)
        if (!dead(id)) out.add(p.nodes.get(id)?.label ?? deviceLabel(ctx, id));
    }
    for (const e of deadEdges) {
      // A parallel uplink from the same node survives (another vmnic or vPC leg).
      for (const o of p.edges)
        if (o !== e && o.a === e.a && !o.ports.some(f.port)) {
          // Name the surviving leg by its far end: "leaf102 eth1/22".
          const far = o.ports.at(-1);
          const [dev, name] = far
            ? [
                far.slice(0, far.lastIndexOf("|")),
                far.slice(far.lastIndexOf("|") + 1),
              ]
            : [];
          out.add(
            dev && name
              ? `${deviceLabel(ctx, dev)} ${name}`
              : (p.nodes.get(o.b)?.label ?? o.b),
          );
        }
    }
    // Every leg of a node is down (a whole vPC): its group peer carries the traffic.
    if (!out.size)
      for (const e of deadEdges)
        for (const g of p.groups)
          if (g.includes(e.a))
            for (const id of g)
              if (id !== e.a && !dead(id))
                out.add(p.nodes.get(id)?.label ?? deviceLabel(ctx, id));
    return [...out];
  };
  const reason = (alt: string[]) => {
    const tiers = new Set(
      [...p.cand].filter(dead).map((id) => p.nodes.get(id)?.tier),
    );
    if (deadEdges.length && !tiers.size)
      return alt.length ? "other uplink" : "single uplink";
    if (tiers.has("spine")) return "ECMP";
    if (tiers.has("fi")) return "FI pair";
    if (tiers.has("leaf"))
      return p.a.basis
        .concat(p.b.basis)
        .some((b) => b.startsWith("vPC") || b.startsWith("FI"))
        ? "vPC peer"
        : "other leaf";
    return "alternate path";
  };
  if ((p.a.known && p.b.known) || p.local) {
    const ok = p.local
      ? reachable(adj, p.a.start, (id) => id === p.b.start, dead)
      : fabricReach(p, dead, f, fabAdj);
    if (!ok)
      return {
        severity: "outage",
        alternate: [],
        reason: singleReason(p, dead),
        failedAt,
      };
    if (!failedAt.length)
      return {
        severity: "unknown",
        alternate: [],
        reason: "observed at element; path not modelled",
        failedAt,
      };
    const alt = alternates();
    return {
      severity: "degraded",
      alternate: alt,
      reason: reason(alt),
      failedAt,
    };
  }
  const known = p.a.known ? p.a : p.b.known ? p.b : undefined;
  if (!known)
    return {
      severity: failedAt.length || observedAt ? "unknown" : "unaffected",
      alternate: [],
      reason: "attachment not collected",
      failedAt,
    };
  // One side unknown (external, overlay, uncollected): the known side must still
  // reach a live attachment, and a live spine when the fabric is crossed.
  const live = (id: string) => !dead(id);
  const ok = reachable(
    adj,
    known.start,
    (id) =>
      known.exits.includes(id) &&
      (!p.core.length ||
        (fabAdj.get(id) ?? []).some((s) => p.core.includes(s) && live(s))),
    dead,
  );
  if (!ok)
    return {
      severity: "outage",
      alternate: [],
      reason: singleReason(p, dead),
      failedAt,
    };
  const onKnown =
    [...known.nodes.keys(), ...p.core].some(dead) || deadEdges.length > 0;
  if (!onKnown)
    return {
      severity: "unknown",
      alternate: [],
      reason: "other side not collected",
      failedAt,
    };
  const alt = alternates();
  return {
    severity: "degraded",
    alternate: alt,
    reason: reason(alt),
    failedAt,
  };
}

/** Each side reaches a live attachment on its own; the attachments meet or are joined by the fabric. */
function fabricReach(
  p: PairPath,
  dead: (id: string) => boolean,
  f: Failure,
  fabAdj: Map<string, string[]>,
): boolean {
  const exitsOf = (acc: Access) => {
    const adj = new Map<string, string[]>();
    for (const e of acc.edges)
      if (!e.ports.some(f.port)) {
        adj.set(e.a, [...(adj.get(e.a) ?? []), e.b]);
        adj.set(e.b, [...(adj.get(e.b) ?? []), e.a]);
      }
    return acc.exits.filter(
      (x) => !dead(x) && reachable(adj, acc.start, (id) => id === x, dead),
    );
  };
  const xa = exitsOf(p.a);
  const xb = new Set(exitsOf(p.b));
  if (!xa.length || !xb.size) return false;
  if (xa.some((x) => xb.has(x))) return true;
  return xa.some((x) => reachable(fabAdj, x, (id) => xb.has(id), dead));
}

function singleReason(p: PairPath, dead: (id: string) => boolean): string {
  const tiers = [...p.cand].filter(dead).map((id) => p.nodes.get(id)?.tier);
  if (tiers.includes("hypervisor") || tiers.includes("host"))
    return "host down";
  if (tiers.includes("vswitch")) return "virtual switch down";
  const both = p.groups.some((g) => g.length > 1 && g.every(dead));
  return both ? "all redundant members down" : "single-homed";
}

/** The endpoint's own attachment still reaches a live fabric switch (its peer may not). */
export function sideReachesFabric(
  acc: Access,
  ep: ImpactEndpoint,
  f: Failure,
): boolean {
  if (f.endpoint(ep)) return false;
  if (!acc.known) return true;
  const dead = (id: string) => (acc.nodes.get(id)?.refs ?? [id]).some(f.ref);
  const adj = new Map<string, string[]>();
  for (const e of acc.edges)
    if (!e.ports.some(f.port)) {
      adj.set(e.a, [...(adj.get(e.a) ?? []), e.b]);
      adj.set(e.b, [...(adj.get(e.b) ?? []), e.a]);
    }
  return reachable(adj, acc.start, (id) => acc.exits.includes(id), dead);
}

export interface Classifier {
  ctx: PathContext;
  classify: (conv: ImpactConversation, f: Failure) => Classified;
  path: (conv: ImpactConversation) => PairPath[];
}

/** Classifies conversations against failures; paths and observations are cached per conversation. */
export function classifier(ctx: PathContext): Classifier {
  const fabAdj = fabricAdjacency(ctx);
  const paths = new Map<string, PairPath[]>();
  const observed = new Map<string, Set<string>>();
  const legs = (c: ImpactConversation) =>
    c.backends?.length
      ? c.backends.map((b) => [c.src, b] as const)
      : [[c.src, c.dst] as const];
  const path = (c: ImpactConversation) => {
    let list = paths.get(c.id);
    if (!list) {
      list = legs(c).map(([s, d]) => pairPath(s, d, ctx));
      paths.set(c.id, list);
    }
    return list;
  };
  const classify = (c: ImpactConversation, f: Failure): Classified => {
    let seen = observed.get(c.id);
    if (!seen) {
      seen = observedKeys(c, ctx);
      observed.set(c.id, seen);
    }
    const observedAt = [...f.devices].some((d) => seen!.has(d));
    const results = legs(c).map(([s, d], i) =>
      classifyPair(path(c)[i], s, d, f, ctx, fabAdj, observedAt),
    );
    let r: PairResult;
    if (results.length > 1) {
      // A Service with several backends survives while one backend is reachable.
      const alive = results
        .map((x, i) => [x, c.backends![i]] as const)
        .filter(([x]) => x.severity !== "outage");
      const worst = results.reduce((w, x) =>
        SEVERITY_RANK[x.severity] > SEVERITY_RANK[w.severity] ? x : w,
      );
      const failedAt = [...new Set(results.flatMap((x) => x.failedAt))];
      // A pod with replicas: its own leg decides unless it is out.
      const replica = c.backends![0].key === c.dst.key;
      if (replica && results[0].severity !== "outage") r = results[0];
      else if (!alive.length)
        r = {
          ...worst,
          failedAt,
          reason: replica ? "all replicas down" : "all backends down",
        };
      else if (replica)
        r = {
          severity: "degraded",
          alternate: alive.map(([, b]) => b.name ?? b.ip ?? b.key),
          reason: "other replica",
          failedAt,
        };
      else if (worst.severity === "outage")
        r = {
          severity: "degraded",
          alternate: alive.map(([, b]) => b.name ?? b.ip ?? b.key),
          reason: "other backend",
          failedAt,
        };
      else r = { ...worst, failedAt };
    } else r = results[0];
    const alternateEvidence = r.alternate.length
      ? r.alternate.some((label) =>
          [...seen!].some((k) => lower(deviceLabel(ctx, k)) === lower(label)),
        )
        ? "observed"
        : "inferred"
      : undefined;
    return {
      conv: c,
      severity: r.severity,
      traversal:
        observedAt || r.reason === "endpoint down" ? "observed" : "inferred",
      alternate: r.alternate,
      ...(alternateEvidence ? { alternateEvidence } : {}),
      reason: r.reason,
      failedAt: r.failedAt,
    };
  };
  return { ctx, classify, path };
}
