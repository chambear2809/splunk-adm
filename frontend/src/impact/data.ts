import type { Graph, GraphNode } from "../graph";
import type { SearchClient } from "../data/searchClient";
import { requireNoSearchErrors } from "../data/searchClient";
import {
  indexTopology,
  resolveDevice,
  rowsToTopology,
  type Topology,
  type TopologyIndex,
} from "../topology";
import type { ImpactConversation } from "./classify";
import {
  isIp,
  resolveElement,
  type ImpactElement,
  type PortChannel,
} from "./elements";
import {
  accessFor,
  pathContext,
  type ImpactEndpoint,
  type PathContext,
} from "./paths";

export const MAX_IMPACT_ROWS = 2500;
export const IMPACT_INVENTORY_SEARCH = "| `adm_impact_inventory`";
const MAX_OBSERVERS = 64;
const MAX_ENDPOINTS = 256;
const OBS = /^[A-Za-z0-9_.:/-]{1,128}$/;

const lower = (s?: string) => s?.trim().toLowerCase() ?? "";
const str = (v: unknown): string | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === "string" && x.trim()
    ? x.trim()
    : typeof x === "number"
      ? String(x)
      : undefined;
};
const list = (v: unknown): string[] =>
  (Array.isArray(v) ? v : v == null ? [] : [v])
    .map(str)
    .filter((x): x is string => !!x);
const num = (v: unknown) => {
  const n = Number(str(v));
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};

/** One element's search anchors: exporters at or around it, and addresses behind it. */
export interface Anchors {
  observers: string[];
  endpoints: string[];
}

/** The SPL for anchors; tokens are validated, never quoted into free text. */
export function impactSearch(a: Anchors, source?: "raw" | "summary"): string {
  const obs = [...new Set(a.observers.filter((o) => OBS.test(o)))].slice(
    0,
    MAX_OBSERVERS,
  );
  const eps = [...new Set(a.endpoints.filter(isIp))].slice(0, MAX_ENDPOINTS);
  const args = [
    obs.join(";") || "-",
    eps.join(";") || "-",
    ...(source ? [source] : []),
  ];
  return `| \`adm_impact_element(${args.join(",")})\``;
}

/** VMs (by vNIC IP) whose collected access path includes a failed element. */
export function anchorsFor(
  elements: ImpactElement[],
  ctx: PathContext,
): Anchors {
  const obs = new Set<string>();
  const eps = new Set<string>();
  const devices = new Set(elements.flatMap((e) => [...e.devices]));
  const ifaces = elements.filter((e) => e.kind === "interface");
  const members = new Set(elements.flatMap((e) => e.ports ?? []));
  // A vPC's member leaves export the flows that cross it.
  for (const p of members) {
    const d = ctx.devByKey.get(p.slice(0, p.lastIndexOf("|")));
    if (d?.mgmt_ip && isIp(d.mgmt_ip)) obs.add(d.mgmt_ip);
    if (d?.aci_node) obs.add(d.aci_node);
  }
  for (const e of elements) {
    for (const r of e.endpoints) if (r.startsWith("ip:")) eps.add(r.slice(3));
    for (const id of e.devices) {
      const d = ctx.devByKey.get(id);
      if (!d) continue;
      if (d.mgmt_ip && isIp(d.mgmt_ip)) obs.add(d.mgmt_ip);
      // ACI ACL logs are keyed by pod-N/node-N.
      if (d.role === "leaf" && d.aci_node) obs.add(d.aci_node);
      for (const o of d.ipfix_observers ?? []) obs.add(o.split("|")[0]);
      // Spines export nothing: their leaves see every fabric-crossing flow.
      if (d.role === "spine")
        for (const n of ctx.topo.adjacency.get(id) ?? []) {
          const leaf = ctx.devByKey.get(n.to);
          if (leaf?.role === "leaf" && leaf.mgmt_ip) obs.add(leaf.mgmt_ip);
        }
    }
  }
  const seenVm = new Set<string>();
  for (const ports of ctx.topo.virtualPorts.values())
    for (const p of ports) {
      if (!p.ip || seenVm.has(p.vm)) continue;
      seenVm.add(p.vm);
      const acc = accessFor(
        { key: `ip:${lower(p.ip)}`, ip: p.ip, kind: "vm", name: p.vm_name },
        ctx,
      );
      const hit =
        [...acc.nodes.values()].some((n) =>
          n.refs.some((r) => devices.has(r)),
        ) ||
        acc.edges.some((edge) =>
          edge.ports.some(
            (x) =>
              members.has(x) ||
              ifaces.some(
                (i) =>
                  x.endsWith(`|${i.iface}`) &&
                  (!i.devices.size || i.devices.has(x.split("|")[0])),
              ),
          ),
        );
      if (!hit) continue;
      eps.add(p.ip);
      // The host's VDS IPFIX export sees the VM's flows too.
      if (p.hypervisor) {
        const hv = ctx.devByKey.get(lower(p.hypervisor));
        if (hv?.mgmt_ip && isIp(hv.mgmt_ip)) obs.add(hv.mgmt_ip);
      }
    }
  return {
    observers: [...obs].slice(0, MAX_OBSERVERS),
    endpoints: [...eps].slice(0, MAX_ENDPOINTS),
  };
}

const KIND_ORDER = [
  "pod",
  "k8s_hostnet_pod",
  "k8s_service",
  "vm",
  "k8s_node",
  "endpoint",
];
const REPLICABLE = new Set(["Deployment", "ReplicaSet", "DaemonSet"]);
// A hostNetwork pod shares its node's address: the address is the node.
const pickKind = (kinds: string[]) =>
  kinds.includes("k8s_node") && kinds.includes("k8s_hostnet_pod")
    ? "k8s_node"
    : (KIND_ORDER.find((k) => kinds.includes(k)) ?? kinds[0]);

export interface HubbleApps {
  srcNode?: string;
  dstNode: string;
  srcApp?: string;
  dstApp: string;
  flows: number;
  firstSeen?: number;
  lastSeen?: number;
  ports: number[];
}
/** Tunnel ports: the inner pod port is hidden, so a node-pair match is enough. */
const OVERLAY_PORTS = new Set([4789, 8472, 8473, 6081]);
const HOSTED_LIMIT = 12;

/**
 * Applications for conversations between node addresses (overlay traffic hides
 * pod addresses): Hubble workload pairs on the same node pair with overlapping
 * time (and the same port unless the conversation is a tunnel), else the
 * applications hosted on either node in the window (inferred). Nodes are
 * matched by name within their cluster only.
 */
export function attributeApps(
  conversations: ImpactConversation[],
  hubble: readonly HubbleApps[],
  hosted: ReadonlyMap<string, string[]>,
): void {
  const nodeOf = (e: ImpactEndpoint) =>
    e.kind === "k8s_node" ? lower(e.node ?? e.name) : undefined;
  const hostedOn = (e: ImpactEndpoint) => {
    const n = nodeOf(e);
    if (!n) return [];
    return (
      hosted.get(`${lower(e.cluster)}|${n}`) ??
      (e.cluster ? [] : (hosted.get(`|${n}`) ?? []))
    );
  };
  for (const c of conversations) {
    if (c.app || c.dst.app || c.src.app) continue;
    const a = nodeOf(c.src);
    const b = nodeOf(c.dst);
    if (!a && !b) continue;
    const overlaps = (h: HubbleApps) =>
      c.firstSeen === undefined ||
      h.lastSeen === undefined ||
      h.firstSeen === undefined ||
      c.lastSeen === undefined ||
      (h.firstSeen <= c.lastSeen && h.lastSeen >= c.firstSeen);
    const portOk = (h: HubbleApps) =>
      c.port === undefined ||
      OVERLAY_PORTS.has(c.port) ||
      h.ports.includes(c.port);
    // The Hubble source node is known only when its pod address has identity;
    // otherwise the receiving node must be one end of the conversation.
    const pairOk = (h: HubbleApps) =>
      h.srcNode
        ? !!a &&
          !!b &&
          ((lower(h.srcNode) === a && lower(h.dstNode) === b) ||
            (lower(h.srcNode) === b && lower(h.dstNode) === a))
        : lower(h.dstNode) === b || (!!a && !!b && lower(h.dstNode) === a);
    const seen = hubble
      .filter((h) => pairOk(h) && overlaps(h) && portOk(h))
      .sort((x, y) => y.flows - x.flows);
    if (seen.length) {
      c.apps = [...new Set(seen.map((h) => h.dstApp))]
        .slice(0, HOSTED_LIMIT)
        .map((name) => ({ name, basis: "hubble" as const }));
      continue;
    }
    // Hosted-on: the listener's node owns the service port (inferred).
    const inferred = [
      ...new Set(hostedOn(c.dst).length ? hostedOn(c.dst) : hostedOn(c.src)),
    ];
    if (inferred.length)
      c.apps = inferred
        .slice(0, HOSTED_LIMIT)
        .map((name) => ({ name, basis: "hosted" as const }));
  }
}

/** adm_impact_port_channels rows → leaf port-channels with canonical leaf IDs. */
export function portChannelRows(
  rows: readonly unknown[],
  topo: TopologyIndex,
): PortChannel[] {
  const out: PortChannel[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type !== "port_channel") continue;
    const node = str(r.node);
    const id = str(r.port_channel);
    const members = list(r.members);
    if (!node || !id || !members.length || !/^pod-\d+\/node-\d+$/.test(node))
      continue;
    const leaf = resolveDevice(node, topo);
    if (!leaf) continue;
    const policies = [...new Set(list(r.policy))];
    const snapshotTime = num(r.snapshot_time);
    out.push({
      device: lower(leaf.id),
      id,
      members,
      ...(policies.length === 1 ? { policy: policies[0] } : {}),
      ...(snapshotTime !== undefined ? { snapshotTime } : {}),
      ...(str(r.after_window) === "1" ? { afterWindow: true } : {}),
    });
  }
  return out;
}

export interface LiveImpactRows {
  conversations: ImpactConversation[];
  k8sNodes: Map<string, string>;
  total: number;
  truncated: boolean;
  capped: boolean;
  source?: string;
}

/** adm_impact_element rows → conversations. Rows are untrusted; invalid rows are skipped. */
export function rowsToImpact(rows: unknown): LiveImpactRows {
  if (!Array.isArray(rows)) throw new Error("Impact rows must be an array.");
  const conversations: ImpactConversation[] = [];
  const k8sNodes = new Map<string, string>();
  let total = 0;
  let truncated = false;
  let capped = false;
  let source: string | undefined;
  const hubble: HubbleApps[] = [];
  const hosted = new Map<string, string[]>();
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type === "hosted") {
      const node = str(r.node);
      const apps = list(r.hosted_apps);
      if (node && apps.length)
        hosted.set(`${lower(str(r.cluster))}|${lower(node)}`, apps);
      continue;
    }
    if (r.row_type === "hubble_apps") {
      const dstNode = str(r.dst_node);
      const dstApp = str(r.dst_app);
      if (!dstNode || !dstApp) continue;
      const srcNode = str(r.src_node);
      const srcApp = str(r.src_app);
      hubble.push({
        dstNode,
        dstApp,
        flows: num(r.flows) ?? 0,
        ports: list(r.dports)
          .map(Number)
          .filter((n) => Number.isInteger(n)),
        ...(srcNode && srcNode !== "-" ? { srcNode } : {}),
        ...(srcApp && srcApp !== "-" ? { srcApp } : {}),
        ...(num(r.first_seen) !== undefined
          ? { firstSeen: num(r.first_seen) }
          : {}),
        ...(num(r.last_seen) !== undefined
          ? { lastSeen: num(r.last_seen) }
          : {}),
      });
      continue;
    }
    if (r.row_type === "k8s_node") {
      const name = str(r.entity_name);
      const ip = str(r.ip);
      if (name && ip && isIp(ip)) k8sNodes.set(lower(name), ip);
      continue;
    }
    if (r.row_type !== "conversation") continue;
    const src = str(r.src);
    const dst = str(r.dst);
    const protocol = str(r.protocol);
    if (!src || !dst || !protocol || !isIp(src) || !isIp(dst)) continue;
    total = num(r.total_conversations) ?? total;
    truncated ||= str(r.truncated) === "1";
    capped ||= str(r.records_capped) === "1";
    source ??= str(r.source);
    const end = (side: "src" | "dst"): ImpactEndpoint => {
      const ip = side === "src" ? src : dst;
      const e: ImpactEndpoint = { key: `ip:${lower(ip)}`, ip };
      const name = str(r[`${side}_name`]);
      const kind = pickKind(list(r[`${side}_kinds`]));
      const node = str(r[`${side}_node`]);
      const cluster = str(r[`${side}_cluster`]);
      const epg = str(r[`${side}_epg`]);
      if (name) e.name = name;
      if (kind) e.kind = kind;
      if (node) e.node = node;
      if (cluster) e.cluster = cluster;
      if (epg) e.epg = epg;
      return e;
    };
    const s = end("src");
    const d = end("dst");
    // An owner of a hostNetwork pod does not own its node's other traffic.
    const sideApp = (side: "src" | "dst", e: ImpactEndpoint) =>
      e.kind === "k8s_node" ? undefined : str(r[`${side}_app`]);
    const sided = "src_app" in r || "dst_app" in r;
    const sa = sideApp("src", s);
    const da = sideApp("dst", d);
    if (sa) s.app = sa;
    if (da) d.app = da;
    const app = sided ? (da ?? sa) : str(r.app);
    if (!sided && app) d.app = app;
    const port = num(r.dest_port);
    const c: ImpactConversation = {
      id: `${src}|${dst}|${port ?? ""}|${protocol}`,
      src: s,
      dst: d,
      protocol,
      flows: num(r.flows) ?? 0,
      observers: list(r.observers),
      ...(port !== undefined ? { port } : {}),
      ...(num(r.bytes) !== undefined ? { bytes: num(r.bytes) } : {}),
      ...(app ? { app } : {}),
      ...(num(r.bytes_fwd) !== undefined ? { bytesFwd: num(r.bytes_fwd) } : {}),
      ...(num(r.bytes_rev) !== undefined ? { bytesRev: num(r.bytes_rev) } : {}),
      ...(["both", "forward", "reverse"].includes(str(r.directions) ?? "")
        ? { directions: str(r.directions) as "both" | "forward" | "reverse" }
        : {}),
      ...(num(r.first_seen) !== undefined
        ? { firstSeen: num(r.first_seen) }
        : {}),
      ...(num(r.last_seen) !== undefined ? { lastSeen: num(r.last_seen) } : {}),
    };
    // A replicated pod: its owner's replicas on other nodes are alternates.
    const owner = str(r.dst_owner);
    const replicaNodes = list(r.dst_replica_nodes).filter(
      (n) => lower(n) !== lower(d.node),
    );
    if (
      d.kind === "pod" &&
      owner &&
      REPLICABLE.has(str(r.dst_owner_kind) ?? "") &&
      replicaNodes.length
    )
      c.backends = [
        d,
        ...replicaNodes.slice(0, 8).map((n) => ({
          key: `replica:${owner}@${lower(n)}`,
          name: `${owner} on ${n}`,
          kind: "pod",
          node: n,
          ...(d.cluster ? { cluster: d.cluster } : {}),
          app: owner,
        })),
      ];
    conversations.push(c);
  }
  attributeApps(conversations, hubble, hosted);
  return {
    conversations,
    k8sNodes,
    total: Math.max(total, conversations.length),
    truncated,
    capped,
    ...(source ? { source } : {}),
  };
}

const graphEndpoint = (n: GraphNode): ImpactEndpoint => {
  const a = n.attributes ?? {};
  return {
    key: n.id,
    ...(n.addresses?.[0] ? { ip: n.addresses[0] } : {}),
    name: n.endpoint_kind === "k8s_service" ? (a.service ?? n.label) : n.label,
    kind: n.kind === "workload" ? "pod" : (n.endpoint_kind ?? n.kind),
    ...(a.owner || a.service || a.app_profile
      ? { app: a.owner ?? a.service ?? a.app_profile }
      : {}),
    ...(a.node ? { node: a.node } : {}),
    ...(n.cluster ? { cluster: n.cluster } : {}),
    ...(a.epg ? { epg: a.epg } : {}),
    graph: n,
  };
};

/** Network conversations of a map graph; a Service frontend carries its backends, a pod its replicas. */
export function graphConversations(graph: Graph): ImpactConversation[] {
  const node = new Map(graph.nodes.map((n) => [n.id, n]));
  const out: ImpactConversation[] = [];
  for (const e of graph.edges) {
    if (e.relationship !== "communicates_with") continue;
    const s = node.get(e.source);
    const t = node.get(e.target);
    if (!s || !t) continue;
    const dst = graphEndpoint(t);
    let backends: ImpactEndpoint[] | undefined;
    if (t.endpoint_kind === "k8s_service") {
      const ids = [
        ...new Set(
          graph.edges
            .filter(
              (f) => f.relationship === "forwards_to" && f.source === t.id,
            )
            .map((f) => f.target),
        ),
      ];
      backends = ids
        .map((id) => node.get(id))
        .filter((n): n is GraphNode => !!n)
        .map(graphEndpoint);
    } else if (t.kind === "workload" && t.attributes?.owner) {
      const replicas = graph.nodes.filter(
        (n) =>
          n.kind === "workload" &&
          n.id !== t.id &&
          n.attributes?.owner === t.attributes?.owner &&
          n.namespace === t.namespace &&
          n.cluster === t.cluster &&
          REPLICABLE.has(n.attributes?.owner_kind ?? ""),
      );
      if (replicas.length) backends = [dst, ...replicas.map(graphEndpoint)];
    }
    out.push({
      id: e.id,
      src: graphEndpoint(s),
      dst,
      protocol: e.transport ?? "ip",
      flows: e.count,
      observers: [
        ...(e.observers ?? []),
        ...(e.acl_leaf ? [`aci_acllog:${e.acl_leaf}`] : []),
      ],
      ...(e.server_port !== undefined ? { port: e.server_port } : {}),
      ...(e.bytes !== undefined ? { bytes: e.bytes } : {}),
      ...(dst.app ? { app: dst.app } : {}),
      ...(backends?.length ? { backends } : {}),
    });
  }
  return out;
}

/** Window length in hours for "/h" rates; undefined when it cannot be known. */
export function windowHours(
  earliest: string,
  latest = "now",
): number | undefined {
  const rel = (s: string) => {
    if (s === "now") return 0;
    const m = /^-(\d+)([smhdw])(?:@\w+)?$/.exec(s);
    if (!m) return undefined;
    const unit = { s: 1 / 3600, m: 1 / 60, h: 1, d: 24, w: 168 }[m[2] as "s"];
    return -Number(m[1]) * unit;
  };
  const e = rel(earliest),
    l = rel(latest);
  if (e !== undefined && l !== undefined) return l - e || undefined;
  const ne = Number(earliest),
    nl = Number(latest);
  if (Number.isFinite(ne) && Number.isFinite(nl) && nl > ne)
    return (nl - ne) / 3600;
  return undefined;
}

export interface ImpactData {
  topology: Topology;
  topo: TopologyIndex;
  ctx: PathContext;
  elements: ImpactElement[];
  conversations: ImpactConversation[];
  graph?: Graph;
  total: number;
  truncated: boolean;
  capped: boolean;
  hours?: number;
  source: string;
  search?: string;
  portChannels?: PortChannel[];
  /** Limits of this analysis the reader should see (e.g. unread members). */
  notes?: string[];
}

export function resolveAll(
  tokens: string[],
  topology: Topology,
  topo: TopologyIndex,
  graph?: Graph,
  portChannels: readonly PortChannel[] = [],
) {
  return tokens.map((t) =>
    resolveElement(t, topology, topo, graph, portChannels),
  );
}

/** Live: inventory, then one bounded impact search for every element together. */
export async function loadLiveImpact(opts: {
  tokens: string[];
  client: SearchClient;
  earliest: string;
  latest?: string;
  timezone?: string;
  signal: AbortSignal;
  loadBaseTopology: () => Promise<Topology>;
  merge: (base: Topology, rows: readonly unknown[]) => Topology;
}): Promise<ImpactData> {
  const { client, earliest, latest, timezone, signal } = opts;
  const run = (search: string, maxRows: number) =>
    client.search({
      search,
      earliest,
      latest,
      timezone,
      maxRows,
      allowEmpty: true,
      signal,
    });
  const [base, inventory] = await Promise.all([
    opts.loadBaseTopology(),
    run(IMPACT_INVENTORY_SEARCH, 20000).then(
      (r) => requireNoSearchErrors(r, "Impact inventory").rows,
    ),
  ]);
  const topology = opts.merge(base, inventory);
  const topo = indexTopology(topology);
  const ctx = pathContext(topo);
  const portChannels = portChannelRows(inventory, topo);
  const elements = resolveAll(
    opts.tokens,
    topology,
    topo,
    undefined,
    portChannels,
  );
  // Application and EPG members come from identity.
  const extra: string[] = [];
  const notes: string[] = [];
  for (const e of elements) {
    const name =
      e.kind === "app" || e.kind === "epg" ? (e.app ?? e.epg) : undefined;
    if (!name) continue;
    const member = impactMembersSearch(name);
    if (!member) {
      notes.push(
        memberNameNote(e.kind === "epg" ? "EPG" : "application", name),
      );
      continue;
    }
    const r = await run(member, 256);
    for (const row of r.rows) {
      const ip = str((row as Record<string, unknown>).ip);
      if (ip && isIp(ip)) {
        extra.push(ip);
        e.endpoints.add(`ip:${lower(ip)}`);
      }
    }
  }
  const anchors = anchorsFor(elements, ctx);
  anchors.endpoints.push(...extra);
  const search = impactSearch(anchors);
  const result = requireNoSearchErrors(
    await run(search, MAX_IMPACT_ROWS),
    "Impact",
  );
  const live = rowsToImpact(result.rows);
  const withNodes = pathContext(topo, undefined, live.k8sNodes);
  return {
    topology,
    topo,
    ctx: withNodes,
    elements,
    conversations: live.conversations,
    total: live.total,
    truncated: live.truncated,
    capped: live.capped,
    source: live.source ?? "raw",
    portChannels,
    search,
    ...(notes.length ? { notes } : {}),
  };
}

const MEMBER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/|-]{0,127}$/;

/** adm_impact_members search for an application or EPG name, or undefined
 * when the name is outside the macro's validated alphabet (e.g. it has spaces). */
export function impactMembersSearch(name: string): string | undefined {
  return MEMBER_NAME.test(name)
    ? `| \`adm_impact_members(${name})\``
    : undefined;
}

/** Why an application or EPG contributed no member addresses. */
export function memberNameNote(kind: string, name: string): string {
  return `Members of ${kind} "${name.slice(0, 80)}" were not read: names with spaces or characters other than letters, digits and . _ : / | - are not supported, so its addresses are not in this analysis.`;
}

/** Demo rows for the Impact page: map graph, vSphere overlay and the redundancy overlay. */
export function demoImpactTopology(
  base: Topology,
  overlay: readonly unknown[],
): Topology {
  const extra = rowsToTopology(
    overlay.filter((r) =>
      ["device", "link", "interface"].includes(
        String((r as Record<string, unknown>)?.row_type),
      ),
    ),
  );
  const replaced = new Set(
    extra.links
      .filter((l) => l.kind === "uplink" && l.hypervisor)
      .map((l) => lower(l.hypervisor)),
  );
  const ids = new Set(base.devices.map((d) => d.id));
  return {
    ...base,
    devices: [...base.devices, ...extra.devices.filter((d) => !ids.has(d.id))],
    links: [
      // The overlay re-cables these hosts: their direct uplinks are replaced.
      ...base.links
        .filter(
          (l) => !(l.kind === "uplink" && replaced.has(lower(l.hypervisor))),
        )
        .map((l) => {
          const vp = extra.links.find(
            (x) => x.kind === "virtual_port" && x.b_device === l.b_device,
          );
          return vp && l.kind === "virtual_port"
            ? {
                ...l,
                attach_nodes: vp.attach_nodes,
                attach_interface: vp.attach_interface,
              }
            : l;
        }),
      ...extra.links.filter((l) => l.kind !== "virtual_port"),
    ],
  };
}
