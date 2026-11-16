import {
  tunnelLabel,
  tunnelOf,
  type Graph,
  type GraphEdge,
  type GraphIndex,
  type GraphNode,
} from "./graph";
import { isUnknown } from "./glossary";
import type { GraphTruncation } from "./graph";
import { LOD_CARDS, STRAIGHT_ROUTE_EDGES } from "./scale/limits";
import { edgeVolume, strokeWidth } from "./scale/weight";

export type View = "network" | "services";
export type LaneKind =
  "sources" | "entry" | "application" | "dependencies" | "infrastructure";
export interface LaneLabel {
  kind: LaneKind;
  title: string;
  x: number;
  y: number;
  width: number;
}
export interface Item {
  /** Graph node ID, or `summary:<group>` for a collapsed pod list. */
  nodeId: string;
  /** Nodes represented by a collapsed summary row. */
  members?: string[];
  /** Summary text, e.g. "128 endpoints". */
  label?: string;
  groupId: string;
  role: "header" | "row" | "summary";
  x: number;
  y: number;
  w: number;
  h: number;
  column: number;
}
export interface Group {
  id: string;
  title: string;
  subtitle?: string;
  kind:
    | "service"
    | "workloads"
    | "namespace"
    | "epg"
    | "endpoints"
    | "nodes"
    | "frontdoor";
  lane: LaneKind;
  headerNodeId?: string;
  x: number;
  y: number;
  w: number;
  h: number;
  column: number;
  items: Item[];
  /** Has two or more pod rows that can be collapsed into a summary. */
  collapsible: boolean;
  collapsed: boolean;
}
/** Server-side port label shared by every conversation into one item and port. */
export interface Pill {
  id: string;
  label: string;
  itemId: string;
  side: "left" | "right";
  x: number;
  y: number;
  w: number;
  h: number;
  edgeIds: string[];
  connector: { x1: number; x2: number; y: number };
}
export interface RoutedEdge {
  id: string;
  edge: GraphEdge;
  /** Polyline from the source attachment to the target (or pill) attachment. */
  points: [number, number][];
  d: string;
  arrow: "end" | "none";
  /** Client and server are known; the arrowhead may be drawn by the pill. */
  directed: boolean;
  pill?: string;
  label?: string;
  /** The fabric dropped this conversation (ACL log). */
  blocked?: boolean;
  /** Every graph edge drawn by this line (parallel hand-offs share one). */
  members: string[];
  mid: { x: number; y: number };
  /** Summed volume (bytes, else count) of every member. */
  weight: number;
  /** Stroke width from volume (log scale), set for aggregated or large maps. */
  width?: number;
  /** Members bundled because an end is a summary card. */
  bundle?: number;
  /** Card-pair bundle: drawn card to card, titled by the two cards. */
  card?: { title: string };
  /** Every member is inferred (drawn dashed). */
  inferred?: boolean;
}
export interface Layout {
  width: number;
  height: number;
  lanes: LaneLabel[];
  groups: Group[];
  /** Keyed by graph node ID; collapsed pods map to their summary item. */
  items: Map<string, Item>;
  edges: RoutedEdge[];
  pills: Pill[];
  /** Drawn item IDs in reading order (column, then top to bottom). */
  order: string[];
  collapsed: boolean;
  /** Groups summarized by level-of-detail aggregation (not pod collapse). */
  aggregated: number;
  /** Lines drawn straight because there were too many to route. */
  straight: boolean;
  truncation?: GraphTruncation;
}
export interface LayoutOptions {
  /** Collapse pod lists of two or more into "N pods" rows. */
  collapse?: boolean;
  /** Group IDs kept expanded while collapsing. */
  expanded?: ReadonlySet<string>;
  /** Merge Service frontends into one card while retaining every node id as an anchor. */
  mergeFrontends?: boolean;
  /** Summarize the largest groups when more than `lodCards` cards would show (default on). */
  aggregate?: boolean;
  lodCards?: number;
  /** Routed lines above which channel routing is skipped. */
  straightAbove?: number;
  truncation?: GraphTruncation;
  /** Draw one line per card pair (network view) instead of one per row pair. */
  cardBundles?: boolean;
  /** Omit inferred relationships (shown only on request). */
  hideInferred?: boolean;
  /** Collapse untraced workloads and other-namespace pods into summary cards. */
  quiet?: boolean;
}

export const CARD_W = 196;
/** Gutter holding server-port pills; other gutters are narrow. */
export const GUTTER = 108;
export const GUTTER_NARROW = 52;
export const HEADER_H = 44;
export const ROW_H = 40;
export const GROUP_PAD = 6;
export const GROUP_GAP = 28;
export const STACK_GAP = 56;
export const TOP = 56;
export const LEFT = 16;
export const PILL_H = 18;
const ARROW = 10;
const CHANNEL_START = 8;
const CHANNEL_STEP = 4;
const CHANNEL_SLOTS = 6;

/** Column x positions and gutter widths (gutter c sits right of column c). */
interface Columns {
  x: number[];
  gutter: number[];
}
/** A conversation gets a port pill at its server end unless that is a Service frontend. */
const pillTarget = (e: GraphEdge, frontDoors: ReadonlySet<string>) =>
  e.relationship === "communicates_with" &&
  !tunnelOf(e) &&
  e.direction_basis !== "unknown" &&
  e.server_port !== undefined &&
  !frontDoors.has(e.target);

interface Draft {
  id: string;
  title: string;
  subtitle?: string;
  kind: Group["kind"];
  lane: LaneKind;
  header?: GraphNode;
  rows: GraphNode[];
  column: number;
  sort: string;
  stacked?: boolean;
  aliases?: string[];
  /** Background noise collapsed by default (untraced workloads, other namespaces). */
  quiet?: boolean;
}

const podOwner = (n: GraphNode) => n.attributes?.owner ?? n.label;
/** Service frontends and Cilium Envoy addresses: where traffic enters the cluster. */
export const isFrontDoor = (n: GraphNode) =>
  n.endpoint_kind === "k8s_service" || n.endpoint_kind === "k8s_node_proxy";
const MODE: Record<string, string> = {
  snat: "SNAT",
  dsr: "DSR",
  hybrid: "Hybrid",
};
/** Full policy text, e.g. "Cluster/SNAT". */
export function policyText(a: Record<string, string>): string {
  return [a.traffic_policy, a.lb_mode && MODE[a.lb_mode]]
    .filter(Boolean)
    .join("/");
}
/** Only what differs from Kubernetes/Cilium defaults (Cluster, SNAT), e.g. "Local/DSR". */
export function policyBadge(a: Record<string, string>): string {
  return [
    a.traffic_policy !== "Cluster" && a.traffic_policy,
    a.lb_mode && a.lb_mode !== "snat" && MODE[a.lb_mode],
  ]
    .filter(Boolean)
    .join("/");
}
/** One frontend in a few words: "10.50.0.30:8080" or "NodePort 30081". */
export function frontendText(n: GraphNode): string {
  const a = n.attributes ?? {};
  const f = a.frontend ?? n.label;
  return a.type === "NodePort" ? `NodePort ${f.split(":").at(-1)}` : f;
}
function frontDoorSubtitle(rows: GraphNode[]): string {
  const types = [
    ...new Set(
      rows.flatMap((row) => {
        const attrs = row.attributes ?? {};
        return [
          attrs.type === "LoadBalancer" ? "VIP" : attrs.type,
          attrs.controller === "cilium_ingress"
            ? "Ingress"
            : attrs.controller === "cilium_gateway"
              ? "Gateway"
              : undefined,
        ].filter((value): value is string => !!value);
      }),
    ),
  ];
  const policies = [
    ...new Set(rows.map((r) => policyText(r.attributes ?? {}))),
  ];
  return [types.join(" + "), policies.length === 1 ? policies[0] : undefined]
    .filter(Boolean)
    .join(" · ");
}
const conversations = (index: GraphIndex, id: string) =>
  (index.incident.get(id) ?? []).filter(
    (e) => e.relationship === "communicates_with",
  );

function draftGroups(
  graph: Graph,
  index: GraphIndex,
  view: View,
  options: LayoutOptions,
): Draft[] {
  const root = graph.boundary.root_node_id;
  const ns = graph.boundary.namespace;
  const services = graph.nodes.filter((n) => n.kind === "service");
  const depth = new Map<string, number>([[root, 0]]);
  const queue = [root];
  for (let head = 0; head < queue.length; head++) {
    const cur = queue[head];
    for (const e of index.outgoing.get(cur) ?? [])
      if (e.relationship === "calls" && !depth.has(e.target)) {
        depth.set(e.target, depth.get(cur)! + 1);
        queue.push(e.target);
      }
  }
  let maxDepth = 0;
  for (const d of depth.values()) maxDepth = Math.max(maxDepth, d);
  for (const s of services) if (!depth.has(s.id)) depth.set(s.id, maxDepth + 1);
  const frontDoors = view === "network" ? graph.nodes.filter(isFrontDoor) : [];
  const appStart = view === "network" ? (frontDoors.length ? 2 : 1) : 0;
  const drafts: Draft[] = [];
  const podService = new Map<string, string>();
  for (const e of graph.edges)
    if (e.relationship === "runs_on" && !podService.has(e.target))
      podService.set(e.target, e.source);
  const podsOf = new Map<string, GraphNode[]>();
  if (view === "network")
    for (const n of graph.nodes) {
      const owner = podService.get(n.id);
      if (owner === undefined) continue;
      const list = podsOf.get(owner);
      if (list) list.push(n);
      else podsOf.set(owner, [n]);
    }
  for (const s of services)
    drafts.push({
      id: `group:${s.id}`,
      title: s.label,
      subtitle: s.id === root ? "Entry service" : "Service",
      kind: "service",
      lane: "application",
      header: s,
      rows: (podsOf.get(s.id) ?? []).sort((a, b) =>
        a.label.localeCompare(b.label),
      ),
      column: appStart + depth.get(s.id)!,
      sort: `0|${s.label}`,
    });
  if (view === "services") return drafts;

  const serviceClusters = new Map<string, Set<string>>();
  for (const f of frontDoors) {
    if (f.endpoint_kind !== "k8s_service") continue;
    const name = f.attributes?.service ?? f.label;
    const key = `${f.namespace}/${name}`;
    const clusters = serviceClusters.get(key) ?? new Set<string>();
    clusters.add(f.cluster ?? graph.boundary.cluster);
    serviceClusters.set(key, clusters);
  }
  const doors = new Map<string, Draft>();
  for (const f of frontDoors) {
    const proxy = f.endpoint_kind === "k8s_node_proxy";
    const name = proxy ? "Cilium Envoy" : (f.attributes?.service ?? f.label);
    const serviceKey = proxy
      ? "envoy"
      : `${f.cluster && f.cluster !== graph.boundary.cluster ? `${f.cluster}/` : ""}${f.namespace}/${name}`;
    const id = `group:entry:${serviceKey}`;
    const sameNameClusters = serviceClusters.get(`${f.namespace}/${name}`);
    const visibleName =
      !proxy && sameNameClusters && sameNameClusters.size > 1
        ? `${name} · ${f.cluster ?? graph.boundary.cluster}`
        : name;
    const d = doors.get(id) ?? {
      id,
      title: visibleName,
      kind: "frontdoor" as const,
      lane: "entry" as const,
      rows: [],
      column: 1,
      sort: `${proxy ? 1 : 0}|${name}`,
    };
    d.rows.push(f);
    doors.set(id, d);
  }
  for (const d of doors.values()) {
    d.rows.sort((a, b) => a.label.localeCompare(b.label));
    d.subtitle = d.id.endsWith(":envoy")
      ? "Gateway and Ingress upstream"
      : frontDoorSubtitle(d.rows);
    // A Service with one frontend is a single compact card.
    if (
      (d.rows.length === 1 || options.mergeFrontends) &&
      !d.id.endsWith(":envoy")
    ) {
      const [only] = d.rows;
      const frontends = [...d.rows];
      if (options.mergeFrontends && frontends.length > 1)
        d.aliases = frontends.slice(1).map((row) => row.id);
      d.header = only;
      d.rows = [];
      d.subtitle =
        options.mergeFrontends && frontends.length > 1
          ? frontDoorSubtitle(frontends)
          : frontendText(only);
    }
    drafts.push(d);
  }

  let appEnd = appStart;
  for (const s of services)
    appEnd = Math.max(appEnd, appStart + depth.get(s.id)!);
  const columnOf = new Map<string, number>();
  for (const d of drafts) {
    if (d.header) columnOf.set(d.header.id, d.column);
    for (const r of d.rows) columnOf.set(r.id, d.column);
  }

  // Namespace pods without a traced service sit beside the pods they talk to.
  const unbound = new Map<string, GraphNode[]>();
  for (const n of graph.nodes)
    if (n.kind === "workload" && n.namespace === ns && !podService.has(n.id)) {
      const list = unbound.get(podOwner(n));
      if (list) list.push(n);
      else unbound.set(podOwner(n), [n]);
    }
  const placeUnbound = (key: string, title: string, pods: GraphNode[]) => {
    let asClient = 0,
      asServer = 0,
      minCol = Infinity,
      maxCol = -Infinity;
    for (const p of pods)
      for (const e of index.incident.get(p.id) ?? []) {
        const c = columnOf.get(e.source === p.id ? e.target : e.source);
        if (c === undefined) continue;
        minCol = Math.min(minCol, c);
        maxCol = Math.max(maxCol, c);
        if (e.source === p.id && e.direction_basis !== "unknown") asClient++;
        else asServer++;
      }
    const column = !Number.isFinite(minCol)
      ? appEnd
      : asClient > asServer
        ? Math.max(appStart, minCol - 1)
        : maxCol + 1;
    appEnd = Math.max(appEnd, column);
    drafts.push({
      id: `group:workloads:${key}`,
      title,
      subtitle: "Workload · no traces",
      kind: "workloads",
      lane: "application",
      rows: pods.sort((a, b) => a.label.localeCompare(b.label)),
      column,
      sort: `1|${key}`,
      quiet: options.quiet && pods.length > 1,
    });
  };
  const unboundGroups = [...unbound].sort(([a], [b]) => a.localeCompare(b));
  // Quiet maps keep every untraced workload in one card instead of one each.
  if (options.quiet && unboundGroups.length > 1)
    placeUnbound(
      "*",
      "Untraced workloads",
      unboundGroups.flatMap(([, pods]) => pods),
    );
  else
    for (const [owner, pods] of unboundGroups) placeUnbound(owner, owner, pods);

  const depsCol = appEnd + 1;
  const outer = new Map<string, Draft>();
  const place = (
    n: GraphNode,
    lane: LaneKind,
    gid: string,
    title: string,
    kind: Draft["kind"],
    subtitle?: string,
    quiet = false,
  ) => {
    const column = lane === "sources" ? 0 : depsCol;
    const id = `group:${lane}:${gid}`;
    const d = outer.get(id) ?? {
      id,
      title,
      subtitle,
      kind,
      lane,
      rows: [],
      column,
      sort: `2|${gid}`,
      stacked: lane === "infrastructure",
      quiet: quiet && options.quiet,
    };
    d.rows.push(n);
    outer.set(id, d);
  };
  for (const n of graph.nodes) {
    if (n.kind === "service" || columnOf.has(n.id) || isFrontDoor(n)) continue;
    if (n.kind === "workload" && n.namespace === ns) continue;
    const convs = conversations(index, n.id);
    const app = convs.filter((e) => !tunnelOf(e));
    if (n.endpoint_kind === "k8s_node" && convs.length === 0) {
      place(
        n,
        "infrastructure",
        "hosts",
        "Kubernetes nodes",
        "nodes",
        "Hosting these pods",
      );
      continue;
    }
    if (n.endpoint_kind === "k8s_node" && app.length === 0) {
      place(
        n,
        "infrastructure",
        "nodes",
        "Kubernetes nodes",
        "nodes",
        "Node-to-node traffic only",
      );
      continue;
    }
    // A node that only ever opens connections into the application is a source.
    const lane: LaneKind =
      app.length > 0 &&
      app.every((e) => e.source === n.id && e.direction_basis !== "unknown")
        ? "sources"
        : "dependencies";
    const toward = lane === "sources" ? "sources" : "destinations";
    if (n.endpoint_kind === "k8s_node")
      place(
        n,
        lane,
        "nodes",
        "Kubernetes nodes",
        "nodes",
        lane === "sources" ? "Calling in" : "Node addresses",
      );
    else if (n.kind === "workload")
      place(
        n,
        lane,
        `ns:${n.namespace}`,
        n.namespace ?? "Other namespace",
        "namespace",
        "Namespace",
        true,
      );
    else if (n.endpoint_kind === "vm") {
      const a = n.attributes ?? {};
      const sub = [
        a.tenant && `Tenant ${a.tenant}`,
        a.app_profile && `App ${a.app_profile}`,
      ]
        .filter(Boolean)
        .join(" · ");
      place(
        n,
        lane,
        `epg:${a.tenant}/${a.app_profile}/${a.epg}`,
        a.epg ? `EPG ${a.epg}` : "Fabric endpoints",
        "epg",
        sub || "ACI / Nexus Dashboard",
      );
    } else if (isUnknown(n))
      place(
        n,
        lane,
        "unknown",
        `Unknown ${toward}`,
        "endpoints",
        "No identity in this time range",
      );
    else
      place(
        n,
        lane,
        "external",
        `External ${toward}`,
        "endpoints",
        "Outside the fabric",
      );
  }
  for (const d of outer.values()) {
    d.rows.sort((a, b) => a.label.localeCompare(b.label));
    drafts.push(d);
  }
  return drafts;
}

const LANE_TITLES: Record<LaneKind, string> = {
  sources: "Sources",
  entry: "Entry points",
  application: "Application",
  dependencies: "Dependencies",
  infrastructure: "Infrastructure",
};
const collapsible = (d: Draft) =>
  d.rows.length >= 2 && d.rows.every((r) => r.kind === "workload");

export function computeLayout(
  graph: Graph,
  index: GraphIndex,
  view: View,
  options: LayoutOptions = {},
): Layout {
  const drafts = draftGroups(graph, index, view, options);
  const collapsedIds = new Set(
    drafts
      .filter(
        (d) =>
          (options.collapse || (d.quiet && d.rows.length > 1)) &&
          collapsible(d) &&
          !options.expanded?.has(d.id),
      )
      .map((d) => d.id),
  );
  // Level of detail: past the card budget, summarize the largest groups
  // (namespace, EPG, endpoints, nodes, workloads) until the map fits it.
  const aggregatedIds = new Set<string>();
  if (options.aggregate !== false) {
    const budget = options.lodCards ?? LOD_CARDS;
    const cards = (d: Draft) =>
      (d.header ? 1 : 0) + (collapsedIds.has(d.id) ? 1 : d.rows.length);
    let total = drafts.reduce((n, d) => n + cards(d), 0);
    if (total > budget)
      for (const d of [...drafts]
        .filter(
          (d) =>
            d.rows.length >= 2 &&
            !collapsedIds.has(d.id) &&
            !options.expanded?.has(d.id),
        )
        .sort(
          (a, b) => b.rows.length - a.rows.length || a.id.localeCompare(b.id),
        )) {
        if (total <= budget) break;
        total -= d.rows.length - 1;
        collapsedIds.add(d.id);
        aggregatedIds.add(d.id);
      }
  }
  const rowCount = (d: Draft) => (collapsedIds.has(d.id) ? 1 : d.rows.length);
  const groupHeight = (d: Draft) =>
    (d.header || d.kind !== "service" ? HEADER_H : 0) +
    (rowCount(d) ? GROUP_PAD + rowCount(d) * ROW_H + GROUP_PAD : 0);

  const used = [...new Set(drafts.map((d) => d.column))].sort((a, b) => a - b);
  const remap = new Map(used.map((c, i) => [c, i]));
  for (const d of drafts) d.column = remap.get(d.column)!;
  const columns = used.length;
  const byColumn: Draft[][] = Array.from({ length: columns }, () => []);
  for (const d of drafts) byColumn[d.column].push(d);
  for (const col of byColumn) col.sort((a, b) => a.sort.localeCompare(b.sort));

  // Gutters are wide only where a server-port pill sits.
  const colOf = new Map<string, number>();
  for (const d of drafts) {
    if (d.header) colOf.set(d.header.id, d.column);
    for (const r of d.rows) colOf.set(r.id, d.column);
  }
  const frontDoorIds = new Set(
    graph.nodes
      .filter((n) => n.endpoint_kind === "k8s_service")
      .map((n) => n.id),
  );
  const wide = new Set<number>();
  for (const e of graph.edges) {
    const a = colOf.get(e.source),
      b = colOf.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    if (pillTarget(e, frontDoorIds)) wide.add(b > a ? b - 1 : b);
  }
  const cols: Columns = { x: [], gutter: [] };
  for (let c = 0, x = LEFT; c < columns; c++) {
    cols.x.push(x);
    cols.gutter.push(wide.has(c) ? GUTTER : GUTTER_NARROW);
    x += CARD_W + cols.gutter[c];
  }

  // Barycenter ordering of groups; stacked infrastructure stays below.
  const memberOf = new Map<string, Draft>();
  for (const d of drafts) {
    if (d.header) memberOf.set(d.header.id, d);
    for (const r of d.rows) memberOf.set(r.id, d);
  }
  const neighbors = new Map<Draft, Draft[]>();
  for (const e of graph.edges) {
    if (e.relationship === "runs_on") continue;
    const a = memberOf.get(e.source),
      b = memberOf.get(e.target);
    if (!a || !b || a === b) continue;
    const na = neighbors.get(a),
      nb = neighbors.get(b);
    if (na) na.push(b);
    else neighbors.set(a, [b]);
    if (nb) nb.push(a);
    else neighbors.set(b, [a]);
  }
  const rank = new Map<Draft, number>();
  const setRanks = () =>
    byColumn.forEach((col) =>
      col.forEach((d, i) => rank.set(d, i / Math.max(1, col.length - 1))),
    );
  setRanks();
  for (let sweep = 0; sweep < 4; sweep++) {
    for (const col of byColumn) {
      const score = new Map<Draft, number>();
      for (const d of col) {
        const ns = neighbors.get(d) ?? [];
        score.set(
          d,
          ns.length
            ? ns.reduce((s, n) => s + rank.get(n)!, 0) / ns.length
            : rank.get(d)!,
        );
      }
      col.sort(
        (a, b) =>
          Number(!!a.stacked) - Number(!!b.stacked) ||
          score.get(a)! - score.get(b)! ||
          a.sort.localeCompare(b.sort),
      );
    }
    setRanks();
  }

  const heights = byColumn.map((col) => {
    let h = 0,
      prev: Draft | undefined;
    for (const d of col) {
      if (prev) h += d.stacked && !prev.stacked ? STACK_GAP : GROUP_GAP;
      h += groupHeight(d);
      prev = d;
    }
    return h;
  });
  const tallest = heights.reduce((m, h) => Math.max(m, h), 0);
  const groups: Group[] = [];
  const items = new Map<string, Item>();
  const order: string[] = [];
  const lanes: LaneLabel[] = [];
  const topLane: LaneKind[] = [];
  byColumn.forEach((col, c) => {
    let y = TOP + (tallest - heights[c]) / 2;
    const x = cols.x[c];
    let prev: Draft | undefined;
    topLane[c] = col.find((d) => !d.stacked)?.lane ?? "infrastructure";
    for (const d of col) {
      if (prev) y += d.stacked && !prev.stacked ? STACK_GAP : GROUP_GAP;
      if (d.stacked && prev && !prev.stacked)
        lanes.push({
          kind: d.lane,
          title: LANE_TITLES[d.lane],
          x,
          y: y - 22,
          width: CARD_W,
        });
      const h = groupHeight(d);
      const g: Group = {
        id: d.id,
        title: d.title,
        subtitle: d.subtitle,
        kind: d.kind,
        lane: d.lane,
        headerNodeId: d.header?.id,
        x,
        y,
        w: CARD_W,
        h,
        column: c,
        items: [],
        collapsible: collapsible(d) || aggregatedIds.has(d.id),
        collapsed: collapsedIds.has(d.id),
      };
      const add = (it: Item, ids: string[]) => {
        g.items.push(it);
        for (const id of ids) items.set(id, it);
        order.push(it.nodeId);
      };
      if (d.header)
        add(
          {
            nodeId: d.header.id,
            groupId: d.id,
            role: "header",
            members: d.aliases?.length
              ? [d.header.id, ...d.aliases]
              : undefined,
            x,
            y,
            w: CARD_W,
            h: HEADER_H,
            column: c,
          },
          [d.header.id, ...(d.aliases ?? [])],
        );
      const ry = y + HEADER_H + GROUP_PAD;
      if (g.collapsed) {
        const members = d.rows.map((r) => r.id);
        const id = `summary:${d.id}`;
        add(
          {
            nodeId: id,
            members,
            label: `${members.length.toLocaleString("en-US")} ${summaryNoun(d, members.length)}`,
            groupId: d.id,
            role: "summary",
            x,
            y: ry,
            w: CARD_W,
            h: ROW_H,
            column: c,
          },
          [id, ...members],
        );
      } else
        d.rows.forEach((r, i) =>
          add(
            {
              nodeId: r.id,
              groupId: d.id,
              role: "row",
              x,
              y: ry + i * ROW_H,
              w: CARD_W,
              h: ROW_H,
              column: c,
            },
            [r.id],
          ),
        );
      groups.push(g);
      y += h;
      prev = d;
    }
  });
  const top: LaneLabel[] = [];
  for (let c = 0; c < columns; c++) {
    const x = cols.x[c];
    const last = top.at(-1);
    if (last && last.kind === topLane[c]) last.width = x + CARD_W - last.x;
    else
      top.push({
        kind: topLane[c],
        title: LANE_TITLES[topLane[c]],
        x,
        y: 30,
        width: CARD_W,
      });
  }
  lanes.unshift(...top);

  const height = TOP + tallest + 40;
  // Trailing room for same-column loops and their labels (e.g. VXLAN · 8472/udp).
  const last = Math.max(0, columns - 1);
  const width = cols.x[last] + CARD_W + 20;
  const { edges, pills, straight } = routeEdges(
    graph,
    view,
    items,
    groups,
    columns,
    cols,
    frontDoorIds,
    {
      straightAbove: options.straightAbove ?? STRAIGHT_ROUTE_EDGES,
      weighted: aggregatedIds.size > 0,
      cards: options.cardBundles === true && view === "network",
      hideInferred: options.hideInferred === true,
    },
  );
  return {
    width,
    height,
    lanes,
    groups,
    items,
    edges,
    pills,
    order,
    collapsed: collapsedIds.size > 0,
    aggregated: aggregatedIds.size,
    straight,
    ...((options.truncation ?? graph.truncation)
      ? { truncation: options.truncation ?? graph.truncation }
      : {}),
  };
}

function summaryNoun(d: Draft, n: number): string {
  const one = n === 1;
  if (d.rows.every((r) => r.kind === "workload")) return one ? "pod" : "pods";
  if (d.kind === "nodes") return one ? "node" : "nodes";
  if (d.kind === "frontdoor") return one ? "frontend" : "frontends";
  return one ? "endpoint" : "endpoints";
}

export const rounded = (pts: [number, number][], r = 7): string => {
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [px, py] = pts[i - 1],
      [x, y] = pts[i],
      [nx, ny] = pts[i + 1];
    const inLen = Math.hypot(x - px, y - py),
      outLen = Math.hypot(nx - x, ny - y);
    const rr = Math.min(r, inLen / 2, outLen / 2);
    if (rr < 0.5) {
      d += ` L${x},${y}`;
      continue;
    }
    const ax = x - ((x - px) / inLen) * rr,
      ay = y - ((y - py) / inLen) * rr;
    const bx = x + ((nx - x) / outLen) * rr,
      by = y + ((ny - y) / outLen) * rr;
    d += ` L${ax},${ay} Q${x},${y} ${bx},${by}`;
  }
  const last = pts[pts.length - 1];
  return `${d} L${last[0]},${last[1]}`;
};

/** Pill width for 11px semibold digits. */
export const pillWidth = (label: string) =>
  Math.min(
    GUTTER - CHANNEL_START - CHANNEL_SLOTS * CHANNEL_STEP - ARROW - 4,
    label.length * 6.2 + 14,
  );

const parallelEdge = (
  parallel: Map<string, GraphEdge[]>,
  e: GraphEdge,
  id: string,
) => parallel.get(`${e.source}|${e.target}`)!.find((g) => g.id === id)!;

interface Plan {
  members: string[];
  /** Draw the label just before the target instead of mid-route. */
  nearTarget?: boolean;
  edge: GraphEdge;
  s: Item;
  t: Item;
  directed: boolean;
  pillKey?: string;
  label?: string;
  weight: number;
  bundled?: boolean;
  blocked?: boolean;
  card?: { title: string };
}
interface Attach {
  key: string;
  otherY: number;
  y?: number;
}

/** Representative member of a card bundle: problems first, then evidence strength. */
const cardRank = (e: GraphEdge) =>
  e.acl_action === "drop"
    ? 0
    : e.relationship === "calls"
      ? 1
      : e.relationship === "communicates_with"
        ? 2
        : e.relationship === "traffic_observation"
          ? 3
          : e.confidence === "inferred"
            ? 5
            : 4;
const cardDirected = (e: GraphEdge) =>
  e.relationship !== "traffic_observation" && e.direction_basis !== "unknown";

/** "+N inferred" when a card line carries observed and inferred members. */
const cardInferredBadge = (
  members: string[],
  edgeById: ReadonlyMap<string, GraphEdge>,
) => {
  const inferred = members.filter(
    (id) => edgeById.get(id)?.confidence === "inferred",
  ).length;
  return inferred && inferred < members.length
    ? `+${inferred} inferred`
    : undefined;
};

/** Hover lines for a card bundle: link count, records, and the busiest ports. */
export function bundleSummary(edges: GraphEdge[]): string[] {
  let calls = 0,
    records = 0,
    blocked = 0,
    inferred = 0;
  const ports = new Map<string, number>();
  for (const e of edges) {
    if (e.relationship === "calls") calls += e.count;
    else records += e.records ?? e.count;
    if (e.acl_action === "drop") blocked++;
    if (e.confidence === "inferred") inferred++;
    const port = e.server_port ?? e.destination_port;
    if (port !== undefined && e.relationship !== "calls") {
      const k = `${port}${e.transport ? `/${e.transport}` : ""}`;
      ports.set(k, (ports.get(k) ?? 0) + (e.records ?? e.count));
    }
  }
  const n = (v: number) => v.toLocaleString("en-US");
  const top = [...ports].sort(
    (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
  );
  const lines = [
    [
      `${n(edges.length)} link${edges.length === 1 ? "" : "s"}`,
      calls ? `${n(calls)} traced span${calls === 1 ? "" : "s"}` : "",
      records ? `${n(records)} record${records === 1 ? "" : "s"}` : "",
    ]
      .filter(Boolean)
      .join(" · "),
  ];
  if (top.length)
    lines.push(
      `Ports ${top
        .slice(0, 4)
        .map(([k]) => k)
        .join(", ")}${top.length > 4 ? ` +${top.length - 4}` : ""}`,
    );
  if (blocked) lines.push(`${n(blocked)} blocked by the fabric`);
  if (inferred) lines.push(`${n(inferred)} inferred`);
  return lines;
}

function routeEdges(
  graph: Graph,
  view: View,
  items: Map<string, Item>,
  groups: Group[],
  columns: number,
  cols: Columns,
  frontDoors: ReadonlySet<string>,
  mode: {
    straightAbove: number;
    weighted: boolean;
    cards?: boolean;
    hideInferred?: boolean;
  },
): { edges: RoutedEdge[]; pills: Pill[]; straight: boolean } {
  const plans: Plan[] = [];
  const sorted = [...graph.edges].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
  // Hand-offs from one Service to one pod are drawn as a single line.
  const parallel = new Map<string, GraphEdge[]>();
  for (const e of sorted)
    if (e.relationship === "forwards_to") {
      const k = `${e.source}|${e.target}`;
      const list = parallel.get(k);
      if (list) list.push(e);
      else parallel.set(k, [e]);
    }
  // Lines into a summary card are bundled per card pair and relationship.
  const bundles = new Map<string, Plan>();
  const edgeById = new Map(graph.edges.map((e) => [e.id, e]));
  const drawn = new Set<string>();
  const cardBundles = new Map<string, Plan>();
  const groupById = new Map(groups.map((g) => [g.id, g]));
  const groupTitle = new Map(groups.map((g) => [g.id, g.title]));
  const anchors = new Map<string, Item>();
  const anchor = (groupId: string): Item => {
    const id = `card:${groupId}`;
    let it = anchors.get(id);
    if (!it) {
      const g = groupById.get(groupId)!;
      it = {
        nodeId: id,
        groupId,
        role: "header",
        x: g.x,
        y: g.y,
        w: g.w,
        h: g.h,
        column: g.column,
      };
      anchors.set(id, it);
    }
    return it;
  };
  const lookup = (id: string) => anchors.get(id) ?? items.get(id);
  for (const raw of sorted) {
    let e = raw;
    let members = [raw.id];
    if (raw.relationship === "forwards_to") {
      const k = `${raw.source}|${raw.target}`;
      if (drawn.has(k)) continue;
      drawn.add(k);
      let group = parallel.get(k)!;
      if (mode.hideInferred)
        group = group.filter((g) => g.confidence !== "inferred");
      if (!group.length) continue;
      e = group.find((g) => g.confidence === "observed") ?? group[0];
      members = group.map((g) => g.id);
    } else if (mode.hideInferred && raw.confidence === "inferred") continue;
    if (e.relationship === "runs_on") continue;
    if (view === "services" && e.relationship !== "calls") continue;
    const s = items.get(e.source),
      t = items.get(e.target);
    if (!s || !t || s === t) continue;
    if (mode.cards) {
      // One line per card pair: the relationships it carries are listed on hover.
      if (s.groupId === t.groupId) continue;
      const gs = anchor(s.groupId),
        gt = anchor(t.groupId);
      const key =
        gs.nodeId < gt.nodeId
          ? `${gs.nodeId}|${gt.nodeId}`
          : `${gt.nodeId}|${gs.nodeId}`;
      const weight = members.reduce(
        (sum, id) => sum + edgeVolume(edgeById.get(id)!),
        0,
      );
      const b = cardBundles.get(key);
      if (b) {
        b.members.push(...members);
        b.weight += weight;
        if (
          cardRank(e) < cardRank(b.edge) ||
          (cardRank(e) === cardRank(b.edge) &&
            edgeVolume(e) > edgeVolume(b.edge))
        )
          b.edge = e;
        if (e.acl_action === "drop") b.blocked = true;
        b.directed = b.directed && cardDirected(e) && b.s === gs;
        continue;
      }
      const plan: Plan = {
        edge: e,
        s: gs,
        t: gt,
        directed: cardDirected(e),
        members: [...members],
        bundled: true,
        blocked: e.acl_action === "drop",
        weight,
        card: {
          title: `${groupTitle.get(s.groupId)} – ${groupTitle.get(t.groupId)}`,
        },
      };
      cardBundles.set(key, plan);
      plans.push(plan);
      continue;
    }
    // In level-of-detail mode every card pair shares one line per relationship.
    if (s.role === "summary" || t.role === "summary" || mode.weighted) {
      const key = `${s.nodeId}|${t.nodeId}|${e.relationship}`;
      const b = bundles.get(key);
      if (b) {
        b.members.push(...members);
        b.weight += members.reduce(
          (sum, id) => sum + edgeVolume(edgeById.get(id)!),
          0,
        );
        if (edgeVolume(e) > edgeVolume(b.edge)) b.edge = e;
        if (e.acl_action === "drop") b.blocked = true;
        b.directed = b.directed && e.direction_basis !== "unknown";
        continue;
      }
      const plan: Plan = {
        edge: e,
        s,
        t,
        directed:
          e.relationship !== "traffic_observation" &&
          e.direction_basis !== "unknown",
        members: [...members],
        bundled: true,
        blocked: e.acl_action === "drop",
        weight: members.reduce(
          (sum, id) => sum + edgeVolume(edgeById.get(id)!),
          0,
        ),
      };
      bundles.set(key, plan);
      plans.push(plan);
      continue;
    }
    const conv = e.relationship === "communicates_with";
    const directed =
      e.relationship === "traffic_observation"
        ? false
        : !(conv && e.direction_basis === "unknown");
    const port =
      e.server_port !== undefined
        ? `${e.server_port}/${e.transport ?? "?"}`
        : undefined;
    const plan: Plan = {
      edge: e,
      s,
      t,
      directed,
      members,
      weight: members.reduce(
        (sum, id) => sum + edgeVolume(edgeById.get(id)!),
        0,
      ),
    };
    if (members.length > 1) {
      const group = members.map((id) => parallelEdge(parallel, e, id));
      const inferred = group.filter((g) => g.confidence === "inferred").length;
      // Short badge at the target; the inspector lists every hand-off.
      plan.label =
        inferred === members.length
          ? `${members.length} inferred`
          : inferred
            ? `+${inferred} inferred`
            : `${members.length} observed`;
      plan.nearTarget = true;
    } else if (
      e.relationship === "forwards_to" &&
      e.confidence === "inferred"
    ) {
      plan.label = "inferred";
      plan.nearTarget = true;
    } else if (tunnelOf(e))
      plan.label = `${tunnelLabel(tunnelOf(e)!)}${port ? ` · ${port}` : ""}`;
    else if (conv && directed && port && pillTarget(e, frontDoors)) {
      if (s.column !== t.column)
        plan.pillKey = `${t.nodeId}|${t.column > s.column ? "left" : "right"}|${port}`;
      else plan.label = port;
    }
    plans.push(plan);
  }

  // Attachment points: one distinct y per edge (or pill) on each card side.
  const sides = new Map<string, Attach[]>();
  const requested = new Set<string>();
  const sideKey = (it: Item, side: "left" | "right") => `${it.nodeId}|${side}`;
  const request = (
    it: Item,
    side: "left" | "right",
    key: string,
    otherY: number,
  ) => {
    const k = sideKey(it, side);
    if (requested.has(`${k}|${key}`)) return;
    requested.add(`${k}|${key}`);
    const list = sides.get(k);
    if (list) list.push({ key, otherY });
    else sides.set(k, [{ key, otherY }]);
  };
  const cy = (it: Item) => it.y + it.h / 2;
  const pillMembers = new Map<string, Plan[]>();
  for (const p of plans) {
    const sameCol = p.s.column === p.t.column;
    // A loop in the last column turns left, into the gutter, to stay in view.
    const loopSide = p.s.column === columns - 1 ? "left" : "right";
    const sSide = sameCol
      ? loopSide
      : p.s.column < p.t.column
        ? "right"
        : "left";
    const tSide = sameCol ? loopSide : sSide === "right" ? "left" : "right";
    request(p.s, sSide, `edge:${p.edge.id}`, cy(p.t));
    if (p.pillKey) {
      const list = pillMembers.get(p.pillKey);
      if (list) list.push(p);
      else pillMembers.set(p.pillKey, [p]);
      request(p.t, tSide, `pill:${p.pillKey}`, cy(p.s));
    } else request(p.t, tSide, `edge:${p.edge.id}`, cy(p.s));
  }
  // Pills sit where the average of their clients is.
  for (const [key, members] of pillMembers) {
    const t = members[0].t;
    const side = key.split("|").at(-2) as "left" | "right";
    const a = sides
      .get(sideKey(t, side))!
      .find((x) => x.key === `pill:${key}`)!;
    a.otherY = members.reduce((s, m) => s + cy(m.s), 0) / members.length;
  }
  const point = new Map<string, number>();
  for (const [k, list] of sides) {
    const nodeId = k.slice(0, k.lastIndexOf("|"));
    const it = lookup(nodeId)!;
    list.sort((a, b) => a.otherY - b.otherY || a.key.localeCompare(b.key));
    const pad = it.role === "header" ? 9 : 7;
    const span = it.h - 2 * pad;
    list.forEach((a, i) => {
      a.y =
        list.length === 1
          ? it.y + it.h / 2
          : it.y + pad + (span * i) / (list.length - 1);
      point.set(`${k}|${a.key}`, a.y);
    });
  }
  const at = (it: Item, side: "left" | "right", key: string) =>
    point.get(`${sideKey(it, side)}|${key}`)!;

  const pills: Pill[] = [];
  const pillEntry = new Map<string, { x: number; ys: Map<string, number> }>();
  for (const [key, members] of pillMembers) {
    const t = members[0].t;
    const side = key.split("|").at(-2) as "left" | "right";
    const label = key.slice(key.lastIndexOf("|") + 1);
    const y = at(t, side, `pill:${key}`);
    const w = pillWidth(label);
    const h = Math.min(28, Math.max(PILL_H, members.length * 4 + 8));
    const x = side === "left" ? t.x - ARROW - w : t.x + t.w + ARROW;
    const pill: Pill = {
      id: key,
      label,
      itemId: t.nodeId,
      side,
      x,
      y: y - h / 2,
      w,
      h,
      edgeIds: members.map((m) => m.edge.id),
      connector:
        side === "left"
          ? { x1: x + w, x2: t.x, y }
          : { x1: x, x2: t.x + t.w, y },
    };
    pills.push(pill);
    const ordered = [...members].sort(
      (a, b) => cy(a.s) - cy(b.s) || a.edge.id.localeCompare(b.edge.id),
    );
    const ys = new Map<string, number>();
    ordered.forEach((m, i) =>
      ys.set(
        m.edge.id,
        ordered.length === 1
          ? y
          : pill.y + 4 + ((h - 8) * i) / (ordered.length - 1),
      ),
    );
    pillEntry.set(key, { x: side === "left" ? x : x + w, ys });
  }

  // Free horizontal tracks for long edges, per column.
  const occupied: [number, number][][] = Array.from(
    { length: columns },
    () => [],
  );
  for (const g of groups) occupied[g.column].push([g.y - 10, g.y + g.h + 10]);
  for (const col of occupied) col.sort((a, b) => a[0] - b[0]);
  const free = (c: number, y: number) =>
    occupied[c].every(([a, b]) => y < a || y > b);
  const candidates = (c: number) => {
    const col = occupied[c];
    if (!col.length) return [];
    const ys = [col[0][0] - 4, col[col.length - 1][1] + 4];
    for (let i = 0; i + 1 < col.length; i++)
      ys.push((col[i][1] + col[i + 1][0]) / 2);
    return ys;
  };
  const topTrack = groups.reduce((m, g) => Math.min(m, g.y), Infinity) - 14;
  const slots = new Map<string, number>();
  const slot = (key: string) => {
    const n = slots.get(key) ?? 0;
    slots.set(key, n + 1);
    return n % CHANNEL_SLOTS;
  };
  const trackUse = new Map<number, number>();
  const trackOffset = (y: number) => {
    const n = trackUse.get(y) ?? 0;
    trackUse.set(y, n + 1);
    return Math.ceil(n / 2) * 4 * (n % 2 ? 1 : -1);
  };
  // Channel x inside a gutter: near the client side, away from pills.
  const channel = (gutter: number, fromRight: boolean) => {
    const left = cols.x[gutter] + CARD_W;
    const width = cols.gutter[gutter];
    const k = slot(`${gutter}|${fromRight}`);
    return fromRight
      ? left + width - CHANNEL_START - k * CHANNEL_STEP
      : left + CHANNEL_START + k * CHANNEL_STEP;
  };

  const edges: RoutedEdge[] = [];
  const ordered = [...plans].sort(
    (a, b) =>
      Math.min(a.s.column, a.t.column) - Math.min(b.s.column, b.t.column) ||
      cy(a.s) - cy(b.s) ||
      cy(a.t) - cy(b.t) ||
      a.edge.id.localeCompare(b.edge.id),
  );
  const straight = plans.length > mode.straightAbove;
  // Card lines stay one quiet width; volume is on hover, not in the ink.
  const weighted = mode.weighted || straight || bundles.size > 0;
  const maxWeight = weighted
    ? plans.reduce((m, p) => Math.max(m, p.weight), 0)
    : 0;
  for (const p of ordered) {
    const { s, t, edge } = p;
    const sameCol = s.column === t.column;
    const rightward = sameCol || s.column < t.column;
    const loopSide = s.column === columns - 1 ? "left" : "right";
    const sSide = sameCol ? loopSide : rightward ? "right" : "left";
    const tSide = sameCol ? loopSide : rightward ? "left" : "right";
    const sx = sSide === "right" ? s.x + s.w : s.x;
    const sy = at(s, sSide, `edge:${edge.id}`);
    let tx: number, ty: number;
    if (p.pillKey) {
      const entry = pillEntry.get(p.pillKey)!;
      tx = entry.x;
      ty = entry.ys.get(edge.id)!;
    } else {
      tx = tSide === "right" ? t.x + t.w : t.x;
      ty = at(t, tSide, `edge:${edge.id}`);
    }
    let pts: [number, number][];
    let mid: { x: number; y: number };
    if (straight && !sameCol) {
      // Too many lines to route through channels: draw them directly.
      pts = [
        [sx, sy],
        [tx, ty],
      ];
      mid = { x: (sx + tx) / 2, y: (sy + ty) / 2 };
    } else if (sameCol) {
      const k = slot(`loop|${s.column}`) * 4;
      const left = loopSide === "left";
      const gx = left ? s.x - 14 - k : s.x + s.w + 14 + k;
      pts = [
        [sx, sy],
        [gx, sy],
        [gx, ty],
        [tx, ty],
      ];
      const w = p.label ? p.label.length * 6.2 + 14 : 0;
      // Labels sit outside the loop: right of it, or left when it turns left.
      mid = { x: left ? gx - w - 12 : gx, y: (sy + ty) / 2 };
    } else {
      const lo = Math.min(s.column, t.column),
        hi = Math.max(s.column, t.column);
      // The pill (server side) owns its gutter's far side; route on the client side.
      const firstGutter = rightward ? lo : hi - 1;
      const lastGutter = rightward ? hi - 1 : lo;
      if (hi - lo === 1) {
        const cx = channel(firstGutter, !rightward);
        pts = [
          [sx, sy],
          [cx, sy],
          [cx, ty],
          [tx, ty],
        ];
        mid = { x: cx, y: (sy + ty) / 2 };
      } else {
        const between = Array.from(
          { length: hi - lo - 1 },
          (_, i) => lo + 1 + i,
        );
        const options = [...new Set(between.flatMap(candidates))].filter((y) =>
          between.every((c) => free(c, y)),
        );
        const base = options.length
          ? options.reduce((best, y) =>
              Math.abs(y - sy) + Math.abs(y - ty) <
              Math.abs(best - sy) + Math.abs(best - ty)
                ? y
                : best,
            )
          : topTrack;
        const track = base + trackOffset(base);
        const g1 = channel(firstGutter, !rightward);
        const g2 = channel(lastGutter, !rightward);
        pts = [
          [sx, sy],
          [g1, sy],
          [g1, track],
          [g2, track],
          [g2, ty],
          [tx, ty],
        ];
        mid = { x: (g1 + g2) / 2, y: track };
      }
    }
    if (p.nearTarget && p.label) {
      const w = p.label.length * 6.2 + 14;
      mid = { x: tx - ARROW - w - 8, y: ty - 12 };
    }
    const routed: RoutedEdge = {
      id: edge.id,
      edge,
      points: pts,
      d: straight ? `M${sx},${sy} L${tx},${ty}` : rounded(pts),
      arrow: p.directed && !p.pillKey ? "end" : "none",
      directed: p.directed,
      pill: p.pillKey,
      label: p.card
        ? cardInferredBadge(p.members, edgeById)
        : p.bundled && p.members.length > 1
          ? `×${p.members.length.toLocaleString("en-US")}`
          : p.label,
      blocked:
        (p.bundled ? p.blocked : edge.acl_action === "drop") || undefined,
      members: p.members,
      mid,
      weight: p.weight,
    };
    if (weighted) routed.width = strokeWidth(p.weight, maxWeight);
    if (p.bundled) routed.bundle = p.members.length;
    if (p.card) routed.card = p.card;
    if (p.members.every((id) => edgeById.get(id)?.confidence === "inferred"))
      routed.inferred = true;
    edges.push(routed);
  }
  edges.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { edges, pills, straight };
}
