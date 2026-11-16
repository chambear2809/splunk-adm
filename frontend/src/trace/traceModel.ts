import type { DeviceConversation, DeviceFlows } from "../data/deviceFlows";
import {
  serviceOrder,
  type PathTrace,
  type TraceDrop,
  type TraceHop,
} from "../data/pathTrace";
import { sourceLabel } from "../glossary";
import {
  rowsToTopology,
  type Device,
  type Topology,
  type TopologyIndex,
} from "../topology";

/** Per-pair totals from adm_path_trace observation rows. Rows are untrusted. */
export interface TraceSummary {
  records: number;
  bytes?: number;
  protocols: string[];
  /** Listener (service) ports, e.g. "47001"; client ports are not included. */
  ports: string[];
  /** Listener services, e.g. "tcp/47001" (adm_path_trace services). */
  services: string[];
  /** Client-side ports seen against those services (detail only). */
  clientPorts: string[];
  firstSeen?: number;
  lastSeen?: number;
  /** Last seen per collector label (e.g. "Stream NetFlow"). */
  lastSeenBySource: Map<string, number>;
}

const text = (v: unknown): string[] =>
  (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v])
    .map((x) => (typeof x === "number" && Number.isFinite(x) ? String(x) : x))
    .filter((x): x is string => typeof x === "string" && x.trim() !== "")
    .map((x) => x.trim());
const count = (v: unknown): number | undefined => {
  const n = Number(text(v)[0]);
  return text(v).length && Number.isFinite(n) && n >= 0 ? n : undefined;
};

export function traceSummary(rows: readonly unknown[]): TraceSummary {
  const out: TraceSummary = {
    records: 0,
    protocols: [],
    ports: [],
    services: [],
    clientPorts: [],
    lastSeenBySource: new Map(),
  };
  const protocols = new Set<string>(),
    ports = new Set<string>(),
    services = new Set<string>(),
    clients = new Set<string>();
  // Rows from searches that name the listener side carry services; older rows
  // only have dest_ports, which mix in the reverse direction's client ports.
  const named = rows.some(
    (r) =>
      !!r &&
      typeof r === "object" &&
      (r as Record<string, unknown>).row_type === "observation" &&
      text((r as Record<string, unknown>).services).length > 0,
  );
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type !== "observation") continue;
    out.records += count(r.records) ?? 0;
    const bytes = count(r.bytes);
    if (bytes !== undefined) out.bytes = (out.bytes ?? 0) + bytes;
    text(r.protocols).forEach((p) => protocols.add(p.toLowerCase()));
    if (named) {
      for (const s of text(r.services)) {
        const [proto, port] = s.toLowerCase().split("/");
        if (!/^[a-z0-9-]{1,16}$/.test(proto)) continue;
        services.add(port ? `${proto}/${port}` : proto);
        if (port && /^\d{1,5}$/.test(port)) ports.add(port);
      }
      for (const p of text(r.client_ports))
        if (/^\d{1,5}$/.test(p)) clients.add(p);
    } else if (text(r.direction)[0] !== "reverse")
      text(r.dest_ports).forEach((p) => ports.add(p));
    const first = count(r.first_seen),
      last = count(r.last_seen);
    if (first !== undefined)
      out.firstSeen = Math.min(out.firstSeen ?? first, first);
    if (last !== undefined) {
      out.lastSeen = Math.max(out.lastSeen ?? last, last);
      const source = text(r.flow_source)[0];
      if (source) {
        const label = sourceLabel(source);
        out.lastSeenBySource.set(
          label,
          Math.max(out.lastSeenBySource.get(label) ?? last, last),
        );
      }
    }
  }
  out.protocols = [...protocols].sort();
  out.ports = [...ports].sort((a, b) => Number(a) - Number(b));
  out.services = [...services].sort(serviceOrder);
  for (const p of ports) clients.delete(p);
  out.clientPorts = [...clients].sort((a, b) => Number(a) - Number(b));
  return out;
}

/** "tcp/5432", "tcp/443 +2", or undefined when nothing was observed. */
export function portProtoLabel(
  protocols: readonly string[],
  ports: readonly string[],
): string | undefined {
  if (!protocols.length && !ports.length) return undefined;
  const proto = protocols.length > 1 ? protocols.join("+") : protocols[0];
  const port = ports[0];
  const more = ports.length > 1 ? ` +${ports.length - 1}` : "";
  return [proto, port].filter(Boolean).join("/") + more;
}

/** Topology for a live trace: loaded inventory plus the pair's vSphere rows. */
export function traceTopology(base: Topology, rows: readonly unknown[]) {
  const extra = rowsToTopology(
    rows.filter(
      (r) =>
        !!r &&
        typeof r === "object" &&
        ["device", "link", "interface"].includes(
          String((r as Record<string, unknown>).row_type),
        ),
    ),
  );
  if (!extra.devices.length && !extra.links.length && !extra.interfaces.length)
    return base;
  const known = new Set(base.devices.map((d) => d.id));
  const linkKey = (l: Topology["links"][number]) => JSON.stringify(l);
  const links = new Set(base.links.map(linkKey));
  return {
    ...base,
    devices: [
      ...base.devices,
      ...extra.devices.filter((d) => !known.has(d.id)),
    ],
    links: [
      ...base.links,
      ...extra.links.filter((l) => !links.has(linkKey(l))),
    ],
    interfaces: [...base.interfaces, ...extra.interfaces],
  };
}

export type HopIcon =
  | "vm"
  | "pod"
  | "host"
  | "vswitch"
  | "fi"
  | "leaf"
  | "spine"
  | "switch"
  | "firewall"
  | "external"
  | "handoff"
  | "gap";

/** Icon and short kind label for one hop. */
export function hopIcon(
  hop: TraceHop,
  topo?: TopologyIndex,
): { icon: HopIcon; kind: string } {
  const device = hop.device ? topo?.byId.get(hop.device) : undefined;
  const first = hop.alternatives?.[0]
    ? topo?.byId.get(hop.alternatives[0].device)
    : undefined;
  const role = (device ?? first)?.role ?? "";
  const detail = hop.detail ?? "";
  switch (hop.kind) {
    case "endpoint":
      if (/^VM\b/.test(detail)) return { icon: "vm", kind: "VM" };
      if (/^(Pod|Service)\b/.test(detail)) return { icon: "pod", kind: "Pod" };
      if (/^Host\b|node/i.test(detail)) return { icon: "host", kind: "Host" };
      return { icon: "external", kind: "External" };
    case "host":
      return { icon: "host", kind: "Host" };
    case "virtual_switch":
      return {
        icon: "vswitch",
        kind: /^VSS\b/.test(detail)
          ? "VSS"
          : /^VDS\b/.test(detail)
            ? "VDS"
            : "vSwitch",
      };
    case "firewall":
      return { icon: "firewall", kind: "Firewall" };
    case "handoff":
      return { icon: "handoff", kind: "Handoff" };
    case "gap":
      return { icon: "gap", kind: "Gap" };
    default:
      if (role === "spine" || /\bspine/i.test(detail + hop.label))
        return { icon: "spine", kind: "Spine" };
      if (role === "leaf" || /\bleaf\b/i.test(detail))
        return { icon: "leaf", kind: "Leaf" };
      if (
        (device ?? first)?.kind === "network_device" ||
        /fabric interconnect|\bFI\b/i.test(detail)
      )
        return { icon: "fi", kind: "FI" };
      return { icon: "switch", kind: "Switch" };
  }
}

export type HopItem =
  | { type: "hop"; hop: TraceHop; index: number }
  | { type: "more"; from: number; hops: TraceHop[] };

/** Paths longer than this collapse their middle into "+N hops". */
export const COLLAPSE_OVER = 7;

/**
 * Keeps the first two and last two hops, gaps and blocked hops; runs of two or
 * more other hops in between collapse into one "+N hops" item.
 */
export function collapseHops(
  hops: readonly TraceHop[],
  expanded: boolean,
  keep: (hop: TraceHop, index: number) => boolean = () => false,
): HopItem[] {
  const items: HopItem[] = hops.map((hop, index) => ({
    type: "hop",
    hop,
    index,
  }));
  if (expanded || hops.length <= COLLAPSE_OVER) return items;
  const out: HopItem[] = [];
  let run: { from: number; hops: TraceHop[] } | undefined;
  const flush = () => {
    if (!run) return;
    if (run.hops.length >= 2) out.push({ type: "more", ...run });
    else
      run.hops.forEach((hop, i) =>
        out.push({ type: "hop", hop, index: run!.from + i }),
      );
    run = undefined;
  };
  hops.forEach((hop, index) => {
    const fold =
      index >= 2 &&
      index < hops.length - 2 &&
      hop.evidence !== "gap" &&
      !keep(hop, index);
    if (fold) {
      run ??= { from: index, hops: [] };
      run.hops.push(hop);
    } else {
      flush();
      out.push({ type: "hop", hop, index });
    }
  });
  flush();
  return out;
}

const lower = (s?: string) => (s ?? "").trim().toLowerCase();

/** Where and what a hop blocked: an ACI contract at a leaf or Kubernetes policy at a node. */
export interface BlockedHop {
  kind: "aci" | "k8s";
  /** Dropped services, e.g. "tcp/47003"; empty when the record has none. */
  services: string[];
  reasons: string[];
}

export const blockedKindLabel = (b: BlockedHop) =>
  b.kind === "k8s" ? "Kubernetes policy" : "ACI contract";

/** "Blocked tcp/47003" (or "Blocked" when no service was recorded). */
export const blockedLabel = (b: BlockedHop) =>
  [
    "Blocked",
    b.services.slice(0, 2).join(", "),
    b.services.length > 2 ? `+${b.services.length - 2}` : "",
  ]
    .filter(Boolean)
    .join(" ");

/**
 * Hops where records of the pair were logged as dropped: ACL-log leaves
 * (graph conversations or adm_path_trace drop rows) and Hubble nodes. A vPC or
 * ECMP hop is blocked when the enforcing leaf is one of its members.
 */
export function blockedHops(
  trace: PathTrace,
  topo?: TopologyIndex,
): Map<number, BlockedHop> {
  const drops: TraceDrop[] = [
    ...(trace.drops ?? []),
    ...trace.conversations
      .filter((e) => e.acl_action === "drop" && e.acl_leaf)
      .map((e): TraceDrop => ({
        source: "aci_acllog",
        device: e.acl_leaf!,
        services:
          e.transport && typeof e.server_port === "number"
            ? [`${lower(e.transport)}/${e.server_port}`]
            : [],
        reasons: [],
        records: e.acl_drops ?? 1,
      })),
  ];
  const out = new Map<number, BlockedHop>();
  if (!drops.length) return out;
  const names = (id?: string) => {
    const d = id ? topo?.byId.get(id) : undefined;
    return [id, d?.id, d?.name, d?.aci_node].map(lower).filter(Boolean);
  };
  trace.hops.forEach((hop, i) => {
    const ids = [hop.device, ...(hop.alternatives ?? []).map((a) => a.device)];
    const own = new Set([
      ...ids.flatMap(names),
      lower(hop.label),
      ...(hop.alternatives ?? []).map((a) => lower(a.label)),
    ]);
    for (const drop of drops) {
      const kind = drop.source === "hubble" ? "k8s" : "aci";
      // Kubernetes policy is enforced at the node, ACI contracts at a switch.
      if (kind === "k8s" ? hop.kind !== "host" : hop.kind !== "switch")
        continue;
      if (!own.has(lower(drop.device))) continue;
      const prior = out.get(i);
      out.set(i, {
        kind,
        services: [
          ...new Set([...(prior?.services ?? []), ...drop.services]),
        ].sort(serviceOrder),
        reasons: [...new Set([...(prior?.reasons ?? []), ...drop.reasons])],
      });
    }
  });
  return out;
}

/** Services seen for the pair that no blocked hop dropped. */
export function openServices(
  summary: TraceSummary,
  blocked: ReadonlyMap<number, BlockedHop>,
): string[] {
  const dropped = new Set([...blocked.values()].flatMap((b) => b.services));
  return summary.services.filter((s) => s.includes("/") && !dropped.has(s));
}

/** Graph node and edge IDs to emphasize on the map for a trace. */
export function traceHighlight(trace: PathTrace): {
  nodes: Set<string>;
  edges: Set<string>;
} {
  const nodes = new Set<string>();
  for (const e of [trace.src, trace.dst]) if (e.node) nodes.add(e.node.id);
  for (const h of trace.hops) {
    if (h.device) nodes.add(h.device);
    h.alternatives?.forEach((a) => nodes.add(a.device));
  }
  return { nodes, edges: new Set(trace.conversations.map((e) => e.id)) };
}

/** Device tokens accepted by adm_device_flows, best first, at most four. */
export function flowTokens(device: Device): string[] {
  const valid = (s?: string) =>
    !!s && /^[A-Za-z0-9_.:/-]{1,128}$/.test(s) ? [s] : [];
  const tokens =
    device.kind === "virtual_switch" && device.ipfix_observers?.length
      ? device.ipfix_observers.flatMap((o) => valid(o.split("|")[0]))
      : [
          ...valid(device.aci_node),
          ...valid(device.mgmt_ip),
          // Hubble names its observer by the Kubernetes node name.
          ...(device.aci_node ||
          (device.mgmt_ip &&
            !(
              device.kind === "host" &&
              device.sources.includes("kubernetes_node")
            ))
            ? []
            : valid(device.name)),
        ];
  return [...new Set(tokens)].slice(0, 4);
}

/** Lookup by canonical ID, name, management IP, serial, ACI node or DN. */
export function findDevices(query: string, topo: Topology): Device[] {
  const q = lower(query);
  if (!q) return [];
  // topology/pod-1/node-103/sys/... → pod-1/node-103
  const dn = /^(?:topology\/)?(pod-\d+\/node-\d+)(?:\/.*)?$/.exec(q)?.[1];
  const exact = topo.devices.filter((d) => lower(d.id) === q);
  if (exact.length) return exact;
  const hit = (values: (string | undefined)[]) =>
    values.map(lower).some((v) => v && (v === q || (!!dn && v === dn)));
  const named = topo.devices.filter((d) =>
    hit([
      d.name,
      d.mgmt_ip,
      d.serial,
      d.aci_node,
      d.native_device_id,
      ...(d.aliases ?? []),
    ]),
  );
  if (named.length) return named;
  // ACI node ID ("101", "node-101") → pod-N/node-101.
  const node = /^(?:node-?)?(\d{1,5})$/.exec(q)?.[1];
  if (node) {
    const byNode = topo.devices.filter((d) =>
      lower(d.aci_node)?.endsWith(`/node-${node}`),
    );
    if (byNode.length) return byNode;
  }
  // An exporter address names the virtual switch it observes for.
  const observing = topo.devices.filter((d) =>
    hit((d.ipfix_observers ?? []).map((o) => o.split("|")[0])),
  );
  if (observing.length) return observing;
  // A short name of a fabric-prefixed node ("leaf101" for
  // "nyc-aci-fabric-01-leaf101"); several matches are offered, never merged.
  if (q.length < 3 || /^[0-9.:]+$/.test(q)) return [];
  return topo.devices.filter((d) => {
    const n = lower(d.name);
    return (
      !!n &&
      (n.endsWith(`-${q}`) || n.endsWith(`.${q}`) || n.startsWith(`${q}.`))
    );
  });
}

/** Seconds since epoch → "2026-10-07 12:00" (UTC). */
export function epochLabel(seconds?: number): string | undefined {
  if (seconds === undefined || !Number.isFinite(seconds)) return undefined;
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime())
    ? undefined
    : d.toISOString().slice(0, 16).replace("T", " ");
}

/** One device's flows across its tokens (e.g. each IPFIX exporter of a VDS). */
export function mergeDeviceFlows(
  device: string,
  parts: readonly DeviceFlows[],
): DeviceFlows {
  const byKey = new Map<string, DeviceConversation>();
  for (const p of parts)
    for (const c of p.conversations) {
      const key = conversationKey(c);
      const prior = byKey.get(key);
      if (!prior || (c.bytes ?? c.flows) > (prior.bytes ?? prior.flows))
        byKey.set(key, c);
    }
  const bytes = parts
    .map((p) => p.totals.bytes)
    .filter((b): b is number => b !== undefined);
  const limits = parts
    .map((p) => p.limit)
    .filter((n): n is number => n !== undefined && n > 0);
  const limit = limits.length ? Math.min(...limits) : undefined;
  const truncated = parts.some((p) => p.truncated);
  const sorted = [...byKey.values()].sort(
    (a, b) => (b.bytes ?? -1) - (a.bytes ?? -1) || b.flows - a.flows,
  );
  return {
    device,
    // Several exporter tokens can each return the configured top N; the
    // merged list keeps the same top N so "Top N of M" matches the setting.
    conversations:
      truncated && limit !== undefined ? sorted.slice(0, limit) : sorted,
    ...(limit !== undefined ? { limit } : {}),
    totals: {
      // Exporters can report the same conversation; only a cut list needs the sum.
      conversations: parts.some((p) => p.truncated)
        ? Math.max(
            byKey.size,
            parts.reduce((n, p) => n + p.totals.conversations, 0),
          )
        : byKey.size,
      flows: parts.reduce((n, p) => n + p.totals.flows, 0),
      ...(bytes.length ? { bytes: bytes.reduce((n, b) => n + b, 0) } : {}),
    },
    truncated,
    recordsCapped: parts.some((p) => p.recordsCapped),
  };
}

export const conversationKey = (c: DeviceConversation) =>
  `${c.src}|${c.dst}|${c.protocol}|${c.destPort ?? ""}`;
