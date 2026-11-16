import type { Graph, GraphNode } from "../graph";
import type { Device, Topology, TopologyIndex } from "../topology";
import { findDevices } from "../trace/traceModel";

/** At most this many elements fail together in one what-if. */
export const MAX_IMPACT_ELEMENTS = 5;

/**
 * Element tokens: a device (name, IP, serial, pod-N/node-N, ID), an
 * interface `<device>|<interface>` (vmnic, port-channel, vPC leg), a vPC or
 * port-channel on every member `if:<name>`, an endpoint (IP, graph card ID,
 * VM name), `app:<name>`, `epg:<name>` or a subnet `a.b.c.d/n`.
 */
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:/@[\]|-]{0,254}$/;
export const isImpactToken = (s: string) => TOKEN.test(s);

export type ElementKind =
  "device" | "interface" | "endpoint" | "app" | "epg" | "subnet";

export type Tier =
  | "endpoint"
  | "host"
  | "hypervisor"
  | "vswitch"
  | "fi"
  | "leaf"
  | "spine"
  | "switch"
  | "controller";

export interface ImpactElement {
  token: string;
  label: string;
  kind: ElementKind;
  tier?: Tier;
  /** Lower-case canonical device IDs that fail together (an FI has one per LLDP chassis MAC). */
  devices: Set<string>;
  /** Normalized interface name; with no devices it fails on every device carrying it (vPC). */
  iface?: string;
  /** Graph card IDs and `ip:<address>` endpoint keys. */
  endpoints: Set<string>;
  app?: string;
  epg?: string;
  subnet?: { base: number; bits: number };
  resolved: boolean;
  /** Several inventory identities matched and they are not one device. */
  candidates?: Device[];
  /** Member links that fail together (a port-channel or vPC), as `<device>|<interface>`. */
  ports?: string[];
  /** Membership came from an APIC snapshot after the window: its epoch seconds. */
  membershipAfter?: number;
}

/** One leaf port-channel from pc:AggrIf / pc:RsMbrIfs (adm_impact_port_channels). */
export interface PortChannel {
  /** Lower-case canonical device ID of the leaf. */
  device: string;
  /** e.g. "po2". */
  id: string;
  /** Access policy group, e.g. "vpc-1-22-UCS-FI"; a vPC shares it on both leaves. */
  policy?: string;
  members: string[];
  /** Epoch seconds of the newest pcAggrIf/pcRsMbrIfs record used. */
  snapshotTime?: number;
  /** No snapshot in the window: membership is from the first one after it. */
  afterWindow?: boolean;
}

const lower = (s?: string) => s?.trim().toLowerCase() ?? "";
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
export const isIp = (s: string) =>
  IPV4.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(":"));

/** "Ethernet1/21", "eth1/21" and "Eth1/21" compare equal. */
export function normIface(name?: string): string {
  const n = lower(name)
    .replace(/\s*\(inferred\)$/, "")
    .replace(/^ethernet/, "eth");
  return n;
}

/** Fabric-prefixed node names keep their role and number: "…-leaf101" → "leaf101". */
export function shortName(name?: string): string {
  if (!name) return "";
  const t = name.trim();
  if (isIp(t)) return t;
  const m = /(?:^|[-_.])((?:leaf|spine|bleaf|border-leaf)-?\d+)$/i.exec(
    t.split(".")[0],
  );
  if (m) return m[1];
  return t.includes(".") && !/^\d/.test(t) ? t.split(".")[0] : t;
}

export function deviceTier(d: Device | undefined, topo: TopologyIndex): Tier {
  if (!d) return "switch";
  if (d.role === "leaf") return "leaf";
  if (d.role === "spine") return "spine";
  if (d.role === "controller" || d.kind === "controller") return "controller";
  if (d.kind === "hypervisor") return "hypervisor";
  if (d.kind === "virtual_switch") return "vswitch";
  if (d.kind === "host") return "host";
  if (topo.uplinks.get(`${lower(d.id)}|`)?.length) return "fi";
  return "switch";
}

function ipv4(s: string): number | undefined {
  const m = IPV4.exec(s);
  if (!m) return undefined;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return undefined;
  return (
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  );
}
export function inSubnet(
  ip: string,
  subnet: { base: number; bits: number },
): boolean {
  const n = ipv4(ip);
  if (n === undefined) return false;
  const mask = subnet.bits === 0 ? 0 : (~0 << (32 - subnet.bits)) >>> 0;
  return (n & mask) >>> 0 === (subnet.base & mask) >>> 0;
}

/** One device or several identities of one device (same name or management IP). */
function oneDevice(found: Device[]): boolean {
  if (found.length <= 1) return true;
  const names = new Set(found.map((d) => lower(shortName(d.name))));
  const ips = new Set(found.map((d) => d.mgmt_ip ?? ""));
  return names.size === 1 || (ips.size === 1 && !ips.has(""));
}

function deviceElement(
  token: string,
  found: Device[],
  topo: TopologyIndex,
): ImpactElement {
  // Every identity sharing the name (or management IP) is the same box.
  const group = topo.byId.size
    ? [...topo.byId.values()].filter((d) =>
        found.some(
          (f) =>
            f.id === d.id ||
            (lower(shortName(f.name)) === lower(shortName(d.name)) &&
              d.kind === f.kind &&
              d.fabric === f.fabric &&
              d.device_authority === f.device_authority) ||
            (!!f.mgmt_ip &&
              f.mgmt_ip === d.mgmt_ip &&
              d.kind === f.kind &&
              f.kind === "network_device"),
        ),
      )
    : found;
  const first = found[0];
  return {
    token,
    label: shortName(first.name) || token,
    kind: "device",
    tier: deviceTier(first, topo),
    devices: new Set((group.length ? group : found).map((d) => lower(d.id))),
    endpoints: new Set(),
    resolved: true,
  };
}

const nodeMatches = (n: GraphNode, q: string) =>
  lower(n.id) === q ||
  lower(n.label) === q ||
  lower(n.attributes?.vm_name) === q ||
  (n.addresses ?? []).some((a) => lower(a) === q);

/** Resolves a token against inventory and the loaded graph. Never guesses between candidates. */
export function resolveElement(
  token: string,
  topology: Topology,
  topo: TopologyIndex,
  graph?: Graph,
  portChannels: readonly PortChannel[] = [],
): ImpactElement {
  const t = token.trim();
  const base: ImpactElement = {
    token: t,
    label: t,
    kind: "endpoint",
    devices: new Set(),
    endpoints: new Set(),
    resolved: false,
  };
  if (!isImpactToken(t)) return base;
  const q = lower(t);
  if (q.startsWith("app:"))
    return {
      ...base,
      kind: "app",
      label: t.slice(4),
      app: t.slice(4),
      resolved: true,
    };
  if (q.startsWith("epg:"))
    return {
      ...base,
      kind: "epg",
      label: `EPG ${t.slice(4)}`,
      epg: t.slice(4),
      resolved: true,
    };
  // A vPC or port-channel by its policy group: every member on every leaf.
  const policy = q.startsWith("if:") ? q.slice(3) : q;
  const group = portChannels.filter((p) => lower(p.policy) === policy);
  if (group.length)
    return {
      ...base,
      kind: "interface",
      label: t.startsWith("if:") ? t.slice(3) : t,
      iface: normIface(policy),
      ports: memberPorts(group),
      ...membershipAsOf(group),
      resolved: true,
    };
  if (q.startsWith("if:"))
    return {
      ...base,
      kind: "interface",
      label: t.slice(3),
      iface: normIface(t.slice(3)),
      resolved: true,
    };
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(t);
  if (cidr && Number(cidr[2]) <= 32 && ipv4(cidr[1]) !== undefined)
    return {
      ...base,
      kind: "subnet",
      label: t,
      subnet: { base: ipv4(cidr[1])!, bits: Number(cidr[2]) },
      resolved: true,
    };
  if (t.includes("|")) {
    const [dev, ...rest] = t.split("|");
    const iface = rest.join("|");
    const found = findDevices(dev, topology);
    if (!iface || !found.length || !oneDevice(found))
      return { ...base, candidates: found.length > 1 ? found : undefined };
    const d = deviceElement(dev, found, topo);
    // "leaf101|po2", "leaf101|port-channel2" or the policy group on that leaf.
    const pc = /^(?:po|port-channel)\s*(\d+)$/i.exec(iface);
    const own = portChannels.filter(
      (p) =>
        d.devices.has(p.device) &&
        ((pc && lower(p.id) === `po${pc[1]}`) ||
          lower(p.policy) === lower(iface)),
    );
    return {
      ...d,
      token: t,
      kind: "interface",
      label: `${d.label} ${iface}`,
      iface: normIface(own[0]?.policy ?? iface),
      ...(own.length
        ? { ports: memberPorts(own), ...membershipAsOf(own) }
        : {}),
    };
  }
  // A graph card ID wins: it is exact.
  const card = graph?.nodes.find((n) => n.id === t);
  if (card) return endpointElement(t, card, graph!);
  const found = findDevices(t, topology).filter(
    (d) => d.kind !== "network_client",
  );
  if (found.length && oneDevice(found)) return deviceElement(t, found, topo);
  if (found.length > 1) return { ...base, candidates: found };
  const nodes = graph?.nodes.filter((n) => nodeMatches(n, q)) ?? [];
  if (nodes.length === 1) return endpointElement(t, nodes[0], graph!);
  if (isIp(t)) {
    const names = new Set(
      (topo.virtualPorts.get(q) ?? []).map((p) => p.vm_name).filter(Boolean),
    );
    return {
      ...base,
      label: names.size === 1 ? [...names][0]! : t,
      endpoints: new Set([`ip:${q}`]),
      resolved: true,
    };
  }
  // A VM known only to vSphere inventory.
  const ports = [...topo.virtualPorts.values()]
    .flat()
    .filter((p) => lower(p.vm_name) === q && p.ip);
  const ips = new Set(ports.map((p) => lower(p.ip)));
  if (ips.size === 1)
    return {
      ...base,
      label: ports[0].vm_name ?? t,
      endpoints: new Set([`ip:${[...ips][0]}`]),
      resolved: true,
    };
  return base;
}

/** The latest snapshot time among after-window port-channel rows, if any. */
const membershipAsOf = (pcs: readonly PortChannel[]) => {
  const after = pcs
    .filter((p) => p.afterWindow && p.snapshotTime !== undefined)
    .map((p) => p.snapshotTime!);
  return after.length ? { membershipAfter: Math.max(...after) } : {};
};

const memberPorts = (pcs: readonly PortChannel[]) => [
  ...new Set(
    pcs.flatMap((p) => p.members.map((m) => `${p.device}|${normIface(m)}`)),
  ),
];

function endpointElement(
  token: string,
  n: GraphNode,
  graph: Graph,
): ImpactElement {
  const endpoints = new Set([
    n.id,
    ...(n.addresses ?? []).map((a) => `ip:${lower(a)}`),
  ]);
  // A service card stands for its pods.
  if (n.kind === "service")
    for (const e of graph.edges)
      if (e.relationship === "runs_on" && e.source === n.id)
        endpoints.add(e.target);
  return {
    token,
    label: n.label,
    kind: n.kind === "service" ? "app" : "endpoint",
    ...(n.kind === "service" ? { app: n.label } : {}),
    devices: new Set(),
    endpoints,
    resolved: true,
  };
}
