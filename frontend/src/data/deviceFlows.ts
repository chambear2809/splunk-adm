import { ifIndexOf, unnamedIfIndexLabel } from "../ifIndex";
import type { SearchClient } from "./searchClient";
import type { Device, TopologyIndex } from "../topology";
/** Device-centric conversations from `adm_device_flows(1)` rows. Rows are untrusted. */
export interface DeviceConversation {
  src: string;
  srcName?: string;
  dst: string;
  dstName?: string;
  destPort?: number;
  protocol: string;
  bytes?: number;
  packets?: number;
  flows: number;
  firstSeen?: number;
  lastSeen?: number;
  interfaces: string[];
  blocked: boolean;
  drops: number;
  permits: number;
  vlans: string[];
  /** Overlay segment IDs (IPFIX layer2SegmentId): underlay attribution does not apply. */
  segments: string[];
  /** Owning Service/owner, only when exactly one is known. */
  app?: string;
  sources: string[];
}
export interface DeviceFlows {
  device: string;
  conversations: DeviceConversation[];
  totals: { conversations: number; flows: number; bytes?: number };
  /** More conversations exist than were returned (top-N by bytes). */
  truncated: boolean;
  /** Configured top-N (`adm_device_flows_limit`), when the search reports it. */
  limit?: number;
  /** The raw record cap was reached; totals are lower bounds. */
  recordsCapped: boolean;
}

export const MAX_DEVICE_FLOW_ROWS = 1000;

const str = (v: unknown): string | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === "string" && x.trim() !== ""
    ? x.trim()
    : typeof x === "number" && Number.isFinite(x)
      ? String(x)
      : undefined;
};
const list = (v: unknown): string[] =>
  (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v])
    .map(str)
    .filter((x): x is string => !!x);
const num = (v: unknown): number | undefined => {
  const s = str(v);
  if (s === undefined) return undefined;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};

/** Parses adm_device_flows rows; rows missing src, dst or protocol are rejected. */
export function rowsToDeviceFlows(device: string, rows: unknown): DeviceFlows {
  if (!Array.isArray(rows))
    throw new Error("Device flow rows must be an array.");
  if (rows.length > MAX_DEVICE_FLOW_ROWS)
    throw new Error("Device flows exceed the row limit.");
  const conversations: DeviceConversation[] = [];
  let total: Record<string, unknown> | undefined;
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error("Invalid device flow row.");
    const r = raw as Record<string, unknown>;
    const src = str(r.src),
      dst = str(r.dst),
      protocol = str(r.protocol);
    if (!src || !dst || !protocol) throw new Error("Invalid device flow row.");
    if (str(r.device) !== undefined && str(r.device) !== device)
      throw new Error("Device flow row belongs to another device.");
    total ??= r;
    const c: DeviceConversation = {
      src,
      dst,
      protocol,
      flows: num(r.flows) ?? 0,
      interfaces: list(r.interfaces),
      blocked: str(r.blocked) === "1",
      drops: num(r.drops) ?? 0,
      permits: num(r.permits) ?? 0,
      vlans: list(r.vlans),
      segments: list(r.segments),
      sources: list(r.sources),
    };
    const opt = {
      srcName: str(r.src_name),
      dstName: str(r.dst_name),
      destPort: num(r.dest_port),
      bytes: num(r.bytes),
      packets: num(r.packets),
      firstSeen: num(r.first_seen),
      lastSeen: num(r.last_seen),
      app: str(r.app),
    };
    for (const [k, v] of Object.entries(opt))
      if (v !== undefined) (c as unknown as Record<string, unknown>)[k] = v;
    conversations.push(c);
  }
  conversations.sort(
    (a, b) =>
      (b.bytes ?? -1) - (a.bytes ?? -1) ||
      b.flows - a.flows ||
      a.src.localeCompare(b.src) ||
      a.dst.localeCompare(b.dst),
  );
  return {
    device,
    conversations,
    totals: {
      conversations: num(total?.total_conversations) ?? conversations.length,
      flows:
        num(total?.total_flows) ??
        conversations.reduce((n, c) => n + c.flows, 0),
      ...(num(total?.total_bytes) !== undefined
        ? { bytes: num(total?.total_bytes) }
        : {}),
    },
    truncated: str(total?.truncated) === "1",
    recordsCapped: str(total?.records_capped) === "1",
    ...(num(total?.flows_limit) ? { limit: num(total?.flows_limit) } : {}),
  };
}

/** Compact interface name: port-channel2 → po2, Ethernet1/2 → Eth1/2. */
export function compactInterface(name: string): string {
  const text = name.trim();
  const pair = /^(port-channel\d+)\s*(?:\(|·)\s*([^()]+?)\)?$/i.exec(text);
  if (pair) return `${compactInterface(pair[1])} · ${pair[2].trim()}`;
  return text
    .replace(/^port-channel(\d+)$/i, "po$1")
    .replace(/^Ethernet(\d)/i, "Eth$1");
}

export interface InterfaceSide {
  /** Compact display name. */
  text: string;
  /** Full name for the tooltip, with provenance. */
  title: string;
  inferred: boolean;
}

/**
 * Ingress and egress sides of a conversation's named interface pairs
 * ("A > B", "A", "→ B", "A > B (inferred)"), deduplicated per side.
 */
export function interfaceSides(pairs: readonly string[]): {
  in: InterfaceSide[];
  out: InterfaceSide[];
} {
  const sides = {
    in: new Map<string, InterfaceSide>(),
    out: new Map<string, InterfaceSide>(),
  };
  const add = (side: "in" | "out", raw: string | undefined) => {
    let name = raw?.trim();
    if (!name || name === "?") return;
    const inferred = / \(inferred\)$/.test(name);
    name = name.replace(/ \(inferred\)$/, "");
    if (!name || sides[side].has(name)) return;
    sides[side].set(name, {
      text: compactInterface(name),
      title: inferred ? `${name} (inferred)` : name,
      inferred,
    });
  };
  for (const pair of pairs) {
    const text = pair.trim();
    if (text.startsWith("→ ")) add("out", text.slice(2));
    else {
      const [ingress, egress] = text.split(" > ");
      add("in", ingress);
      add("out", egress);
    }
  }
  return { in: [...sides.in.values()], out: [...sides.out.values()] };
}

/** Distinct peers and blocked conversations, for a device summary line. */
export function deviceFlowSummary(f: DeviceFlows): {
  peers: number;
  blocked: number;
  overlay: number;
} {
  const peers = new Set(f.conversations.flatMap((c) => [c.src, c.dst]));
  return {
    peers: peers.size,
    blocked: f.conversations.filter((c) => c.blocked).length,
    overlay: f.conversations.filter((c) => c.segments.length > 0).length,
  };
}

/** The SPL for one device; the argument must already be a valid observer token. */
export function deviceFlowsSearch(device: string): string {
  if (!/^[A-Za-z0-9_.:/-]{1,128}$/.test(device))
    throw new Error("Invalid device identifier for device flows.");
  return `| \`adm_device_flows(${device})\``;
}
/** The SPL for one address pair; names must be resolved to IPs first. */
export function pathTraceSearch(src: string, dst: string): string {
  const ip = /^[0-9A-Fa-f:.]{2,45}$/;
  if (!ip.test(src) || !ip.test(dst))
    throw new Error("Path trace search expects two IP literals.");
  return `| \`adm_path_trace(${src},${dst})\``;
}

/** ACI node and vSphere device identities for the Device page. */
export { isNxosDevice } from "../ifIndex";
export const DEVICE_INVENTORY_SEARCH = "| `adm_device_inventory`";
export const MAX_DEVICE_INVENTORY_ROWS = 5000;
const MAX_INTERFACE_NAME_ROWS = 5000;
const IP_TOKEN = /^[0-9A-Fa-f:.]{2,45}$/;

/** The SPL for one exporter's interface names; the token must be an IP literal. */
export function interfaceNamesSearch(exporter: string): string {
  if (!IP_TOKEN.test(exporter) || !/[.:]/.test(exporter))
    throw new Error("Interface names expect an exporter IP literal.");
  return `| \`adm_interface_names(${exporter})\``;
}

/** ifIndex → collected interface name from adm_interface_names rows. Rows are untrusted. */
export function interfaceNameRows(
  exporter: string,
  rows: unknown,
): Map<number, string> {
  const out = new Map<number, string>();
  const conflicting = new Set<number>();
  if (!Array.isArray(rows)) return out;
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type !== "interface" || str(r.device_id) !== exporter) continue;
    const n = num(r.ifindex),
      name = str(r.interface);
    if (n === undefined || !Number.isSafeInteger(n) || !name) continue;
    if (out.has(n) && out.get(n) !== name) conflicting.add(n);
    out.set(n, name);
  }
  for (const n of conflicting) out.delete(n);
  return out;
}

/** Interface names for an IP token; non-IP tokens and failures yield none. */
export async function loadInterfaceNames(
  client: SearchClient,
  token: string,
  w: {
    earliest: string;
    latest?: string;
    timezone?: string;
    signal: AbortSignal;
  },
): Promise<Map<number, string>> {
  if (!IP_TOKEN.test(token) || !/[.:]/.test(token)) return new Map();
  try {
    const result = await client.search({
      search: interfaceNamesSearch(token),
      earliest: w.earliest,
      latest: w.latest,
      timezone: w.timezone,
      maxRows: MAX_INTERFACE_NAME_ROWS,
      allowEmpty: true,
      signal: w.signal,
    });
    return result.errors.length
      ? new Map()
      : interfaceNameRows(token, result.rows);
  } catch (e) {
    if (w.signal.aborted) throw e;
    return new Map();
  }
}

/**
 * "ifIndex 7 > ifIndex 0" → collected names; else decoded (NX-OS) or neutral
 * ifIndex text. An absent side ("?", or ifIndex 0 off NX-OS, as in
 * ingress-only NetFlow v9) is omitted: "port-channel1", or "→ Eth1/2" when only
 * the egress is known. Never "?".
 */
export function nameInterfacePair(
  pair: string,
  names: ReadonlyMap<number, string>,
  nxos: boolean,
): string {
  const [ingress, egress] = pair.split(" > ").map((side) => {
    const text = side.trim();
    if (!text || text === "?") return undefined;
    const n = ifIndexOf(text);
    if (n === undefined) return text;
    if (n === 0 && !nxos) return undefined;
    return names.get(n) ?? unnamedIfIndexLabel(n, nxos);
  });
  if (pair.split(" > ").length < 2) return ingress ?? "";
  if (ingress && egress) return `${ingress} > ${egress}`;
  if (ingress) return ingress;
  return egress ? `→ ${egress}` : "";
}

const INFERRED = " (inferred)";

/**
 * ACI leaf NetFlow exports ingress only. For an ingress-only pair at a leaf,
 * the egress is inferred from the destination's ACI endpoint attachment
 * (fvCEp / fvRsCEpToPathEp, carried on its unique vNIC by IP and MAC): the
 * attached interface when the destination is on this leaf, else "fabric"
 * (toward a spine). Unknown destinations keep the ingress alone.
 */
export function inferLeafEgress(
  flows: DeviceFlows,
  device: Device | undefined,
  topo: TopologyIndex,
): DeviceFlows {
  const leaf = device?.aci_node?.trim().toLowerCase();
  if (!leaf) return flows;
  const attachment = (ip: string) => {
    const ports = [
      ...new Map(
        (topo.virtualPorts.get(ip.trim().toLowerCase()) ?? [])
          .filter((p) => p.mac && p.ip === ip)
          .map((p) => [`${p.switch}|${p.vm}`, p]),
      ).values(),
    ];
    return ports.length === 1 ? ports[0] : undefined;
  };
  return {
    ...flows,
    conversations: flows.conversations.map((c) => {
      const port = attachment(c.dst);
      if (!port?.attach_nodes?.length) return c;
      const local = port.attach_nodes.some((n) => n.toLowerCase() === leaf);
      const egress = local ? port.attach_interface : "fabric";
      if (!egress) return c;
      return {
        ...c,
        interfaces: c.interfaces.map((i) =>
          i && !i.includes(" > ") && !i.startsWith("→ ")
            ? `${i} > ${egress}${INFERRED}`
            : i,
        ),
      };
    }),
  };
}

export function nameDeviceInterfaces(
  flows: DeviceFlows,
  names: ReadonlyMap<number, string>,
  nxos: boolean,
): DeviceFlows {
  return {
    ...flows,
    conversations: flows.conversations.map((c) => ({
      ...c,
      interfaces: [
        ...new Set(
          c.interfaces
            .map((i) => nameInterfacePair(i, names, nxos))
            .filter(Boolean),
        ),
      ],
    })),
  };
}
