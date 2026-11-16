import type { GraphEdge, GraphIndex } from "../graph";
import { sourceLabel } from "../glossary";
import {
  edgeDeviceContext,
  edgeObservers,
  parseEdgeObserver,
  virtualPortFor,
  type Device,
  type TopologyIndex,
} from "../topology";
import { inferLeafHopEgress } from "./pathTrace";

/** One observer device and interface pair of a conversation, for the inspector. */
export interface ObserverInterfaceRow {
  /** Observer device key; rows of one device are adjacent. */
  device: string;
  label: string;
  in?: string;
  out?: string;
  /** Records this observer exported, when attributable to it. */
  records?: number;
  sources: string[];
  /** The egress was inferred (ACI leaf NetFlow exports ingress only). */
  inferredOut: boolean;
}

const OBSERVER_IP = /^[^:]+:(.*?)(?::[^:>]*>[^:>]*)?$/;
const lower = (s: string) => s.trim().toLowerCase();

/** Records of one observer: its own qualified records, else the edge total when it is the only observer. */
function observerRecords(
  edge: GraphEdge,
  observer: string,
  devices: number,
): number | undefined {
  const obs = edge.traffic_observations;
  if (obs?.length) {
    const ip = OBSERVER_IP.exec(observer)?.[1];
    const n = obs.filter((o) => !!ip && o.exporter_ip === ip).length;
    return n || undefined;
  }
  return devices === 1 ? (edge.records ?? edge.count) : undefined;
}

/**
 * In and out interfaces per observer device for one conversation, named as
 * the path does (collected ifDescr/DVS names, decoded NX-OS ifIndex, vPC
 * attachment names). An ingress-only ACI leaf gets the destination's ACI
 * attachment on that leaf, else "fabric", both marked inferred.
 */
export function observerInterfaceRows(
  edge: GraphEdge,
  index: GraphIndex,
  topo: TopologyIndex,
): ObserverInterfaceRow[] {
  if (edge.relationship !== "communicates_with") return [];
  const context = edgeDeviceContext(edge, index);
  const byKey = new Map<string, Device>(
    [...topo.byId.values()].map((d) => [lower(d.id), d]),
  );
  const attachment = virtualPortFor(index.node.get(edge.target), topo);
  const points = edgeObservers(edge).flatMap((o) =>
    parseEdgeObserver(o, edge, topo, context).map((p) => ({ o, p })),
  );
  const devices = new Set(points.map(({ p }) => p.key)).size;
  const rows = new Map<string, ObserverInterfaceRow>();
  for (const { o, p } of points) {
    let out = p.out;
    let inferredOut = false;
    const device = p.resolved ? byKey.get(p.key) : undefined;
    if (
      p.in &&
      !out &&
      device?.aci_node &&
      edge.direction_basis !== "unknown"
    ) {
      const [hop] = inferLeafHopEgress(
        [
          {
            kind: "switch",
            label: p.label,
            device: device.id,
            in: p.in,
            evidence: "observed",
            sources: [],
            seen: [],
          },
        ],
        attachment,
        topo,
      );
      if (hop.out) {
        out = hop.out;
        inferredOut = true;
      }
    }
    const k = JSON.stringify([p.key, p.in ?? "", out ?? ""]);
    const row = rows.get(k) ?? {
      device: p.key,
      label: p.label,
      ...(p.in ? { in: p.in } : {}),
      ...(out ? { out } : {}),
      sources: [],
      inferredOut,
    };
    const src = sourceLabel(p.source);
    if (!row.sources.includes(src)) row.sources.push(src);
    const n = observerRecords(edge, o, devices);
    if (n !== undefined) row.records = (row.records ?? 0) + n;
    rows.set(k, row);
  }
  // Group rows per device, keeping first-seen device order.
  const order = [...new Set([...rows.values()].map((r) => r.device))];
  return [...rows.values()].sort(
    (a, b) => order.indexOf(a.device) - order.indexOf(b.device),
  );
}

/** Rows of several conversations merged per device and interface pair. */
export function mergeObserverRows(
  lists: ObserverInterfaceRow[][],
): ObserverInterfaceRow[] {
  const rows = new Map<string, ObserverInterfaceRow>();
  for (const r of lists.flat()) {
    const k = JSON.stringify([r.device, r.in ?? "", r.out ?? ""]);
    const prior = rows.get(k);
    if (!prior) {
      rows.set(k, { ...r, sources: [...r.sources] });
      continue;
    }
    for (const s of r.sources)
      if (!prior.sources.includes(s)) prior.sources.push(s);
    if (r.records !== undefined)
      prior.records = (prior.records ?? 0) + r.records;
    prior.inferredOut ||= r.inferredOut;
  }
  const order = [...new Set([...rows.values()].map((r) => r.device))];
  return [...rows.values()].sort(
    (a, b) => order.indexOf(a.device) - order.indexOf(b.device),
  );
}

/** "→ fabric (inferred)" for the fabric egress; other names unchanged. */
export const outLabel = (out?: string) =>
  out && /^fabric\b/.test(out) ? `→ ${out}` : out;
