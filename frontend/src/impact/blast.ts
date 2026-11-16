import { type Classifier, type Failure, type Severity } from "./classify";
import type { Tier } from "./elements";
import type { FailsResult } from "./model";

/** Smartscape-style layers, top to bottom. */
export const BANDS = [
  "Apps",
  "Workloads",
  "Hosts",
  "Network",
  "Spines",
] as const;
export type Band = (typeof BANDS)[number];
export type NodeState =
  "down" | "outage" | "degraded" | "unknown" | "alternate" | "path";

export interface BlastNode {
  id: string;
  label: string;
  band: Band;
  state: NodeState;
  weight: number;
}
export interface BlastGraph {
  bands: { band: Band; nodes: BlastNode[]; more: number }[];
  links: [string, string][];
}

const bandOf = (tier: Tier): Band | undefined =>
  tier === "endpoint"
    ? "Workloads"
    : tier === "host" || tier === "hypervisor" || tier === "vswitch"
      ? "Hosts"
      : tier === "spine"
        ? "Spines"
        : tier === "controller"
          ? undefined
          : "Network";
const STATE_RANK: Record<NodeState, number> = {
  down: 5,
  outage: 4,
  unknown: 3,
  degraded: 2,
  alternate: 1,
  path: 0,
};
const fromSeverity = (s: Severity): NodeState =>
  s === "unaffected" ? "path" : s;

/** Layers of the affected apps, workloads and infrastructure; at most `perBand` nodes each. */
export function blastGraph(
  r: FailsResult,
  cls: Classifier,
  f: Failure,
  perBand = 12,
): BlastGraph {
  const nodes = new Map<string, BlastNode>();
  const links = new Set<string>();
  const put = (
    id: string,
    label: string,
    band: Band,
    state: NodeState,
    weight: number,
  ) => {
    const cur = nodes.get(id);
    if (!cur) nodes.set(id, { id, label, band, state, weight });
    else {
      if (STATE_RANK[state] > STATE_RANK[cur.state]) cur.state = state;
      cur.weight += weight;
    }
  };
  const alternates = new Set(r.rows.flatMap((c) => c.alternate));
  for (const c of r.rows.slice(0, 300)) {
    const w = c.conv.bytes ?? 1;
    const sev = fromSeverity(c.severity);
    const app = c.conv.app ?? c.conv.dst.app ?? c.conv.src.app;
    for (const p of cls.path(c.conv)) {
      for (const n of p.nodes.values()) {
        if (!p.cand.has(n.id)) continue;
        const band = bandOf(n.tier);
        if (!band) continue;
        const dead = n.refs.some(f.ref);
        const state: NodeState = dead
          ? "down"
          : band === "Workloads"
            ? sev
            : alternates.has(n.label)
              ? "alternate"
              : "path";
        put(n.id, n.label, band, state, w);
      }
      for (const e of p.edges)
        if (
          p.cand.has(e.a) &&
          p.cand.has(e.b) &&
          nodes.has(e.a) &&
          nodes.has(e.b)
        )
          links.add(`${e.a}\u0000${e.b}`);
      // Fabric: each exit to each spine layer member used.
      const spines = [...p.cand].filter(
        (id) => p.nodes.get(id)?.tier === "spine",
      );
      const exits = [...p.a.exits, ...p.b.exits].filter((id) => p.cand.has(id));
      for (const s of spines)
        for (const x of exits) links.add(`${x}\u0000${s}`);
      if (app) {
        const id = `app:${app}`;
        put(id, app, "Apps", sev, w);
        for (const end of [p.a.start, p.b.start])
          if (nodes.has(end)) links.add(`${id}\u0000${end}`);
      }
    }
  }
  const bands = BANDS.map((band) => {
    const all = [...nodes.values()]
      .filter((n) => n.band === band)
      .sort(
        (a, b) =>
          STATE_RANK[b.state] - STATE_RANK[a.state] || b.weight - a.weight,
      );
    return {
      band,
      nodes: all.slice(0, perBand),
      more: Math.max(0, all.length - perBand),
    };
  }).filter((b) => b.nodes.length);
  const shown = new Set(bands.flatMap((b) => b.nodes.map((n) => n.id)));
  return {
    bands,
    links: [...links]
      .map((l) => l.split("\u0000") as [string, string])
      .filter(([a, b]) => shown.has(a) && shown.has(b)),
  };
}
