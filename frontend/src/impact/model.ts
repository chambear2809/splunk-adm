import { prettyBytes } from "../glossary";
import {
  classifier,
  compileFailure,
  sideReachesFabric,
  SEVERITY_RANK,
  type Classified,
  type Classifier,
  type Evidence,
  type ImpactConversation,
  type Severity,
} from "./classify";
import {
  deviceTier,
  shortName,
  type ImpactElement,
  type Tier,
} from "./elements";
import { isPublic, type ImpactEndpoint, type PathContext } from "./paths";

export type ImpactMode = "fails" | "depends";
export type Split = { outage: number; degraded: number; unknown: number };
const zero = (): Split => ({ outage: 0, degraded: 0, unknown: 0 });

export interface AppImpact {
  app: string;
  severity: Exclude<Severity, "unaffected">;
  conversations: number;
  split: Split;
  bytes: number;
  /** Most common surviving alternate. */
  alternate?: string;
  /** identity: adm_ip_identity binding; hubble: observed pod flows on the node pair; hosted: pods on the node (inferred). */
  basis: AppBasis;
}
export type AppBasis = "identity" | "hubble" | "hosted";
export interface FailsResult {
  mode: "fails";
  label: string;
  headline: string;
  rows: Classified[];
  apps: AppImpact[];
  kpis: {
    apps: Split;
    services: Split;
    workloads: Split;
    conversations: Split;
    bytes: Split;
    external: Split;
  };
  /** Apps with pods on affected nodes whose traffic is not attributed (hosted-on, inferred). */
  possibleApps: AppImpact[];
  /** Headline without the possibly-affected tail, for a muted secondary item. */
  headlineMain: string;
  possiblyAffected: number;
  peers: number;
  /** Bytes per hour of degraded traffic, by the alternate that carries it. */
  shifts: { to: string; bytesPerHour: number }[];
  total: number;
  /** Graph card and edge IDs → severity, for the map overlay. */
  nodes: Map<string, Exclude<Severity, "unaffected">>;
  edges: Map<string, Exclude<Severity, "unaffected">>;
}
export interface Dependency {
  id: string;
  label: string;
  tier: Tier;
  /** outage: single point of failure; degraded: redundant. */
  severity: Exclude<Severity, "unaffected">;
  alternate: string[];
  conversations: number;
  bytes: number;
  evidence: Evidence;
  /** Element token to open "If this fails" on this dependency. */
  token: string;
}
export interface DependsResult {
  mode: "depends";
  label: string;
  headline: string;
  rows: Dependency[];
  conversations: number;
}

const lower = (s?: string) => s?.trim().toLowerCase() ?? "";
const appOf = (c: ImpactConversation) => c.app ?? c.dst.app ?? c.src.app;
/** Every application a conversation is attributed to, with how. */
export const appsOf = (
  c: ImpactConversation,
): { name: string; basis: AppBasis }[] => {
  const a = appOf(c);
  return a ? [{ name: a, basis: "identity" }] : (c.apps ?? []);
};
const BASIS_RANK: Record<AppBasis, number> = {
  identity: 2,
  hubble: 1,
  hosted: 0,
};
const endpointName = (e: ImpactEndpoint) => e.name ?? e.ip ?? e.key;
const isExternal = (e: ImpactEndpoint) =>
  e.kind === "external" ||
  e.graph?.endpoint_kind === "external" ||
  isPublic(e.ip);
const isWorkload = (e: ImpactEndpoint) => {
  const k = e.graph?.endpoint_kind ?? e.kind;
  return (
    e.graph?.kind === "workload" ||
    ["vm", "pod", "k8s_node", "k8s_hostnet_pod", "endpoint", "host"].includes(
      k ?? "",
    )
  );
};

export const elementsLabel = (els: ImpactElement[]) =>
  els.map((e) => e.label).join(" + ");

/** Rate over the window; undefined when the window is unknown. */
export const perHour = (bytes: number, hours?: number) =>
  hours && hours > 0 ? bytes / hours : undefined;

function bump(s: Split, sev: Severity, n = 1) {
  if (sev !== "unaffected") s[sev] += n;
}

/** Group severity: outage only if every member conversation is out; else degraded. */
function groupSeverity(
  all: Classified[],
): Exclude<Severity, "unaffected"> | undefined {
  const hit = all.filter((c) => c.severity !== "unaffected");
  if (!hit.length) return undefined;
  if (hit.every((c) => c.severity === "unknown")) return "unknown";
  // Unverified conversations neither prove nor rule out an outage.
  const known = all.filter((c) => c.severity !== "unknown");
  if (known.every((c) => c.severity === "outage")) return "outage";
  return "degraded";
}

export function failsImpact(
  elements: ImpactElement[],
  conversations: ImpactConversation[],
  ctx: PathContext,
  opts: { hours?: number; total?: number; cls?: Classifier } = {},
): FailsResult {
  const cls = opts.cls ?? classifier(ctx);
  const f = compileFailure(elements);
  const all = conversations.map((c) => cls.classify(c, f));
  const rows = all
    .filter((c) => c.severity !== "unaffected")
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        (b.conv.bytes ?? 0) - (a.conv.bytes ?? 0),
    );
  const by = <K>(key: (c: Classified) => K | K[] | undefined) => {
    const m = new Map<K, Classified[]>();
    for (const c of all) {
      const k = key(c);
      for (const x of k === undefined ? [] : Array.isArray(k) ? k : [k])
        m.set(x, [...(m.get(x) ?? []), c]);
    }
    return m;
  };
  const kpis = {
    apps: zero(),
    services: zero(),
    workloads: zero(),
    conversations: zero(),
    bytes: zero(),
    external: zero(),
  };
  const apps: AppImpact[] = [];
  const possibleApps: AppImpact[] = [];
  for (const [app, list] of by((c) => appsOf(c.conv).map((a) => a.name))) {
    const sev = groupSeverity(list);
    if (!sev) continue;
    const basis = list
      .flatMap((c) => appsOf(c.conv).filter((a) => a.name === app))
      .reduce<AppBasis>(
        (b, a) => (BASIS_RANK[a.basis] > BASIS_RANK[b] ? a.basis : b),
        "hosted",
      );
    // Only traffic- or identity-confirmed apps are counted.
    if (basis !== "hosted") bump(kpis.apps, sev);
    const hit = list.filter((c) => c.severity !== "unaffected");
    const split = zero();
    for (const c of hit) bump(split, c.severity);
    const alt = new Map<string, number>();
    for (const c of hit)
      for (const a of c.alternate) alt.set(a, (alt.get(a) ?? 0) + 1);
    (basis === "hosted" ? possibleApps : apps).push({
      app,
      basis,
      severity: sev,
      conversations: hit.length,
      split,
      bytes: hit.reduce((n, c) => n + (c.conv.bytes ?? 0), 0),
      ...(alt.size
        ? { alternate: [...alt].sort((x, y) => y[1] - x[1])[0][0] }
        : {}),
    });
  }
  for (const list of [apps, possibleApps])
    list.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.bytes - a.bytes,
    );
  for (const [, list] of by(
    (c) => `${lower(c.conv.dst.ip ?? c.conv.dst.key)}:${c.conv.port ?? ""}`,
  )) {
    const sev = groupSeverity(list);
    if (sev) bump(kpis.services, sev);
  }
  // An endpoint is in outage when every conversation it has is out.
  const endpointSev = new Map<string, Classified[]>();
  const peers = new Set<string>();
  for (const c of all)
    for (const e of [c.conv.src, c.conv.dst]) {
      endpointSev.set(e.key, [...(endpointSev.get(e.key) ?? []), c]);
      if (c.severity !== "unaffected") peers.add(e.key);
    }
  const nodes = new Map<string, Exclude<Severity, "unaffected">>();
  const endpoints = new Map(
    all.flatMap((c) => [c.conv.src, c.conv.dst]).map((e) => [e.key, e]),
  );
  for (const [k, list] of endpointSev) {
    const sev = groupSeverity(list);
    if (!sev) continue;
    const e = endpoints.get(k)!;
    if (isWorkload(e)) bump(kpis.workloads, sev);
    nodes.set(k, sev);
  }
  const edges = new Map<string, Exclude<Severity, "unaffected">>();
  const shiftBytes = new Map<string, number>();
  for (const c of rows) {
    bump(kpis.conversations, c.severity);
    bump(kpis.bytes, c.severity, c.conv.bytes ?? 0);
    if (isExternal(c.conv.src) || isExternal(c.conv.dst))
      bump(kpis.external, c.severity);
    if (c.severity !== "unaffected") edges.set(c.conv.id, c.severity);
    // Replica and backend fail-over is not a traffic shift between network elements.
    if (
      c.severity === "degraded" &&
      c.alternate.length &&
      c.reason !== "other backend" &&
      c.reason !== "other replica"
    )
      for (const a of c.alternate)
        shiftBytes.set(
          a,
          (shiftBytes.get(a) ?? 0) + (c.conv.bytes ?? 0) / c.alternate.length,
        );
  }
  const shifts = [...shiftBytes]
    .map(([to, b]) => ({ to, bytesPerHour: perHour(b, opts.hours) ?? b }))
    .sort((a, b) => b.bytesPerHour - a.bytesPerHour);
  const label = elementsLabel(elements);
  const top = shifts[0];
  // Apps when identity attributes them; else the workloads (VMs, pods, hosts).
  const unit =
    kpis.apps.outage + kpis.apps.degraded + kpis.apps.unknown
      ? { split: kpis.apps, one: "app", many: "apps" }
      : { split: kpis.workloads, one: "workload", many: "workloads" };
  const main = [
    `${label} down: ${unit.split.outage} outage`,
    `${unit.split.degraded} ${unit.split.degraded === 1 ? unit.one : unit.many} degraded`,
    ...(unit.split.unknown ? [`${unit.split.unknown} unverified`] : []),
    `${peers.size} ${peers.size === 1 ? "peer" : "peers"}`,
    ...(top && top.bytesPerHour > 0
      ? [
          `${prettyBytes(Math.round(top.bytesPerHour))}${opts.hours ? "/h" : ""} shifts to ${top.to}`,
        ]
      : []),
  ];
  const possible = possibleApps.length;
  const headlineMain = main.join(" · ");
  const headline = possible
    ? [
        ...main.slice(0, unit.split.unknown ? 3 : 2),
        `~${possible} possibly affected`,
        ...main.slice(unit.split.unknown ? 3 : 2),
      ].join(" · ")
    : headlineMain;
  return {
    mode: "fails",
    label,
    headline,
    headlineMain,
    possiblyAffected: possible,
    possibleApps,
    rows,
    apps,
    kpis,
    peers: peers.size,
    shifts,
    total: opts.total ?? conversations.length,
    nodes,
    edges,
  };
}

const TIER_RANK: Record<Tier, number> = {
  endpoint: 0,
  host: 1,
  hypervisor: 2,
  vswitch: 2,
  fi: 3,
  switch: 4,
  leaf: 4,
  spine: 5,
  controller: 6,
};

/** What the element needs: each dependency's effect on the element's conversations if it alone fails. */
export function dependsImpact(
  elements: ImpactElement[],
  conversations: ImpactConversation[],
  ctx: PathContext,
  opts: { cls?: Classifier } = {},
): DependsResult {
  const cls = opts.cls ?? classifier(ctx);
  const self = compileFailure(elements);
  const selfRefs = (refs: string[]) => refs.some(self.ref);
  const deviceRank = Math.min(
    ...elements.map((e) =>
      e.kind === "device" || e.kind === "interface"
        ? TIER_RANK[e.tier ?? "switch"]
        : -1,
    ),
  );
  // The element's own conversations: it is an end, or it is on the candidate path.
  const mine = conversations.filter((c) => {
    if (self.endpoint(c.src) || self.endpoint(c.dst)) return true;
    return cls
      .path(c)
      .some((p) =>
        [...p.cand].some((id) => selfRefs(p.nodes.get(id)?.refs ?? [id])),
      );
  });
  const cands = new Map<
    string,
    { label: string; tier: Tier; token: string; refs: string[] }
  >();
  for (const c of mine)
    for (const p of cls.path(c)) {
      // An element needs its own side's attachment and the fabric, not its peer's.
      const onSide = (acc: typeof p.a) =>
        [...acc.nodes.values()].some((n) => selfRefs(n.refs));
      const other =
        deviceRank >= 0
          ? onSide(p.a) && !onSide(p.b)
            ? p.b
            : onSide(p.b) && !onSide(p.a)
              ? p.a
              : undefined
          : self.endpoint(c.src)
            ? p.b
            : self.endpoint(c.dst)
              ? p.a
              : undefined;
      const own = other === p.a ? p.b : p.a;
      for (const id of p.cand) {
        const n = p.nodes.get(id)!;
        if (n.tier === "endpoint" || selfRefs(n.refs)) continue;
        if (other?.nodes.has(id) && !own.nodes.has(id)) continue;
        if (deviceRank >= 0 && TIER_RANK[n.tier] <= deviceRank) continue;
        // A host+VDS instance stands for two identities: list each.
        for (const ref of n.refs) {
          if (self.ref(ref) || ref.startsWith("ip:") || ref.startsWith("pod:"))
            continue;
          const d = ctx.devByKey.get(ref);
          if (!d && !ref.startsWith("host:") && !ref.startsWith("node:"))
            continue;
          const label = d ? shortName(d.name) : n.label;
          const tier = d ? deviceTier(d, ctx.topo) : n.tier;
          const group = `${tier}|${label.toLowerCase()}`;
          const prev = cands.get(group);
          if (prev) {
            if (!prev.refs.includes(ref)) prev.refs.push(ref);
            continue;
          }
          cands.set(group, {
            label,
            tier,
            token: d
              ? (d.mgmt_ip ?? d.id)
              : ref.startsWith("host:")
                ? ref.slice(5)
                : ref,
            refs: [ref],
          });
        }
      }
    }
  const rows: Dependency[] = [];
  for (const [id, cand] of cands) {
    const f = compileFailure([
      {
        token: cand.token,
        label: cand.label,
        kind: "device",
        devices: new Set(cand.refs.filter((r) => ctx.devByKey.has(r))),
        endpoints: new Set(cand.refs.filter((r) => !ctx.devByKey.has(r))),
        resolved: true,
      },
    ]);
    const hit = mine
      .map((c) => {
        const r = cls.classify(c, f);
        if (r.severity !== "outage" || deviceRank >= 0) return r;
        // An outage caused only by the peer's own attachment is the peer's dependency.
        const p = cls.path(c)[0];
        const mineIsSrc = self.endpoint(c.src);
        const own = mineIsSrc ? p.a : p.b;
        const ownEp = mineIsSrc ? c.src : c.dst;
        return r.reason !== "endpoint down" &&
          sideReachesFabric(own, ownEp, f) &&
          !p.core.some((s) => f.devices.has(s))
          ? { ...r, severity: "degraded" as const, alternate: r.alternate }
          : r;
      })
      .filter((c) => c.severity !== "unaffected");
    if (!hit.length) continue;
    const sev = hit.reduce<Exclude<Severity, "unaffected">>(
      (w, c) =>
        SEVERITY_RANK[c.severity] > SEVERITY_RANK[w]
          ? (c.severity as Exclude<Severity, "unaffected">)
          : w,
      "degraded",
    );
    rows.push({
      id,
      label: cand.label,
      tier: cand.tier,
      severity: sev,
      alternate: [...new Set(hit.flatMap((c) => c.alternate))],
      conversations: hit.length,
      bytes: hit.reduce((n, c) => n + (c.conv.bytes ?? 0), 0),
      evidence: hit.some((c) => c.traversal === "observed")
        ? "observed"
        : "inferred",
      token: cand.token,
    });
  }
  // Servers the element calls: each is a dependency, redundant only through backends.
  if (deviceRank < 0)
    for (const c of mine) {
      if (!self.endpoint(c.src) || self.endpoint(c.dst)) continue;
      const id = `peer:${c.dst.key}`;
      const prev = rows.find((r) => r.id === id);
      if (prev) {
        prev.conversations += 1;
        prev.bytes += c.bytes ?? 0;
        continue;
      }
      const replicas = c.backends?.length ?? 0;
      rows.push({
        id,
        label: `${endpointName(c.dst)}${c.port ? `:${c.port}` : ""}`,
        tier: "endpoint",
        severity: replicas > 1 ? "degraded" : "outage",
        alternate: replicas > 1 ? c.backends!.map(endpointName) : [],
        conversations: 1,
        bytes: c.bytes ?? 0,
        evidence: c.observers.length ? "observed" : "inferred",
        token: c.dst.graph?.id ?? c.dst.ip ?? c.dst.key,
      });
    }
  rows.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      TIER_RANK[b.tier] - TIER_RANK[a.tier] ||
      b.bytes - a.bytes,
  );
  const label = elementsLabel(elements);
  const single = rows.filter((r) => r.severity === "outage");
  const redundant = rows.filter((r) => r.severity === "degraded").length;
  const headline = rows.length
    ? [
        `${label} depends on ${rows.length}`,
        `${single.length} single ${single.length === 1 ? "point" : "points"}${
          single.length
            ? ` (${single
                .slice(0, 3)
                .map((r) => r.label)
                .join(", ")}${single.length > 3 ? "…" : ""})`
            : ""
        }`,
        `${redundant} redundant`,
      ].join(" · ")
    : `${label}: no dependency observed`;
  return { mode: "depends", label, headline, rows, conversations: mine.length };
}
