import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "../graph";
import { sourceLabel } from "../glossary";
import {
  buildPath,
  type Device,
  resolveDevice,
  virtualPortFor,
  type Stage,
  type TopologyIndex,
  type VirtualPort,
} from "../topology";
import { inferL3OutEgress, type L3OutEvidence } from "./l3outEgress";

/** Shown when adm_l3out_path_evidence hit its per-kind row bound. */
export const L3OUT_TRUNCATED_NOTE =
  "L3Out evidence reached its row limit (adm_l3out_path_limit); some border-leaf paths or external subnets were not read, so routed egress may be missing or incomplete.";

/** One hop of a traced path, in order from source to destination. */
export interface TraceHop {
  kind:
    | "endpoint"
    | "virtual_switch"
    | "switch"
    | "firewall"
    | "host"
    | "handoff"
    | "gap";
  /** Canonical device or node ID when the hop is one known identity. */
  device?: string;
  label: string;
  detail?: string;
  in?: string;
  out?: string;
  /** observed: a collected flow record placed this hop; inferred: topology only; gap: no evidence. */
  evidence: "observed" | "inferred" | "gap";
  /** Collector names that observed the hop (e.g. "Stream NetFlow"). */
  sources: string[];
  /** Interfaces reported by the observers. */
  seen: string[];
  /** ECMP or vPC choices: the hop is exactly one of these devices. */
  alternatives?: { device: string; label: string }[];
  /** vPC members that did not observe the flow (the hop is the other member). */
  notSeen?: { device: string; label: string }[];
  /** Inferred hop backed by control-plane evidence (never packet observation). */
  support?: string[];
}
/** adm_fabric_path_evidence rows: IS-IS adjacencies and COOP endpoint records. */
export interface FabricEvidence {
  kind: "isis_adjacency" | "coop_endpoint";
  apic?: string;
  /** ACI `pod-N/node-N` reporting the record. */
  node: string;
  interface?: string;
  /** isis: peer node resolved through fabricLink only. */
  peerNode?: string;
  /** coop: endpoint MAC (upper case) and citizen TEP. */
  mac?: string;
  citizen?: string;
}
export interface TraceEndpoint {
  query: string;
  node?: GraphNode;
  /** Set when the endpoint was found only in vSphere virtual-port inventory. */
  virtualPort?: VirtualPort;
  candidates: number;
}
/**
 * Dropped records of the pair at one enforcement point: an ACI leaf (ACL log
 * of a deny-and-log contract) or a Cilium node (Hubble DROPPED/ERROR).
 */
export interface TraceDrop {
  source: "aci_acllog" | "hubble";
  /** ACI `pod-N/node-N`, or the Kubernetes node name. */
  device: string;
  /** Dropped services, e.g. "tcp/47003" (listener side). */
  services: string[];
  /** Hubble drop reasons, e.g. "POLICY_DENIED". */
  reasons: string[];
  records: number;
}
export interface PathTrace {
  status: "traced" | "partial" | "unresolved";
  src: TraceEndpoint;
  dst: TraceEndpoint;
  hops: TraceHop[];
  /** Explicit gaps, in hop order. */
  gaps: string[];
  /** Graph conversations between the pair that supplied observations. */
  conversations: GraphEdge[];
  /** Drops logged for the pair (adm_path_trace observation rows). */
  drops: TraceDrop[];
  notes: string[];
  reason?: string;
}
export interface PathTraceInput {
  src: string;
  dst: string;
  graph: Graph;
  topology: TopologyIndex;
  /** Extra observer strings for this pair, e.g. adm_path_trace observation rows. */
  observers?: string[];
  /** Spine evidence from adm_path_trace fabric_evidence rows. */
  fabricEvidence?: FabricEvidence[];
  /** ACI L3Out paths and matching external subnets (adm_l3out_path_evidence). */
  l3out?: L3OutEvidence;
  /** Drops from adm_path_trace observation rows (pathTraceDrops). */
  drops?: TraceDrop[];
}

const norm = (s: string) => s.trim().toLowerCase();

/** IP literal or entity name → one graph node, else a vSphere-only endpoint. */
export function resolveTraceEndpoint(
  query: string,
  graph: Graph,
  topo: TopologyIndex,
): TraceEndpoint {
  const q = norm(query);
  if (!q) return { query, candidates: 0 };
  const byAddress = graph.nodes.filter((n) =>
    (n.addresses ?? []).some((a) => norm(a) === q),
  );
  const matches = byAddress.length
    ? byAddress
    : graph.nodes.filter(
        (n) =>
          norm(n.label) === q ||
          norm(n.attributes?.vm_name ?? "") === q ||
          n.id.toLowerCase() === q,
      );
  if (matches.length === 1) return { query, node: matches[0], candidates: 1 };
  if (matches.length > 1) return { query, candidates: matches.length };
  // Not in the graph: a VM vNIC known only to virtual switch inventory.
  const ports = [
    ...new Map(
      [...topo.virtualPorts.values()]
        .flat()
        .filter(
          (p) =>
            norm(p.ip ?? "") === q ||
            norm(p.mac ?? "") === q ||
            norm(p.vm_name ?? "") === q,
        )
        .map((p) => [`${p.switch}|${p.vm}`, p]),
    ).values(),
  ];
  if (ports.length !== 1) return { query, candidates: ports.length };
  const p = ports[0];
  const node: GraphNode = {
    id: p.vm,
    label: p.vm_name ?? p.ip ?? p.vm,
    kind: "endpoint",
    endpoint_kind: "vm",
    addresses: p.ip ? [p.ip] : [],
    attributes: {
      ...(p.mac ? { mac: p.mac } : {}),
      ...(p.scope ? { scope: p.scope } : {}),
    },
  };
  return { query, node, virtualPort: p, candidates: 1 };
}

const hopKind = (s: Stage): TraceHop["kind"] =>
  s.kind === "entity" ? "endpoint" : s.kind;

/**
 * ACI leaf NetFlow exports ingress only. A leaf hop with an ingress and no
 * exported egress gets the destination's ACI attachment on that leaf, or
 * "fabric" (toward a spine), labelled inferred.
 */
export function inferLeafHopEgress(
  hops: TraceHop[],
  attachment: VirtualPort | undefined,
  topo: TopologyIndex,
): TraceHop[] {
  if (!attachment?.mac || !attachment.attach_nodes?.length) return hops;
  const nodes = new Set(attachment.attach_nodes.map((n) => n.toLowerCase()));
  return hops.map((hop) => {
    if (!hop.in || hop.out || !hop.device) return hop;
    const leaf = topo.byId.get(hop.device)?.aci_node?.toLowerCase();
    if (!leaf) return hop;
    const egress = nodes.has(leaf) ? attachment.attach_interface : "fabric";
    return egress ? { ...hop, out: `${egress} (inferred)` } : hop;
  });
}

function toHop(s: Stage, topo: TopologyIndex): TraceHop {
  const evidence: TraceHop["evidence"] =
    s.kind === "gap"
      ? "gap"
      : s.kind === "entity" || s.observed
        ? "observed"
        : "inferred";
  const hop: TraceHop = {
    kind: hopKind(s),
    label: s.title,
    ...(s.subtitle ? { detail: s.subtitle } : {}),
    ...(s.ports?.in ? { in: s.ports.in } : {}),
    ...(s.ports?.out ? { out: s.ports.out } : {}),
    evidence: s.kind === "entity" ? "observed" : evidence,
    sources: [...s.observedBy],
    seen: [...s.seenInterfaces],
  };
  if (s.nodeId && !s.alternatives) hop.device = s.nodeId;
  if (s.notSeen?.length)
    hop.notSeen = s.notSeen.map((id) => ({
      device: resolveDevice(id, topo)?.id ?? id,
      label: topo.byId.get(id)?.name ?? resolveDevice(id, topo)?.name ?? id,
    }));
  if (s.alternatives)
    hop.alternatives = s.alternatives.map((id) => ({
      device: resolveDevice(id, topo)?.id ?? id,
      label: topo.byId.get(id)?.name ?? resolveDevice(id, topo)?.name ?? id,
    }));
  if (s.handoff) hop.detail = s.handoff.text;
  return hop;
}

/**
 * Ordered hops between two arbitrary endpoints, from collected topology and
 * the observations of their conversations. Pure: no search is issued.
 * Observations mark hops; they never prove packet order. Gaps stay explicit.
 */
export function tracePath(input: PathTraceInput): PathTrace {
  const { graph, topology: topo } = input;
  const src = resolveTraceEndpoint(input.src, graph, topo);
  const dst = resolveTraceEndpoint(input.dst, graph, topo);
  const base = {
    src,
    dst,
    hops: [],
    gaps: [],
    conversations: [],
    drops: input.drops ?? [],
    notes: [],
  };
  const why = (e: TraceEndpoint, side: string) =>
    e.candidates > 1
      ? `${side} "${e.query}" matches ${e.candidates} endpoints; choose an address.`
      : `${side} "${e.query}" is not a known endpoint.`;
  if (!src.node || !dst.node)
    return {
      ...base,
      status: "unresolved",
      reason: !src.node ? why(src, "Source") : why(dst, "Destination"),
    };
  if (src.node.id === dst.node.id)
    return {
      ...base,
      status: "unresolved",
      reason: "Source and destination are the same endpoint.",
    };
  const extraNodes = [src, dst]
    .filter((e) => e.virtualPort)
    .map((e) => e.node!);
  const pair = (e: GraphEdge, a: string, b: string) =>
    e.relationship === "communicates_with" && e.source === a && e.target === b;
  const forward = graph.edges.filter((e) =>
    pair(e, src.node!.id, dst.node!.id),
  );
  const reverse = graph.edges.filter((e) =>
    pair(e, dst.node!.id, src.node!.id),
  );
  const conversations = [...forward, ...reverse];
  const observers = [
    ...new Set([
      ...conversations.flatMap((e) => e.observers ?? []),
      ...(input.observers ?? []),
    ]),
  ];
  const first = forward[0] ?? reverse[0];
  const aclEdge = conversations.find((e) => e.acl_leaf);
  const synthetic: GraphEdge = {
    ...(first ?? {}),
    id: "path-trace",
    source: src.node.id,
    target: dst.node.id,
    relationship: "communicates_with",
    evidence: first?.evidence ?? [],
    confidence: first?.confidence ?? "inferred",
    count: conversations.reduce((n, e) => n + e.count, 0),
    observers,
    ...(aclEdge
      ? {
          acl_leaf: aclEdge.acl_leaf,
          acl_action: aclEdge.acl_action,
          acl_drops: aclEdge.acl_drops,
          acl_permits: aclEdge.acl_permits,
        }
      : {}),
  };
  const traced: Graph = {
    ...graph,
    nodes: [...graph.nodes, ...extraNodes],
    edges: [...graph.edges, synthetic],
  };
  const path = buildPath(synthetic, traced, indexGraph(traced), topo);
  const dstAttachment = dst.virtualPort ?? virtualPortFor(dst.node, topo);
  let hops = inferLeafHopEgress(
    path.stages.map((s) => toHop(s, topo)),
    dstAttachment,
    topo,
  );
  const dstMac = dst.node.attributes?.mac ?? dst.virtualPort?.mac ?? undefined;
  const qualifyNote = input.fabricEvidence?.length
    ? qualifySpines(hops, input.fabricEvidence, dstMac, topo)
    : undefined;
  // Routed egress: a destination with no ACI endpoint that matches an L3Out.
  const dstIp = dst.node.addresses?.[0];
  const routed =
    input.l3out?.paths.length &&
    dstIp &&
    !dstAttachment?.attach_nodes?.length &&
    !dst.node.attributes?.attach_device
      ? inferL3OutEgress({
          hops,
          dst: dstIp,
          evidence: input.l3out,
          topo,
          observers,
          fabric: input.fabricEvidence ?? [],
        })
      : undefined;
  if (routed) hops = routed.hops;
  const gaps = hops.filter((h) => h.kind === "gap").map((h) => h.label);
  const notes = [...path.notes, ...path.policy.map((p) => p.text)];
  if (path.sameHost)
    notes.push("Both endpoints share one host and virtual switch segment.");
  for (const u of path.unplaced)
    notes.push(
      `Also seen at ${u.label} (${u.sources.join(", ")}) outside the drawn hops.`,
    );
  if (qualifyNote) notes.push(qualifyNote);
  if (routed?.note) notes.push(routed.note);
  if (input.l3out?.truncated) notes.push(L3OUT_TRUNCATED_NOTE);
  if (!conversations.length && !(input.observers ?? []).length)
    notes.push(
      "No conversation between these endpoints was collected; every hop is inferred from topology.",
    );
  return {
    ...base,
    status: gaps.length ? "partial" : "traced",
    hops,
    gaps,
    conversations,
    notes,
  };
}

const SPINE_SUPPORT = ["ACI IS-IS adjacency", "ACI COOP endpoint"];
/**
 * Narrows an ECMP spine hop to spines with an up IS-IS adjacency from the
 * previous (source) leaf and a COOP record for the destination MAC. The hop
 * stays inferred: this proves candidates, not which spine forwarded.
 */
function qualifySpines(
  hops: TraceHop[],
  evidence: FabricEvidence[],
  dstMac: string | undefined,
  topo: TopologyIndex,
): string | undefined {
  const mac = dstMac?.toUpperCase();
  let note: string | undefined;
  hops.forEach((hop, i) => {
    const ids =
      hop.alternatives?.map((a) => a.device) ??
      (hop.device ? [hop.device] : []);
    const spines = ids.map((id) => topo.byId.get(id));
    if (
      hop.kind !== "switch" ||
      !ids.length ||
      spines.some((d) => d?.role !== "spine")
    )
      return;
    const prev = hops[i - 1];
    const leaves = (
      prev?.alternatives?.map((a) => a.device) ??
      (prev?.device ? [prev.device] : [])
    )
      .map((id) => topo.byId.get(id))
      .filter((d) => d?.aci_node);
    const sameFabric = (d: Device | undefined, apic?: string) =>
      !apic ||
      (!d?.fabric && !d?.device_authority) ||
      d?.fabric === `apic:${apic}` ||
      d?.device_authority === apic;
    const qualified = spines.filter(
      (s) =>
        !!s?.aci_node &&
        evidence.some(
          (e) =>
            e.kind === "isis_adjacency" &&
            e.peerNode === s.aci_node &&
            leaves.some(
              (l) => l!.aci_node === e.node && sameFabric(l, e.apic),
            ) &&
            sameFabric(s, e.apic),
        ) &&
        !!mac &&
        evidence.some(
          (e) =>
            e.kind === "coop_endpoint" &&
            e.node === s.aci_node &&
            e.mac?.toUpperCase() === mac &&
            sameFabric(s, e.apic),
        ),
    ) as Device[];
    if (!qualified.length) {
      note =
        "No spine has both an up IS-IS adjacency from the source leaf and a COOP record for the destination; spine candidates are topology-only.";
      return;
    }
    hop.support = [...SPINE_SUPPORT];
    hop.evidence = "inferred";
    const leafNames = leaves.map((l) => l!.name).join(", ");
    hop.detail = `IS-IS adjacency up from ${leafNames}; COOP knows ${mac} · ECMP, forwarding spine not observed`;
    if (qualified.length === 1) {
      hop.label = qualified[0].name;
      hop.device = qualified[0].id;
      delete hop.alternatives;
    } else {
      hop.label = `One of ${qualified.length} spines`;
      hop.alternatives = qualified.map((d) => ({
        device: d.id,
        label: d.name,
      }));
    }
  });
  return note;
}

/** fabric_evidence rows from adm_path_trace; malformed rows are skipped. */
export function fabricEvidenceRows(rows: unknown): FabricEvidence[] {
  if (!Array.isArray(rows)) return [];
  const out: FabricEvidence[] = [];
  const s = (v: unknown) =>
    typeof v === "string" && v.trim() ? v.trim() : undefined;
  for (const r of rows) {
    if (!r || typeof r !== "object") continue;
    const x = r as Record<string, unknown>;
    if (x.row_type !== "fabric_evidence") continue;
    const kind = x.evidence_kind;
    const node = s(x.node);
    if ((kind !== "isis_adjacency" && kind !== "coop_endpoint") || !node)
      continue;
    if (!/^pod-\d+\/node-\d+$/.test(node)) continue;
    out.push({
      kind,
      node,
      ...(s(x.apic_host) ? { apic: s(x.apic_host) } : {}),
      ...(s(x.interface) ? { interface: s(x.interface) } : {}),
      ...(s(x.peer_node) ? { peerNode: s(x.peer_node) } : {}),
      ...(s(x.mac) ? { mac: s(x.mac)!.toUpperCase() } : {}),
      ...(s(x.citizen) ? { citizen: s(x.citizen) } : {}),
    });
  }
  return out;
}

const rowText = (v: unknown): string[] =>
  (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v])
    .map((x) => (typeof x === "number" && Number.isFinite(x) ? String(x) : x))
    .filter((x): x is string => typeof x === "string" && x.trim() !== "")
    .map((x) => x.trim());
const SERVICE = /^[a-z0-9-]{1,16}(?:\/\d{1,5})?$/;

/**
 * Drops per enforcement point from adm_path_trace observation rows. Rows are
 * untrusted: only ACL-log leaves (pod-N/node-N) and Hubble nodes with a
 * positive drop count are kept. Rows from searches without drop_services fall
 * back to protocol/port pairs of the row (one protocol only).
 */
export function pathTraceDrops(rows: unknown): TraceDrop[] {
  if (!Array.isArray(rows)) return [];
  const byKey = new Map<string, TraceDrop>();
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type !== "observation") continue;
    const source = rowText(r.flow_source)[0];
    const device = rowText(r.observer_device)[0];
    const drops = Number(rowText(r.drops)[0] ?? 0);
    if (!device || !Number.isFinite(drops) || drops <= 0) continue;
    if (source === "aci_acllog") {
      if (!/^pod-\d+\/node-\d+$/.test(device)) continue;
    } else if (source === "hubble") {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/.test(device)) continue;
    } else continue;
    const listed = rowText(r.drop_services).map((s) => s.toLowerCase());
    const protocols = rowText(r.protocols).map((p) => p.toLowerCase());
    const services = (
      listed.length
        ? listed
        : protocols.length === 1
          ? rowText(r.dest_ports).map((p) => `${protocols[0]}/${p}`)
          : []
    ).filter((s) => SERVICE.test(s));
    const k = `${source}|${device.toLowerCase()}`;
    const prior = byKey.get(k) ?? {
      source,
      device,
      services: [],
      reasons: [],
      records: 0,
    };
    prior.records += drops;
    for (const s of services)
      if (!prior.services.includes(s)) prior.services.push(s);
    for (const reason of rowText(r.drop_reasons))
      if (!prior.reasons.includes(reason)) prior.reasons.push(reason);
    byKey.set(k, prior);
  }
  return [...byKey.values()].map((d) => ({
    ...d,
    services: d.services.sort(serviceOrder),
  }));
}

/** "tcp/80" before "tcp/443"; protocol, then numeric port. */
export const serviceOrder = (a: string, b: string) => {
  const [pa, na] = a.split("/");
  const [pb, nb] = b.split("/");
  return pa.localeCompare(pb) || Number(na ?? 0) - Number(nb ?? 0);
};

/** Observer strings from adm_path_trace observation rows. */
export function pathTraceObservers(rows: unknown): string[] {
  if (!Array.isArray(rows)) return [];
  const out = new Set<string>();
  for (const r of rows)
    if (
      r &&
      typeof r === "object" &&
      (r as Record<string, unknown>).row_type === "observation" &&
      typeof (r as Record<string, unknown>).observer === "string"
    )
      out.add((r as Record<string, string>).observer);
  return [...out];
}

/** Plain-text summary of one hop's evidence for tables and exports. */
export const hopEvidenceText = (h: TraceHop) =>
  h.evidence === "observed" && h.kind !== "endpoint"
    ? `Observed by ${h.sources.map(sourceLabel).join(", ")}`
    : h.evidence === "gap"
      ? "No evidence"
      : h.support?.length
        ? `Inferred; supported by ${h.support.join(", ")}`
        : h.kind === "endpoint"
          ? "Endpoint"
          : "Inferred from topology";
