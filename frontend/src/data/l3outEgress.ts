import {
  interfaceLabel,
  parseObserver,
  type Device,
  type TopologyIndex,
} from "../topology";
import type { FabricEvidence, TraceHop } from "./pathTrace";

/**
 * ACI routed egress for a destination outside the fabric. adm_path_trace
 * appends adm_l3out_path_evidence rows: every l3ext:RsPathL3OutAtt (the
 * border leaf path, interface type, encap and address of an L3Out) and the
 * l3ext:Subnet external EPG subnets containing either address.
 */
export interface L3OutPath {
  apic?: string;
  tenant?: string;
  l3out: string;
  l3outDn: string;
  /** Border leaves, ACI `pod-N/node-N` (two for a vPC path). */
  nodes: string[];
  interface?: string;
  ifType?: string;
  encap?: string;
  /** Interface address in CIDR form, when not 0.0.0.0. */
  address?: string;
}
export interface L3OutSubnet {
  apic?: string;
  l3out: string;
  l3outDn: string;
  instp?: string;
  subnet: string;
}
export interface L3OutEvidence {
  paths: L3OutPath[];
  subnets: L3OutSubnet[];
  /** adm_l3out_path_limit cut paths or subnets (truncated=1 rows). */
  truncated?: boolean;
}
export interface L3OutMatch {
  l3out: string;
  l3outDn: string;
  apic?: string;
  /** How the destination was tied to the L3Out, strongest first. */
  basis: "interface_address" | "connected" | "external_subnet" | "only_l3out";
  subnet?: string;
  instp?: string;
  paths: L3OutPath[];
}

const str = (v: unknown): string | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === "string" && x.trim() ? x.trim() : undefined;
};
const strs = (v: unknown): string[] =>
  (Array.isArray(v) ? v : [v])
    .filter((x): x is string => typeof x === "string")
    .flatMap((x) => x.split(","))
    .map((x) => x.trim())
    .filter(Boolean);
const ACI_NODE = /^pod-\d+\/node-\d+$/;
const L3OUT_DN = /^uni\/tn-[^/]+\/out-[^/]+$/;

/** l3out_path and l3out_subnet rows; malformed rows are skipped. */
export function l3outRows(rows: unknown): L3OutEvidence {
  const out: L3OutEvidence = { paths: [], subnets: [] };
  if (!Array.isArray(rows)) return out;
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const r = raw as Record<string, unknown>;
    if (
      (r.row_type === "l3out_path" || r.row_type === "l3out_subnet") &&
      String(str(r.truncated) ?? r.truncated) === "1"
    )
      out.truncated = true;
    const l3out = str(r.l3out),
      l3outDn = str(r.l3out_dn);
    if (!l3out || !l3outDn || !L3OUT_DN.test(l3outDn)) continue;
    const apic = str(r.apic_host);
    if (r.row_type === "l3out_path") {
      const nodes = strs(r.nodes).filter((n) => ACI_NODE.test(n));
      if (!nodes.length) continue;
      const address = str(r.address);
      out.paths.push({
        l3out,
        l3outDn,
        nodes,
        ...(apic ? { apic } : {}),
        ...(str(r.tenant) ? { tenant: str(r.tenant) } : {}),
        ...(str(r.interface) ? { interface: str(r.interface) } : {}),
        ...(str(r.if_type) ? { ifType: str(r.if_type) } : {}),
        ...(str(r.encap) ? { encap: str(r.encap) } : {}),
        ...(address && parseCidr(address) ? { address } : {}),
      });
    } else if (r.row_type === "l3out_subnet") {
      const subnet = str(r.subnet);
      if (!subnet || !parseCidr(subnet)) continue;
      out.subnets.push({
        l3out,
        l3outDn,
        subnet,
        ...(apic ? { apic } : {}),
        ...(str(r.instp) ? { instp: str(r.instp) } : {}),
      });
    }
  }
  return out;
}

/** IPv4 or IPv6 literal → [bits, value]. */
function parseIp(s: string): [number, bigint] | undefined {
  const t = s.trim();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (v4) {
    const parts = v4.slice(1).map(Number);
    if (parts.some((p) => p > 255)) return undefined;
    return [32, parts.reduce((n, p) => (n << 8n) | BigInt(p), 0n)];
  }
  if (!/^[0-9A-Fa-f:]+$/.test(t) || !t.includes(":")) return undefined;
  const halves = t.split("::");
  if (halves.length > 2) return undefined;
  const groups = (h: string) => (h ? h.split(":") : []);
  const head = groups(halves[0]),
    tail = halves.length === 2 ? groups(halves[1]) : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return undefined;
  const all = [...head, ...Array<string>(fill).fill("0"), ...tail];
  if (all.some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return undefined;
  return [128, all.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n)];
}
function parseCidr(s: string): [number, bigint, number] | undefined {
  const [ip, len, extra] = s.trim().split("/");
  if (extra !== undefined || len === undefined || !/^\d{1,3}$/.test(len))
    return undefined;
  const p = parseIp(ip);
  const n = Number(len);
  if (!p || n > p[0]) return undefined;
  return [p[0], p[1], n];
}
/** Prefix length when `ip` is inside `cidr`, else undefined. */
export function cidrContains(cidr: string, ip: string): number | undefined {
  const c = parseCidr(cidr),
    a = parseIp(ip);
  if (!c || !a || c[0] !== a[0]) return undefined;
  const shift = BigInt(c[0] - c[2]);
  return c[1] >> shift === a[1] >> shift ? c[2] : undefined;
}
const sameIp = (cidr: string, ip: string) => {
  const c = parseCidr(cidr),
    a = parseIp(ip);
  return !!c && !!a && c[0] === a[0] && c[1] === a[1];
};

/**
 * The one L3Out a destination leaves the fabric through: the L3Out whose
 * interface subnet contains it, else the longest external EPG subnet
 * containing it, else the fabric's only L3Out. Ties across L3Outs yield none.
 */
export function matchL3Out(
  dst: string,
  ev: L3OutEvidence,
  apic?: string,
): L3OutMatch | undefined {
  const inFabric = <T extends { apic?: string }>(xs: T[]) =>
    xs.filter((x) => !apic || !x.apic || x.apic === apic);
  const paths = inFabric(ev.paths);
  if (!paths.length) return undefined;
  const one = <T extends { l3outDn: string }>(xs: T[]) =>
    new Set(xs.map((x) => x.l3outDn)).size === 1;
  const best = <T>(xs: T[], len: (x: T) => number | undefined) => {
    const scored = xs
      .map((x) => [x, len(x)] as const)
      .filter((x): x is readonly [T, number] => x[1] !== undefined);
    const top = Math.max(...scored.map((x) => x[1]));
    return scored.filter((x) => x[1] === top).map((x) => x[0]);
  };
  const connected = best(paths, (p) =>
    p.address ? cidrContains(p.address, dst) : undefined,
  );
  if (connected.length) {
    if (!one(connected)) return undefined;
    const p = connected[0];
    return {
      l3out: p.l3out,
      l3outDn: p.l3outDn,
      ...(p.apic ? { apic: p.apic } : {}),
      basis: connected.some((c) => sameIp(c.address!, dst))
        ? "interface_address"
        : "connected",
      subnet: p.address,
      paths: connected,
    };
  }
  const subnets = best(inFabric(ev.subnets), (s) =>
    cidrContains(s.subnet, dst),
  ).filter((s) => paths.some((p) => p.l3outDn === s.l3outDn));
  const pick = (dn: string): L3OutMatch | undefined => {
    const ps = paths.filter((p) => p.l3outDn === dn);
    return ps.length
      ? {
          l3out: ps[0].l3out,
          l3outDn: dn,
          ...(ps[0].apic ? { apic: ps[0].apic } : {}),
          basis: "only_l3out",
          paths: ps,
        }
      : undefined;
  };
  if (subnets.length) {
    if (!one(subnets)) return undefined;
    const m = pick(subnets[0].l3outDn);
    return (
      m && {
        ...m,
        basis: "external_subnet",
        subnet: subnets[0].subnet,
        ...(subnets[0].instp ? { instp: subnets[0].instp } : {}),
      }
    );
  }
  return one(paths) ? pick(paths[0].l3outDn) : undefined;
}

/**
 * "Eth1/24.15 vlan-304 (inferred, L3Out CV-L3Out-01)". `named` may return the
 * collected name of a path's interface (e.g. its one sub-interface).
 */
export function l3outEgressLabel(
  paths: L3OutPath[],
  l3out: string,
  named: (p: L3OutPath) => string | undefined = () => undefined,
): string {
  const names = [
    ...new Set(
      paths.map((p) => {
        const name = named(p) ?? p.interface;
        return [name ? interfaceLabel(name) : undefined, p.encap]
          .filter(Boolean)
          .join(" ");
      }),
    ),
  ].filter(Boolean);
  return `${names.join(", ") || "L3Out path"} (inferred, L3Out ${l3out})`;
}

const lower = (s?: string) => (s ?? "").trim().toLowerCase();
const apicOf = (d?: Device) =>
  d?.fabric?.startsWith("apic:") ? d.fabric.slice(5) : d?.device_authority;
/** One device per APIC and ACI node, in name order. */
const uniqueNodes = (ds: Device[]) =>
  [
    ...new Map(
      ds.map((d) => [`${apicOf(d) ?? ""}|${lower(d.aci_node)}`, d]),
    ).values(),
  ].sort((a, b) => a.name.localeCompare(b.name));

/**
 * The collected (SNMP ifDescr) name of an L3Out sub-interface: the only
 * `<interface>.<n>` the border leaf reports under its management address.
 * ACI numbers sub-interfaces internally, not by VLAN, so two or more
 * candidates name none.
 */
export function subInterfaceName(
  topo: TopologyIndex,
  device: Device,
  path: L3OutPath,
): string | undefined {
  if (path.ifType !== "sub-interface" || !path.interface) return undefined;
  const owners = [device.mgmt_ip, device.id]
    .filter((o): o is string => !!o)
    .map((o) => `${lower(o)}|`);
  const parent = lower(path.interface);
  const found = new Set<string>();
  for (const [k, name] of topo.ifName)
    if (
      owners.some((o) => k.startsWith(o)) &&
      lower(name).startsWith(`${parent}.`) &&
      /^\d+$/.test(name.slice(parent.length + 1))
    )
      found.add(name);
  return found.size === 1 ? [...found][0] : undefined;
}

export interface L3OutEgressInput {
  hops: TraceHop[];
  dst: string;
  evidence: L3OutEvidence;
  topo: TopologyIndex;
  /** Observer strings of the pair (adm_path_trace observations). */
  observers: string[];
  fabric: FabricEvidence[];
}

/**
 * ACI leaf NetFlow is ingress-only, so a destination with no fabric endpoint
 * ends the observed path at a leaf followed by an attachment gap. When the
 * destination matches an L3Out, the gap is replaced by the routed path: the
 * border leaf's L3Out interface when the ingress leaf is the border leaf,
 * else "fabric" toward the border leaf, the spines with an up IS-IS adjacency
 * to both leaves (COOP holds no external addresses), and the border leaf.
 * Every added hop and interface is labelled inferred.
 */
export function inferL3OutEgress(input: L3OutEgressInput): {
  hops: TraceHop[];
  note?: string;
} {
  const { hops, topo } = input;
  const end = hops.length - 1;
  const gap = hops[end - 1];
  const leafHop = hops[end - 2];
  if (
    hops[end]?.kind !== "endpoint" ||
    gap?.kind !== "gap" ||
    !/^Attachment of /.test(gap.label) ||
    leafHop?.kind !== "switch" ||
    leafHop.out
  )
    return { hops };
  const candidates = (
    leafHop.alternatives?.map((a) => a.device) ??
    (leafHop.device ? [leafHop.device] : [])
  )
    .map((id) => topo.byId.get(id))
    .filter((d): d is Device => !!d?.aci_node && d.role !== "spine");
  if (
    !candidates.length ||
    candidates.length !== (leafHop.alternatives?.length ?? 1)
  )
    return { hops };
  const apic = apicOf(candidates[0]);
  const match = matchL3Out(input.dst, input.evidence, apic);
  if (!match) return { hops };
  const sameFabric = (d: Device) => !apic || !apicOf(d) || apicOf(d) === apic;
  const devices = [...topo.byId.values()];
  const borderNodes = new Set(match.paths.flatMap((p) => p.nodes.map(lower)));
  const borders = uniqueNodes(
    devices.filter(
      (d) => d.aci_node && borderNodes.has(lower(d.aci_node)) && sameFabric(d),
    ),
  );
  if (!borders.length) return { hops };
  // The exporting leaf of a vPC pair is the ingress leaf.
  const exported = new Set(
    input.observers.flatMap((o) => parseObserver(o, topo).map((p) => p.key)),
  );
  const seen = candidates.filter((d) => exported.has(lower(d.id)));
  const ingress =
    candidates.length === 1
      ? candidates[0]
      : seen.length === 1
        ? seen[0]
        : undefined;
  const pathsOn = (d: Device) =>
    match.paths.filter((p) =>
      p.nodes.some((n) => lower(n) === lower(d.aci_node)),
    );
  const egress = (d: Device) =>
    l3outEgressLabel(pathsOn(d), match.l3out, (p) =>
      subInterfaceName(topo, d, p),
    );
  const isBorder = (d: Device) => borders.some((b) => b.id === d.id);
  const dstHop: TraceHop = {
    ...hops[end],
    detail: [
      "External",
      match.basis === "interface_address"
        ? `L3Out ${match.l3out} interface address`
        : match.basis === "connected"
          ? `connected to L3Out ${match.l3out} (${match.subnet})`
          : match.basis === "external_subnet"
            ? `external EPG ${match.instp ?? match.l3out} (${match.subnet})`
            : `via L3Out ${match.l3out}`,
    ].join(" · "),
  };
  const narrowed = (d: Device, out: string): TraceHop => {
    const hop: TraceHop = { ...leafHop, out };
    if (candidates.length > 1) {
      const peers = candidates.filter((c) => c.id !== d.id);
      hop.device = d.id;
      hop.label = d.name;
      hop.detail = `ACI leaf · vPC peer ${peers.map((c) => c.name).join(", ")} · flow exporter`;
      delete hop.alternatives;
      // Its observed ingress is the exporter's own.
      const ingress = leafHop.seen.filter((s) => !s.includes(" → "));
      if (!hop.in && ingress.length === 1) hop.in = ingress[0];
    }
    return hop;
  };
  const head = hops.slice(0, end - 2);
  const note = `Egress inferred from ACI L3Out ${match.l3out} (l3extRsPathL3OutAtt); ACI leaf NetFlow is ingress-only.`;
  if (ingress && isBorder(ingress))
    return {
      hops: [...head, narrowed(ingress, egress(ingress)), dstHop],
      note,
    };
  const local = ingress ? [] : candidates.filter(isBorder);
  if (local.length === 1)
    // A border leaf is a member of the ingress vPC pair and neither member is
    // singled out: the flow leaves on that border leaf, directly or from its
    // vPC peer across a spine. Neither is observed.
    return {
      hops: [
        ...head,
        {
          ...leafHop,
          out: `${egress(local[0])} on ${local[0].name}`,
          detail: `${leafHop.detail ? `${leafHop.detail} · ` : ""}ingress member not determined`,
        },
        dstHop,
      ],
      note: `${note} The ingress vPC member is not determined; traffic from ${candidates
        .filter((d) => !isBorder(d))
        .map((d) => d.name)
        .join(", ")} would cross a spine to ${local[0].name}.`,
    };
  if (local.length) return { hops };
  const from = ingress ? [ingress] : candidates;
  const fabricOut = `fabric (inferred, to border leaf ${borders.map((b) => b.name).join(", ")})`;
  const first = ingress
    ? narrowed(ingress, fabricOut)
    : { ...leafHop, out: fabricOut };
  const spine = spineStage(
    from,
    borders,
    input.fabric.filter((e) => !apic || !e.apic || e.apic === apic),
    devices,
    sameFabric,
  );
  return {
    hops: [
      ...head,
      first,
      ...(spine ? [spine] : []),
      borderStage(borders, match, egress),
      dstHop,
    ],
    note: spine ? note : `${note} No spine evidence between the leaves.`,
  };
}

function borderStage(
  borders: Device[],
  match: L3OutMatch,
  egress: (d: Device) => string,
): TraceHop {
  const detail = `Border leaf · L3Out ${match.l3out}`;
  const base: TraceHop = {
    kind: "switch",
    label: borders[0].name,
    evidence: "inferred",
    sources: [],
    seen: [],
    detail,
  };
  if (borders.length === 1)
    return { ...base, device: borders[0].id, out: egress(borders[0]) };
  const outs = [...new Set(borders.map(egress))];
  return {
    ...base,
    label: `One of ${borders.length} border leaves`,
    alternatives: borders.map((d) => ({ device: d.id, label: d.name })),
    ...(outs.length === 1 ? { out: outs[0] } : {}),
  };
}

/**
 * Spines with an up IS-IS adjacency to a source leaf and to a border leaf.
 * COOP is not used: it holds fabric endpoints, never external addresses.
 */
function spineStage(
  from: Device[],
  to: Device[],
  fabric: FabricEvidence[],
  devices: Device[],
  sameFabric: (d: Device) => boolean,
): TraceHop | undefined {
  const spines = uniqueNodes(
    devices.filter((d) => d.role === "spine" && d.aci_node && sameFabric(d)),
  );
  if (!spines.length) return undefined;
  const adjacent = (s: Device, leaf: Device) =>
    fabric.some(
      (e) =>
        e.kind === "isis_adjacency" &&
        ((lower(e.node) === lower(s.aci_node) &&
          lower(e.peerNode) === lower(leaf.aci_node)) ||
          (lower(e.node) === lower(leaf.aci_node) &&
            lower(e.peerNode) === lower(s.aci_node))),
    );
  const qualified = spines.filter(
    (s) => from.some((l) => adjacent(s, l)) && to.some((b) => adjacent(s, b)),
  );
  const chosen = qualified.length ? qualified : spines;
  const names = (ds: Device[]) => ds.map((d) => d.name).join(", ");
  const hop: TraceHop = {
    kind: "switch",
    label:
      chosen.length === 1 ? chosen[0].name : `One of ${chosen.length} spines`,
    evidence: "inferred",
    sources: [],
    seen: [],
    detail: qualified.length
      ? `IS-IS adjacency up to ${names(from)} and ${names(to)} · ECMP, forwarding spine not observed`
      : "ACI spine · no IS-IS adjacency evidence · topology only",
  };
  if (qualified.length) hop.support = ["ACI IS-IS adjacency"];
  if (chosen.length === 1) hop.device = chosen[0].id;
  else hop.alternatives = chosen.map((d) => ({ device: d.id, label: d.name }));
  return hop;
}
