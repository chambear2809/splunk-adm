/** A bounded, offline resolver. All timestamps are Unix seconds. */
export const DEVICE_PATH_LIMITS = {
  records: 512,
  paths: 16,
  hops: 16,
  expansions: 4096,
} as const;

export type IdentitySource = "appdynamics" | "teastore_otel" | "other";
export type Layer = "ownership" | "attachment" | "topology";
export interface Authority {
  source: string;
  fabric: string;
  routingDomain: string;
  layer: Layer;
}
export interface EvidenceRecord {
  id: string;
  // Provenance belongs to the record, not an inferred join.
  observedAt: number;
  receivedAt: number;
  kind: "owner" | "attachment" | "link";
  address?: string;
  identitySource?: IdentitySource;
  identityAuthority?: string;
  identityId?: string;
  device?: string;
  interface?: string;
  peerDevice?: string;
  peerInterface?: string;
  exporter?: string;
  translation?: "none" | "nat" | "overlay" | "unknown";
}
export interface EvidenceSnapshot extends Authority {
  snapshotId: string;
  producer: "apic" | "teastore_watch" | "other";
  complete: boolean;
  expectedCount: number;
  records: EvidenceRecord[];
}
export interface Endpoint {
  address: string;
  identitySource: IdentitySource;
  identityAuthority: string;
  identityId: string;
}
export interface DevicePathInput {
  asOf: number;
  receiptCutoff: number;
  maxAge: number;
  maxReceiptDelay: number;
  fabric: string;
  routingDomain: string;
  authorities: Authority[];
  endpoints: [Endpoint, Endpoint];
  snapshots: EvidenceSnapshot[];
}
export interface Provenance {
  source: string;
  snapshotId: string;
  recordId: string;
  observedAt: number;
  receivedAt: number;
}
export interface PathHop {
  device: string;
  interface: string;
  peerDevice: string;
  peerInterface: string;
  provenance: Provenance;
}
export interface DevicePathResult {
  status: "candidate" | "unavailable";
  reason: string;
  /** Paths are topology candidates, never packet or flow traversal observations. */
  traversal: "not_observed";
  endpoints: {
    endpoint: Endpoint;
    owners: {
      identitySource: IdentitySource;
      identityAuthority: string;
      identityId: string;
      provenance: Provenance;
    }[];
    attachments: {
      device: string;
      interface: string;
      provenance: Provenance;
    }[];
  }[];
  alternatives: PathHop[][];
  issues: { code: string; provenance?: Provenance }[];
}

const text = (v: unknown): v is string =>
  typeof v === "string" &&
  v.length > 0 &&
  v.length <= 256 &&
  Array.from(v).every((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127);
const time = (v: number) => Number.isFinite(v) && v >= 0 && v <= 253402300799;
const key = (a: Authority) =>
  JSON.stringify([a.source, a.fabric, a.routingDomain, a.layer]);
const identity = (e: Endpoint) =>
  JSON.stringify([e.identitySource, e.identityAuthority, e.identityId]);
const prov = (s: EvidenceSnapshot, r: EvidenceRecord): Provenance => ({
  source: s.source,
  snapshotId: s.snapshotId,
  recordId: r.id,
  observedAt: r.observedAt,
  receivedAt: r.receivedAt,
});

/** No external lookup, clock, source-specific identity bridge, or traversal inference. */
export function resolveDevicePath(input: DevicePathInput): DevicePathResult {
  const result: DevicePathResult = {
    status: "unavailable",
    reason: "invalid_input",
    traversal: "not_observed",
    endpoints: (input.endpoints ?? []).map((endpoint) => ({
      endpoint,
      owners: [],
      attachments: [],
    })),
    alternatives: [],
    issues: [],
  };
  const fail = (code: string, provenance?: Provenance) => {
    result.issues.push({ code, ...(provenance ? { provenance } : {}) });
    result.reason = code;
    return result;
  };
  if (
    !time(input.asOf) ||
    !time(input.receiptCutoff) ||
    input.receiptCutoff < input.asOf ||
    !time(input.maxAge) ||
    !time(input.maxReceiptDelay) ||
    input.maxAge === 0 ||
    !text(input.fabric) ||
    !text(input.routingDomain) ||
    !Array.isArray(input.endpoints) ||
    input.endpoints.length !== 2 ||
    !Array.isArray(input.authorities) ||
    !Array.isArray(input.snapshots) ||
    input.endpoints.some(
      (e) =>
        !text(e.address) ||
        !text(e.identityAuthority) ||
        !text(e.identityId) ||
        !["appdynamics", "teastore_otel", "other"].includes(e.identitySource),
    )
  )
    return fail("invalid_input");
  if (
    input.snapshots.length > DEVICE_PATH_LIMITS.records ||
    input.authorities.length > DEVICE_PATH_LIMITS.records ||
    input.snapshots.reduce(
      (n, s) =>
        n +
        (Array.isArray(s.records)
          ? s.records.length
          : DEVICE_PATH_LIMITS.records + 1),
      0,
    ) > DEVICE_PATH_LIMITS.records
  )
    return fail("input_cap");
  if (
    input.authorities.some(
      (a) =>
        !text(a.source) ||
        !text(a.fabric) ||
        !text(a.routingDomain) ||
        !["ownership", "attachment", "topology"].includes(a.layer),
    ) ||
    new Set(input.authorities.map(key)).size !== input.authorities.length
  )
    return fail("invalid_authority");
  const allowed = new Set(input.authorities.map(key));
  const relevant = input.snapshots.filter(
    (s) => s.fabric === input.fabric && s.routingDomain === input.routingDomain,
  );
  if (!relevant.length) return fail("missing_scope_evidence");
  const snapshotKeys = new Set<string>();
  const records: { snapshot: EvidenceSnapshot; record: EvidenceRecord }[] = [];
  for (const s of relevant) {
    if (
      !allowed.has(key(s)) ||
      !text(s.source) ||
      !text(s.snapshotId) ||
      !Array.isArray(s.records) ||
      !["ownership", "attachment", "topology"].includes(s.layer) ||
      !["apic", "teastore_watch", "other"].includes(s.producer)
    )
      return fail("unqualified_authority");
    if (s.producer === "apic") return fail("apic_quarantined");
    if (s.producer === "teastore_watch") return fail("watch_discontinuity");
    if (
      !s.complete ||
      !Number.isSafeInteger(s.expectedCount) ||
      s.expectedCount !== s.records.length
    )
      return fail("partial_snapshot");
    // Multiple captures for an authority are not ordered by an unverified timestamp.
    if (snapshotKeys.has(key(s))) return fail("snapshot_conflict");
    snapshotKeys.add(key(s));
    const ids = new Map<string, string>();
    for (const r of s.records) {
      const p = prov(s, r);
      if (!text(r.id)) return fail("invalid_record", p);
      const serialized = JSON.stringify(r);
      if (ids.has(r.id))
        return fail(
          ids.get(r.id) === serialized ? "duplicate_record" : "replay_conflict",
          p,
        );
      ids.set(r.id, serialized);
      if (
        !time(r.observedAt) ||
        !time(r.receivedAt) ||
        r.observedAt > input.asOf ||
        input.asOf - r.observedAt > input.maxAge ||
        r.receivedAt < r.observedAt ||
        r.receivedAt > input.receiptCutoff ||
        r.receivedAt - r.observedAt > input.maxReceiptDelay
      )
        return fail("time_window", p);
      if (
        (s.layer === "ownership" && r.kind !== "owner") ||
        (s.layer === "attachment" && r.kind !== "attachment") ||
        (s.layer === "topology" && r.kind !== "link")
      )
        return fail("invalid_record", p);
      records.push({ snapshot: s, record: r });
    }
  }
  // The caller must supply every configured authority for each required layer.
  for (const layer of ["ownership", "attachment", "topology"] as const) {
    const expected = input.authorities.filter(
      (a) =>
        a.fabric === input.fabric &&
        a.routingDomain === input.routingDomain &&
        a.layer === layer,
    );
    if (!expected.length || expected.some((a) => !snapshotKeys.has(key(a))))
      return fail("missing_snapshot");
  }
  const owners = records.filter(({ record: r }) => r.kind === "owner");
  const attachments = records.filter(
    ({ record: r }) => r.kind === "attachment",
  );
  const links = records.filter(({ record: r }) => r.kind === "link");
  for (const { snapshot: s, record: r } of records) {
    if (
      (r.kind === "owner" &&
        (!text(r.address) ||
          !text(r.identityAuthority) ||
          !text(r.identityId) ||
          !["appdynamics", "teastore_otel", "other"].includes(
            r.identitySource ?? "",
          ))) ||
      (r.kind === "attachment" &&
        (!text(r.identityAuthority) ||
          !text(r.identityId) ||
          !["appdynamics", "teastore_otel", "other"].includes(
            r.identitySource ?? "",
          ) ||
          !text(r.device) ||
          !text(r.interface))) ||
      (r.kind === "link" &&
        (!text(r.device) ||
          !text(r.interface) ||
          !text(r.peerDevice) ||
          !text(r.peerInterface) ||
          !text(r.exporter)))
    )
      return fail("incomplete_record", prov(s, r));
    if (r.kind !== "owner" && r.translation !== "none")
      return fail("translation_ambiguous", prov(s, r));
  }
  const devices: string[] = [];
  for (const [i, e] of input.endpoints.entries()) {
    const matches = owners.filter(({ record: r }) => r.address === e.address);
    result.endpoints[i].owners = matches.map(({ snapshot, record }) => ({
      identitySource: record.identitySource!,
      identityAuthority: record.identityAuthority!,
      identityId: record.identityId!,
      provenance: prov(snapshot, record),
    }));
    const identities = new Set(
      matches.map(({ record: r }) =>
        identity({
          address: e.address,
          identitySource: r.identitySource!,
          identityAuthority: r.identityAuthority!,
          identityId: r.identityId!,
        }),
      ),
    );
    if (identities.size !== 1 || !identities.has(identity(e)))
      return fail(
        identities.size > 1 ? "competing_owners" : "owner_unresolved",
      );
    const attached = attachments.filter(
      ({ record: r }) =>
        identity({
          address: e.address,
          identitySource: r.identitySource!,
          identityAuthority: r.identityAuthority!,
          identityId: r.identityId!,
        }) === identity(e),
    );
    result.endpoints[i].attachments = attached.map(({ snapshot, record }) => ({
      device: record.device!,
      interface: record.interface!,
      provenance: prov(snapshot, record),
    }));
    const locations = new Set(
      attached.map(({ record: r }) => JSON.stringify([r.device, r.interface])),
    );
    if (locations.size !== 1)
      return fail(
        locations.size > 1 ? "attachment_ambiguous" : "attachment_unresolved",
      );
    devices.push(attached[0].record.device!);
  }
  // Enumerate simple paths with explicit ceilings. Exceeding either ceiling invalidates the whole result.
  let capped = false;
  let expansions = 0;
  const visit = (device: string, seen: Set<string>, path: PathHop[]) => {
    if (++expansions > DEVICE_PATH_LIMITS.expansions) {
      capped = true;
      return;
    }
    if (device === devices[1]) {
      result.alternatives.push(path);
      if (result.alternatives.length > DEVICE_PATH_LIMITS.paths) capped = true;
      return;
    }
    for (const { snapshot, record: r } of links) {
      const forward = r.device === device;
      if (!forward && r.peerDevice !== device) continue;
      const next = (forward ? r.peerDevice : r.device)!;
      if (seen.has(next)) continue;
      if (path.length >= DEVICE_PATH_LIMITS.hops) {
        capped = true;
        continue;
      }
      const hop: PathHop = {
        device,
        interface: (forward ? r.interface : r.peerInterface)!,
        peerDevice: next,
        peerInterface: (forward ? r.peerInterface : r.interface)!,
        provenance: prov(snapshot, r),
      };
      visit(next, new Set([...seen, next]), [...path, hop]);
      if (capped) return;
    }
  };
  visit(devices[0], new Set([devices[0]]), []);
  if (capped) {
    result.alternatives = [];
    return fail("path_cap");
  }
  if (!result.alternatives.length) return fail("disconnected_or_unknown");
  result.status = "candidate";
  result.reason = "topology_candidates_only";
  return result;
}
