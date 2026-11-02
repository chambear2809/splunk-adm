import {
  APPDYNAMICS_SCHEMA,
  APPDYNAMICS_SOURCETYPE,
} from "./appdynamicsEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import { literal, normalizeIp, routingScope } from "./evidence";
import { indexNames } from "./deploymentHealth";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";
import type { Row } from "../rows";

export interface ControllerNode {
  id: string;
  name: string;
  machine?: string;
  addresses: string[];
}
export interface ControllerTier {
  id: string;
  name: string;
  nodes: ControllerNode[];
}
export interface ControllerApplication {
  id: string;
  name: string;
  tiers: ControllerTier[];
  backends: { id: string; name: string; exitPointType?: string }[];
}
export interface ControllerCatalog {
  authority: string;
  scope: string;
  snapshotId: string;
  snapshotAt: number;
  applications: ControllerApplication[];
}

function configuration(config: SupplementalSourceConfiguration) {
  const mappings = config.mappings.filter(
    (m) =>
      m.observer_kind === "appd_controller" && m.mapping_status === "verified",
  );
  if (
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    config.indexes.length !== 1 ||
    config.authorities.length !== 1 ||
    mappings.length !== 1 ||
    mappings[0].observer !== config.authorities[0] ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > 30 * 86400
  )
    throw new Error(
      "AppDynamics Controller source is not uniquely configured and qualified.",
    );
  const index = indexNames({
    name: "adm_index_appdynamics_inventory",
    definition: `index=${config.indexes[0]}`,
  });
  if (index.length !== 1 || index[0] !== config.indexes[0])
    throw new Error("Invalid AppDynamics index.");
  return {
    index: index[0],
    authority: literal(mappings[0].observer),
    scope: routingScope(mappings[0].scope),
  };
}
const text = (v: unknown): string => {
  if (
    (typeof v !== "string" && typeof v !== "number") ||
    !String(v) ||
    String(v).length > 512 ||
    Array.from(String(v)).some(
      (c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127,
    )
  )
    throw new Error("Invalid Controller inventory field.");
  return String(v);
};
const num = (v: unknown): number => {
  const n = Number(v);
  if (
    (typeof v !== "number" && typeof v !== "string") ||
    !Number.isFinite(n) ||
    n < 0
  )
    throw new Error("Invalid Controller inventory time.");
  return n;
};

/** Admit only a single, complete latest snapshot. No fallback to an older capture. */
export function normalizeControllerCatalog(
  rows: readonly Row[],
  config: SupplementalSourceConfiguration,
  cutoff: number,
): ControllerCatalog {
  const mapping = configuration(config);
  if (!rows.length || rows.length > 10000)
    throw new Error("Controller inventory is empty or exceeds its scan limit.");
  const records = rows.map((row) => {
    if (String(row.index) !== mapping.index || num(row._indextime) > cutoff)
      throw new Error("Controller inventory receipt is outside the cutoff.");
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(String(row._raw));
    } catch {
      throw new Error("Invalid Controller inventory record.");
    }
    if (
      !raw ||
      typeof raw !== "object" ||
      Array.isArray(raw) ||
      JSON.stringify(raw).length > 65536 ||
      raw.schema !== APPDYNAMICS_SCHEMA ||
      Number(raw.schema_version) !== 1 ||
      raw.source !== "appdynamics_inventory" ||
      raw.controller_authority !== mapping.authority ||
      raw.scope !== mapping.scope ||
      raw.identity_basis !== "controller_application_model_ids" ||
      ![true, "true", 1, "1"].includes(raw.snapshot_complete as never)
    )
      throw new Error("Unqualified Controller inventory record.");
    text(raw.snapshot_id);
    text(raw.record_id);
    if (!/^[0-9a-f]{64}$/.test(text(raw.record_fingerprint)))
      throw new Error("Invalid record fingerprint.");
    if (
      !["snapshot", "application", "tier", "node", "backend"].includes(
        text(raw.record_type),
      )
    )
      throw new Error("Invalid Controller record type.");
    const at = num(raw.snapshot_at),
      start = num(raw.collection_started_at),
      end = num(raw.collection_completed_at),
      observed = num(raw.observed_at),
      skew = num(raw.collection_skew_seconds);
    if (
      at !== end ||
      start > end ||
      observed < start ||
      observed > end ||
      Math.abs(end - start - skew) > 1 ||
      at > cutoff ||
      at < cutoff - config.staleAfterSeconds
    )
      throw new Error("Invalid or stale Controller capture time.");
    return raw;
  });
  const latest = Math.max(...records.map((r) => num(r.snapshot_at)));
  const selected = records.filter((r) => num(r.snapshot_at) === latest);
  const snapshotIds = new Set(selected.map((r) => text(r.snapshot_id)));
  if (snapshotIds.size !== 1)
    throw new Error("Ambiguous latest Controller snapshot.");
  const snapshotId = text(selected[0].snapshot_id);
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(snapshotId))
    throw new Error("Invalid Controller snapshot identity.");
  const capture = records.filter((r) => r.snapshot_id === snapshotId);
  const first = capture[0];
  if (
    capture.some((r) =>
      [
        "snapshot_at",
        "collection_started_at",
        "collection_completed_at",
        "collection_skew_seconds",
      ].some((k) => r[k] !== first[k]),
    )
  )
    throw new Error("Controller snapshot times disagree.");
  const manifests = capture.filter((r) => r.record_type === "snapshot");
  const counts = manifests[0]?.record_counts as
    Record<string, unknown> | undefined;
  if (
    manifests.length !== 1 ||
    !counts ||
    num(counts.total_records) !== capture.length ||
    new Set(capture.map((r) => text(r.record_id))).size !== capture.length ||
    new Set(capture.map((r) => text(r.record_fingerprint))).size !==
      capture.length
  )
    throw new Error(
      "Controller snapshot is incomplete or has duplicate identities.",
    );
  for (const [type, field] of [
    ["application", "applications"],
    ["tier", "tiers"],
    ["node", "nodes"],
    ["backend", "backends"],
  ])
    if (
      num(counts[field]) !==
      capture.filter((r) => r.record_type === type).length
    )
      throw new Error("Controller snapshot counts disagree.");
  const applications: ControllerApplication[] = [];
  const appMap = new Map<string, ControllerApplication>();
  for (const r of capture.filter((r) => r.record_type === "application")) {
    const id = text(r.application_id);
    if (!/^[0-9]{1,20}$/.test(id) || appMap.has(id))
      throw new Error("Invalid Controller application identity.");
    const app: ControllerApplication = {
      id,
      name: text(r.application_name),
      tiers: [],
      backends: [],
    };
    appMap.set(id, app);
    applications.push(app);
  }
  const tiers = new Map<string, ControllerTier>();
  for (const r of capture.filter((r) => r.record_type === "tier")) {
    const app = appMap.get(text(r.application_id));
    const id = text(r.tier_id);
    const key = `${text(r.application_id)}:${id}`;
    if (!app || tiers.has(key))
      throw new Error("Invalid Controller tier identity.");
    const tier = { id, name: text(r.tier_name), nodes: [] };
    tiers.set(key, tier);
    app.tiers.push(tier);
  }
  const nodes = new Set<string>();
  for (const r of capture.filter((r) => r.record_type === "node")) {
    const key = `${text(r.application_id)}:${text(r.tier_id)}`;
    const tier = tiers.get(key);
    const id = text(r.node_id);
    if (!tier || nodes.has(`${key}:${id}`) || !Array.isArray(r.ip_addresses))
      throw new Error("Invalid Controller node identity.");
    nodes.add(`${key}:${id}`);
    const addresses = r.ip_addresses
      .filter((v: { matchable?: boolean }) => v.matchable === true)
      .map((v: { ip?: string }) => normalizeIp(text(v.ip)));
    tier.nodes.push({
      id,
      name: text(r.node_name),
      ...(r.machine_name ? { machine: text(r.machine_name) } : {}),
      addresses,
    });
  }
  const backends = new Set<string>();
  for (const r of capture.filter((r) => r.record_type === "backend")) {
    const app = appMap.get(text(r.application_id));
    const id = text(r.backend_id);
    const key = `${text(r.application_id)}:${id}`;
    if (!app || backends.has(key))
      throw new Error("Invalid Controller backend identity.");
    backends.add(key);
    app.backends.push({
      id,
      name: text(r.backend_name),
      ...(r.exit_point_type ? { exitPointType: text(r.exit_point_type) } : {}),
    });
  }
  return {
    authority: mapping.authority,
    scope: mapping.scope,
    snapshotId,
    snapshotAt: latest,
    applications,
  };
}

export async function loadControllerCatalog(
  client: SearchClient,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<ControllerCatalog> {
  const before = await configurationClient.read(signal);
  const source = before.supplemental?.find(
    (s) => s.source === "appdynamics_inventory",
  );
  if (!source)
    throw new Error("AppDynamics Controller source is not configured.");
  const mapping = configuration(source);
  const cutoff = Math.floor(Date.now() / 1000);
  const search = `search index=${mapping.index} sourcetype="${APPDYNAMICS_SOURCETYPE}" source="appdynamics_inventory" schema="${APPDYNAMICS_SCHEMA}" controller_authority="${mapping.authority}" scope="${literal(mapping.scope)}" | head 10001 | fields _raw index _indextime`;
  const result = requireNoSearchErrors(
    await client.search({
      search,
      earliest: String(cutoff - source.staleAfterSeconds),
      latest: String(cutoff + 1),
      maxRows: 10001,
      allowEmpty: true,
      signal,
    }),
    "Controller inventory search",
  );
  if (result.warnings.length)
    throw new Error(
      "Controller inventory search returned warnings; completeness is unknown.",
    );
  const catalog = normalizeControllerCatalog(result.rows, source, cutoff);
  const after = await configurationClient.read(signal);
  if (before.fingerprint !== after.fingerprint)
    throw new Error("Controller configuration changed during the search.");
  return catalog;
}
