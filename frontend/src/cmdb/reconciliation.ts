import type { Row } from "../rows";
import { csvRow } from "../csv";
import { literal, normalizeIp, routingScope } from "../data/evidence";
import type { SupplementalSourceConfiguration } from "../data/evidenceConfig";
import { validateIndexName } from "../data/deploymentHealth";
import type { AtlasServiceKey } from "./itsiExport";

/** Row caps; one extra row proves truncation. */
export const CMDB_LIMITS = {
  relationships: 5000,
  assetScan: 10000,
  assets: 5000,
  cmdbRelationships: 5000,
  windowDays: [1, 7, 14, 30] as const,
} as const;
const MAX_TIME = 253_402_300_799;

export type SourceState =
  "complete" | "incomplete" | "unavailable" | "not_configured";

export interface SourceCompleteness {
  state: SourceState;
  reasons: string[];
  inputCount: number;
  returnedCount: number;
  rejected: number;
}

export type ServiceBindingState =
  "bound" | "unbound" | "ambiguous" | "not_workload";

export interface EndpointObservation {
  kind?: string;
  endpointKind?: string;
  name?: string;
  identityState: "resolved" | "ambiguous" | "none";
  service?: AtlasServiceKey;
  serviceState: ServiceBindingState;
}

export interface ObservedRelationship {
  scope: string;
  clientIp: string;
  serverIp: string;
  serverPort?: number;
  transport: string;
  firstSeen: number;
  lastSeen: number;
  blocked: boolean;
  client: EndpointObservation;
  server: EndpointObservation;
}

export interface CmdbAssetRecord {
  authority: string;
  scope: string;
  ip: string;
  recordId: string;
  revision: number;
  assetId: string;
  assetName?: string;
  validityBasis: "source_interval" | "snapshot_current";
  validFrom: number;
  validTo?: number;
  snapshotAt: number;
  revisionConflict: boolean;
}

export interface CmdbRelationshipRecord {
  authority: string;
  relationshipId: string;
  scope: string;
  clientIp: string;
  serverIp: string;
  serverPort?: number;
  transport?: string;
  relationshipType?: string;
  clientCi?: string;
  serverCi?: string;
  snapshotAt?: number;
}

export interface Parsed<T> {
  records: T[];
  completeness: SourceCompleteness;
}

const SCOPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$/;

function checkedScope(scope: string): string {
  const value = routingScope(scope);
  if (!SCOPE_PATTERN.test(value)) throw new Error("Invalid routing scope.");
  return value;
}

function checkedWindow(window: { start: number; end: number }) {
  if (
    !Number.isSafeInteger(window.start) ||
    !Number.isSafeInteger(window.end) ||
    window.start < 0 ||
    window.end > MAX_TIME ||
    window.end <= window.start
  )
    throw new Error("Reconciliation needs an absolute half-open window.");
  return window;
}

/** Observed relationships in one routing scope; caller dispatches the window. */
export function buildObservedRelationshipSearch(scope: string): string {
  const cap = CMDB_LIMITS.relationships;
  return `| \`adm_cmdb_observed_relationships("${checkedScope(scope)}")\`
| eval kind="relationship"
| eventstats count AS input_count max(identity_invalid) AS identity_invalid_any
| appendpipe [| stats count AS adm_n max(input_count) AS input_count max(identity_invalid_any) AS identity_invalid_any | eval kind="completion",input_count=coalesce(input_count,0),identity_invalid=coalesce(identity_invalid_any,0)]
| sort 0 kind - last_seen client_ip server_ip server_port transport
| streamstats count AS kind_rank BY kind
| where kind="completion" OR kind_rank<=${cap}
| eval returned_count=if(kind="completion",min(input_count,${cap}),null()),capped=if(kind="completion",if(input_count>${cap},1,0),null())
| fields kind input_count returned_count capped identity_invalid scope client_ip server_ip server_port transport first_seen last_seen blocked client_service server_service client_service_state server_service_state client_kind server_kind client_endpoint_kind server_endpoint_kind client_identity_state server_identity_state client_name server_name`;
}

/** Same authority checks as the per-selection asset-history reader. */
export function assetAuthorities(
  config: SupplementalSourceConfiguration,
  scope: string,
): string[] {
  if (
    config.source !== "asset_history" ||
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified
  )
    throw new Error("Asset-history source is not active and schema-qualified.");
  const mapped = config.mappings
    .filter(
      (m) =>
        m.observer_kind === "asset_authority" &&
        m.scope === scope &&
        m.mapping_status === "verified",
    )
    .map((m) => literal(m.observer));
  if (
    !mapped.length ||
    mapped.length > 32 ||
    new Set(mapped).size !== mapped.length ||
    mapped.some((a) => !config.authorities.includes(a)) ||
    config.authorities.some((a) => !mapped.includes(a))
  )
    throw new Error("Asset-history authority mapping is missing or ambiguous.");
  return mapped.sort();
}

/** Latest revision of every scoped asset record overlapping the window. */
export function buildCmdbAssetSearch(
  config: SupplementalSourceConfiguration,
  scopeInput: string,
  windowInput: { start: number; end: number },
): string {
  const scope = checkedScope(scopeInput);
  const { start, end } = checkedWindow(windowInput);
  if (
    !config.indexes.length ||
    config.indexes.length > 16 ||
    config.indexes.some((index) => validateIndexName(index))
  )
    throw new Error("Asset-history index configuration is unavailable.");
  const authorities = assetAuthorities(config, scope);
  const scan = CMDB_LIMITS.assetScan;
  const cap = CMDB_LIMITS.assets;
  const indexes = config.indexes.map((i) => `index=${i}`).join(" OR ");
  const authority = authorities
    .map((a) => `asset_authority="${a}"`)
    .join(" OR ");
  return `search (${indexes}) sourcetype="adm:asset_history" schema_version=1 (${authority})
| head ${scan + 1}
| eval revision_number=tonumber(revision),valid_from_number=tonumber(valid_from),valid_to_number=tonumber(valid_to),snapshot_at_number=tonumber(snapshot_at)
| eval source_row_invalid=if(isnull(revision_number) OR revision_number<0 OR revision_number!=floor(revision_number) OR len(coalesce(record_id,""))=0 OR len(coalesce(asset_id,""))=0 OR len(coalesce(scope,""))=0 OR len(coalesce(ip,""))=0 OR isnull(valid_from_number) OR isnull(snapshot_at_number) OR NOT (validity_basis="source_interval" OR validity_basis="snapshot_current") OR (len(coalesce(valid_to,""))>0 AND (isnull(valid_to_number) OR valid_to_number<=valid_from_number)),1,0)
| eventstats count AS source_scan_count sum(source_row_invalid) AS source_scan_invalid_count
| eventstats max(revision_number) AS latest_revision BY asset_authority record_id
| eval revision_semantic=sha256(json_array(asset_authority,record_id,revision_number,asset_id,scope,ip,validity_basis,valid_from,valid_to))
| eventstats dc(revision_semantic) AS revision_variants BY asset_authority record_id revision_number
| eval revision_conflict=if(revision_variants>1,1,0)
| eval adm_eligible=if(source_row_invalid=0 AND revision_number=latest_revision AND scope="${scope}" AND ((validity_basis="source_interval" AND valid_from_number<${end} AND coalesce(valid_to_number,snapshot_at_number)>${start}) OR (validity_basis="snapshot_current" AND snapshot_at_number>=${start} AND snapshot_at_number<${end})),1,0)
| eventstats sum(adm_eligible) AS input_count
| eval kind=if(adm_eligible=1,"asset_record","asset_filtered")
| appendpipe [| stats count AS adm_n max(source_scan_count) AS source_scan_count max(source_scan_invalid_count) AS source_scan_invalid_count max(input_count) AS input_count | eval kind="completion",source_scan_count=coalesce(source_scan_count,0),source_scan_invalid_count=coalesce(source_scan_invalid_count,0),input_count=coalesce(input_count,0),source_scan_capped=if(source_scan_count>${scan},1,0)]
| where kind="completion" OR kind="asset_record"
| sort 0 kind ip asset_authority record_id
| streamstats count AS kind_rank BY kind
| where kind="completion" OR kind_rank<=${cap}
| eval returned_count=if(kind="completion",min(input_count,${cap}),null()),capped=if(kind="completion",if(input_count>${cap},1,0),null())
| fields kind input_count returned_count capped source_scan_count source_scan_invalid_count source_scan_capped asset_authority scope ip record_id revision revision_conflict asset_id asset_name validity_basis valid_from valid_to snapshot_at`;
}

/** Operator-maintained CSV lookup; inert until the qualification macro is 1. */
export function buildCmdbRelationshipSearch(scopeInput: string): string {
  const scope = checkedScope(scopeInput);
  const scan = CMDB_LIMITS.cmdbRelationships;
  return `| \`adm_cmdb_relationship_rows\`
| head ${scan + 1}
| eval kind="cmdb_relationship"
| eventstats count AS source_scan_count
| appendpipe [| stats count AS adm_n max(source_scan_count) AS source_scan_count | eval kind="completion",source_scan_count=coalesce(source_scan_count,0),source_scan_capped=if(source_scan_count>${scan},1,0)]
| eval qualified=\`adm_cmdb_relationships_schema_qualified\`
| where kind="completion" OR scope="${scope}"
| eventstats count(eval(kind="cmdb_relationship")) AS input_count
| sort 0 kind client_ip server_ip server_port transport relationship_id
| fields kind qualified source_scan_count source_scan_capped input_count authority relationship_id scope client_ip server_ip server_port transport relationship_type client_ci server_ci snapshot_at`;
}

const first = (value: unknown): unknown =>
  Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value;
const values = (value: unknown): string[] =>
  (Array.isArray(value) ? value : value === undefined ? [] : [value]).filter(
    (v): v is string => typeof v === "string" && v !== "",
  );

function text(value: unknown, max = 512): string | undefined {
  const v = first(value);
  if (v === undefined || v === null || v === "") return undefined;
  if (
    typeof v !== "string" ||
    v.length > max ||
    [...v].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw new Error("Invalid text field.");
  return v;
}
function required(value: unknown, name: string): string {
  const v = text(value);
  if (v === undefined) throw new Error(`Missing ${name}.`);
  return v;
}
function epoch(value: unknown, name: string, optional = false) {
  const v = first(value);
  if (v === undefined || v === null || v === "") {
    if (optional) return undefined;
    throw new Error(`Missing ${name}.`);
  }
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n) || n < 0 || n > MAX_TIME)
    throw new Error(`Invalid ${name}.`);
  return n;
}
function count(value: unknown): number {
  const v = first(value);
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("Invalid completion count.");
  return n;
}
const flag = (value: unknown) => {
  const v = first(value);
  if (v === 1 || v === "1") return true;
  if (v === 0 || v === "0" || v === undefined || v === null || v === "")
    return false;
  throw new Error("Invalid flag.");
};
function port(value: unknown): number | undefined {
  const v = first(value);
  if (v === undefined || v === null || v === "" || v === "-") return undefined;
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 65535)
    throw new Error("Invalid port.");
  return n;
}
function transportValue(value: unknown, optional: boolean) {
  const v = text(value, 16)?.toLowerCase();
  if (v === undefined) {
    if (optional) return undefined;
    throw new Error("Missing transport.");
  }
  if (!/^[a-z0-9-]{1,16}$/.test(v)) throw new Error("Invalid transport.");
  return v;
}

function completionRow(rows: readonly Row[]): Row | undefined {
  const completions = rows.filter((row) => row.kind === "completion");
  return completions.length === 1 ? completions[0] : undefined;
}

function serviceKey(value: unknown): AtlasServiceKey | undefined {
  const all = values(value);
  if (all.length !== 1) return undefined;
  const parsed: unknown = JSON.parse(all[0]);
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 4 ||
    parsed.some((part) => typeof part !== "string")
  )
    throw new Error("Invalid service key.");
  const [service, environment, cluster, namespace] = parsed as string[];
  return { service, environment, cluster, namespace };
}

function endpoint(row: Row, side: "client" | "server"): EndpointObservation {
  const states = values(row[`${side}_service_state`]);
  const service = serviceKey(row[`${side}_service`]);
  const serviceState: ServiceBindingState =
    states.length === 1 && service && states[0] === "bound"
      ? "bound"
      : states.includes("ambiguous") ||
          values(row[`${side}_service`]).length > 1 ||
          (states.includes("bound") && states.length > 1)
        ? "ambiguous"
        : states.includes("unbound")
          ? "unbound"
          : "not_workload";
  const identity = values(row[`${side}_identity_state`]);
  const kinds = values(row[`${side}_kind`]);
  const endpointKinds = values(row[`${side}_endpoint_kind`]);
  const names = values(row[`${side}_name`]);
  return {
    ...(kinds.length === 1 ? { kind: text(kinds[0], 64) } : {}),
    ...(endpointKinds.length === 1
      ? { endpointKind: text(endpointKinds[0], 64) }
      : {}),
    ...(names.length === 1 ? { name: text(names[0], 255) } : {}),
    identityState:
      identity.length === 1 && identity[0] === "resolved"
        ? kinds.length === 1
          ? "resolved"
          : "ambiguous"
        : identity.length > 1 || identity.includes("ambiguous")
          ? "ambiguous"
          : "none",
    ...(serviceState === "bound" && service ? { service } : {}),
    serviceState,
  };
}

export function parseObservedRelationships(
  rows: readonly Row[],
  scope: string,
): Parsed<ObservedRelationship> & { identityIncomplete: boolean } {
  const completion = completionRow(rows);
  const reasons: string[] = [];
  let rejected = 0;
  const records: ObservedRelationship[] = [];
  for (const row of rows) {
    if (row.kind !== "relationship") continue;
    try {
      if (required(row.scope, "scope") !== scope)
        throw new Error("Scope mismatch.");
      const firstSeen = epoch(row.first_seen, "first_seen")!;
      const lastSeen = epoch(row.last_seen, "last_seen")!;
      if (lastSeen < firstSeen) throw new Error("Out-of-order times.");
      records.push({
        scope,
        clientIp: normalizeIp(required(row.client_ip, "client IP")),
        serverIp: normalizeIp(required(row.server_ip, "server IP")),
        ...(port(row.server_port) === undefined
          ? {}
          : { serverPort: port(row.server_port) }),
        transport: transportValue(row.transport, false)!,
        firstSeen,
        lastSeen,
        blocked: flag(row.blocked),
        client: endpoint(row, "client"),
        server: endpoint(row, "server"),
      });
    } catch {
      rejected += 1;
    }
  }
  let inputCount = records.length + rejected;
  let returnedCount = records.length + rejected;
  let identityIncomplete = true;
  if (!completion) reasons.push("The search did not return a completion row.");
  else {
    try {
      inputCount = count(completion.input_count);
      returnedCount = count(completion.returned_count);
      if (flag(completion.capped))
        reasons.push(
          `More than ${CMDB_LIMITS.relationships.toLocaleString()} observed relationships; only the most recent are shown.`,
        );
      identityIncomplete = flag(completion.identity_invalid);
      if (returnedCount !== records.length + rejected)
        reasons.push("Returned rows do not match the completion count.");
    } catch {
      reasons.push("The completion row is malformed.");
    }
  }
  if (rejected)
    reasons.push(`${rejected} observed relationship rows were malformed.`);
  return {
    records,
    identityIncomplete,
    completeness: {
      state: reasons.length ? "incomplete" : "complete",
      reasons,
      inputCount,
      returnedCount,
      rejected,
    },
  };
}

export function parseCmdbAssets(
  rows: readonly Row[],
  scope: string,
  authorities: readonly string[],
): Parsed<CmdbAssetRecord> {
  const completion = completionRow(rows);
  const reasons: string[] = [];
  let rejected = 0;
  const byRecord = new Map<string, CmdbAssetRecord>();
  for (const row of rows) {
    if (row.kind !== "asset_record") continue;
    try {
      const authority = required(row.asset_authority, "authority");
      if (!authorities.includes(authority))
        throw new Error("Unconfigured authority.");
      if (required(row.scope, "scope") !== scope)
        throw new Error("Scope mismatch.");
      const validityBasis = required(row.validity_basis, "validity basis");
      if (
        validityBasis !== "source_interval" &&
        validityBasis !== "snapshot_current"
      )
        throw new Error("Invalid validity basis.");
      const validFrom = epoch(row.valid_from, "valid_from")!;
      const validTo = epoch(row.valid_to, "valid_to", true);
      const snapshotAt = epoch(row.snapshot_at, "snapshot_at")!;
      if (validTo !== undefined && validTo <= validFrom)
        throw new Error("Interval must be half-open.");
      const record: CmdbAssetRecord = {
        authority,
        scope,
        ip: normalizeIp(required(row.ip, "IP")),
        recordId: required(row.record_id, "record ID"),
        revision: count(row.revision),
        assetId: required(row.asset_id, "asset ID"),
        ...(text(row.asset_name) ? { assetName: text(row.asset_name) } : {}),
        validityBasis,
        validFrom,
        ...(validTo === undefined ? {} : { validTo }),
        snapshotAt,
        revisionConflict: flag(row.revision_conflict),
      };
      const key = JSON.stringify([
        authority,
        record.recordId,
        record.revision,
        record.assetId,
        record.ip,
      ]);
      const existing = byRecord.get(key);
      if (!existing || existing.snapshotAt < record.snapshotAt)
        byRecord.set(key, record);
    } catch {
      rejected += 1;
    }
  }
  let inputCount = byRecord.size + rejected;
  let returnedCount = inputCount;
  if (!completion) reasons.push("The search did not return a completion row.");
  else {
    try {
      inputCount = count(completion.input_count);
      returnedCount = count(completion.returned_count);
      if (flag(completion.source_scan_capped))
        reasons.push(
          `Asset history exceeded the ${CMDB_LIMITS.assetScan.toLocaleString()}-row scan cap.`,
        );
      if (count(completion.source_scan_invalid_count) > 0)
        reasons.push(
          `${count(completion.source_scan_invalid_count)} asset-history source rows were malformed.`,
        );
      if (flag(completion.capped))
        reasons.push(
          `More than ${CMDB_LIMITS.assets.toLocaleString()} asset records in scope.`,
        );
    } catch {
      reasons.push("The completion row is malformed.");
    }
  }
  if (rejected) reasons.push(`${rejected} asset records were rejected.`);
  return {
    records: [...byRecord.values()],
    completeness: {
      state: reasons.length ? "incomplete" : "complete",
      reasons,
      inputCount,
      returnedCount,
      rejected,
    },
  };
}

export function parseCmdbRelationships(
  rows: readonly Row[],
  scope: string,
): Parsed<CmdbRelationshipRecord> {
  const completion = completionRow(rows);
  if (!completion)
    return {
      records: [],
      completeness: {
        state: "incomplete",
        reasons: ["The search did not return a completion row."],
        inputCount: 0,
        returnedCount: 0,
        rejected: 0,
      },
    };
  if (!flag(completion.qualified))
    return {
      records: [],
      completeness: {
        state: "not_configured",
        reasons: [
          "The CMDB relationship lookup is not configured and qualified (adm_cmdb_relationships_schema_qualified=0).",
        ],
        inputCount: 0,
        returnedCount: 0,
        rejected: 0,
      },
    };
  const reasons: string[] = [];
  let rejected = 0;
  const records: CmdbRelationshipRecord[] = [];
  const ids = new Set<string>();
  for (const row of rows) {
    if (row.kind !== "cmdb_relationship") continue;
    try {
      const authority = literal(required(row.authority, "authority"));
      const relationshipId = required(row.relationship_id, "relationship ID");
      const key = JSON.stringify([authority, relationshipId]);
      if (ids.has(key)) throw new Error("Duplicate relationship ID.");
      ids.add(key);
      if (required(row.scope, "scope") !== scope)
        throw new Error("Scope mismatch.");
      const serverPort = port(row.server_port);
      const transport = transportValue(row.transport, true);
      const relationshipType = text(row.relationship_type, 128);
      const clientCi = text(row.client_ci, 255);
      const serverCi = text(row.server_ci, 255);
      const snapshotAt = epoch(row.snapshot_at, "snapshot_at", true);
      records.push({
        authority,
        relationshipId,
        scope,
        clientIp: normalizeIp(required(row.client_ip, "client IP")),
        serverIp: normalizeIp(required(row.server_ip, "server IP")),
        ...(serverPort === undefined ? {} : { serverPort }),
        ...(transport ? { transport } : {}),
        ...(relationshipType ? { relationshipType } : {}),
        ...(clientCi ? { clientCi } : {}),
        ...(serverCi ? { serverCi } : {}),
        ...(snapshotAt === undefined ? {} : { snapshotAt }),
      });
    } catch {
      rejected += 1;
    }
  }
  let inputCount = records.length + rejected;
  try {
    if (flag(completion.source_scan_capped))
      reasons.push(
        `The CMDB relationship lookup exceeds the ${CMDB_LIMITS.cmdbRelationships.toLocaleString()}-row cap.`,
      );
    inputCount = count(completion.input_count);
    if (inputCount !== records.length + rejected)
      reasons.push("Returned rows do not match the completion count.");
  } catch {
    reasons.push("The completion row is malformed.");
  }
  if (rejected)
    reasons.push(`${rejected} CMDB relationship rows were rejected.`);
  return {
    records,
    completeness: {
      state: reasons.length ? "incomplete" : "complete",
      reasons,
      inputCount,
      returnedCount: records.length + rejected,
      rejected,
    },
  };
}

export type EndpointStatus =
  "matched" | "not_in_cmdb" | "ambiguous" | "external" | "coverage_unknown";

export interface EndpointFinding {
  scope: string;
  ip: string;
  status: EndpointStatus;
  basis: string[];
  assetIds: string[];
  identity?: string;
  firstSeen: number;
  lastSeen: number;
  relationships: number;
  note: string;
}

export type RelationshipStatus =
  | "matched"
  | "not_observed_in_window"
  | "observed_not_in_cmdb"
  | "coverage_unknown";

export interface RelationshipFinding {
  scope: string;
  clientIp: string;
  serverIp: string;
  serverPort?: number;
  transport?: string;
  status: RelationshipStatus;
  relationshipIds: string[];
  relationshipType?: string;
  endpointCoverage: "both" | "client_only" | "server_only" | "neither";
  firstSeen?: number;
  lastSeen?: number;
  note: string;
}

export interface ReconciliationInput {
  scope: string;
  window: { start: number; end: number };
  observed: Parsed<ObservedRelationship>;
  assets: Parsed<CmdbAssetRecord>;
  relationships: Parsed<CmdbRelationshipRecord>;
}

export interface Reconciliation {
  scope: string;
  window: { start: number; end: number };
  endpoints: EndpointFinding[];
  relationships: RelationshipFinding[];
  endpointCounts: Record<EndpointStatus, number>;
  relationshipCounts: Record<RelationshipStatus, number>;
  sources: {
    observed: SourceCompleteness;
    assets: SourceCompleteness;
    relationships: SourceCompleteness;
  };
  caveats: string[];
}

export const ENDPOINT_STATUS_LABEL: Record<EndpointStatus, string> = {
  matched: "Matched",
  not_in_cmdb: "Not in CMDB",
  ambiguous: "Conflicting CMDB records",
  external: "External (no CMDB expected)",
  coverage_unknown: "CMDB coverage unknown",
};
export const RELATIONSHIP_STATUS_LABEL: Record<RelationshipStatus, string> = {
  matched: "Matched",
  not_observed_in_window: "Not observed in window",
  observed_not_in_cmdb: "Observed, not in CMDB",
  coverage_unknown: "Observation coverage unknown",
};

export const RECONCILIATION_CAVEATS = [
  "Observed traffic comes from Atlas conversation summaries in the selected scope and window; endpoints or paths outside collection coverage never appear.",
  "Not observed in window means no matching conversation was collected. It does not mean the relationship was removed or is absent.",
  "Not in CMDB requires complete asset history for the scope and window, and a complete relationship lookup when one is configured; otherwise the endpoint is reported as coverage unknown.",
  "Matching uses scoped IP addresses and, where the CMDB row specifies them, server port and transport. Names, hostnames and display labels are never matched.",
] as const;

const overlaps = (r: CmdbAssetRecord, start: number, end: number) =>
  r.validityBasis === "snapshot_current"
    ? r.snapshotAt >= start && r.snapshotAt < end
    : r.validFrom < end && (r.validTo ?? r.snapshotAt) > start;

const isPrivate = (ip: string) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
    ip,
  ) || /^(f[cd]|fe[89ab]|::1$)/i.test(ip);

export function reconcileCmdb(input: ReconciliationInput): Reconciliation {
  const { scope } = input;
  const { start, end } = checkedWindow(input.window);
  const observedComplete = input.observed.completeness.state === "complete";
  const assetState = input.assets.completeness.state;
  const relState = input.relationships.completeness.state;
  const cmdbConfigured = [assetState, relState].some(
    (s) => s !== "not_configured",
  );
  const cmdbComplete =
    assetState === "complete" &&
    (relState === "complete" || relState === "not_configured");

  const assetsByIp = new Map<string, CmdbAssetRecord[]>();
  for (const record of input.assets.records)
    if (overlaps(record, start, end))
      assetsByIp.set(record.ip, [...(assetsByIp.get(record.ip) ?? []), record]);
  const relIps = new Set(
    input.relationships.records.flatMap((r) => [r.clientIp, r.serverIp]),
  );

  interface Seen {
    ip: string;
    firstSeen: number;
    lastSeen: number;
    relationships: number;
    identities: Set<string>;
    external: boolean;
  }
  const seen = new Map<string, Seen>();
  const note = (
    ip: string,
    rel: ObservedRelationship,
    e: EndpointObservation,
  ) => {
    const current = seen.get(ip) ?? {
      ip,
      firstSeen: rel.firstSeen,
      lastSeen: rel.lastSeen,
      relationships: 0,
      identities: new Set<string>(),
      external: true,
    };
    current.firstSeen = Math.min(current.firstSeen, rel.firstSeen);
    current.lastSeen = Math.max(current.lastSeen, rel.lastSeen);
    current.relationships += 1;
    if (e.name || e.kind)
      current.identities.add(
        [e.kind, e.name].filter(Boolean).join(" ") || "identity",
      );
    current.external &&= e.endpointKind === "external" && !isPrivate(ip);
    seen.set(ip, current);
  };
  for (const rel of input.observed.records) {
    note(rel.clientIp, rel, rel.client);
    note(rel.serverIp, rel, rel.server);
  }

  const endpoints: EndpointFinding[] = [...seen.values()].map((entry) => {
    const records = assetsByIp.get(entry.ip) ?? [];
    const assetIds = [...new Set(records.map((r) => r.assetId))].sort();
    const basis = [
      ...(records.length ? ["asset_history"] : []),
      ...(relIps.has(entry.ip) ? ["cmdb_relationship_lookup"] : []),
    ];
    const conflict =
      records.some((r) => r.revisionConflict) || assetIds.length > 1;
    let status: EndpointStatus;
    let text: string;
    if (conflict) {
      status = "ambiguous";
      text = "Different asset IDs or a conflicting revision claim this IP.";
    } else if (basis.length) {
      status = "matched";
      text = `CMDB record from ${basis.join(" and ")}.`;
    } else if (entry.external) {
      status = "external";
      text =
        "Public address without an Atlas identity; CMDB records are not expected.";
    } else if (cmdbComplete) {
      status = "not_in_cmdb";
      text =
        "Observed talking in the window; no configured CMDB source has a record.";
    } else {
      status = "coverage_unknown";
      text =
        assetState === "not_configured"
          ? "Asset history is not configured for this scope, so a missing record is not conclusive."
          : cmdbConfigured
            ? "A configured CMDB source is incomplete, so a missing record is not conclusive."
            : "No CMDB source is configured for this scope.";
    }
    return {
      scope,
      ip: entry.ip,
      status,
      basis,
      assetIds,
      ...(entry.identities.size
        ? { identity: [...entry.identities].sort().join(", ") }
        : {}),
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      relationships: entry.relationships,
      note: text,
    };
  });
  endpoints.sort(
    (a, b) => a.status.localeCompare(b.status) || a.ip.localeCompare(b.ip),
  );

  const relationships: RelationshipFinding[] = [];
  const relEnabled = relState !== "not_configured";
  if (relEnabled) {
    const matchedObserved = new Set<ObservedRelationship>();
    const grouped = new Map<string, CmdbRelationshipRecord[]>();
    for (const record of input.relationships.records) {
      const key = JSON.stringify([
        record.clientIp,
        record.serverIp,
        record.serverPort ?? null,
        record.transport ?? null,
      ]);
      grouped.set(key, [...(grouped.get(key) ?? []), record]);
    }
    for (const group of grouped.values()) {
      const record = group[0];
      const matches = input.observed.records.filter(
        (o) =>
          o.clientIp === record.clientIp &&
          o.serverIp === record.serverIp &&
          (record.serverPort === undefined ||
            o.serverPort === record.serverPort) &&
          (record.transport === undefined || o.transport === record.transport),
      );
      matches.forEach((m) => matchedObserved.add(m));
      const clientSeen = seen.has(record.clientIp);
      const serverSeen = seen.has(record.serverIp);
      const endpointCoverage = clientSeen
        ? serverSeen
          ? "both"
          : "client_only"
        : serverSeen
          ? "server_only"
          : "neither";
      const types = [
        ...new Set(group.map((r) => r.relationshipType).filter(Boolean)),
      ] as string[];
      const status: RelationshipStatus = matches.length
        ? "matched"
        : observedComplete
          ? "not_observed_in_window"
          : "coverage_unknown";
      relationships.push({
        scope,
        clientIp: record.clientIp,
        serverIp: record.serverIp,
        ...(record.serverPort === undefined
          ? {}
          : { serverPort: record.serverPort }),
        ...(record.transport ? { transport: record.transport } : {}),
        status,
        relationshipIds: group
          .map((r) => `${r.authority}/${r.relationshipId}`)
          .sort(),
        ...(types.length ? { relationshipType: types.sort().join(", ") } : {}),
        endpointCoverage,
        ...(matches.length
          ? {
              firstSeen: Math.min(...matches.map((m) => m.firstSeen)),
              lastSeen: Math.max(...matches.map((m) => m.lastSeen)),
            }
          : {}),
        note:
          status === "matched"
            ? "Observed in the window."
            : status === "coverage_unknown"
              ? "Observed traffic is incomplete, so absence of a match is not conclusive."
              : endpointCoverage === "neither"
                ? "Not observed in window. Neither endpoint appeared in collected traffic; it may be outside collection coverage."
                : endpointCoverage === "both"
                  ? "Not observed in window. Both endpoints were seen talking to other peers."
                  : "Not observed in window. Only one endpoint appeared in collected traffic.",
      });
    }
    if (relState === "complete") {
      const unmatched = new Map<string, ObservedRelationship[]>();
      for (const o of input.observed.records) {
        if (matchedObserved.has(o)) continue;
        const key = JSON.stringify([
          o.clientIp,
          o.serverIp,
          o.serverPort ?? null,
          o.transport,
        ]);
        unmatched.set(key, [...(unmatched.get(key) ?? []), o]);
      }
      for (const group of unmatched.values()) {
        const o = group[0];
        relationships.push({
          scope,
          clientIp: o.clientIp,
          serverIp: o.serverIp,
          ...(o.serverPort === undefined ? {} : { serverPort: o.serverPort }),
          transport: o.transport,
          status: "observed_not_in_cmdb",
          relationshipIds: [],
          endpointCoverage: "both",
          firstSeen: Math.min(...group.map((g) => g.firstSeen)),
          lastSeen: Math.max(...group.map((g) => g.lastSeen)),
          note: "Observed in the window; the CMDB relationship lookup has no matching row.",
        });
      }
    }
  }
  relationships.sort(
    (a, b) =>
      a.status.localeCompare(b.status) ||
      a.clientIp.localeCompare(b.clientIp) ||
      a.serverIp.localeCompare(b.serverIp) ||
      (a.serverPort ?? -1) - (b.serverPort ?? -1),
  );

  const endpointCounts = {
    matched: 0,
    not_in_cmdb: 0,
    ambiguous: 0,
    external: 0,
    coverage_unknown: 0,
  };
  for (const e of endpoints) endpointCounts[e.status] += 1;
  const relationshipCounts = {
    matched: 0,
    not_observed_in_window: 0,
    observed_not_in_cmdb: 0,
    coverage_unknown: 0,
  };
  for (const r of relationships) relationshipCounts[r.status] += 1;
  const caveats: string[] = [...RECONCILIATION_CAVEATS];
  if (!relEnabled)
    caveats.push(
      "CMDB relationships are unavailable until the relationship lookup is configured and qualified.",
    );
  if (relState === "incomplete")
    caveats.push(
      "The CMDB relationship lookup is incomplete, so observed relationships are not classified as missing from the CMDB.",
    );
  return {
    scope,
    window: { start, end },
    endpoints,
    relationships,
    endpointCounts,
    relationshipCounts,
    sources: {
      observed: input.observed.completeness,
      assets: input.assets.completeness,
      relationships: input.relationships.completeness,
    },
    caveats,
  };
}

const utc = (epoch?: number) =>
  epoch === undefined
    ? ""
    : new Date(epoch * 1000).toISOString().replace(".000Z", "Z");

export function endpointFindingsCsv(rows: readonly EndpointFinding[]): string {
  return [
    csvRow([
      "status",
      "scope",
      "ip",
      "basis",
      "asset_ids",
      "atlas_identity",
      "first_seen_utc",
      "last_seen_utc",
      "observed_relationships",
      "note",
    ]),
    ...rows.map((r) =>
      csvRow([
        ENDPOINT_STATUS_LABEL[r.status],
        r.scope,
        r.ip,
        r.basis.join(" "),
        r.assetIds.join(" "),
        r.identity,
        utc(r.firstSeen),
        utc(r.lastSeen),
        r.relationships,
        r.note,
      ]),
    ),
  ].join("\r\n");
}

export function relationshipFindingsCsv(
  rows: readonly RelationshipFinding[],
): string {
  return [
    csvRow([
      "status",
      "scope",
      "client_ip",
      "server_ip",
      "server_port",
      "transport",
      "cmdb_relationship_ids",
      "relationship_type",
      "endpoint_coverage",
      "first_seen_utc",
      "last_seen_utc",
      "note",
    ]),
    ...rows.map((r) =>
      csvRow([
        RELATIONSHIP_STATUS_LABEL[r.status],
        r.scope,
        r.clientIp,
        r.serverIp,
        r.serverPort,
        r.transport,
        r.relationshipIds.join(" "),
        r.relationshipType,
        r.endpointCoverage,
        utc(r.firstSeen),
        utc(r.lastSeen),
        r.note,
      ]),
    ),
  ].join("\r\n");
}
