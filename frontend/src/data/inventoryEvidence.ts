import type { Row } from "../rows";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  EVIDENCE_LIMITS,
  literal,
  normalizeIp,
  routingScope,
  validateSelection,
  type EvidenceSelection,
} from "./evidence";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "./supplementalEvidence";
import { indexNames, validateIndexName } from "./deploymentHealth";
import type { SearchClient } from "./searchClient";

export type AssetHistoryValidityBasis = "source_interval" | "snapshot_current";
export type AssetHistoryAttribution =
  "historical_interval" | "current_snapshot_context" | "ambiguous";
export type AssetHistoryFreshness = "fresh" | "stale" | "unknown";

export interface AssetHistoryRecord {
  schemaVersion: 1;
  source: "asset_history";
  authority: string;
  scope: string;
  ip: string;
  recordId: string;
  revision: number;
  assetId: string;
  assetName?: string;
  serviceId?: string;
  serviceName?: string;
  environment?: string;
  ownerId?: string;
  ownerName?: string;
  networkId?: string;
  validityBasis: AssetHistoryValidityBasis;
  validFrom: number;
  validTo?: number;
  retiredAt?: number;
  snapshotId: string;
  snapshotAt: number;
  snapshotComplete: boolean;
  sourceFingerprint: string;
  index: string;
  indexedAt?: number;
  freshness: AssetHistoryFreshness;
  attribution: AssetHistoryAttribution;
  windowCoverage: "full" | "partial" | "point" | "context_only";
  conflict: boolean;
  conflictReason?: string;
}

export type AssetHistoryResult = SupplementalResult<AssetHistoryRecord>;

const SOURCE = "asset_history" as const;
const SOURCETYPE = "adm:asset_history";
const MAX_TEXT = 512;
const MAX_TIME = 253_402_300_799;

export const ASSET_HISTORY_COVERAGE = [
  "Asset history is supplemental inventory context. It does not create traffic, graph edges, or counters.",
  "The search reads the configured asset-history indexes from epoch zero through the later of the selected window end and capture time. It scans each verified authority across scopes and addresses, resolves revisions, then applies selected identity and time filters. Index retention, permissions, the 30-second search deadline, and the 10,001-row source-scan cap bound actual coverage.",
  "A timeout or source/result cap makes history incomplete; overlapping asset IDs remain ambiguous, and a current-only snapshot never attributes earlier traffic.",
  "Only source-provided half-open validity intervals support historical attribution. Snapshot freshness reports feed age; it does not extend an assignment interval or imply retirement.",
] as const;

function safeName(value: string): string {
  if (
    !value ||
    value.length > MAX_TEXT ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("Invalid asset-history text.");
  return value;
}

function text(
  value: unknown,
  field: string,
  optional = false,
): string | undefined {
  if (value === undefined || value === null || value === "") {
    if (optional) return undefined;
    throw new Error(`Missing asset-history ${field}.`);
  }
  if (typeof value !== "string")
    throw new Error(`Invalid asset-history ${field}.`);
  return safeName(value);
}

function finiteTime(
  value: unknown,
  field: string,
  optional = false,
): number | undefined {
  if (value === undefined || value === null || value === "") {
    if (optional) return undefined;
    throw new Error(`Missing asset-history ${field}.`);
  }
  const result = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(result) || result < 0 || result > MAX_TIME)
    throw new Error(`Invalid asset-history ${field}.`);
  return result;
}

function integer(value: unknown, field: string): number {
  const result = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(result) || result < 0)
    throw new Error(`Invalid asset-history ${field}.`);
  return result;
}

function boolean(value: unknown, field: string): boolean {
  if (value === true || value === 1 || value === "1" || value === "true")
    return true;
  if (value === false || value === 0 || value === "0" || value === "false")
    return false;
  throw new Error(`Invalid asset-history ${field}.`);
}

function indexes(config: SupplementalSourceConfiguration): string[] {
  if (!config.indexes.length || config.indexes.length > 16)
    throw new Error("Asset-history index configuration is unavailable.");
  if (config.indexes.some((value) => validateIndexName(value)))
    throw new Error("Invalid asset-history index configuration.");
  const canonical = indexNames({
    name: "asset_history",
    definition:
      config.indexes.length === 1
        ? `index=${config.indexes[0]}`
        : `(${config.indexes.map((name) => `index=${name}`).join(" OR ")})`,
  });
  if (canonical.length !== config.indexes.length)
    throw new Error("Invalid asset-history index configuration.");
  return canonical;
}

function verifiedAuthorities(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): string[] {
  if (
    config.source !== SOURCE ||
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60
  )
    throw new Error("Asset-history source is not active and schema-qualified.");
  const scope = routingScope(selection.scope);
  const mappings = config.mappings.filter(
    (mapping) =>
      mapping.observer_kind === "asset_authority" &&
      mapping.scope === scope &&
      mapping.mapping_status === "verified",
  );
  const authorities = mappings.map((mapping) => literal(mapping.observer));
  if (
    !authorities.length ||
    authorities.length > 32 ||
    new Set(authorities).size !== authorities.length ||
    authorities.some((authority) => !config.authorities.includes(authority)) ||
    config.authorities.some((authority) => !authorities.includes(authority))
  )
    throw new Error("Asset-history authority mapping is missing or ambiguous.");
  return authorities.sort();
}

/** Search only the configured history source and validated mapping/address literals. */
export function buildAssetHistorySearch(
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const selectedIndexes = indexes(config);
  const authorities = verifiedAuthorities(config, selection);
  const addresses = selection.identityAddresses ?? selection.addresses;
  if (
    !addresses.length ||
    addresses.length > 16 ||
    addresses.some((address) => normalizeIp(address) !== address)
  )
    throw new Error("Narrow the asset-history address selection.");
  const indexSelector = selectedIndexes
    .map((index) => `index=${index}`)
    .join(" OR ");
  const authoritySelector = authorities
    .map((authority) => `asset_authority="${authority}"`)
    .join(" OR ");
  const scope = routingScope(selection.scope);
  const start = selection.window.start;
  const end = selection.window.end;
  const scopeLiteral = literal(scope);
  const addressPredicate = addresses
    .map((address) => `ip="${address}"`)
    .join(" OR ");
  const eligible = `(scope="${scopeLiteral}" AND (${addressPredicate}) AND ((validity_basis="source_interval" AND tonumber(valid_from)<${end} AND ((isnotnull(tonumber(valid_to)) AND tonumber(valid_to)>${start}) OR (isnull(tonumber(valid_to)) AND tonumber(snapshot_at)>${start}))) OR (validity_basis="snapshot_current" AND tonumber(snapshot_at)>=${start} AND tonumber(snapshot_at)<${end})))`;
  return `search (${indexSelector}) sourcetype="${SOURCETYPE}" schema_version=1 (${authoritySelector})
| head ${EVIDENCE_LIMITS.input + 1}
| eval revision_number=tonumber(revision),valid_from_number=tonumber(valid_from),valid_to_number=tonumber(valid_to),snapshot_at_number=tonumber(snapshot_at),retired_at_number=tonumber(retired_at)
| eval source_row_invalid=if(isnull(revision_number) OR revision_number<0 OR revision_number>9007199254740991 OR revision_number!=floor(revision_number) OR isnull(record_id) OR len(coalesce(record_id,""))=0 OR isnull(asset_id) OR len(coalesce(asset_id,""))=0 OR isnull(scope) OR len(coalesce(scope,""))=0 OR isnull(ip) OR len(coalesce(ip,""))=0 OR isnull(valid_from_number) OR valid_from_number<0 OR valid_from_number>253402300799 OR isnull(snapshot_at_number) OR snapshot_at_number<0 OR snapshot_at_number>253402300799 OR isnull(validity_basis) OR NOT (validity_basis="source_interval" OR validity_basis="snapshot_current") OR (validity_basis="source_interval" AND (snapshot_at_number<valid_from_number OR (len(coalesce(valid_to,""))>0 AND (isnull(valid_to_number) OR valid_to_number<=valid_from_number OR valid_to_number>253402300799 OR valid_to_number<0)) OR (len(coalesce(retired_at,""))>0 AND (isnull(retired_at_number) OR isnull(valid_to_number) OR retired_at_number!=valid_to_number)))) OR (validity_basis="snapshot_current" AND (valid_from_number!=snapshot_at_number OR len(coalesce(valid_to,""))>0 OR len(coalesce(retired_at,""))>0)),1,0)
| eventstats count AS source_scan_count sum(source_row_invalid) AS source_scan_invalid_count
| eval source_scan_capped=if(source_scan_count>${EVIDENCE_LIMITS.input},1,0)
| eventstats max(revision_number) AS latest_revision BY asset_authority record_id
| eval revision_semantic=sha256(json_array(asset_authority,record_id,revision_number,asset_id,asset_name,service_id,service_name,environment,owner_id,owner_name,network_id,scope,ip,validity_basis,valid_from,valid_to,retired_at))
| eventstats values(revision_semantic) AS revision_semantics BY asset_authority record_id revision_number
| eval revision_conflict=if(mvcount(revision_semantics)>1,1,0)
| eval __latest=if(revision_number=latest_revision,1,0)
| eval __eligible=if(__latest=1 AND ${eligible},1,0)
| eventstats sum(__eligible) AS input_count
| eval kind=if(__eligible=1,"supplemental_record","supplemental_filtered")
| appendpipe [| stats max(source_scan_count) AS source_scan_count max(source_scan_invalid_count) AS source_scan_invalid_count max(source_scan_capped) AS source_scan_capped max(input_count) AS input_count | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),returned_count=min(coalesce(input_count,0),${EVIDENCE_LIMITS.records}),input_capped=if(coalesce(input_count,0)>${EVIDENCE_LIMITS.input},1,0),source_scan_count=coalesce(source_scan_count,0),source_scan_invalid_count=coalesce(source_scan_invalid_count,0),source_scan_capped=coalesce(source_scan_capped,0),oversized=0]
| eval indexed_at=_indextime,record_fingerprint=coalesce(record_fingerprint,sha256(json_array(asset_authority,snapshot_id,record_id,revision,asset_id,scope,ip,valid_from,valid_to,validity_basis)))
| where kind="supplemental_completion" OR kind="supplemental_record"
| sort 0 kind - _time record_fingerprint
| streamstats count AS kind_rank BY kind
| where kind="supplemental_completion" OR kind_rank<=${EVIDENCE_LIMITS.records}
| fields kind schema_version input_count returned_count input_capped source_scan_count source_scan_invalid_count source_scan_capped oversized index _time indexed_at asset_authority scope ip record_id revision revision_conflict asset_id asset_name service_id service_name environment owner_id owner_name network_id validity_basis valid_from valid_to retired_at snapshot_id snapshot_at snapshot_complete record_fingerprint`;
}

interface Candidate {
  record: AssetHistoryRecord;
  semanticFingerprint: string;
}

function semanticFingerprint(row: AssetHistoryRecord): string {
  return JSON.stringify({
    authority: row.authority,
    scope: row.scope,
    ip: row.ip,
    recordId: row.recordId,
    revision: row.revision,
    assetId: row.assetId,
    assetName: row.assetName,
    serviceId: row.serviceId,
    serviceName: row.serviceName,
    environment: row.environment,
    ownerId: row.ownerId,
    ownerName: row.ownerName,
    networkId: row.networkId,
    validityBasis: row.validityBasis,
    validFrom: row.validFrom,
    validTo: row.validTo,
    retiredAt: row.retiredAt,
  });
}

function contradictoryClaims(
  a: AssetHistoryRecord,
  b: AssetHistoryRecord,
): boolean {
  if (a.assetId !== b.assetId) return true;
  return [
    a.ownerId === undefined ||
      b.ownerId === undefined ||
      a.ownerId === b.ownerId,
    a.environment === undefined ||
      b.environment === undefined ||
      a.environment === b.environment,
    a.networkId === undefined ||
      b.networkId === undefined ||
      a.networkId === b.networkId,
    a.serviceId === undefined ||
      b.serviceId === undefined ||
      a.serviceId === b.serviceId,
  ].some((compatible) => !compatible);
}

function normalizeRow(
  row: Row,
  config: SupplementalSourceConfiguration,
  authorities: readonly string[],
): Candidate {
  if (row.schema_version !== 1 && row.schema_version !== "1")
    throw new Error("Unsupported asset-history schema version.");
  const authority = text(row.asset_authority, "authority")!;
  if (
    !config.authorities.includes(authority) ||
    !authorities.includes(authority)
  )
    throw new Error("Unconfigured asset-history authority.");
  const scope = routingScope(text(row.scope, "scope")!);
  const ip = normalizeIp(text(row.ip, "IP address")!);
  const recordId = text(row.record_id, "record ID")!;
  const revision = integer(row.revision, "revision");
  const assetId = text(row.asset_id, "asset ID")!;
  const assetName = text(row.asset_name, "asset name", true);
  const serviceId = text(row.service_id, "service ID", true);
  const serviceName = text(row.service_name, "service name", true);
  const environment = text(row.environment, "environment", true);
  const ownerId = text(row.owner_id, "owner ID", true);
  const ownerName = text(row.owner_name, "owner name", true);
  const networkId = text(row.network_id, "network ID", true);
  if (serviceName && !serviceId)
    throw new Error("Service name has no stable service ID.");
  if (ownerName && !ownerId)
    throw new Error("Owner name has no stable owner ID.");
  const validityBasis = text(row.validity_basis, "validity basis")!;
  if (
    validityBasis !== "source_interval" &&
    validityBasis !== "snapshot_current"
  )
    throw new Error("Invalid asset-history validity basis.");
  const snapshotId = text(row.snapshot_id, "snapshot ID")!;
  const snapshotAt = finiteTime(row.snapshot_at, "snapshot time")!;
  const snapshotComplete = boolean(
    row.snapshot_complete,
    "snapshot completeness",
  );
  const revisionConflict = boolean(row.revision_conflict, "revision conflict");
  const validFrom = finiteTime(row.valid_from, "valid_from")!;
  const rowTime = finiteTime(row._time, "indexed event time")!;
  const validTo = finiteTime(row.valid_to, "valid_to", true);
  const retiredAt = finiteTime(row.retired_at, "retired_at", true);
  if (Math.abs(rowTime - validFrom) > 0.001)
    throw new Error("Indexed asset-history time does not match valid_from.");
  if (validityBasis === "source_interval") {
    if (validTo !== undefined && validTo <= validFrom)
      throw new Error("Asset-history intervals must be half-open [from,to).");
    if (snapshotAt < validFrom)
      throw new Error("An interval cannot be observed before valid_from.");
    if (retiredAt !== undefined && validTo !== retiredAt)
      throw new Error("Retirement must equal the explicit exclusive valid_to.");
  } else if (
    validFrom !== snapshotAt ||
    validTo !== undefined ||
    retiredAt !== undefined
  ) {
    throw new Error("Current snapshots cannot claim a historical interval.");
  }
  const sourceFingerprint = text(row.record_fingerprint, "source fingerprint")!;
  if (!/^[a-f0-9]{64}$/.test(sourceFingerprint))
    throw new Error("Invalid asset-history source fingerprint.");
  const index = text(row.index, "index")!;
  if (!config.indexes.includes(index))
    throw new Error("Asset-history index mismatch.");
  const indexedAt = finiteTime(row.indexed_at, "index time", true);
  const capturedAt = Date.now() / 1000;
  const freshness: AssetHistoryFreshness =
    snapshotAt > capturedAt + 300
      ? "unknown"
      : capturedAt - snapshotAt <= config.staleAfterSeconds
        ? "fresh"
        : "stale";
  const attribution: AssetHistoryAttribution = revisionConflict
    ? "ambiguous"
    : validityBasis === "snapshot_current"
      ? "current_snapshot_context"
      : "historical_interval";
  const record: AssetHistoryRecord = {
    schemaVersion: 1,
    source: SOURCE,
    authority,
    scope,
    ip,
    recordId,
    revision,
    assetId,
    ...(assetName ? { assetName } : {}),
    ...(serviceId ? { serviceId } : {}),
    ...(serviceName ? { serviceName } : {}),
    ...(environment ? { environment } : {}),
    ...(ownerId ? { ownerId } : {}),
    ...(ownerName ? { ownerName } : {}),
    ...(networkId ? { networkId } : {}),
    validityBasis,
    validFrom,
    ...(validTo === undefined ? {} : { validTo }),
    ...(retiredAt === undefined ? {} : { retiredAt }),
    snapshotId,
    snapshotAt,
    snapshotComplete,
    sourceFingerprint,
    index,
    ...(indexedAt === undefined ? {} : { indexedAt }),
    freshness,
    attribution,
    windowCoverage: "context_only",
    conflict: revisionConflict,
    ...(revisionConflict
      ? {
          conflictReason:
            "The same source record revision contains conflicting asset history.",
        }
      : {}),
  };
  return { record, semanticFingerprint: semanticFingerprint(record) };
}

function eligibleForSelection(
  record: AssetHistoryRecord,
  selection: EvidenceSelection,
): boolean {
  const addresses = selection.identityAddresses ?? selection.addresses;
  if (record.scope !== selection.scope || !addresses.includes(record.ip))
    return false;
  if (record.validityBasis === "snapshot_current")
    return (
      record.snapshotAt >= selection.window.start &&
      record.snapshotAt < selection.window.end
    );
  const observedEnd = record.validTo ?? record.snapshotAt;
  return (
    record.validFrom < selection.window.end &&
    observedEnd > selection.window.start
  );
}

function setWindowCoverage(
  record: AssetHistoryRecord,
  selection: EvidenceSelection,
): void {
  if (record.validityBasis === "snapshot_current") {
    record.windowCoverage = "point";
    return;
  }
  const observedEnd = record.validTo ?? record.snapshotAt;
  record.windowCoverage =
    record.validFrom <= selection.window.start &&
    observedEnd >= selection.window.end
      ? "full"
      : "partial";
}

function conflicts(
  candidates: Candidate[],
  selection: EvidenceSelection,
): number {
  let conflictCount = 0;
  for (let left = 0; left < candidates.length; left += 1) {
    const a = candidates[left].record;
    for (let right = left + 1; right < candidates.length; right += 1) {
      const b = candidates[right].record;
      if (a.scope !== b.scope || a.ip !== b.ip || !contradictoryClaims(a, b))
        continue;
      const reason =
        a.assetId !== b.assetId
          ? "Different asset IDs have overlapping claims for this scoped IP."
          : "The same asset has incompatible owner, service, environment, or network claims at the same time.";
      const aStart = a.validFrom;
      const bStart = b.validFrom;
      if (a.validityBasis === "snapshot_current") {
        const point = a.snapshotAt;
        const bEnd = b.validTo ?? b.snapshotAt;
        const overlaps =
          b.validityBasis === "snapshot_current"
            ? point === b.snapshotAt
            : bStart <= point && point < bEnd;
        if (
          overlaps &&
          point >= selection.window.start &&
          point < selection.window.end
        ) {
          a.conflict = true;
          b.conflict = true;
          a.conflictReason = b.conflictReason = reason;
          a.attribution = b.attribution = "ambiguous";
          conflictCount += 1;
        }
      } else if (b.validityBasis === "snapshot_current") {
        const point = b.snapshotAt;
        const aEnd = a.validTo ?? a.snapshotAt;
        if (
          aStart <= point &&
          point < aEnd &&
          point >= selection.window.start &&
          point < selection.window.end
        ) {
          a.conflict = true;
          b.conflict = true;
          a.conflictReason = b.conflictReason = reason;
          a.attribution = b.attribution = "ambiguous";
          conflictCount += 1;
        }
      } else {
        const aEnd = a.validTo ?? a.snapshotAt;
        const bEnd = b.validTo ?? b.snapshotAt;
        const start = Math.max(aStart, bStart, selection.window.start);
        const end = Math.min(aEnd, bEnd, selection.window.end);
        if (start < end) {
          a.conflict = true;
          b.conflict = true;
          a.attribution = b.attribution = "ambiguous";
          a.conflictReason = b.conflictReason = reason;
          conflictCount += 1;
        }
      }
    }
  }
  return conflictCount;
}

/** Normalize only rows admitted by the shared completion envelope. */
export function normalizeAssetHistoryEvidence(
  rows: readonly Row[],
  selection: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: AssetHistoryRecord[]; rejected: number } {
  const authorities = verifiedAuthorities(config, selection);
  const candidates: Candidate[] = [];
  let rejected = 0;
  for (const row of rows) {
    try {
      candidates.push(normalizeRow(row, config, authorities));
    } catch {
      rejected += 1;
    }
  }
  // A source revision is the only permitted way to supersede an earlier copy
  // of the same immutable history record. Equal-revision disagreements remain
  // visible as conflicts instead of silently choosing whichever row arrived last.
  const byRecord = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const key = `${candidate.record.authority}\u0000${candidate.record.recordId}`;
    byRecord.set(key, [...(byRecord.get(key) ?? []), candidate]);
  }
  const admitted: Candidate[] = [];
  for (const group of byRecord.values()) {
    const highest = Math.max(
      ...group.map((candidate) => candidate.record.revision),
    );
    const newest = group.filter(
      (candidate) => candidate.record.revision === highest,
    );
    const semantic = new Set(
      newest.map((candidate) => candidate.semanticFingerprint),
    );
    if (semantic.size > 1) {
      newest.forEach((candidate) => {
        candidate.record.attribution = "ambiguous";
        candidate.record.conflict = true;
        candidate.record.conflictReason =
          "The same source record revision contains conflicting asset history.";
      });
      admitted.push(...newest);
      continue;
    }
    newest.sort((a, b) => b.record.snapshotAt - a.record.snapshotAt);
    admitted.push(newest[0]);
  }
  const eligible = admitted.filter((candidate) =>
    eligibleForSelection(candidate.record, selection),
  );
  eligible.forEach((candidate) =>
    setWindowCoverage(candidate.record, selection),
  );
  conflicts(eligible, selection);
  const records = eligible.map((candidate) => candidate.record);
  records.sort(
    (a, b) =>
      a.ip.localeCompare(b.ip) ||
      a.validFrom - b.validFrom ||
      a.authority.localeCompare(b.authority) ||
      a.assetId.localeCompare(b.assetId),
  );
  if (records.length > EVIDENCE_LIMITS.records)
    throw new Error("Asset-history result exceeds the evidence record cap.");
  return { records, rejected };
}

export function loadAssetHistoryEvidence(
  client: SearchClient,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<AssetHistoryResult> {
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    SOURCE,
    buildAssetHistorySearch,
    normalizeAssetHistoryEvidence,
    configurationClient,
    false,
    (value) => ({
      start: 0,
      end: Math.floor(Math.max(value.window.end, Date.now() / 1000)),
    }),
    ASSET_HISTORY_COVERAGE,
  );
}
