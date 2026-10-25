import type { Row } from "../rows";
import {
  configuredHttpsOrigin,
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  EVIDENCE_LIMITS,
  isObject,
  literal,
  normalizeIp,
  routingScope,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "./evidence";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "./supplementalEvidence";
import { indexNames } from "./deploymentHealth";
import type { SearchClient } from "./searchClient";

export const APPDYNAMICS_SCHEMA = "application_atlas.appdynamics_inventory.v1";
export const APPDYNAMICS_SOURCETYPE = "adm:appdynamics_inventory";
const SOURCE = "appdynamics_inventory" as const;
const OBSERVER_KIND = "appd_controller";
const MAX_SNAPSHOT_AGE_SECONDS = 30 * 24 * 60 * 60;

export const APPDYNAMICS_COVERAGE = [
  "AppDynamics contributes a current Controller Application Model snapshot. Its node IPs are point-in-time context; they do not establish who owned an address earlier in the selected traffic interval or imply retirement.",
  "Application, tier, node and backend identifiers are Controller-local identities scoped by the configured Controller authority. Names are labels, not identities. A shared IP can match multiple distinct nodes.",
  "Backends are modeled candidates. Only positive association IDs verified within this same complete snapshot are shown as Controller-reported node associations; neither backend presence nor an endpoint candidate proves observed traffic or a selected runtime destination.",
  "Snapshots are admitted only when the indexed record fingerprints, snapshot manifest count, completion flag and latest-snapshot identity agree. A 10,001-row source scan or a 64-row focused result cap suppresses associations.",
  "The Controller has no documented stable application, tier, node or backend UI deep-link contract in the checked 26.10 documentation. The configured Controller origin is the only link; use the displayed IDs to locate objects in its UI. This source does not apply a historical time filter.",
] as const;

export interface AppDynamicsNodeContext {
  applicationId: string;
  applicationName: string;
  tierId: string;
  tierName: string;
  nodeId: string;
  nodeName: string;
  machineName?: string;
  addresses: string[];
  matchedAddresses: string[];
}

export interface AppDynamicsEndpointCandidate {
  property: string;
  kind: "ip" | "hostname_unresolved" | "port";
  value: string | number;
  port?: number;
  matchesSelection: boolean;
}

export interface AppDynamicsBackendCandidate {
  applicationId: string;
  applicationName: string;
  backendId: string;
  name: string;
  exitPointType?: string;
  associationStatus:
    "verified_node" | "application_scope_only" | "unverified_reported_ids";
  tierId?: string;
  nodeId?: string;
  associatedWithMatchedNode: boolean;
  endpointCandidates: AppDynamicsEndpointCandidate[];
}

export interface AppDynamicsInventoryContext {
  authority: string;
  scope: string;
  snapshotId: string;
  snapshotAt: number;
  collectionStartedAt: number;
  collectionCompletedAt: number;
  collectionSkewSeconds: number;
  expectedRecordCount: number;
  indexedRecordCount: number;
  controllerOrigin?: string;
  nodes: AppDynamicsNodeContext[];
  backends: AppDynamicsBackendCandidate[];
}

export type AppDynamicsEvidenceResult =
  SupplementalResult<AppDynamicsInventoryContext>;

function checkedIndexes(config: SupplementalSourceConfiguration): string[] {
  if (
    config.source !== SOURCE ||
    !Array.isArray(config.indexes) ||
    !config.indexes.length ||
    config.indexes.length > 16
  )
    throw new Error("AppDynamics index configuration is unavailable.");
  const definition = config.indexes
    .map((index) => `index=${index}`)
    .join(" OR ");
  const indexes = indexNames({
    name: "adm_index_appdynamics_inventory",
    definition: indexesDefinition(definition, config.indexes.length),
  });
  if (
    indexes.length !== config.indexes.length ||
    new Set(indexes).size !== indexes.length
  )
    throw new Error("AppDynamics index configuration is invalid.");
  return indexes;
}

function indexesDefinition(definition: string, count: number): string {
  return count === 1 ? definition : `(${definition})`;
}

function verifiedMappings(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): SupplementalSourceConfiguration["mappings"] {
  if (
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > MAX_SNAPSHOT_AGE_SECONDS ||
    !Array.isArray(config.authorities) ||
    !config.authorities.length ||
    config.authorities.length > 32 ||
    !Array.isArray(config.mappings)
  )
    throw new Error("AppDynamics source is not active and schema-qualified.");
  const mappings = config.mappings.filter(
    (mapping) =>
      mapping.observer_kind === OBSERVER_KIND &&
      mapping.scope === routingScope(selection.scope) &&
      mapping.mapping_status === "verified",
  );
  if (
    mappings.length !== config.authorities.length ||
    new Set(mappings.map((mapping) => mapping.observer)).size !==
      config.authorities.length ||
    config.authorities.some(
      (authority) =>
        !mappings.some((mapping) => mapping.observer === authority),
    )
  )
    throw new Error("AppDynamics Controller authority mapping is ambiguous.");
  mappings.forEach((mapping) => literal(mapping.observer));
  mappings.forEach((mapping) => {
    if (mapping.controller_origin !== undefined)
      configuredHttpsOrigin(mapping.controller_origin);
  });
  return mappings;
}

/** Bound the index time scan to the configured current-snapshot freshness age. */
export function appDynamicsSearchWindow(
  selection: EvidenceSelection,
  source: SupplementalSourceConfiguration,
): EvidenceWindow {
  validateSelection(selection);
  if (
    !Number.isSafeInteger(source.staleAfterSeconds) ||
    source.staleAfterSeconds < 60 ||
    source.staleAfterSeconds > MAX_SNAPSHOT_AGE_SECONDS
  )
    throw new Error("AppDynamics snapshot freshness setting is invalid.");
  const end = Math.floor(Date.now() / 1000) + 60;
  return {
    start: Math.max(0, end - 60 - source.staleAfterSeconds),
    end,
  };
}

function regexEscape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function nodeAddressPattern(selection: EvidenceSelection): string {
  const addresses = selection.addresses.map(normalizeIp);
  if (!addresses.length || addresses.length > EVIDENCE_LIMITS.addresses)
    throw new Error("Narrow the AppDynamics address selection.");
  return `^(${[...new Set(addresses)].map(regexEscape).join("|")})$`;
}

/** Search complete current snapshots, then return only exact-IP node context. */
export function buildAppDynamicsSearch(
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const indexes = checkedIndexes(config);
  const mappings = verifiedMappings(config, selection);
  const indexClause = indexes.map((index) => `index=${index}`).join(" OR ");
  const authorityClause = mappings
    .map((mapping) => `controller_authority="${literal(mapping.observer)}"`)
    .join(" OR ");
  const selectedNodePattern = nodeAddressPattern(selection);
  const scope = literal(routingScope(selection.scope), 253);
  const sourceScanLimit = EVIDENCE_LIMITS.input + 1;
  const outputLimit = EVIDENCE_LIMITS.records;
  return `search (${indexClause}) sourcetype="${APPDYNAMICS_SOURCETYPE}" source="${SOURCE}" schema="${APPDYNAMICS_SCHEMA}" schema_version=1 (${authorityClause})
| spath input=_raw path=record_counts.total_records output=declared_record_count
| spath input=_raw path=ip_addresses{}.ip output=appd_node_ip_values
| eval snapshot_at_number=tonumber(snapshot_at),started_at_number=tonumber(collection_started_at),completed_at_number=tonumber(collection_completed_at),skew_number=tonumber(collection_skew_seconds),record_fingerprint_valid=if(match(record_fingerprint,"^[0-9a-f]{64}$"),1,0),complete_flag=if(snapshot_complete="true" OR snapshot_complete="1" OR snapshot_complete=1,1,0),source_row_oversized=if(len(_raw)>${EVIDENCE_LIMITS.recordBytes},1,0),source_row_invalid=if(isnull(snapshot_id) OR len(snapshot_id)>128 OR record_fingerprint_valid=0 OR isnull(snapshot_at_number) OR snapshot_at_number<0 OR isnull(tonumber(observed_at)) OR complete_flag=0 OR identity_basis!="controller_application_model_ids" OR NOT (record_type="snapshot" OR record_type="application" OR record_type="tier" OR record_type="node" OR record_type="backend") OR isnull(record_id) OR source_row_oversized=1,1,0)
| where scope="${scope}" AND snapshot_at_number>=${Math.max(0, Math.floor(Date.now() / 1000) - config.staleAfterSeconds)} AND snapshot_at_number<${Math.floor(Date.now() / 1000) + 60}
| head ${sourceScanLimit}
| eventstats count AS source_scan_count sum(source_row_invalid) AS source_row_invalid_count
| eval endpoint_node_match=if(record_type="node" AND mvfind(appd_node_ip_values,"${selectedNodePattern}")>=0,1,0),selected_app_id=if(endpoint_node_match=1,tostring(application_id),null()),selected_app_tier=if(endpoint_node_match=1,tostring(application_id).":".tostring(tier_id),null())
| eventstats values(selected_app_id) AS selected_app_ids values(selected_app_tier) AS selected_app_tiers BY controller_authority snapshot_id
| eventstats dc(_raw) AS fingerprint_variant_count BY controller_authority snapshot_id record_fingerprint
| eventstats dc(record_fingerprint) AS capture_record_count dc(record_id) AS capture_id_count dc(eval(if(record_type="snapshot",record_fingerprint,null()))) AS snapshot_record_count max(eval(if(record_type="snapshot",tonumber(declared_record_count),null()))) AS expected_record_count min(complete_flag) AS capture_complete min(snapshot_at_number) AS min_snapshot_at max(snapshot_at_number) AS max_snapshot_at min(started_at_number) AS min_started_at max(started_at_number) AS max_started_at min(completed_at_number) AS min_completed_at max(completed_at_number) AS max_completed_at min(skew_number) AS min_skew max(skew_number) AS max_skew max(fingerprint_variant_count) AS max_fingerprint_variants BY controller_authority snapshot_id
| eval capture_valid=if(snapshot_record_count=1 AND capture_record_count=expected_record_count AND capture_id_count=capture_record_count AND expected_record_count>0 AND capture_complete=1 AND max_fingerprint_variants=1 AND min_snapshot_at=max_snapshot_at AND min_started_at=max_started_at AND min_completed_at=max_completed_at AND min_skew=max_skew AND max_completed_at>=min_started_at AND abs((max_completed_at-min_started_at)-max_skew)<=1,1,0)
| eventstats max(snapshot_at_number) AS latest_snapshot_at BY controller_authority
| eval is_latest=if(snapshot_at_number=latest_snapshot_at,1,0)
| eventstats dc(eval(if(is_latest=1,snapshot_id,null()))) AS latest_snapshot_count BY controller_authority
| eval latest_valid=if(is_latest=1 AND latest_snapshot_count=1 AND capture_valid=1,1,0)
| eventstats max(eval(if(is_latest=1 AND (latest_snapshot_count!=1 OR capture_valid=0),1,0))) AS latest_capture_invalid
| eval source_scan_invalid_count=source_row_invalid_count+coalesce(latest_capture_invalid,0)
| eval appdynamics_relevant=case(is_latest=1 AND latest_snapshot_count=1 AND record_type="snapshot",1,latest_valid=1 AND record_type="application" AND mvfind(selected_app_ids,"^".tostring(application_id)."$")>=0,1,latest_valid=1 AND record_type="tier" AND mvfind(selected_app_tiers,"^".tostring(application_id).":".tostring(tier_id)."$")>=0,1,latest_valid=1 AND record_type="node" AND endpoint_node_match=1,1,latest_valid=1 AND record_type="backend" AND mvfind(selected_app_ids,"^".tostring(application_id)."$")>=0,1,true(),0)
| eval appdynamics_record_invalid=if(latest_valid=1 AND appdynamics_relevant=1 AND (isnull(record_type) OR isnull(record_id) OR record_type!="snapshot" AND isnull(record_fingerprint)),1,0)
| eventstats sum(appdynamics_relevant) AS input_count sum(appdynamics_record_invalid) AS focused_invalid_count
| eval kind=if(appdynamics_relevant=1,"supplemental_record","supplemental_filtered"),oversized=if(len(_raw)>${EVIDENCE_LIMITS.recordBytes},1,0)
| eval _raw=if(oversized=1,"{}",json_object("schema_version",schema_version,"schema",schema,"source","${SOURCE}","controller_authority",controller_authority,"scope",scope,"identity_basis",identity_basis,"snapshot_id",snapshot_id,"snapshot_at",snapshot_at,"collection_started_at",collection_started_at,"collection_completed_at",collection_completed_at,"collection_skew_seconds",collection_skew_seconds,"snapshot_complete",snapshot_complete,"record_type",record_type,"record_id",record_id,"record_fingerprint",record_fingerprint,"observed_at",observed_at,"application_id",application_id,"application_name",application_name,"tier_id",tier_id,"reported_tier_id",reported_tier_id,"verified_tier_id",verified_tier_id,"verified_node_id",verified_node_id,"tier_name",tier_name,"tier_type",tier_type,"agent_type",agent_type,"reported_node_count",reported_node_count,"node_id",node_id,"node_name",node_name,"machine_name",machine_name,"ip_addresses",json_extract(_raw,"ip_addresses"),"backend_id",backend_id,"backend_name",backend_name,"exit_point_type",exit_point_type,"association_status",association_status,"reported_application_component_node_id",reported_application_component_node_id,"endpoint_candidates",json_extract(_raw,"endpoint_candidates"),"expected_record_count",expected_record_count,"capture_record_count",capture_record_count,"capture_id_count",capture_id_count,"snapshot_record_count",snapshot_record_count,"capture_valid",capture_valid,"latest_snapshot_count",latest_snapshot_count,"endpoint_node_match",endpoint_node_match))
| fields _raw _time _indextime index kind input_count source_scan_count source_scan_invalid_count focused_invalid_count oversized
| appendpipe [| stats max(input_count) AS input_count max(source_scan_count) AS source_scan_count max(source_scan_invalid_count) AS source_scan_invalid_count max(focused_invalid_count) AS focused_invalid_count sum(eval(if(kind="supplemental_record",oversized,0))) AS oversized | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),returned_count=min(coalesce(input_count,0),${outputLimit}),input_capped=if(input_count>${EVIDENCE_LIMITS.input},1,0),source_scan_count=coalesce(source_scan_count,0),source_scan_capped=if(source_scan_count>${EVIDENCE_LIMITS.input},1,0),source_scan_invalid_count=coalesce(source_scan_invalid_count,0)+coalesce(focused_invalid_count,0),oversized=coalesce(oversized,0)]
| where kind="supplemental_record" OR kind="supplemental_completion"
| sort 0 kind record_type controller_authority snapshot_id record_id
| head ${outputLimit + 1}
| fields kind schema_version input_count returned_count input_capped source_scan_count source_scan_capped source_scan_invalid_count focused_invalid_count oversized _raw _time _indextime index`;
}

function first(value: unknown): unknown {
  return Array.isArray(value) ? value[0] : value;
}

function safeText(value: unknown, max = 2_048): string | undefined {
  value = first(value);
  if (typeof value !== "string" && typeof value !== "number") return undefined;
  const result = String(value);
  if (
    !result ||
    result.length > max ||
    Array.from(result).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    return undefined;
  return result;
}

function finite(value: unknown, max = 253_402_300_799): number | undefined {
  value = first(value);
  if (typeof value !== "number" && typeof value !== "string") return undefined;
  const result = Number(value);
  return Number.isFinite(result) && result >= 0 && result <= max
    ? result
    : undefined;
}

function parseRaw(row: Row): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(String(row._raw ?? ""));
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

interface ParsedRecord {
  authority: string;
  scope: string;
  snapshotId: string;
  snapshotAt: number;
  startedAt: number;
  completedAt: number;
  skew: number;
  expected: number;
  indexed: number;
  origin?: string;
  raw: Record<string, unknown>;
  fingerprint: string;
  recordType: string;
}

function endpointCandidates(
  value: unknown,
  selected: ReadonlySet<string>,
): AppDynamicsEndpointCandidate[] {
  if (!Array.isArray(value) || value.length > 64) return [];
  const result: AppDynamicsEndpointCandidate[] = [];
  for (const item of value) {
    if (!isObject(item)) continue;
    const property = safeText(item.property, 128);
    const kind = safeText(item.kind, 32);
    const candidateValue =
      typeof item.value === "number" ? item.value : safeText(item.value, 255);
    if (
      !property ||
      !candidateValue ||
      (kind !== "ip" && kind !== "hostname_unresolved" && kind !== "port")
    )
      continue;
    const port = finite(item.port, 65_535);
    const ip =
      kind === "ip" && typeof candidateValue === "string"
        ? (() => {
            try {
              return normalizeIp(candidateValue);
            } catch {
              return undefined;
            }
          })()
        : undefined;
    result.push({
      property,
      kind,
      value: ip ?? candidateValue,
      ...(port !== undefined && port > 0 ? { port } : {}),
      matchesSelection: ip !== undefined && selected.has(ip),
    });
  }
  return result;
}

/** Normalize focused records only after the search completion envelope is verified. */
export function normalizeAppDynamicsEvidence(
  rows: readonly Row[],
  selectionInput: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: AppDynamicsInventoryContext[]; rejected: number } {
  const selection = validateSelection(selectionInput);
  const mappings = verifiedMappings(config, selection);
  const origins = new Map(
    mappings.map((mapping) => [
      mapping.observer,
      mapping.controller_origin
        ? configuredHttpsOrigin(mapping.controller_origin)
        : undefined,
    ]),
  );
  const selected = new Set(selection.addresses.map(normalizeIp));
  const indexes = new Set(checkedIndexes(config));
  const parsed: ParsedRecord[] = [];
  let rejected = 0;
  for (const row of rows) {
    const raw = parseRaw(row);
    const authority = raw && safeText(raw.controller_authority, 255);
    const scope = raw && safeText(raw.scope, 253);
    const snapshotId = raw && safeText(raw.snapshot_id, 128);
    const snapshotAt = raw && finite(raw.snapshot_at);
    const startedAt = raw && finite(raw.collection_started_at);
    const completedAt = raw && finite(raw.collection_completed_at);
    const skew = raw && finite(raw.collection_skew_seconds, 600);
    const observedAt = raw && finite(raw.observed_at);
    const expected =
      raw && finite(raw.expected_record_count, EVIDENCE_LIMITS.input);
    const indexed = finite(row._indextime);
    const fingerprint = raw && safeText(raw.record_fingerprint, 64);
    const recordType = raw && safeText(raw.record_type, 32);
    const authorityOrigin = authority ? origins.get(authority) : undefined;
    if (
      !raw ||
      !authority ||
      !scope ||
      !snapshotId ||
      snapshotAt === undefined ||
      startedAt === undefined ||
      completedAt === undefined ||
      skew === undefined ||
      observedAt === undefined ||
      expected === undefined ||
      indexed === undefined ||
      !fingerprint ||
      !/^[0-9a-f]{64}$/.test(fingerprint) ||
      !recordType ||
      !indexes.has(String(row.index)) ||
      !origins.has(authority) ||
      raw.schema !== APPDYNAMICS_SCHEMA ||
      finite(raw.schema_version, 1) !== 1 ||
      raw.source !== SOURCE ||
      raw.identity_basis !== "controller_application_model_ids" ||
      scope !== routingScope(selection.scope) ||
      (raw.snapshot_complete !== true &&
        raw.snapshot_complete !== "true" &&
        raw.snapshot_complete !== 1 &&
        raw.snapshot_complete !== "1") ||
      (raw.capture_valid !== 1 &&
        raw.capture_valid !== "1" &&
        raw.capture_valid !== true) ||
      finite(raw.capture_record_count, EVIDENCE_LIMITS.input) !== expected ||
      finite(raw.capture_id_count, EVIDENCE_LIMITS.input) !== expected ||
      finite(raw.snapshot_record_count, 1) !== 1 ||
      finite(raw.latest_snapshot_count, 1) !== 1 ||
      finite(raw.expected_record_count, EVIDENCE_LIMITS.input) !== expected ||
      expected < 1 ||
      !Number.isSafeInteger(expected) ||
      startedAt > completedAt ||
      observedAt < startedAt ||
      observedAt > completedAt ||
      completedAt !== snapshotAt ||
      Math.abs(completedAt - startedAt - skew) > 1 ||
      snapshotAt < Date.now() / 1000 - config.staleAfterSeconds - 1 ||
      snapshotAt > Date.now() / 1000 + 60
    ) {
      rejected++;
      continue;
    }
    if (
      !["snapshot", "application", "tier", "node", "backend"].includes(
        recordType,
      ) ||
      !safeText(raw.record_id, 512)
    ) {
      rejected++;
      continue;
    }
    parsed.push({
      authority,
      scope,
      snapshotId,
      snapshotAt,
      startedAt,
      completedAt,
      skew,
      expected,
      indexed,
      ...(authorityOrigin ? { origin: authorityOrigin } : {}),
      raw,
      fingerprint,
      recordType,
    });
  }

  const groups = new Map<string, ParsedRecord[]>();
  for (const record of parsed) {
    const key = `${record.authority}\u0000${record.snapshotId}`;
    const rowsForCapture = groups.get(key) ?? [];
    rowsForCapture.push(record);
    groups.set(key, rowsForCapture);
  }
  const records: AppDynamicsInventoryContext[] = [];
  for (const capture of groups.values()) {
    const firstRow = capture[0];
    const uniqueCapture = new Map<string, ParsedRecord>();
    let duplicateConflict = false;
    for (const record of capture) {
      const previous = uniqueCapture.get(record.fingerprint);
      if (
        previous &&
        JSON.stringify(previous.raw) !== JSON.stringify(record.raw)
      )
        duplicateConflict = true;
      else if (!previous) uniqueCapture.set(record.fingerprint, record);
    }
    const uniqueRecords = [...uniqueCapture.values()];
    if (
      duplicateConflict ||
      uniqueRecords.some(
        (record) =>
          record.scope !== firstRow.scope ||
          record.snapshotAt !== firstRow.snapshotAt ||
          record.startedAt !== firstRow.startedAt ||
          record.completedAt !== firstRow.completedAt ||
          record.skew !== firstRow.skew ||
          record.expected !== firstRow.expected ||
          record.origin !== firstRow.origin,
      ) ||
      !uniqueRecords.some((record) => record.recordType === "snapshot")
    ) {
      rejected += capture.length;
      continue;
    }
    const appNames = new Map<string, string>();
    const tierNames = new Map<string, string>();
    const nodes: AppDynamicsNodeContext[] = [];
    const nodeKeys = new Set<string>();
    for (const record of uniqueRecords) {
      const raw = record.raw;
      const appId = safeText(raw.application_id, 64);
      const appName = safeText(raw.application_name);
      const tierId = safeText(raw.tier_id, 64);
      const tierName = safeText(raw.tier_name);
      if (appId && appName) appNames.set(appId, appName);
      if (appId && tierId && tierName)
        tierNames.set(`${appId}:${tierId}`, tierName);
      if (
        record.recordType !== "node" ||
        !appId ||
        !appName ||
        !tierId ||
        !tierName
      )
        continue;
      const nodeId = safeText(raw.node_id, 64);
      const nodeName = safeText(raw.node_name);
      if (!nodeId || !nodeName || !Array.isArray(raw.ip_addresses)) {
        rejected++;
        continue;
      }
      const addresses: string[] = [];
      for (const address of raw.ip_addresses) {
        if (
          !isObject(address) ||
          address.matchable !== true ||
          typeof address.ip !== "string"
        )
          continue;
        try {
          addresses.push(normalizeIp(address.ip));
        } catch {
          rejected++;
        }
      }
      const uniqueAddresses = [...new Set(addresses)].sort();
      const matchedAddresses = uniqueAddresses.filter((address) =>
        selected.has(address),
      );
      if (!matchedAddresses.length) continue;
      const nodeKey = `${appId}:${tierId}:${nodeId}`;
      if (nodeKeys.has(nodeKey)) {
        rejected++;
        continue;
      }
      nodeKeys.add(nodeKey);
      nodes.push({
        applicationId: appId,
        applicationName: appName,
        tierId,
        tierName,
        nodeId,
        nodeName,
        ...(safeText(raw.machine_name)
          ? { machineName: safeText(raw.machine_name) }
          : {}),
        addresses: uniqueAddresses,
        matchedAddresses,
      });
    }
    const matchedApps = new Set(nodes.map((node) => node.applicationId));
    const matchedNodeIds = new Set(
      nodes.map(
        (node) => `${node.applicationId}:${node.tierId}:${node.nodeId}`,
      ),
    );
    const backends: AppDynamicsBackendCandidate[] = [];
    const backendIds = new Set<string>();
    for (const record of uniqueRecords) {
      if (record.recordType !== "backend") continue;
      const raw = record.raw;
      const applicationId = safeText(raw.application_id, 64);
      const backendId = safeText(raw.backend_id, 64);
      const name = safeText(raw.backend_name);
      const associationStatus = safeText(raw.association_status, 64);
      if (
        !applicationId ||
        !matchedApps.has(applicationId) ||
        !backendId ||
        !name ||
        ![
          "verified_node",
          "application_scope_only",
          "unverified_reported_ids",
        ].includes(associationStatus ?? "")
      )
        continue;
      const tierId = safeText(raw.reported_tier_id, 64);
      const nodeId = safeText(raw.reported_application_component_node_id, 64);
      const verifiedTierId = safeText(raw.verified_tier_id, 64);
      const verifiedNodeId = safeText(raw.verified_node_id, 64);
      const associatedWithMatchedNode =
        associationStatus === "verified_node" &&
        !!verifiedTierId &&
        !!verifiedNodeId &&
        matchedNodeIds.has(
          `${applicationId}:${verifiedTierId}:${verifiedNodeId}`,
        );
      const key = `${applicationId}:${backendId}`;
      if (backendIds.has(key)) {
        rejected++;
        continue;
      }
      backendIds.add(key);
      backends.push({
        applicationId,
        applicationName:
          appNames.get(applicationId) ?? "Application name unavailable",
        backendId,
        name,
        ...(safeText(raw.exit_point_type, 128)
          ? { exitPointType: safeText(raw.exit_point_type, 128) }
          : {}),
        associationStatus:
          associationStatus as AppDynamicsBackendCandidate["associationStatus"],
        ...(tierId ? { tierId } : {}),
        ...(nodeId ? { nodeId } : {}),
        associatedWithMatchedNode,
        endpointCandidates: endpointCandidates(
          raw.endpoint_candidates,
          selected,
        ),
      });
    }
    records.push({
      authority: firstRow.authority,
      scope: firstRow.scope,
      snapshotId: firstRow.snapshotId,
      snapshotAt: firstRow.snapshotAt,
      collectionStartedAt: firstRow.startedAt,
      collectionCompletedAt: firstRow.completedAt,
      collectionSkewSeconds: firstRow.skew,
      expectedRecordCount: firstRow.expected,
      indexedRecordCount:
        finite(firstRow.raw.capture_record_count, EVIDENCE_LIMITS.input) ?? 0,
      ...(firstRow.origin ? { controllerOrigin: firstRow.origin } : {}),
      nodes,
      backends,
    });
  }
  return { records, rejected };
}

export function loadAppDynamicsEvidence(
  client: SearchClient,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<AppDynamicsEvidenceResult> {
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    SOURCE,
    buildAppDynamicsSearch,
    normalizeAppDynamicsEvidence,
    configurationClient,
    false,
    appDynamicsSearchWindow,
    APPDYNAMICS_COVERAGE,
  );
}
