import { routingScope, type OptionalSource } from "../data/evidence";
import { optionalJobs } from "../data/optionalJobs";
import {
  requireNoSearchErrors,
  type RunResult,
  type SearchClient,
  type SearchRequest,
} from "../data/searchClient";
import { validateIndexName } from "../data/deploymentHealth";
import {
  canonicalJson,
  HASH_ID,
  parseCanonicalJson,
  sha256Hex,
  withoutKeys,
} from "./canonicalJson";
import {
  attributeChangeRow,
  extractRetainedRelationships,
} from "./relationships";
export { attributeChangeRow } from "./relationships";
import type {
  ChangeGenerationActivation,
  ChangeGenerationManifest,
  ChangeHistoryRow,
  ChangeJsonValue,
  ChangeTimelineContext,
  ChangeTimelineExclusions,
  ChangeTimelineResult,
  ChangeTimelineSelection,
  ChangeTimelineWindow,
  ChangeTimelineRecordView,
} from "./types";

export const MAX_GENERATION_ROWS = 10_000;
const MAX_QUERY_RESULTS = MAX_GENERATION_ROWS + 1;
const QUERY_HEAD = MAX_QUERY_RESULTS + 1;
const MAX_GENERATION_BYTES = 32 * 1024 * 1024;
const MAX_ROW_BYTES = 64 * 1024;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_ACTIVATION_BYTES = 1024 * 1024;
const MAX_CHANGE_WINDOW_SECONDS = 86_400;
const MAX_EPOCH = 253_402_300_799;
const CHANGE_TIMELINE_SOURCE = "change_timeline" as OptionalSource;
const CHANGE_SOURCETYPE = "adm:configuration_change:v1";
const MANIFEST_SOURCETYPE = "adm:configuration_change_manifest:v1";
const ACTIVATION_SOURCETYPE = "adm:configuration_change_activation:v1";
const HASH_FIELDS = ["record_id", "generation_id"] as const;

function nextMillisecond(value: number): number {
  const milliseconds = Math.round(value * 1000);
  if (
    value !== milliseconds / 1000 ||
    !Number.isSafeInteger(milliseconds) ||
    milliseconds + 1 > MAX_EPOCH * 1000
  )
    throw new Error("Activation source bound cannot be widened safely.");
  const next = (milliseconds + 1) / 1000;
  canonicalJson(next);
  return next;
}

function projectedNumber(value: number, label: string) {
  if (!Number.isFinite(value)) throw new Error(`${label} is invalid.`);
  canonicalJson(value);
}

const ROW_FIELDS = [
  "actor",
  "attributes",
  "authority",
  "change_type",
  "context_only",
  "coverage_complete",
  "clock_uncertainty_unknown",
  "earliest_at",
  "effective_at",
  "event_at",
  "family",
  "field_diffs",
  "gap",
  "generation_id",
  "kind",
  "latest_at",
  "native_sample_unqualified",
  "object_id",
  "partition",
  "permissions_fingerprint",
  "product",
  "projection_qualification",
  "qualification",
  "received_at",
  "record_id",
  "record_type",
  "revision",
  "scope",
  "schema_version",
  "source_refs",
  "source_version",
  "time_qualification",
  "observed_at",
].sort();
const MANIFEST_FIELDS = [
  "algorithm_version",
  "canonicalization",
  "generation_id",
  "record_id_hash_excludes",
  "record_type",
  "row_count",
  "row_hash_excludes",
  "row_order",
  "rows_sha256",
  "schema_version",
  "source_earliest",
  "source_latest",
  "source_receipt_hashes",
].sort();
const ACTIVATION_FIELDS = [
  "activated_at",
  "activation_id",
  "generation_id",
  "index",
  "index_earliest",
  "index_latest",
  "manifest",
  "record_type",
  "schema_version",
  "source_earliest",
  "source_latest",
  "validation_method",
  "viewer_entitlement_attested",
].sort();

export type ChangeTimelineSearchRunner = (
  source: OptionalSource,
  key: string,
  client: SearchClient,
  request: SearchRequest,
) => Promise<RunResult>;

const defaultRunner: ChangeTimelineSearchRunner = (
  source,
  key,
  client,
  request,
) => optionalJobs.run(source, key, client, request);

const object = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  )
    throw new Error(`${label} has an unsupported field shape.`);
}

function text(value: unknown, label: string, max = 512): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error(`${label} is invalid.`);
  return value;
}

function sourceReference(value: unknown, label: string): string {
  const reference = text(value, label);
  if (/^(?:[a-z][a-z0-9+.-]*:\/\/|www\.)/i.test(reference))
    throw new Error(`${label} must be a native reference, not a URL.`);
  return reference;
}

function projectedFieldName(value: unknown, label: string, max = 128): string {
  const name = text(value, label, max);
  if (
    /(?:^|[_-])(raw|payload|config|script|secret|password|token|url)(?:$|[_-])/i.test(
      name,
    )
  )
    throw new Error(`${label} is not an approved projected field.`);
  return name;
}

function boundedText(value: unknown, label: string, max = 2048): string {
  if (
    typeof value !== "string" ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error(`${label} is invalid.`);
  return value;
}

function nullableText(value: unknown, label: string, max = 512) {
  return value === null ? null : text(value, label, max);
}

function timestamp(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0 ||
    value > 253_402_300_799
  )
    throw new Error(`${label} is invalid.`);
  canonicalJson(value);
  return value;
}

function nullableTimestamp(value: unknown, label: string) {
  return value === null ? null : timestamp(value, label);
}

function validateJsonValue(
  value: unknown,
  label: string,
  depth = 0,
  budget = { entries: 0 },
): ChangeJsonValue {
  budget.entries += 1;
  if (budget.entries > 4096 || depth > 4)
    throw new Error(`${label} exceeds the projected-value limit.`);
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return boundedText(value, label, 2048);
  if (typeof value === "number") {
    projectedNumber(value, label);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 256)
      throw new Error(`${label} exceeds the projected-array limit.`);
    return value.map((item) =>
      validateJsonValue(item, label, depth + 1, budget),
    );
  }
  const record = object(value);
  if (!record || Object.keys(record).length > 128)
    throw new Error(`${label} is not a bounded projected value.`);
  const normalized: Record<string, ChangeJsonValue> = {};
  for (const [key, item] of Object.entries(record)) {
    projectedFieldName(key, `${label} field`);
    normalized[key] = validateJsonValue(item, label, depth + 1, budget);
  }
  return normalized;
}

function validateFieldDiff(value: unknown, index: number) {
  const record = object(value);
  const label = `Field difference ${index + 1}`;
  if (!record) throw new Error(`${label} is invalid.`);
  exactKeys(
    record,
    ["field", "before", "after", "before_present", "after_present"],
    label,
  );
  if (
    typeof record.before_present !== "boolean" ||
    typeof record.after_present !== "boolean"
  )
    throw new Error(`${label} presence flags are invalid.`);
  return {
    field: projectedFieldName(record.field, `${label} field`),
    before: validateJsonValue(record.before, `${label} previous value`),
    after: validateJsonValue(record.after, `${label} next value`),
    before_present: record.before_present,
    after_present: record.after_present,
  };
}

function validateHistoryRow(value: unknown): ChangeHistoryRow {
  const row = object(value);
  if (!row) throw new Error("Generation row is not a JSON object.");
  exactKeys(row, ROW_FIELDS, "Generation row");
  if (
    row.schema_version !== 1 ||
    !["change", "coverage", "baseline", "observation"].includes(
      String(row.record_type),
    )
  )
    throw new Error("Generation row schema is unsupported.");
  if (
    typeof row.record_id !== "string" ||
    typeof row.generation_id !== "string" ||
    !HASH_ID.test(row.record_id) ||
    !HASH_ID.test(row.generation_id)
  )
    throw new Error("Generation row identity is invalid.");
  if (
    typeof row.coverage_complete !== "boolean" ||
    typeof row.gap !== "boolean" ||
    typeof row.clock_uncertainty_unknown !== "boolean" ||
    typeof row.native_sample_unqualified !== "boolean" ||
    typeof row.context_only !== "boolean"
  )
    throw new Error("Generation row completeness flags are invalid.");
  if (!Array.isArray(row.source_refs) || row.source_refs.length > 64)
    throw new Error("Generation source references are invalid.");
  const sourceRefs = row.source_refs.map((item, index) =>
    sourceReference(item, `Source reference ${index + 1}`),
  );
  if (
    sourceRefs.some((item, index) => index > 0 && sourceRefs[index - 1] >= item)
  )
    throw new Error("Generation source references are not sorted and unique.");
  if (!Array.isArray(row.field_diffs) || row.field_diffs.length > 128)
    throw new Error("Generation field differences are invalid.");
  const attributes = object(row.attributes);
  if (!attributes || Object.keys(attributes).length > 128)
    throw new Error("Generation projected attributes are invalid.");
  const normalizedAttributes: Record<string, ChangeJsonValue> = {};
  for (const [key, item] of Object.entries(attributes)) {
    projectedFieldName(key, "Projected attribute name");
    normalizedAttributes[key] = validateJsonValue(item, `Attribute ${key}`);
  }
  const rowType = row.record_type as ChangeHistoryRow["record_type"];
  const timeQualification = text(
    row.time_qualification,
    "Generation time qualification",
  );
  if (
    ![
      "snapshot_interval",
      "collection_interval",
      "coverage_interval",
      "source_event_time_reported",
      "unknown_source_time",
    ].includes(timeQualification)
  )
    throw new Error("Generation time qualification is unsupported.");
  const nullableString = (key: string) =>
    nullableText(row[key], `Generation ${key}`);
  const nullableTime = (key: string) =>
    nullableTimestamp(row[key], `Generation ${key}`);
  const earliestAt = nullableTime("earliest_at");
  const latestAt = nullableTime("latest_at");
  if ((earliestAt === null) !== (latestAt === null) && rowType !== "coverage")
    throw new Error("Generation row has an incomplete uncertainty interval.");
  if (earliestAt !== null && latestAt !== null && earliestAt > latestAt)
    throw new Error("Generation row has reversed uncertainty bounds.");
  if (
    timeQualification === "source_event_time_reported" &&
    (earliestAt !== null ||
      latestAt !== null ||
      row.event_at === null ||
      row.clock_uncertainty_unknown !== true)
  )
    throw new Error(
      "Reported native event time has unsupported interval qualification.",
    );
  if (
    (rowType === "change" || rowType === "baseline") &&
    (earliestAt === null || latestAt === null)
  )
    throw new Error("Change and baseline rows require complete time bounds.");
  const permissionsFingerprint =
    row.permissions_fingerprint === null
      ? null
      : text(row.permissions_fingerprint, "Generation permission fingerprint");
  if (permissionsFingerprint === null && row.coverage_complete === true)
    throw new Error(
      "Complete generation rows require a permission fingerprint.",
    );
  return {
    schema_version: 1,
    record_type: rowType,
    change_type: nullableText(row.change_type, "Generation change type"),
    record_id: row.record_id as string,
    generation_id: row.generation_id as string,
    product: text(row.product, "Generation product"),
    authority: text(row.authority, "Generation authority"),
    source_version: nullableString("source_version"),
    family: text(row.family, "Generation family"),
    partition: text(row.partition, "Generation partition"),
    scope: text(row.scope, "Generation scope"),
    permissions_fingerprint: permissionsFingerprint,
    object_id: nullableString("object_id"),
    revision: nullableString("revision"),
    kind: nullableString("kind"),
    actor: nullableString("actor"),
    event_at: nullableTime("event_at"),
    effective_at: nullableTime("effective_at"),
    observed_at: nullableTime("observed_at"),
    received_at: nullableTime("received_at"),
    earliest_at: earliestAt,
    latest_at: latestAt,
    source_refs: sourceRefs,
    field_diffs: row.field_diffs.map(validateFieldDiff),
    attributes: normalizedAttributes,
    coverage_complete: row.coverage_complete,
    gap: row.gap,
    qualification: text(row.qualification, "Generation qualification"),
    time_qualification: timeQualification,
    clock_uncertainty_unknown: row.clock_uncertainty_unknown,
    projection_qualification: text(
      row.projection_qualification,
      "Generation projection qualification",
    ),
    native_sample_unqualified: row.native_sample_unqualified,
    context_only: row.context_only,
  };
}

function validateManifest(value: unknown): ChangeGenerationManifest {
  const manifest = object(value);
  if (!manifest) throw new Error("Activated generation manifest is invalid.");
  exactKeys(manifest, MANIFEST_FIELDS, "Generation manifest");
  if (
    new TextEncoder().encode(canonicalJson(manifest)).byteLength >
    MAX_MANIFEST_BYTES
  )
    throw new Error("Generation manifest exceeds the validation budget.");
  if (
    manifest.schema_version !== 1 ||
    manifest.record_type !== "generation_manifest" ||
    manifest.algorithm_version !== "configuration-history-v1" ||
    manifest.canonicalization !== "bounded-decimal-json-v1" ||
    manifest.row_order !== "record_id-asc-v1" ||
    !Array.isArray(manifest.record_id_hash_excludes) ||
    canonicalJson(manifest.record_id_hash_excludes) !==
      canonicalJson(["record_id", "generation_id"]) ||
    !Array.isArray(manifest.row_hash_excludes) ||
    canonicalJson(manifest.row_hash_excludes) !==
      canonicalJson(["generation_id"])
  )
    throw new Error("Activated generation manifest is unsupported.");
  if (
    typeof manifest.row_count !== "number" ||
    !Number.isSafeInteger(manifest.row_count) ||
    manifest.row_count < 0 ||
    manifest.row_count > MAX_GENERATION_ROWS ||
    !HASH_ID.test(String(manifest.rows_sha256)) ||
    !HASH_ID.test(String(manifest.generation_id))
  )
    throw new Error("Activated generation manifest limits are invalid.");
  const receipts = manifest.source_receipt_hashes;
  if (
    !Array.isArray(receipts) ||
    receipts.length > MAX_GENERATION_ROWS ||
    !receipts.every((hash) => typeof hash === "string" && HASH_ID.test(hash)) ||
    receipts.some((hash, index) => index > 0 && receipts[index - 1] >= hash)
  )
    throw new Error("Generation manifest receipt hashes are invalid.");
  const sourceEarliest = timestamp(
    manifest.source_earliest,
    "Generation source start",
  );
  const sourceLatest = timestamp(
    manifest.source_latest,
    "Generation source end",
  );
  if (sourceLatest < sourceEarliest)
    throw new Error("Generation manifest source bounds are invalid.");
  return {
    schema_version: 1,
    record_type: "generation_manifest",
    algorithm_version: "configuration-history-v1",
    canonicalization: "bounded-decimal-json-v1",
    row_order: "record_id-asc-v1",
    record_id_hash_excludes: ["record_id", "generation_id"],
    row_hash_excludes: ["generation_id"],
    source_receipt_hashes: receipts as string[],
    row_count: manifest.row_count,
    rows_sha256: manifest.rows_sha256 as string,
    source_earliest: sourceEarliest,
    source_latest: sourceLatest,
    generation_id: manifest.generation_id as string,
  };
}

export async function validateChangeActivation(
  value: unknown,
): Promise<ChangeGenerationActivation> {
  const activation = object(value);
  if (!activation) throw new Error("Selected activation is invalid.");
  exactKeys(activation, ACTIVATION_FIELDS, "Generation activation");
  const manifest = validateManifest(activation.manifest);
  const index = text(activation.index, "Activation index", 80);
  if (validateIndexName(index))
    throw new Error("The selected change history index is invalid.");
  const activationId = text(activation.activation_id, "Activation ID", 64);
  const generationId = text(
    activation.generation_id,
    "Activation generation ID",
    64,
  );
  if (
    !HASH_ID.test(activationId) ||
    !HASH_ID.test(generationId) ||
    manifest.generation_id !== generationId ||
    activation.schema_version !== 1 ||
    activation.record_type !== "generation_activation" ||
    activation.viewer_entitlement_attested !== true ||
    activation.validation_method !== "sha256-full-generation-v1"
  )
    throw new Error(
      "The selected activation does not qualify for history access.",
    );
  const sourceEarliest = timestamp(
    activation.source_earliest,
    "Activation source start",
  );
  const sourceLatest = timestamp(
    activation.source_latest,
    "Activation source end",
  );
  const indexEarliest = timestamp(
    activation.index_earliest,
    "Activation index start",
  );
  const indexLatest = timestamp(
    activation.index_latest,
    "Activation index end",
  );
  const activatedAt = timestamp(activation.activated_at, "Activation time");
  if (
    sourceEarliest !== manifest.source_earliest ||
    sourceLatest !== manifest.source_latest ||
    sourceLatest < sourceEarliest ||
    indexEarliest >= indexLatest ||
    indexLatest > activatedAt
  )
    throw new Error("The selected activation has inconsistent bounds.");
  const normalized: ChangeGenerationActivation = {
    schema_version: 1,
    record_type: "generation_activation",
    activation_id: activationId,
    generation_id: generationId,
    index,
    source_earliest: sourceEarliest,
    source_latest: sourceLatest,
    index_earliest: indexEarliest,
    index_latest: indexLatest,
    activated_at: activatedAt,
    viewer_entitlement_attested: true,
    validation_method: "sha256-full-generation-v1",
    manifest,
  };
  const activationBytes = new TextEncoder().encode(
    canonicalJson(normalized),
  ).byteLength;
  if (activationBytes > MAX_ACTIVATION_BYTES)
    throw new Error("The selected activation exceeds the validation budget.");
  const computedActivationId = await sha256Hex(
    canonicalJson(withoutKeys(normalized, ["activation_id"])),
  );
  const computedGenerationId = await sha256Hex(
    canonicalJson(withoutKeys(manifest, ["generation_id"])),
  );
  if (
    computedActivationId !== activationId ||
    computedGenerationId !== generationId
  )
    throw new Error("The selected activation or manifest hash is invalid.");
  return normalized;
}

export function buildChangeActivationSearch(
  index: string,
  activationId: string,
  now = Math.floor(Date.now() / 1000),
) {
  if (validateIndexName(index))
    throw new Error("The selected change history index is invalid.");
  if (typeof activationId !== "string" || !HASH_ID.test(activationId))
    throw new Error("The selected activation ID is invalid.");
  timestamp(now, "Activation lookup upper bound");
  const search =
    `search index=${index} sourcetype="${ACTIVATION_SOURCETYPE}" ` +
    `| spath input=_raw path=activation_id output=activation_id ` +
    `| where activation_id="${activationId}" ` +
    `| eval timeline_payload=_raw | table timeline_payload | head 2`;
  return { search, earliest: "0", latest: canonicalJson(now), maxRows: 2 };
}

export async function loadChangeActivation(
  client: SearchClient,
  index: string,
  activationId: string,
  signal: AbortSignal,
  run: ChangeTimelineSearchRunner = defaultRunner,
): Promise<ChangeGenerationActivation> {
  const bounds = buildChangeActivationSearch(index, activationId);
  if (signal.aborted) throw new Error("Change activation lookup cancelled.");
  const result = requireNoSearchErrors(
    await run(
      CHANGE_TIMELINE_SOURCE,
      `activation:${index}:${activationId}`,
      client,
      {
        search: bounds.search,
        earliest: bounds.earliest,
        latest: bounds.latest,
        maxRows: bounds.maxRows,
        allowEmpty: false,
        budget: { serverSeconds: 30, clientMilliseconds: 35_000 },
        signal,
      },
    ),
    "Configuration history activation",
  );
  if (signal.aborted) throw new Error("Change activation lookup cancelled.");
  if (result.warnings.length)
    throw new Error("Activation lookup warnings prevent safe selection.");
  if (result.rows.length !== 1)
    throw new Error("Selected history activation is missing or conflicting.");
  exactKeys(result.rows[0], ["timeline_payload"], "Activation search result");
  const payload = result.rows[0].timeline_payload;
  if (typeof payload !== "string")
    throw new Error("Activation search did not return a projected envelope.");
  if (new TextEncoder().encode(payload).byteLength > MAX_ACTIVATION_BYTES)
    throw new Error("Selected activation exceeds the validation budget.");
  const activation = await validateChangeActivation(
    parseCanonicalJson(payload),
  );
  if (signal.aborted) throw new Error("Change activation lookup cancelled.");
  if (activation.index !== index || activation.activation_id !== activationId)
    throw new Error("Activation search returned a conflicting selection.");
  return activation;
}

export function buildChangeGenerationSearch(
  activation: ChangeGenerationActivation,
) {
  if (validateIndexName(activation.index))
    throw new Error("The selected change history index is invalid.");
  if (
    typeof activation.generation_id !== "string" ||
    !HASH_ID.test(activation.generation_id)
  )
    throw new Error("The selected generation ID is invalid.");
  const sourceStart = timestamp(
    activation.source_earliest,
    "Activation source start",
  );
  const sourceEnd = timestamp(
    activation.source_latest,
    "Activation source end",
  );
  const indexStartValue = timestamp(
    activation.index_earliest,
    "Activation index start",
  );
  const indexEndValue = timestamp(
    activation.index_latest,
    "Activation index end",
  );
  const activatedAt = timestamp(activation.activated_at, "Activation time");
  if (
    sourceStart !== activation.manifest.source_earliest ||
    sourceEnd !== activation.manifest.source_latest ||
    sourceEnd < sourceStart ||
    indexStartValue >= indexEndValue ||
    indexEndValue > activatedAt
  )
    throw new Error("The selected activation search bounds are invalid.");
  const indexStart = canonicalJson(indexStartValue);
  const indexEnd = canonicalJson(indexEndValue);
  const search =
    `search index=${activation.index} _index_earliest=${indexStart} ` +
    `_index_latest=${indexEnd} ` +
    `(sourcetype="${CHANGE_SOURCETYPE}" OR sourcetype="${MANIFEST_SOURCETYPE}") ` +
    `| spath input=_raw path=generation_id output=generation_id ` +
    `| where generation_id="${activation.generation_id}" ` +
    `AND _indextime>=${indexStart} AND _indextime<${indexEnd} ` +
    `| eval timeline_payload=_raw | dedup timeline_payload ` +
    `| table timeline_payload | head ${QUERY_HEAD}`;
  const earliest = Math.min(sourceStart, indexStartValue);
  const latest = Math.max(nextMillisecond(sourceEnd), indexEndValue);
  if (earliest >= latest)
    throw new Error("The selected activation search bounds are invalid.");
  return {
    search,
    earliest: canonicalJson(earliest),
    latest: canonicalJson(latest),
  };
}

function parseStoredPayloads(result: RunResult) {
  if (!Array.isArray(result.warnings) || !Array.isArray(result.rows))
    throw new Error("Splunk returned an incomplete history response.");
  if (result.warnings.length)
    throw new Error(
      "Splunk warnings prevent generation completeness verification.",
    );
  if (result.rows.length > MAX_QUERY_RESULTS)
    throw new Error(
      "Activated generation exceeds the 10,000-row readback limit.",
    );
  let totalBytes = 0;
  const payloads = result.rows.map((row, index) => {
    exactKeys(row, ["timeline_payload"], `Search result ${index + 1}`);
    const payload = row.timeline_payload;
    if (typeof payload !== "string")
      throw new Error("Splunk did not return a projected history row.");
    const bytes = new TextEncoder().encode(payload).byteLength;
    totalBytes += bytes;
    if (bytes > MAX_MANIFEST_BYTES || totalBytes > MAX_GENERATION_BYTES)
      throw new Error(
        "Activated generation exceeds the browser readback budget.",
      );
    const parsed = parseCanonicalJson(payload);
    const maximum =
      object(parsed)?.record_type === "generation_manifest"
        ? MAX_MANIFEST_BYTES
        : MAX_ROW_BYTES;
    if (bytes > maximum)
      throw new Error(
        "Activated generation exceeds the browser readback budget.",
      );
    return parsed;
  });
  return payloads;
}

async function verifyGenerationRows(
  payloadRows: unknown[],
  manifest: ChangeGenerationManifest,
  generationId: string,
) {
  if (payloadRows.length > MAX_GENERATION_ROWS * 2 + 2)
    throw new Error("Generation readback exceeds the duplicate-input row cap.");
  const uniqueRows = new Map<string, ChangeHistoryRow>();
  let totalBytes = 0;
  for (const payload of payloadRows) {
    const payloadBytes = new TextEncoder().encode(
      canonicalJson(payload),
    ).byteLength;
    totalBytes += payloadBytes;
    if (payloadBytes > MAX_ROW_BYTES || totalBytes > MAX_GENERATION_BYTES)
      throw new Error(
        "Generation readback exceeds the validation byte budget.",
      );
    const row = validateHistoryRow(payload);
    if (row.generation_id !== generationId)
      throw new Error("Activated generation contains a mixed-generation row.");
    const canonicalRow = canonicalJson(row);
    const previous = uniqueRows.get(row.record_id);
    if (previous && canonicalJson(previous) !== canonicalRow)
      throw new Error(
        "Activated generation contains conflicting duplicate rows.",
      );
    uniqueRows.set(row.record_id, row);
  }
  const rows = [...uniqueRows.values()];
  if (rows.length !== manifest.row_count)
    throw new Error(
      "Activated generation unique row count does not match its manifest.",
    );
  if (rows.length > MAX_GENERATION_ROWS)
    throw new Error("Activated generation exceeds the 10,000-row limit.");
  for (const row of rows) {
    const computed = await sha256Hex(
      canonicalJson(withoutKeys(row, HASH_FIELDS)),
    );
    if (computed !== row.record_id)
      throw new Error("Activated generation contains an invalid row identity.");
  }
  const ordered = [...rows].sort((left, right) =>
    left.record_id < right.record_id
      ? -1
      : left.record_id > right.record_id
        ? 1
        : 0,
  );
  const rowSet = ordered
    .map((row) => canonicalJson(withoutKeys(row, ["generation_id"])))
    .join("\n");
  const rowsSha256 = await sha256Hex(rowSet);
  if (rowsSha256 !== manifest.rows_sha256)
    throw new Error(
      "Activated generation content does not match its manifest.",
    );
  return { rows: ordered, rowsSha256 };
}

function validateManifestRecord(
  value: unknown,
  activation: ChangeGenerationActivation,
) {
  const record = validateManifest(value);
  if (
    record.generation_id !== activation.generation_id ||
    canonicalJson(record) !== canonicalJson(activation.manifest)
  )
    throw new Error(
      "Read-back manifest does not match the selected activation.",
    );
  return record;
}

async function verifyGeneration(
  payloads: unknown[],
  activation: ChangeGenerationActivation,
) {
  const manifestValues = payloads.filter(
    (item) => object(item)?.record_type === "generation_manifest",
  );
  if (!manifestValues.length)
    throw new Error("Activated generation manifest is missing.");
  const manifests = new Map<string, ChangeGenerationManifest>();
  for (const value of manifestValues) {
    const manifest = validateManifestRecord(value, activation);
    manifests.set(canonicalJson(manifest), manifest);
  }
  if (manifests.size !== 1)
    throw new Error("Activated generation contains conflicting manifests.");
  const manifest = [...manifests.values()][0];
  const payloadRows = payloads.filter(
    (item) => object(item)?.record_type !== "generation_manifest",
  );
  return verifyGenerationRows(payloadRows, manifest, activation.generation_id);
}

export function isTimelineWindow(value: ChangeTimelineWindow): boolean {
  try {
    return (
      Number.isFinite(timestamp(value.start, "Selected window start")) &&
      Number.isFinite(timestamp(value.end, "Selected window end")) &&
      value.start < value.end &&
      value.end - value.start <= MAX_CHANGE_WINDOW_SECONDS
    );
  } catch {
    return false;
  }
}

export function validateChangeTimelineSelection(
  selection: ChangeTimelineSelection,
) {
  validateTimelineView(selection);
  return selection;
}

function interval(row: ChangeHistoryRow): [number, number] | undefined {
  if (row.earliest_at !== null && row.latest_at !== null)
    return [row.earliest_at, row.latest_at];
  const point = row.event_at ?? row.observed_at;
  if (point !== null) return [point, point];
  return undefined;
}

export function filterTimelineRows(
  rows: ChangeHistoryRow[],
  view: { scope: string; window: ChangeTimelineWindow },
): ChangeHistoryRow[] {
  validateTimelineView(view);
  return rows
    .filter((row) => {
      if (row.scope !== view.scope) return false;
      if (row.earliest_at !== null && row.latest_at !== null)
        return (
          row.earliest_at < view.window.end &&
          row.latest_at >= view.window.start
        );
      const reportedTime = row.event_at ?? row.observed_at;
      if (reportedTime !== null)
        return (
          reportedTime >= view.window.start && reportedTime < view.window.end
        );
      return row.record_type === "coverage";
    })
    .sort((left, right) => {
      const a = interval(left)?.[0] ?? Number.POSITIVE_INFINITY;
      const b = interval(right)?.[0] ?? Number.POSITIVE_INFINITY;
      return a - b || left.record_id.localeCompare(right.record_id);
    });
}

export function countTimelineExclusions(
  rows: ChangeHistoryRow[],
  view: { scope: string; window: ChangeTimelineWindow },
): ChangeTimelineExclusions {
  const exclusions: ChangeTimelineExclusions = {
    different_verified_scope: 0,
    outside_selected_interval: 0,
    unknown_time_unpositioned: 0,
  };
  for (const row of rows) {
    if (row.scope !== view.scope) {
      exclusions.different_verified_scope += 1;
      continue;
    }
    if (row.earliest_at !== null && row.latest_at !== null) {
      if (
        row.earliest_at >= view.window.end ||
        row.latest_at < view.window.start
      )
        exclusions.outside_selected_interval += 1;
      continue;
    }
    const point = row.event_at ?? row.observed_at;
    if (point !== null) {
      if (point < view.window.start || point >= view.window.end)
        exclusions.outside_selected_interval += 1;
      continue;
    }
    if (row.record_type !== "coverage")
      exclusions.unknown_time_unpositioned += 1;
  }
  return exclusions;
}

export async function loadChangeTimeline(
  client: SearchClient,
  selection: ChangeTimelineSelection,
  signal: AbortSignal,
  run: ChangeTimelineSearchRunner = defaultRunner,
): Promise<ChangeTimelineResult> {
  validateChangeTimelineSelection(selection);
  if (signal.aborted) throw new Error("Change history search cancelled.");
  const activation = await validateChangeActivation(selection.activation);
  if (signal.aborted) throw new Error("Change history search cancelled.");
  const bounds = buildChangeGenerationSearch(activation);
  const key = canonicalJson({
    activation_id: activation.activation_id,
    generation_id: activation.generation_id,
    index: activation.index,
    scope: selection.scope,
    window: selection.window,
  });
  const result = requireNoSearchErrors(
    await run(CHANGE_TIMELINE_SOURCE, key, client, {
      search: bounds.search,
      earliest: bounds.earliest,
      latest: bounds.latest,
      maxRows: MAX_QUERY_RESULTS,
      allowEmpty: false,
      budget: { serverSeconds: 30, clientMilliseconds: 35_000 },
      signal,
    }),
    "Configuration history",
  );
  if (signal.aborted) throw new Error("Change history search cancelled.");
  const payloads = parseStoredPayloads(result);
  const verified = await verifyGeneration(payloads, activation);
  if (signal.aborted) throw new Error("Change history search cancelled.");
  const relationships = await extractRetainedRelationships(
    verified.rows,
    activation.generation_id,
  );
  if (signal.aborted) throw new Error("Change history search cancelled.");
  const filtered = filterTimelineRows(verified.rows, selection);
  return {
    provenance: "validated_live",
    activation,
    manifest: activation.manifest,
    rows: filtered,
    generation_rows: verified.rows,
    retained_relationships: relationships.relationships,
    relationship_evidence_complete: relationships.complete,
    relationship_evidence_reason: relationships.reason,
    validation: {
      method: "sha256-full-generation-v1",
      row_count: verified.rows.length,
      rows_sha256: verified.rowsSha256,
    },
    exclusions: countTimelineExclusions(verified.rows, selection),
  };
}

/**
 * Validate a captured, explicitly synthetic generation received from a loader
 * that has already checked its scenario, query, package and readback hashes.
 * This routine independently validates the complete row set and extracts
 * retained relationships before a UI applies its selected time view.
 */
export async function validateCapturedChangeTimeline(input: {
  manifest: unknown;
  rows: unknown[];
  label: string;
}): Promise<ChangeTimelineResult> {
  const label = text(input.label, "Synthetic timeline label", 256);
  const manifest = validateManifest(input.manifest);
  if (
    new TextEncoder().encode(canonicalJson(manifest)).byteLength >
    MAX_MANIFEST_BYTES
  )
    throw new Error(
      "Captured timeline manifest exceeds the validation budget.",
    );
  const generationId = await sha256Hex(
    canonicalJson(withoutKeys(manifest, ["generation_id"])),
  );
  if (generationId !== manifest.generation_id)
    throw new Error("Captured timeline manifest hash is invalid.");
  const verified = await verifyGenerationRows(
    input.rows,
    manifest,
    generationId,
  );
  const relationships = await extractRetainedRelationships(
    verified.rows,
    generationId,
  );
  return {
    provenance: "synthetic_demo",
    label,
    manifest,
    rows: verified.rows,
    generation_rows: verified.rows,
    retained_relationships: relationships.relationships,
    relationship_evidence_complete: relationships.complete,
    relationship_evidence_reason: relationships.reason,
  };
}

export function viewsForTimelineResult(
  result: ChangeTimelineResult,
  selection: { scope: string; window: ChangeTimelineWindow },
  context?: ChangeTimelineContext,
): ChangeTimelineRecordView[] {
  const rows = filterTimelineRows(result.rows, selection);
  return rows.map((row) => ({
    row,
    attribution: attributeChangeRow(
      row,
      selection,
      context,
      result.retained_relationships ?? [],
      result.relationship_evidence_complete ?? true,
      result.relationship_evidence_reason,
    ),
    selected: false,
  }));
}

/** Used by tests and explicit result mode; no network or live fallback is performed. */
export function validateTimelineView(view: {
  scope: string;
  window: ChangeTimelineWindow;
}) {
  if (!view || typeof view.scope !== "string")
    throw new Error("Choose one verified routing scope.");
  routingScope(view.scope);
  if (!isTimelineWindow(view.window))
    throw new Error(
      "Choose one valid absolute history window of at most 24 hours.",
    );
  return view;
}
