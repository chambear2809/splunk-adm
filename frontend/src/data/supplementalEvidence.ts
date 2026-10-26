import type { Row } from "../rows";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
  type SupplementalSource,
} from "./evidence";
import { optionalJobs } from "./optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "./searchClient";

export interface SupplementalResult<T> {
  schemaVersion: 1;
  source: SupplementalSource;
  selection: EvidenceSelection;
  capturedAt: number;
  inspectedWindow: EvidenceWindow;
  configurationFingerprint: string;
  configurationChanged: boolean;
  state: "not_selected" | "staged" | "complete" | "unavailable";
  schemaQualified: boolean;
  inputCount: number;
  inputCapped: boolean;
  outputCapped: boolean;
  /** Source-wide scan before source-specific revision/identity filtering. */
  sourceScanCount?: number;
  sourceScanCapped?: boolean;
  sourceScanInvalidCount?: number;
  rejected: number;
  oversized: number;
  records: T[];
  coverage: string[];
  errorCode?:
    "configuration" | "execution" | "completion" | "normalization" | "denied";
  error?: string;
}

function nonnegativeCount(value: unknown): number {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    !/^\d+$/.test(String(value)) ||
    !Number.isSafeInteger(Number(value))
  )
    throw new Error("Invalid supplemental completion count.");
  return Number(value);
}

/** Every optional search must account for every transported row. */
export function parseSupplementalEnvelope(rows: readonly Row[]) {
  const metadata = rows.filter((row) => row.kind === "supplemental_completion");
  const records = rows.filter((row) => row.kind === "supplemental_record");
  if (
    metadata.length !== 1 ||
    metadata.length + records.length !== rows.length ||
    nonnegativeCount(metadata[0].schema_version) !== 1
  )
    throw new Error("Supplemental completion envelope is missing or invalid.");
  const meta = metadata[0];
  const inputCount = nonnegativeCount(meta.input_count);
  const returnedCount = nonnegativeCount(meta.returned_count);
  const inputCapped = nonnegativeCount(meta.input_capped);
  const oversized = nonnegativeCount(meta.oversized);
  const hasSourceScan =
    meta.source_scan_count !== undefined ||
    meta.source_scan_capped !== undefined;
  const sourceScanCount = hasSourceScan
    ? nonnegativeCount(meta.source_scan_count)
    : undefined;
  const sourceScanCapped = hasSourceScan
    ? nonnegativeCount(meta.source_scan_capped)
    : undefined;
  const sourceScanInvalidCount =
    meta.source_scan_invalid_count !== undefined
      ? nonnegativeCount(meta.source_scan_invalid_count)
      : undefined;
  if (
    returnedCount !== records.length ||
    returnedCount !== Math.min(inputCount, EVIDENCE_LIMITS.records) ||
    inputCount > EVIDENCE_LIMITS.input + 1 ||
    inputCapped !== Number(inputCount > EVIDENCE_LIMITS.input) ||
    oversized > inputCount ||
    (sourceScanInvalidCount !== undefined &&
      (!hasSourceScan || sourceScanInvalidCount > sourceScanCount!)) ||
    (hasSourceScan &&
      (sourceScanCount! > EVIDENCE_LIMITS.input + 1 ||
        inputCount > sourceScanCount! ||
        sourceScanCapped !== Number(sourceScanCount! > EVIDENCE_LIMITS.input)))
  )
    throw new Error("Supplemental completion counts disagree.");
  return {
    rows: records,
    inputCount,
    inputCapped: inputCapped === 1,
    outputCapped: inputCount > returnedCount,
    oversized,
    ...(hasSourceScan
      ? {
          sourceScanCount,
          sourceScanCapped: sourceScanCapped === 1,
          sourceScanInvalidCount,
        }
      : {}),
  };
}

export type SupplementalSearchBuilder = (
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
) => string;
export type SupplementalNormalizer<T> = (
  rows: readonly Row[],
  selection: EvidenceSelection,
  config: SupplementalSourceConfiguration,
) => { records: T[]; rejected: number };

/** Caller-owned search, exact completion, bounded admission and config recheck. */
export async function loadSupplementalEvidence<T>(
  client: SearchClient,
  input: EvidenceSelection,
  signal: AbortSignal,
  sourceId: SupplementalSource,
  buildSearch: SupplementalSearchBuilder,
  normalize: SupplementalNormalizer<T>,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
  diagnostic = false,
  searchWindow: (
    selection: EvidenceSelection,
    source: SupplementalSourceConfiguration,
  ) => EvidenceWindow = (selection) => selection.window,
  coverage: readonly string[] = [],
): Promise<SupplementalResult<T>> {
  const selection = validateSelection(input);
  const config = await configurationClient.read(
    signal,
    selection.identityAddresses ?? selection.addresses,
    selection.scope,
  );
  if (config.fingerprint !== selection.configurationFingerprint)
    throw new Error("Evidence configuration changed. Refresh the selection.");
  const source = config.supplemental?.find(
    (entry) => entry.source === sourceId,
  );
  if (!source) throw new Error("Optional source configuration is unavailable.");
  const inspectedWindow = searchWindow(selection, source);
  if (
    !Number.isFinite(inspectedWindow.start) ||
    !Number.isFinite(inspectedWindow.end) ||
    inspectedWindow.start < 0 ||
    inspectedWindow.end <= inspectedWindow.start ||
    inspectedWindow.end > 253402300799
  )
    throw new Error("Invalid optional evidence search interval.");
  const stagedDiagnostic = source.state === "staged" && diagnostic;
  const base: SupplementalResult<T> = {
    schemaVersion: 1,
    source: sourceId,
    selection,
    capturedAt: Date.now() / 1000,
    inspectedWindow,
    configurationFingerprint: config.fingerprint,
    configurationChanged: false,
    state: source.state === "active" ? "unavailable" : source.state,
    schemaQualified: source.schemaQualified && !stagedDiagnostic,
    inputCount: 0,
    inputCapped: false,
    outputCapped: false,
    sourceScanCount: undefined,
    sourceScanCapped: undefined,
    sourceScanInvalidCount: undefined,
    rejected: 0,
    oversized: 0,
    records: [],
    coverage: [...coverage],
  };
  if (source.state !== "active" && !stagedDiagnostic) return base;
  let stage: NonNullable<SupplementalResult<T>["errorCode"]> = "configuration";
  try {
    const effective = stagedDiagnostic
      ? { ...source, state: "active" as const }
      : source;
    const search = buildSearch(effective, selection);
    const key = await fingerprint([
      config.fingerprint,
      sourceId,
      selection,
      search,
      inspectedWindow,
    ]);
    stage = "execution";
    const result = requireNoSearchErrors(
      await optionalJobs.run(sourceId, key, client, {
        search,
        earliest: String(inspectedWindow.start),
        latest: String(inspectedWindow.end),
        maxRows: EVIDENCE_LIMITS.records + 1,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
        signal,
      }),
      "Supplemental evidence",
    );
    stage = "completion";
    if (result.warnings.length)
      throw new Error(
        "Splunk warnings prevent source completeness verification.",
      );
    const envelope = parseSupplementalEnvelope(result.rows);
    base.sourceScanCount = envelope.sourceScanCount;
    base.sourceScanCapped = envelope.sourceScanCapped;
    base.sourceScanInvalidCount = envelope.sourceScanInvalidCount;
    if (envelope.sourceScanCapped)
      throw new Error("The source-wide history scan exceeded its row cap.");
    if (envelope.sourceScanInvalidCount)
      throw new Error(
        "The source-wide history scan contained invalid revision identity.",
      );
    if (
      envelope.rows.some(
        (row) =>
          typeof row.index !== "string" || !source.indexes.includes(row.index),
      )
    )
      throw new Error(
        "Optional result origin does not match source configuration.",
      );
    stage = "normalization";
    const normalized = normalize(envelope.rows, selection, effective);
    if (
      !Number.isSafeInteger(normalized.rejected) ||
      normalized.rejected < 0 ||
      normalized.records.length > EVIDENCE_LIMITS.records
    )
      throw new Error("Invalid source normalization counts.");
    base.state = "complete";
    base.inputCount = envelope.inputCount;
    base.inputCapped = envelope.inputCapped;
    base.outputCapped = envelope.outputCapped;
    base.sourceScanCount = envelope.sourceScanCount;
    base.sourceScanCapped = envelope.sourceScanCapped;
    base.sourceScanInvalidCount = envelope.sourceScanInvalidCount;
    base.rejected = normalized.rejected;
    base.oversized = envelope.oversized;
    base.records = normalized.records;
  } catch (error) {
    if (signal.aborted)
      throw new Error("Optional investigation cancelled.", { cause: error });
    base.state = "unavailable";
    base.errorCode =
      error instanceof SearchAccessDeniedError ? "denied" : stage;
    base.error =
      error instanceof SearchAccessDeniedError
        ? "Splunk denied access to this evidence search. Ask an administrator to verify caller permissions."
        : "Optional evidence unavailable: configuration, permissions, execution or completion could not be verified.";
  }
  if (signal.aborted) throw new Error("Optional investigation cancelled.");
  let after;
  try {
    after = await configurationClient.read(
      signal,
      selection.identityAddresses ?? selection.addresses,
      selection.scope,
    );
  } catch {
    // An unreadable configuration invalidates every prior association.
  }
  base.configurationChanged =
    !after || after.fingerprint !== config.fingerprint;
  if (base.configurationChanged) {
    base.schemaQualified = false;
    base.state = "unavailable";
    base.records = [];
    base.errorCode = "configuration";
    base.error = "Optional evidence configuration changed during the search.";
    base.coverage.push(
      "Configuration changed or became unreadable after capture; association is invalid until refreshed.",
    );
  }
  return base;
}
