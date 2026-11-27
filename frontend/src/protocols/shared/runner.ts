import { fingerprint } from "../../data/evidence";
import { protocolConfigClient } from "../../data/evidenceConfig";
import { optionalJobs } from "../../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
  type SearchClient,
} from "../../data/searchClient";
import { parseProtocolProfiles } from "../inputs";
import {
  MAX_INPUT_ROWS,
  PROTOCOL_VERSION,
  sourceForLens,
  type BaseProtocolProfile,
  type LensProfileValidator,
  type ProtocolConfiguration,
  type ProtocolLensId,
  type ProtocolSourceOutcome,
} from "./contract";
import {
  assertNoForbiddenFieldsInSpl,
  projectRowToLensAllowlist,
} from "./fields";

export type ProtocolRow = Record<string, unknown>;

export class ProtocolConfigurationChangedError extends Error {
  constructor() {
    super(
      "Protocol source configuration changed. Refresh sources and investigate again.",
    );
    this.name = "ProtocolConfigurationChangedError";
  }
}

export async function readProtocolConfiguration(
  validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {},
  signal?: AbortSignal,
): Promise<ProtocolConfiguration> {
  const profiles = parseProtocolProfiles(
    await protocolConfigClient.readProtocolProfileDocument(signal),
    validators,
  );
  signal?.throwIfAborted();
  return {
    profiles,
    fingerprint: await fingerprint([PROTOCOL_VERSION, profiles]),
  };
}

export interface BoundedSearchOptions {
  lens: ProtocolLensId;
  profile: BaseProtocolProfile;
  spl: string;
  earliest: number;
  latest: number;
  maxRows?: number;
  includeRowExpansion?: boolean;
  signal: AbortSignal;
  keySuffix?: string;
}

export interface BoundedSearchResult {
  rows: ProtocolRow[];
  capped: boolean;
  outcome: ProtocolSourceOutcome;
}

/**
 * Dispatches one caller-owned, bounded, on-demand search for a protocol lens
 * through `optionalJobs`, enforcing sensitive-field guards, allowlist row
 * projection, empty-result handling, and row caps.
 */
export async function runBoundedProtocolSearch(
  client: SearchClient,
  options: BoundedSearchOptions,
): Promise<BoundedSearchResult> {
  const {
    lens,
    profile,
    spl,
    earliest,
    latest,
    signal,
    includeRowExpansion = false,
    keySuffix = "",
  } = options;
  const requestedRows = options.maxRows ?? MAX_INPUT_ROWS;
  if (
    !Number.isInteger(requestedRows) ||
    requestedRows < 1 ||
    requestedRows > MAX_INPUT_ROWS
  ) {
    throw new Error(
      `Protocol search maxRows must be an integer between 1 and ${MAX_INPUT_ROWS}.`,
    );
  }
  const maxRows = requestedRows;
  assertNoForbiddenFieldsInSpl(lens, spl);
  const outcomeBase: ProtocolSourceOutcome = {
    source: profile.source,
    profile: profile.id,
    state: "unavailable",
  };
  if (earliest < profile.validFrom || latest > profile.validUntil) {
    return {
      rows: [],
      capped: false,
      outcome: {
        ...outcomeBase,
        detail: "Profile validity does not cover the selected UTC window.",
      },
    };
  }
  const queryDigest = await fingerprint([spl, maxRows, keySuffix]);
  signal.throwIfAborted();
  const deadline = AbortSignal.timeout(35000);
  const searchSignal = AbortSignal.any([signal, deadline]);
  const key = `${profile.source}:${profile.id}:${earliest}:${latest}:${queryDigest.slice(0, 16)}`;
  try {
    const result = await optionalJobs.run(sourceForLens(lens), key, client, {
      search: spl,
      earliest: String(earliest),
      latest: String(latest),
      maxRows,
      allowEmpty: true,
      overflow: "truncate",
      signal: searchSignal,
    });
    requireNoSearchErrors(result, `${lens} (${profile.id})`);
    const capped = Boolean(result.truncated) || result.rows.length > maxRows;
    const rawRows =
      result.rows.length > maxRows
        ? result.rows.slice(0, maxRows)
        : result.rows;
    const rows = rawRows.map((row) =>
      projectRowToLensAllowlist(lens, row, { includeRowExpansion }),
    );
    return {
      rows,
      capped,
      outcome: {
        ...outcomeBase,
        state: capped ? "partial" : "complete",
        inputRows: rows.length,
        capped,
        ...(capped ? { detail: `Capped at ${maxRows} rows.` } : {}),
      },
    };
  } catch (error) {
    if (error instanceof SearchAccessDeniedError) {
      return {
        rows: [],
        capped: false,
        outcome: {
          ...outcomeBase,
          state: "blocked",
          detail: "Caller lacks access to this source index.",
        },
      };
    }
    if (signal.aborted) throw error;
    return {
      rows: [],
      capped: false,
      outcome: {
        ...outcomeBase,
        state: "unavailable",
        detail:
          error instanceof Error ? error.message : "Protocol search failed.",
      },
    };
  }
}

/**
 * Verifies the active `adm_protocol_profiles` fingerprint did not change while
 * searches ran; rejects late evidence if it did.
 */
export async function withProtocolConfigRecheck<T>(
  expectedFingerprint: string,
  validators: Partial<Record<ProtocolLensId, LensProfileValidator>>,
  work: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const value = await work();
  const current = await readProtocolConfiguration(validators, signal);
  if (current.fingerprint !== expectedFingerprint)
    throw new ProtocolConfigurationChangedError();
  return value;
}
