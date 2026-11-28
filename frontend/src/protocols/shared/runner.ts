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
  MAX_WINDOW_SECONDS,
  PROTOCOL_VERSION,
  sourceForLens,
  type BaseProtocolProfile,
  type LensProfileValidator,
  type ProtocolConfiguration,
  type ProtocolLensId,
  type ProtocolSourceOutcome,
  type ProtocolStatus,
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
  /**
   * Optional override for Splunk job dispatch `earliest` / `latest` bounds
   * (e.g. a bounded lookback window when SPL embeds explicit `earliest=` /
   * `_index_earliest=` predicates for polled DME snapshots whose `_time` carries
   * historical `modTs`).
   */
  dispatchEarliest?: string;
  dispatchLatest?: string;
  /**
   * Optional pre-dedup `| head <N>` scan limit embedded in DME snapshot SPL.
   * When returned rows carry `_pre_dedup_count >= preDedupLimit`, the search is
   * marked `capped` even if post-dedup rows are fewer than `maxRows`.
   */
  preDedupLimit?: number;
  maxRows?: number;
  includeRowExpansion?: boolean;
  signal: AbortSignal;
  keySuffix?: string;
}

/**
 * Selects profiles for `(lens, scope)` that cover `[earliest, latest]`.
 * If one or more profiles cover the window, expired or future rotated profiles
 * are excluded so they do not inject spurious `unavailable` outcomes. If no
 * profile covers the window, all scoped profiles are returned so the runner
 * surfaces the validity-window gap explicitly.
 */
export function selectActiveProfiles(
  profiles: readonly BaseProtocolProfile[],
  lens: ProtocolLensId,
  scope: string,
  earliest: number,
  latest: number,
): BaseProtocolProfile[] {
  const scoped = profiles.filter((p) => p.lens === lens && p.scope === scope);
  if (scoped.length <= 1) return scoped;
  const covering = scoped.filter(
    (p) => earliest >= p.validFrom && latest <= p.validUntil,
  );
  return covering.length > 0 ? covering : scoped;
}

/**
 * A healthy verdict is only valid when every configured source answered in
 * full for this scope alone. When any source was capped, blocked, failed, or
 * partial, or reads an index shared with another scope, downgrade `ok` to
 * `attention` and say so in the verdict sentence.
 */
export function qualifyVerdictForDegradedSources(
  verdict: string,
  verdictStatus: ProtocolStatus,
  degraded: boolean,
  outcomes: readonly ProtocolSourceOutcome[] = [],
): { verdict: string; verdictStatus: ProtocolStatus } {
  const sharedScopes = [
    ...new Set(outcomes.flatMap((o) => o.sharedIndexScopes ?? [])),
  ].sort((a, b) => a.localeCompare(b, "en"));
  if (verdictStatus !== "ok" || (!degraded && !sharedScopes.length))
    return { verdict, verdictStatus };
  const notes: string[] = [];
  if (degraded)
    notes.push("one or more sources were capped, blocked, or unavailable");
  if (sharedScopes.length)
    notes.push(
      `the index is shared with scope ${sharedScopes.slice(0, 3).join(", ")}${sharedScopes.length > 3 ? ` and ${sharedScopes.length - 3} more` : ""}, so results can include its events`,
    );
  return {
    verdict: `${verdict.replace(/\.$/, "")}, but ${notes.join(" and ")}.`,
    verdictStatus: "attention",
  };
}

/**
 * Builds an explicit dual-window SPL predicate matching events whose `_time` OR
 * `_indextime` falls inside `[earliest, latest]`. Cisco DCN 2.0.10 DME inputs
 * stamp `_time` from NX-OS `modTs` (which can be days or months old for stable
 * interfaces, STP roots, port-channels, and OSPF adjacencies) while polling
 * continuously at `_indextime`; matching either ensures both live DME polls and
 * historical fixtures within the UTC window are returned.
 */
export function buildDmeWindowPredicate(
  earliest?: number,
  latest?: number,
): string | undefined {
  if (earliest === undefined || latest === undefined) return undefined;
  const e = Math.trunc(earliest);
  const l = Math.trunc(latest);
  if (!Number.isFinite(e) || !Number.isFinite(l) || l <= e) return undefined;
  return `((earliest=${e} latest=${l}) OR (_index_earliest=${e} _index_latest=${l}))`;
}

const DME_MAX_MODTS_LOOKBACK_SEC = 180 * 86400;
const DME_STATE_SNAPSHOT_WINDOW_SEC = 1800;

/**
 * Shared pre-dedup raw-event scan cap for DME snapshot queries so builder SPL
 * and `runBoundedProtocolSearch` truncation detection always agree.
 */
export function dmePreDedupLimit(maxRows: number): number {
  const headLimit = Math.max(1, Math.trunc(maxRows)) + 1;
  return Math.max(2048, headLimit * 8);
}

/**
 * Builds a snapshot-scoped dual-window predicate whose `_index_earliest`
 * covers at most the last 30 minutes (`DME_STATE_SNAPSHOT_WINDOW_SEC = 1800`)
 * within `[earliest, latest]`, accommodating 5m–15m DCN poll intervals plus
 * ingest lag while preventing repeated polls over long windows from starving
 * older `modTs` objects before `dedup`.
 */
export function buildDmeSnapshotWindowPredicate(
  earliest?: number,
  latest?: number,
): string | undefined {
  if (earliest === undefined || latest === undefined) return undefined;
  const e = Math.trunc(earliest);
  const l = Math.trunc(latest);
  if (!Number.isFinite(e) || !Number.isFinite(l) || l <= e) return undefined;
  const idxEarliest = Math.max(e, l - DME_STATE_SNAPSHOT_WINDOW_SEC);
  return `((earliest=${e} latest=${l}) OR (_index_earliest=${idxEarliest} _index_latest=${l}))`;
}

/**
 * Computes bounded Splunk job dispatch `earliest` / `latest` bounds for DME
 * snapshot searches so `_index_earliest` catches stable objects with older
 * `modTs` (up to 180 days before the requested window, even when the profile
 * itself was created more recently) without scanning back to epoch 0.
 */
export function buildDmeDispatchBounds(
  _profile: BaseProtocolProfile,
  earliest: number,
  latest: number,
): { dispatchEarliest?: string; dispatchLatest?: string } {
  if (!buildDmeWindowPredicate(earliest, latest)) return {};
  const boundedEarliest = Math.max(
    0,
    Math.trunc(earliest) - DME_MAX_MODTS_LOOKBACK_SEC,
  );
  return {
    dispatchEarliest: String(boundedEarliest),
    dispatchLatest: String(Math.trunc(latest)),
  };
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
  if (
    !Number.isFinite(earliest) ||
    !Number.isFinite(latest) ||
    latest <= earliest ||
    latest - earliest > MAX_WINDOW_SECONDS
  ) {
    throw new Error(
      `Protocol event search window must be between 1 and ${MAX_WINDOW_SECONDS} seconds.`,
    );
  }
  assertNoForbiddenFieldsInSpl(lens, spl);
  const outcomeBase: ProtocolSourceOutcome = {
    source: profile.source,
    profile: profile.id,
    state: "unavailable",
    ...(profile.sharedIndexScopes?.length
      ? { sharedIndexScopes: profile.sharedIndexScopes }
      : {}),
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
      earliest: options.dispatchEarliest ?? String(earliest),
      latest: options.dispatchLatest ?? String(latest),
      maxRows,
      allowEmpty: true,
      overflow: "truncate",
      signal: searchSignal,
    });
    requireNoSearchErrors(result, `${lens} (${profile.id})`);
    const preDedupCapped =
      options.preDedupLimit !== undefined &&
      result.rows.some((row) => {
        const n = Number(row._pre_dedup_count);
        return Number.isFinite(n) && n >= options.preDedupLimit!;
      });
    const capped =
      Boolean(result.truncated) ||
      result.rows.length > maxRows ||
      preDedupCapped;
    const rawRows =
      result.rows.length > maxRows
        ? result.rows.slice(0, maxRows)
        : result.rows;
    const rows = rawRows.map((row) => {
      const projected = projectRowToLensAllowlist(lens, row, {
        includeRowExpansion,
      });
      if ("_pre_dedup_count" in projected) {
        delete projected._pre_dedup_count;
      }
      return projected;
    });
    return {
      rows,
      capped,
      outcome: {
        ...outcomeBase,
        state: capped ? "partial" : "complete",
        inputRows: rows.length,
        capped,
        ...(capped
          ? {
              detail: preDedupCapped
                ? `Pre-dedup scan capped at ${options.preDedupLimit} events.`
                : `Capped at ${maxRows} rows.`,
            }
          : {}),
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
