import { fingerprint, literal } from "../../data/evidence";
import { optionalJobs } from "../../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
  type SearchClient,
} from "../../data/searchClient";
import {
  MAX_INPUT_ROWS,
  MAX_METRICS_WINDOW_SECONDS,
  sourceForLens,
  type BaseProtocolProfile,
  type ProtocolLensId,
  type ProtocolSourceOutcome,
} from "./contract";
import {
  assertNoForbiddenFieldsInSpl,
  isFieldAllowedForLens,
  projectRowToLensAllowlist,
} from "./fields";
import type { BoundedSearchResult, ProtocolRow } from "./runner";

/**
 * Literal Splunk metric-name grammar: allows dots, colons, underscores, and
 * hyphens (e.g. `sc4snmp.IF-MIB.ifHCInOctets`, `Cisco-IOS-XE-nve-oper`) while
 * strictly forbidding `*` wildcards and whitespace/SPL operators.
 */
export const METRIC_NAME_RE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
export const METRIC_DIMENSION_RE = /^[A-Za-z_][A-Za-z0-9._-]{0,127}$/;
export const METRIC_ALIAS_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
export const MAX_TREND_ENTITIES = 8;
export const MAX_TREND_BUCKETS = 32;

export type MetricAggregation = "avg" | "max" | "min" | "latest" | "rate";

export interface MetricSeriesSpec {
  metric: string;
  agg: MetricAggregation;
  alias: string;
}

export interface MetricFilterClause {
  field: string;
  op: "=" | "!=" | "IN";
  values: readonly string[];
}

export interface BoundedMetricsSummaryOptions {
  lens: ProtocolLensId;
  profile: BaseProtocolProfile;
  metrics: readonly MetricSeriesSpec[];
  dimensions: readonly string[];
  filters?: readonly MetricFilterClause[];
  rankBy?: string;
  earliest: number;
  latest: number;
  maxRows?: number;
  signal: AbortSignal;
  keySuffix?: string;
}

export interface BoundedMetricsTrendOptions extends Omit<
  BoundedMetricsSummaryOptions,
  "rankBy"
> {
  entityField: string;
  entityValues: readonly string[];
  spanSeconds?: number;
}

const VALID_AGGS = new Set<MetricAggregation>([
  "avg",
  "max",
  "min",
  "latest",
  "rate",
]);

function quoteMetricIdent(name: string): string {
  return /[:-]/.test(name) ? `"${name}"` : name;
}

function quoteDimIdent(name: string): string {
  return /[.-]/.test(name) ? `"${name}"` : name;
}

/**
 * Guards monotonic Counter64 `rate()` outputs against switch reboot counter
 * resets: returns `undefined` for negative or non-finite values instead of a
 * synthetic zero.
 */
export function clampNonNegativeRate(value: unknown): number | undefined {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n < 0) return undefined;
  return n;
}

/**
 * Computes a bounded `span` in seconds (>= 10s) ensuring `ceil(duration/span)`
 * stays at or below `maxBuckets` (default 32).
 */
export function autoMetricsSpanSeconds(
  earliest: number,
  latest: number,
  maxBuckets = MAX_TREND_BUCKETS,
  requestedSpan?: number,
): number {
  const duration = Math.trunc(latest) - Math.trunc(earliest);
  if (!Number.isFinite(duration) || duration <= 0) {
    throw new Error("Metrics window must have earliest < latest.");
  }
  // Size for (cap - 1) intervals because Splunk aligns span buckets to epoch
  // boundaries, which can add 1 partial bucket at the edges.
  const effectiveDivisor = Math.max(
    1,
    Math.min(MAX_TREND_BUCKETS, Math.trunc(maxBuckets)) - 1,
  );
  const minSpan = Math.max(10, Math.ceil(duration / effectiveDivisor));
  if (requestedSpan !== undefined) {
    if (!Number.isInteger(requestedSpan) || requestedSpan < 10) {
      throw new Error("Metrics spanSeconds must be an integer >= 10.");
    }
    return Math.max(minSpan, requestedSpan);
  }
  return minSpan;
}

function validateMetricsWindow(earliest: number, latest: number): void {
  const e = Math.trunc(earliest);
  const l = Math.trunc(latest);
  if (
    !Number.isFinite(e) ||
    !Number.isFinite(l) ||
    e <= 0 ||
    l <= e ||
    l - e > MAX_METRICS_WINDOW_SECONDS
  ) {
    throw new Error(
      `Metrics window must be positive and at most ${MAX_METRICS_WINDOW_SECONDS} seconds.`,
    );
  }
}

function validateSpecsAndDimensions(
  lens: ProtocolLensId,
  metrics: readonly MetricSeriesSpec[],
  dimensions: readonly string[],
  filters?: readonly MetricFilterClause[],
): { aggClause: string; dimClause: string; filterClause: string } {
  if (!metrics.length) {
    throw new Error(
      `Metrics query for "${lens}" requires at least one metric.`,
    );
  }
  if (!dimensions.length) {
    throw new Error(
      `Metrics query for "${lens}" requires at least one BY dimension.`,
    );
  }
  const aggParts: string[] = [];
  for (const spec of metrics) {
    if (!VALID_AGGS.has(spec.agg)) {
      throw new Error(`Unsupported metrics aggregation "${String(spec.agg)}".`);
    }
    if (!METRIC_NAME_RE.test(spec.metric)) {
      throw new Error(`Invalid metric name "${spec.metric}".`);
    }
    if (!METRIC_ALIAS_RE.test(spec.alias)) {
      throw new Error(`Invalid metric alias "${spec.alias}".`);
    }
    if (!isFieldAllowedForLens(lens, spec.alias)) {
      throw new Error(
        `Metric alias "${spec.alias}" is not allowlisted for protocol lens "${lens}".`,
      );
    }
    aggParts.push(
      `${spec.agg}(${quoteMetricIdent(spec.metric)}) AS ${spec.alias}`,
    );
  }
  const dimParts: string[] = [];
  for (const dim of dimensions) {
    if (!METRIC_DIMENSION_RE.test(dim)) {
      throw new Error(`Invalid metrics dimension "${dim}".`);
    }
    if (!isFieldAllowedForLens(lens, dim)) {
      throw new Error(
        `Metrics dimension "${dim}" is not allowlisted for protocol lens "${lens}".`,
      );
    }
    dimParts.push(quoteDimIdent(dim));
  }
  const filterParts: string[] = [];
  for (const clause of filters ?? []) {
    if (!METRIC_DIMENSION_RE.test(clause.field)) {
      throw new Error(`Invalid metrics filter field "${clause.field}".`);
    }
    if (!isFieldAllowedForLens(lens, clause.field)) {
      throw new Error(
        `Metrics filter field "${clause.field}" is not allowlisted for protocol lens "${lens}".`,
      );
    }
    if (!clause.values.length || clause.values.length > 64) {
      throw new Error(
        `Metrics filter "${clause.field}" must provide 1..64 literal values.`,
      );
    }
    const quotedVals = clause.values.map((v) => `"${literal(v, 128)}"`);
    const lhs = quoteDimIdent(clause.field);
    if (clause.op === "IN") {
      filterParts.push(`${lhs} IN (${quotedVals.join(", ")})`);
    } else if (clause.op === "=" || clause.op === "!=") {
      if (quotedVals.length !== 1) {
        throw new Error(
          `Metrics filter "${clause.field}" with "${clause.op}" requires exactly 1 value.`,
        );
      }
      filterParts.push(`${lhs}${clause.op}${quotedVals[0]}`);
    } else {
      throw new Error(
        `Unsupported metrics filter operator "${String(clause.op)}".`,
      );
    }
  }
  return {
    aggClause: aggParts.join(" "),
    dimClause: dimParts.join(" "),
    filterClause: filterParts.length ? ` AND ${filterParts.join(" AND ")}` : "",
  };
}

/**
 * Builds a bounded entity-summary `| mstats` query (no `span=`) ranked by
 * `rankBy` (default: first metric alias) so up to `maxRows` entities fit
 * without time-bucket multiplication or oldest-first truncation.
 */
export function buildBoundedMstatsSummarySpl(
  options: Omit<BoundedMetricsSummaryOptions, "signal" | "keySuffix">,
): string {
  validateMetricsWindow(options.earliest, options.latest);
  const maxRows = options.maxRows ?? MAX_INPUT_ROWS;
  if (!Number.isInteger(maxRows) || maxRows < 1 || maxRows > MAX_INPUT_ROWS) {
    throw new Error(
      `Metrics maxRows must be an integer between 1 and ${MAX_INPUT_ROWS}.`,
    );
  }
  const idx = literal(options.profile.index, 80);
  const { aggClause, dimClause, filterClause } = validateSpecsAndDimensions(
    options.lens,
    options.metrics,
    options.dimensions,
    options.filters,
  );
  const rankAlias = options.rankBy ?? options.metrics[0].alias;
  if (!options.metrics.some((m) => m.alias === rankAlias)) {
    throw new Error(
      `Metrics rankBy "${rankAlias}" must match one of the requested metric aliases.`,
    );
  }
  const spl =
    `| mstats ${aggClause} WHERE index=${idx}${filterClause} BY ${dimClause} ` +
    `| sort 0 - ${rankAlias} | head ${maxRows + 1}`;
  assertNoForbiddenFieldsInSpl(options.lens, spl);
  return spl;
}

/**
 * Builds a bounded top-N sparkline/trend `| mstats ... span=<N>s` query scoped
 * strictly to `<= 8` entities and `<= 32` buckets so `entities × buckets <= 256`.
 */
export function buildBoundedMstatsTrendSpl(
  options: Omit<BoundedMetricsTrendOptions, "signal" | "keySuffix">,
): string {
  validateMetricsWindow(options.earliest, options.latest);
  if (
    !options.entityValues.length ||
    options.entityValues.length > MAX_TREND_ENTITIES
  ) {
    throw new Error(
      `Metrics trend query requires 1..${MAX_TREND_ENTITIES} entityValues.`,
    );
  }
  if (!METRIC_DIMENSION_RE.test(options.entityField)) {
    throw new Error(`Invalid entityField "${options.entityField}".`);
  }
  if (!options.dimensions.includes(options.entityField)) {
    throw new Error(
      `Metrics trend entityField "${options.entityField}" must be included in dimensions.`,
    );
  }
  const maxRows = options.maxRows ?? MAX_INPUT_ROWS;
  if (!Number.isInteger(maxRows) || maxRows < 1 || maxRows > MAX_INPUT_ROWS) {
    throw new Error(
      `Metrics maxRows must be an integer between 1 and ${MAX_INPUT_ROWS}.`,
    );
  }
  const span = autoMetricsSpanSeconds(
    options.earliest,
    options.latest,
    MAX_TREND_BUCKETS,
    options.spanSeconds,
  );
  const idx = literal(options.profile.index, 80);
  const combinedFilters: MetricFilterClause[] = [
    ...(options.filters ?? []),
    {
      field: options.entityField,
      op: "IN",
      values: options.entityValues,
    },
  ];
  const { aggClause, dimClause, filterClause } = validateSpecsAndDimensions(
    options.lens,
    options.metrics,
    options.dimensions,
    combinedFilters,
  );
  const spl =
    `| mstats ${aggClause} WHERE index=${idx}${filterClause} span=${span}s BY ${dimClause} ` +
    `| sort 0 - _time | head ${maxRows + 1}`;
  assertNoForbiddenFieldsInSpl(options.lens, spl);
  return spl;
}

async function dispatchMetricsSpl(
  client: SearchClient,
  lens: ProtocolLensId,
  profile: BaseProtocolProfile,
  spl: string,
  rateAliases: readonly string[],
  earliest: number,
  latest: number,
  maxRows: number,
  signal: AbortSignal,
  keySuffix: string,
): Promise<BoundedSearchResult> {
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
  const key = `${profile.source}:${profile.id}:mstats:${earliest}:${latest}:${queryDigest.slice(0, 16)}`;
  try {
    const result = await optionalJobs.run(sourceForLens(lens), key, client, {
      search: spl,
      earliest: String(Math.trunc(earliest)),
      latest: String(Math.trunc(latest)),
      maxRows,
      allowEmpty: true,
      overflow: "truncate",
      signal: searchSignal,
    });
    requireNoSearchErrors(result, `${lens} metrics (${profile.id})`);
    const capped = Boolean(result.truncated) || result.rows.length > maxRows;
    const rawRows =
      result.rows.length > maxRows
        ? result.rows.slice(0, maxRows)
        : result.rows;
    const rows: ProtocolRow[] = rawRows.map((row) => {
      const projected = projectRowToLensAllowlist(lens, row);
      for (const alias of rateAliases) {
        if (alias in projected) {
          const clamped = clampNonNegativeRate(projected[alias]);
          if (clamped === undefined) {
            delete projected[alias];
          } else {
            projected[alias] = clamped;
          }
        }
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
          detail: "Caller lacks access to this metrics index.",
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
          error instanceof Error ? error.message : "Metrics search failed.",
      },
    };
  }
}

export async function runBoundedMetricsSummary(
  client: SearchClient,
  options: BoundedMetricsSummaryOptions,
): Promise<BoundedSearchResult> {
  const maxRows = options.maxRows ?? MAX_INPUT_ROWS;
  const spl = buildBoundedMstatsSummarySpl(options);
  const rateAliases = options.metrics
    .filter((m) => m.agg === "rate")
    .map((m) => m.alias);
  return dispatchMetricsSpl(
    client,
    options.lens,
    options.profile,
    spl,
    rateAliases,
    options.earliest,
    options.latest,
    maxRows,
    options.signal,
    options.keySuffix ?? "summary",
  );
}

export async function runBoundedMetricsTrend(
  client: SearchClient,
  options: BoundedMetricsTrendOptions,
): Promise<BoundedSearchResult> {
  const maxRows = options.maxRows ?? MAX_INPUT_ROWS;
  const spl = buildBoundedMstatsTrendSpl(options);
  const rateAliases = options.metrics
    .filter((m) => m.agg === "rate")
    .map((m) => m.alias);
  return dispatchMetricsSpl(
    client,
    options.lens,
    options.profile,
    spl,
    rateAliases,
    options.earliest,
    options.latest,
    maxRows,
    options.signal,
    options.keySuffix ?? "trend",
  );
}
