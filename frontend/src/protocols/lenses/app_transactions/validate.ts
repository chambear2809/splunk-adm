export const APP_TRANSACTIONS_HTTP_SOURCETYPE = "stream:http" as const;
export const APP_TRANSACTIONS_OTEL_SOURCETYPE = "otel:traces" as const;

export const APP_TRANSACTIONS_DB_SOURCETYPES = [
  "stream:mysql",
  "stream:postgres",
  "stream:tds",
  "stream:tns",
] as const;

export const APP_TRANSACTIONS_SOURCETYPES = [
  APP_TRANSACTIONS_HTTP_SOURCETYPE,
  ...APP_TRANSACTIONS_DB_SOURCETYPES,
  APP_TRANSACTIONS_OTEL_SOURCETYPE,
] as const;

export const APP_TRANSACTIONS_STREAM_IDS = [
  "http",
  "mysql",
  "postgres",
  "tds",
  "tns",
] as const;

export type AppTransactionsSourcetype =
  (typeof APP_TRANSACTIONS_SOURCETYPES)[number];

export type AppTransactionsStreamId =
  (typeof APP_TRANSACTIONS_STREAM_IDS)[number];

export type AppTransactionsSourceKind = "auto" | "http" | "db" | "otel";

export interface AppTransactionsExtraConfig {
  sourceKind?: AppTransactionsSourceKind;
  errorRateWarnPct?: number;
  latencyWarnMs?: number;
}

export interface ResolvedAppTransactionsThresholds {
  sourceKind: AppTransactionsSourceKind;
  errorRateWarnPct: number;
  latencyWarnMs: number;
}

export const DEFAULT_APP_TRANSACTIONS_THRESHOLDS: ResolvedAppTransactionsThresholds =
  {
    sourceKind: "auto",
    errorRateWarnPct: 5,
    latencyWarnMs: 500,
  };

const ALLOWED_SOURCE_KINDS = new Set<string>(["auto", "http", "db", "otel"]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "errorRateWarnPct",
  "latencyWarnMs",
]);

function assertFiniteRange(
  value: unknown,
  key: string,
  min: number,
  max: number,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`app_transactions extra.${key} must be a finite number.`);
  }
  if (value <= min || value > max) {
    throw new Error(
      `app_transactions extra.${key} must be > ${min} and <= ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `app_transactions`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateAppTransactionsExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported app_transactions profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourceKind !== undefined) {
    if (
      typeof extra.sourceKind !== "string" ||
      !ALLOWED_SOURCE_KINDS.has(extra.sourceKind)
    ) {
      throw new Error(
        'app_transactions extra.sourceKind must be "auto", "http", "db", or "otel".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.errorRateWarnPct !== undefined) {
    out.errorRateWarnPct = assertFiniteRange(
      extra.errorRateWarnPct,
      "errorRateWarnPct",
      0,
      100,
    );
  }
  if (extra.latencyWarnMs !== undefined) {
    out.latencyWarnMs = assertFiniteRange(
      extra.latencyWarnMs,
      "latencyWarnMs",
      0,
      60_000,
    );
  }
  return Object.keys(out).length ? out : undefined;
}

export function resolveAppTransactionsThresholds(profile?: {
  extra?: Record<string, unknown>;
}): ResolvedAppTransactionsThresholds {
  const extra = profile?.extra as AppTransactionsExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "http" ||
      extra?.sourceKind === "db" ||
      extra?.sourceKind === "otel" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_APP_TRANSACTIONS_THRESHOLDS.sourceKind,
    errorRateWarnPct:
      typeof extra?.errorRateWarnPct === "number"
        ? extra.errorRateWarnPct
        : DEFAULT_APP_TRANSACTIONS_THRESHOLDS.errorRateWarnPct,
    latencyWarnMs:
      typeof extra?.latencyWarnMs === "number"
        ? extra.latencyWarnMs
        : DEFAULT_APP_TRANSACTIONS_THRESHOLDS.latencyWarnMs,
  };
}
