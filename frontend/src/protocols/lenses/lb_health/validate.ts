export type LbHealthSourceKind = "auto" | "f5_ltm" | "aws_alb" | "aws_nlb";

export interface LbHealthExtraConfig {
  sourceKind?: LbHealthSourceKind;
  errorRateWarnPct?: number;
  latencyWarnMs?: number;
  lbFailedWarnCount?: number;
}

export interface ResolvedLbHealthThresholds {
  sourceKind: LbHealthSourceKind;
  errorRateWarnPct: number;
  latencyWarnMs: number;
  lbFailedWarnCount: number;
}

export const DEFAULT_LB_HEALTH_THRESHOLDS: ResolvedLbHealthThresholds = {
  sourceKind: "auto",
  errorRateWarnPct: 2,
  latencyWarnMs: 500,
  lbFailedWarnCount: 1,
};

const ALLOWED_SOURCE_KINDS = new Set<string>([
  "auto",
  "f5_ltm",
  "aws_alb",
  "aws_nlb",
]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "errorRateWarnPct",
  "latencyWarnMs",
  "lbFailedWarnCount",
]);

function assertFiniteInRange(
  value: unknown,
  keyName: string,
  min: number,
  max: number,
  options?: { minExclusive?: boolean; integer?: boolean },
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`lb_health extra.${keyName} must be a finite number.`);
  }
  if (options?.integer && !Number.isInteger(value)) {
    throw new Error(`lb_health extra.${keyName} must be an integer.`);
  }
  const tooLow = options?.minExclusive ? value <= min : value < min;
  if (tooLow || value > max) {
    const lower = options?.minExclusive ? `> ${min}` : `>= ${min}`;
    throw new Error(
      `lb_health extra.${keyName} must be ${lower} and <= ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `lb_health`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateLbHealthExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported lb_health profile extra configuration key "${key}".`,
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
        'lb_health extra.sourceKind must be "auto", "f5_ltm", "aws_alb", or "aws_nlb".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.errorRateWarnPct !== undefined) {
    out.errorRateWarnPct = assertFiniteInRange(
      extra.errorRateWarnPct,
      "errorRateWarnPct",
      0,
      100,
      { minExclusive: true },
    );
  }
  if (extra.latencyWarnMs !== undefined) {
    out.latencyWarnMs = assertFiniteInRange(
      extra.latencyWarnMs,
      "latencyWarnMs",
      0,
      60_000,
      { minExclusive: true },
    );
  }
  if (extra.lbFailedWarnCount !== undefined) {
    out.lbFailedWarnCount = assertFiniteInRange(
      extra.lbFailedWarnCount,
      "lbFailedWarnCount",
      1,
      1000,
      { integer: true },
    );
  }
  return Object.keys(out).length ? out : undefined;
}
