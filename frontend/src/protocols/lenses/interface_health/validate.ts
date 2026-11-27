export type InterfaceHealthSourceKind = "dme" | "syslog" | "auto";

export interface InterfaceHealthExtraConfig {
  sourceKind?: InterfaceHealthSourceKind;
  errorWarnCount?: number;
  discardWarnCount?: number;
  flapWarnCount?: number;
  utilizationWarnPct?: number;
}

export interface ResolvedInterfaceHealthThresholds {
  sourceKind: InterfaceHealthSourceKind;
  errorWarnCount: number;
  discardWarnCount: number;
  flapWarnCount: number;
  utilizationWarnPct: number;
}

export const DEFAULT_INTERFACE_HEALTH_THRESHOLDS: ResolvedInterfaceHealthThresholds =
  {
    sourceKind: "auto",
    errorWarnCount: 1,
    discardWarnCount: 10,
    flapWarnCount: 2,
    utilizationWarnPct: 80,
  };

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "errorWarnCount",
  "discardWarnCount",
  "flapWarnCount",
  "utilizationWarnPct",
]);

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on
 * `interface_health`. Kept in a dependency-free module so `registry.ts` stays light.
 */
export function validateInterfaceHealthExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported interface_health profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourceKind !== undefined) {
    if (
      extra.sourceKind !== "dme" &&
      extra.sourceKind !== "syslog" &&
      extra.sourceKind !== "auto"
    ) {
      throw new Error(
        'interface_health extra.sourceKind must be "dme", "syslog", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.errorWarnCount !== undefined) {
    if (
      typeof extra.errorWarnCount !== "number" ||
      !Number.isInteger(extra.errorWarnCount) ||
      extra.errorWarnCount < 1 ||
      extra.errorWarnCount > 1_000_000
    ) {
      throw new Error(
        "interface_health extra.errorWarnCount must be an integer between 1 and 1000000.",
      );
    }
    out.errorWarnCount = extra.errorWarnCount;
  }
  if (extra.discardWarnCount !== undefined) {
    if (
      typeof extra.discardWarnCount !== "number" ||
      !Number.isInteger(extra.discardWarnCount) ||
      extra.discardWarnCount < 1 ||
      extra.discardWarnCount > 1_000_000
    ) {
      throw new Error(
        "interface_health extra.discardWarnCount must be an integer between 1 and 1000000.",
      );
    }
    out.discardWarnCount = extra.discardWarnCount;
  }
  if (extra.flapWarnCount !== undefined) {
    if (
      typeof extra.flapWarnCount !== "number" ||
      !Number.isInteger(extra.flapWarnCount) ||
      extra.flapWarnCount < 1 ||
      extra.flapWarnCount > 1_000
    ) {
      throw new Error(
        "interface_health extra.flapWarnCount must be an integer between 1 and 1000.",
      );
    }
    out.flapWarnCount = extra.flapWarnCount;
  }
  if (extra.utilizationWarnPct !== undefined) {
    if (
      typeof extra.utilizationWarnPct !== "number" ||
      !Number.isFinite(extra.utilizationWarnPct) ||
      extra.utilizationWarnPct <= 0 ||
      extra.utilizationWarnPct > 100
    ) {
      throw new Error(
        "interface_health extra.utilizationWarnPct must be a positive number up to 100.",
      );
    }
    out.utilizationWarnPct = extra.utilizationWarnPct;
  }
  return Object.keys(out).length ? out : undefined;
}
