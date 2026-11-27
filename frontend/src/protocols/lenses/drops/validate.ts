export type DropsSourceKind =
  "ftd" | "hubble" | "nd" | "aci" | "firewall" | "auto";

export interface DropsExtraConfig {
  sourceKind?: DropsSourceKind;
  sourcetype?: string;
  dropWarnCount?: number;
}

export interface ResolvedDropsThresholds {
  sourceKind: DropsSourceKind;
  sourcetype?: string;
  dropWarnCount: number;
}

export const DEFAULT_DROPS_THRESHOLDS: ResolvedDropsThresholds = {
  sourceKind: "auto",
  dropWarnCount: 1,
};

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "sourcetype",
  "dropWarnCount",
]);

const ALLOWED_SOURCE_KINDS = new Set<DropsSourceKind>([
  "ftd",
  "hubble",
  "nd",
  "aci",
  "firewall",
  "auto",
]);

const SOURCETYPE_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,79}$/;

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `drops`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateDropsExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported drops profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourceKind !== undefined) {
    if (
      typeof extra.sourceKind !== "string" ||
      !ALLOWED_SOURCE_KINDS.has(extra.sourceKind as DropsSourceKind)
    ) {
      throw new Error(
        'drops extra.sourceKind must be "ftd", "hubble", "nd", "aci", "firewall", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.sourcetype !== undefined) {
    if (
      typeof extra.sourcetype !== "string" ||
      !SOURCETYPE_RE.test(extra.sourcetype)
    ) {
      throw new Error(
        "drops extra.sourcetype must be a valid sourcetype string (1-80 characters).",
      );
    }
    out.sourcetype = extra.sourcetype;
  }
  if (extra.dropWarnCount !== undefined) {
    if (
      typeof extra.dropWarnCount !== "number" ||
      !Number.isInteger(extra.dropWarnCount) ||
      extra.dropWarnCount < 1 ||
      extra.dropWarnCount > 1_000_000
    ) {
      throw new Error(
        "drops extra.dropWarnCount must be an integer between 1 and 1000000.",
      );
    }
    out.dropWarnCount = extra.dropWarnCount;
  }
  return Object.keys(out).length ? out : undefined;
}
