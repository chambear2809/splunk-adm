export type L2ControlSourceKind = "stream_dhcp" | "syslog" | "dme" | "auto";

export interface L2ControlExtraConfig {
  sourceKind?: L2ControlSourceKind;
  dhcpNakWarnCount?: number;
  stpTcnWarnCount?: number;
  lacpDropWarnCount?: number;
}

export interface ResolvedL2ControlThresholds {
  sourceKind: L2ControlSourceKind;
  dhcpNakWarnCount: number;
  stpTcnWarnCount: number;
  lacpDropWarnCount: number;
}

export const DEFAULT_L2_CONTROL_THRESHOLDS: ResolvedL2ControlThresholds = {
  sourceKind: "auto",
  dhcpNakWarnCount: 1,
  stpTcnWarnCount: 1,
  lacpDropWarnCount: 1,
};

const ALLOWED_SOURCE_KINDS = new Set<string>([
  "stream_dhcp",
  "syslog",
  "dme",
  "auto",
]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "dhcpNakWarnCount",
  "stpTcnWarnCount",
  "lacpDropWarnCount",
]);

function assertPositiveIntInRange(
  value: unknown,
  keyName: string,
  min: number,
  max: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  ) {
    throw new Error(
      `l2_control extra.${keyName} must be an integer between ${min} and ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `l2_control`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateL2ControlExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported l2_control profile extra configuration key "${key}".`,
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
        'l2_control extra.sourceKind must be "stream_dhcp", "syslog", "dme", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.dhcpNakWarnCount !== undefined) {
    out.dhcpNakWarnCount = assertPositiveIntInRange(
      extra.dhcpNakWarnCount,
      "dhcpNakWarnCount",
      1,
      1000,
    );
  }
  if (extra.stpTcnWarnCount !== undefined) {
    out.stpTcnWarnCount = assertPositiveIntInRange(
      extra.stpTcnWarnCount,
      "stpTcnWarnCount",
      1,
      1000,
    );
  }
  if (extra.lacpDropWarnCount !== undefined) {
    out.lacpDropWarnCount = assertPositiveIntInRange(
      extra.lacpDropWarnCount,
      "lacpDropWarnCount",
      1,
      1000,
    );
  }
  return Object.keys(out).length ? out : undefined;
}
