export type RoutingSourceKind = "syslog" | "dme" | "auto";
export type RoutingProtocolFilter = "all" | "bgp" | "ospf" | "bfd";

export interface RoutingExtraConfig {
  sourceKind?: RoutingSourceKind;
  flapWarnCount?: number;
  protocolFilter?: RoutingProtocolFilter;
}

export interface ResolvedRoutingThresholds {
  sourceKind: RoutingSourceKind;
  flapWarnCount: number;
  protocolFilter: RoutingProtocolFilter;
}

export const DEFAULT_ROUTING_THRESHOLDS: ResolvedRoutingThresholds = {
  sourceKind: "auto",
  flapWarnCount: 2,
  protocolFilter: "all",
};

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "flapWarnCount",
  "protocolFilter",
]);

const ALLOWED_SOURCE_KINDS = new Set<RoutingSourceKind>([
  "syslog",
  "dme",
  "auto",
]);

const ALLOWED_PROTOCOL_FILTERS = new Set<RoutingProtocolFilter>([
  "all",
  "bgp",
  "ospf",
  "bfd",
]);

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `routing`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateRoutingExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported routing profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourceKind !== undefined) {
    if (
      typeof extra.sourceKind !== "string" ||
      !ALLOWED_SOURCE_KINDS.has(extra.sourceKind as RoutingSourceKind)
    ) {
      throw new Error(
        'routing extra.sourceKind must be "syslog", "dme", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.flapWarnCount !== undefined) {
    if (
      typeof extra.flapWarnCount !== "number" ||
      !Number.isInteger(extra.flapWarnCount) ||
      extra.flapWarnCount < 1 ||
      extra.flapWarnCount > 1000
    ) {
      throw new Error(
        "routing extra.flapWarnCount must be an integer between 1 and 1000.",
      );
    }
    out.flapWarnCount = extra.flapWarnCount;
  }
  if (extra.protocolFilter !== undefined) {
    if (
      typeof extra.protocolFilter !== "string" ||
      !ALLOWED_PROTOCOL_FILTERS.has(
        extra.protocolFilter as RoutingProtocolFilter,
      )
    ) {
      throw new Error(
        'routing extra.protocolFilter must be "all", "bgp", "ospf", or "bfd".',
      );
    }
    out.protocolFilter = extra.protocolFilter;
  }
  return Object.keys(out).length ? out : undefined;
}
