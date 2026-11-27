export type EndpointMobilitySourceKind =
  "stream_arp" | "nd_endpoints" | "aci_fvcep" | "dme" | "syslog" | "auto";

export interface EndpointMobilityExtraConfig {
  sourceKind?: EndpointMobilitySourceKind;
  arpSpikeWarnCount?: number;
  macMoveWarnCount?: number;
  portFlapWarnCount?: number;
  anomalyScoreWarn?: number;
}

export interface ResolvedEndpointMobilityThresholds {
  sourceKind: EndpointMobilitySourceKind;
  arpSpikeWarnCount: number;
  macMoveWarnCount: number;
  portFlapWarnCount: number;
  anomalyScoreWarn: number;
}

export const DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS: ResolvedEndpointMobilityThresholds =
  {
    sourceKind: "auto",
    arpSpikeWarnCount: 20,
    macMoveWarnCount: 1,
    portFlapWarnCount: 2,
    anomalyScoreWarn: 50,
  };

const ALLOWED_SOURCE_KINDS = new Set<string>([
  "stream_arp",
  "nd_endpoints",
  "aci_fvcep",
  "dme",
  "syslog",
  "auto",
]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "arpSpikeWarnCount",
  "macMoveWarnCount",
  "portFlapWarnCount",
  "anomalyScoreWarn",
]);

function assertIntInRange(
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
      `endpoint_mobility extra.${keyName} must be an integer between ${min} and ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on
 * `endpoint_mobility`. Kept in its own dependency-free module so `registry.ts`
 * never eagerly pulls in the lens adapter or React view into `protocols-core`.
 */
export function validateEndpointMobilityExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported endpoint_mobility profile extra configuration key "${key}".`,
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
        'endpoint_mobility extra.sourceKind must be "stream_arp", "nd_endpoints", "aci_fvcep", "dme", "syslog", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.arpSpikeWarnCount !== undefined) {
    out.arpSpikeWarnCount = assertIntInRange(
      extra.arpSpikeWarnCount,
      "arpSpikeWarnCount",
      1,
      100000,
    );
  }
  if (extra.macMoveWarnCount !== undefined) {
    out.macMoveWarnCount = assertIntInRange(
      extra.macMoveWarnCount,
      "macMoveWarnCount",
      1,
      1000,
    );
  }
  if (extra.portFlapWarnCount !== undefined) {
    out.portFlapWarnCount = assertIntInRange(
      extra.portFlapWarnCount,
      "portFlapWarnCount",
      1,
      1000,
    );
  }
  if (extra.anomalyScoreWarn !== undefined) {
    if (
      typeof extra.anomalyScoreWarn !== "number" ||
      !Number.isFinite(extra.anomalyScoreWarn) ||
      extra.anomalyScoreWarn < 1 ||
      extra.anomalyScoreWarn > 100
    ) {
      throw new Error(
        "endpoint_mobility extra.anomalyScoreWarn must be a number between 1 and 100.",
      );
    }
    out.anomalyScoreWarn = extra.anomalyScoreWarn;
  }
  return Object.keys(out).length ? out : undefined;
}
