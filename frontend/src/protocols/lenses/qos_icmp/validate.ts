export type QosIcmpSourceKind =
  "stream_netflow" | "stream_icmp" | "nd_flows" | "auto";

export interface QosIcmpExtraConfig {
  sourceKind?: QosIcmpSourceKind;
  icmpUnreachableWarnCount?: number;
  icmpTtlExceededWarnCount?: number;
  dropPktWarnCount?: number;
  unexpectedDscpValues?: number[];
}

export interface ResolvedQosIcmpThresholds {
  sourceKind: QosIcmpSourceKind;
  icmpUnreachableWarnCount: number;
  icmpTtlExceededWarnCount: number;
  dropPktWarnCount: number;
  unexpectedDscpValues: number[];
}

export const DEFAULT_QOS_ICMP_THRESHOLDS: ResolvedQosIcmpThresholds = {
  sourceKind: "auto",
  icmpUnreachableWarnCount: 5,
  icmpTtlExceededWarnCount: 5,
  dropPktWarnCount: 1,
  unexpectedDscpValues: [],
};

const ALLOWED_SOURCE_KINDS = new Set<string>([
  "stream_netflow",
  "stream_icmp",
  "nd_flows",
  "auto",
]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "icmpUnreachableWarnCount",
  "icmpTtlExceededWarnCount",
  "dropPktWarnCount",
  "unexpectedDscpValues",
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
      `qos_icmp extra.${keyName} must be an integer between ${min} and ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `qos_icmp`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateQosIcmpExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported qos_icmp profile extra configuration key "${key}".`,
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
        'qos_icmp extra.sourceKind must be "stream_netflow", "stream_icmp", "nd_flows", or "auto".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.icmpUnreachableWarnCount !== undefined) {
    out.icmpUnreachableWarnCount = assertPositiveIntInRange(
      extra.icmpUnreachableWarnCount,
      "icmpUnreachableWarnCount",
      1,
      100_000,
    );
  }
  if (extra.icmpTtlExceededWarnCount !== undefined) {
    out.icmpTtlExceededWarnCount = assertPositiveIntInRange(
      extra.icmpTtlExceededWarnCount,
      "icmpTtlExceededWarnCount",
      1,
      100_000,
    );
  }
  if (extra.dropPktWarnCount !== undefined) {
    out.dropPktWarnCount = assertPositiveIntInRange(
      extra.dropPktWarnCount,
      "dropPktWarnCount",
      1,
      1_000_000,
    );
  }
  if (extra.unexpectedDscpValues !== undefined) {
    if (
      !Array.isArray(extra.unexpectedDscpValues) ||
      extra.unexpectedDscpValues.length > 64
    ) {
      throw new Error(
        "qos_icmp extra.unexpectedDscpValues must be an array of up to 64 DSCP integers (0..63).",
      );
    }
    const normalized: number[] = [];
    const seen = new Set<number>();
    for (const val of extra.unexpectedDscpValues) {
      if (
        typeof val !== "number" ||
        !Number.isInteger(val) ||
        val < 0 ||
        val > 63
      ) {
        throw new Error(
          "qos_icmp extra.unexpectedDscpValues entries must be integers between 0 and 63.",
        );
      }
      if (!seen.has(val)) {
        seen.add(val);
        normalized.push(val);
      }
    }
    out.unexpectedDscpValues = normalized;
  }
  return Object.keys(out).length ? out : undefined;
}
