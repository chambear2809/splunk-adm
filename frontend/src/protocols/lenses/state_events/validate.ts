export type StateEventsSourceKind = "auto" | "syslog" | "aci_faults";

export interface StateEventsExtraConfig {
  sourceKind?: StateEventsSourceKind;
  burstWarnCount?: number;
  maxSeverityAttention?: number;
  includeAci?: boolean;
}

export interface ResolvedStateEventsThresholds {
  sourceKind: StateEventsSourceKind;
  burstWarnCount: number;
  maxSeverityAttention: number;
  includeAci: boolean;
}

export const DEFAULT_STATE_EVENTS_THRESHOLDS: ResolvedStateEventsThresholds = {
  sourceKind: "auto",
  burstWarnCount: 5,
  maxSeverityAttention: 3,
  includeAci: true,
};

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "burstWarnCount",
  "maxSeverityAttention",
  "includeAci",
]);

const ALLOWED_SOURCE_KINDS = new Set<StateEventsSourceKind>([
  "auto",
  "syslog",
  "aci_faults",
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
      `state_events extra.${keyName} must be an integer between ${min} and ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on
 * `state_events`. Kept in its own dependency-free module so `registry.ts`
 * never eagerly pulls in the lens adapter or React view into `protocols-core`.
 */
export function validateStateEventsExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported state_events profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourceKind !== undefined) {
    if (
      typeof extra.sourceKind !== "string" ||
      !ALLOWED_SOURCE_KINDS.has(extra.sourceKind as StateEventsSourceKind)
    ) {
      throw new Error(
        'state_events extra.sourceKind must be "auto", "syslog", or "aci_faults".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.burstWarnCount !== undefined) {
    out.burstWarnCount = assertIntInRange(
      extra.burstWarnCount,
      "burstWarnCount",
      1,
      1000,
    );
  }
  if (extra.maxSeverityAttention !== undefined) {
    out.maxSeverityAttention = assertIntInRange(
      extra.maxSeverityAttention,
      "maxSeverityAttention",
      0,
      7,
    );
  }
  if (extra.includeAci !== undefined) {
    if (typeof extra.includeAci !== "boolean") {
      throw new Error("state_events extra.includeAci must be a boolean.");
    }
    out.includeAci = extra.includeAci;
  }
  if (out.sourceKind === "aci_faults" && out.includeAci === false) {
    throw new Error(
      'state_events extra.includeAci cannot be false when sourceKind is "aci_faults".',
    );
  }
  return Object.keys(out).length ? out : undefined;
}
