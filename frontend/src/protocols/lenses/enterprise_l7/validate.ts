export const ENTERPRISE_L7_SOURCETYPES = [
  "stream:smb",
  "stream:nfs",
  "stream:ldap",
  "stream:radius",
  "stream:sip",
  "stream:rtp",
  "stream:rtcp",
] as const;

export type EnterpriseL7Sourcetype = (typeof ENTERPRISE_L7_SOURCETYPES)[number];

export const ENTERPRISE_L7_STREAM_IDS = [
  "smb",
  "nfs",
  "ldap",
  "radius",
  "sip",
  "rtp",
  "rtcp",
] as const;

export type EnterpriseL7StreamId = (typeof ENTERPRISE_L7_STREAM_IDS)[number];

export interface EnterpriseL7ExtraConfig {
  sourcetype?: EnterpriseL7Sourcetype;
  sourcetypes?: EnterpriseL7Sourcetype[];
  smbErrorWarnPct?: number;
  nfsLatencyWarnMs?: number;
  nfsErrorWarnPct?: number;
  ldapErrorWarnPct?: number;
  radiusRejectWarnCount?: number;
  voipMosWarnMin?: number;
  voipJitterWarnMs?: number;
  voipLossWarnPct?: number;
}

export interface ResolvedEnterpriseL7Thresholds {
  sourcetypes: EnterpriseL7Sourcetype[];
  smbErrorWarnPct: number;
  nfsLatencyWarnMs: number;
  nfsErrorWarnPct: number;
  ldapErrorWarnPct: number;
  radiusRejectWarnCount: number;
  voipMosWarnMin: number;
  voipJitterWarnMs: number;
  voipLossWarnPct: number;
}

export const DEFAULT_ENTERPRISE_L7_THRESHOLDS: ResolvedEnterpriseL7Thresholds =
  {
    sourcetypes: [...ENTERPRISE_L7_SOURCETYPES],
    smbErrorWarnPct: 5,
    nfsLatencyWarnMs: 50,
    nfsErrorWarnPct: 2,
    ldapErrorWarnPct: 5,
    radiusRejectWarnCount: 5,
    voipMosWarnMin: 3.5,
    voipJitterWarnMs: 30,
    voipLossWarnPct: 1,
  };

const VALID_SOURCETYPES = new Set<string>(ENTERPRISE_L7_SOURCETYPES);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourcetype",
  "sourcetypes",
  "smbErrorWarnPct",
  "nfsLatencyWarnMs",
  "nfsErrorWarnPct",
  "ldapErrorWarnPct",
  "radiusRejectWarnCount",
  "voipMosWarnMin",
  "voipJitterWarnMs",
  "voipLossWarnPct",
]);

function assertFiniteRange(
  value: unknown,
  key: string,
  min: number,
  max: number,
  options?: { minExclusive?: boolean; integer?: boolean },
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`enterprise_l7 extra.${key} must be a finite number.`);
  }
  if (options?.integer && !Number.isInteger(value)) {
    throw new Error(`enterprise_l7 extra.${key} must be an integer.`);
  }
  const tooLow = options?.minExclusive ? value <= min : value < min;
  if (tooLow || value > max) {
    const lower = options?.minExclusive ? `> ${min}` : `>= ${min}`;
    throw new Error(
      `enterprise_l7 extra.${key} must be ${lower} and <= ${max}.`,
    );
  }
  return value;
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `enterprise_l7`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateEnterpriseL7Extra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported enterprise_l7 profile extra configuration key "${key}".`,
      );
    }
  }
  if (extra.sourcetype !== undefined && extra.sourcetypes !== undefined) {
    throw new Error(
      "enterprise_l7 extra cannot specify both sourcetype and sourcetypes.",
    );
  }
  const out: Record<string, unknown> = {};
  if (extra.sourcetype !== undefined) {
    if (
      typeof extra.sourcetype !== "string" ||
      !VALID_SOURCETYPES.has(extra.sourcetype)
    ) {
      throw new Error(
        `enterprise_l7 extra.sourcetype must be one of: ${ENTERPRISE_L7_SOURCETYPES.join(", ")}.`,
      );
    }
    out.sourcetype = extra.sourcetype;
  }
  if (extra.sourcetypes !== undefined) {
    if (!Array.isArray(extra.sourcetypes) || extra.sourcetypes.length === 0) {
      throw new Error(
        "enterprise_l7 extra.sourcetypes must be a non-empty array of supported Stream sourcetypes.",
      );
    }
    const seen = new Set<string>();
    const list: string[] = [];
    for (const item of extra.sourcetypes) {
      if (typeof item !== "string" || !VALID_SOURCETYPES.has(item)) {
        throw new Error(
          `enterprise_l7 extra.sourcetypes contains unsupported sourcetype "${String(item)}".`,
        );
      }
      if (seen.has(item)) {
        throw new Error(
          `enterprise_l7 extra.sourcetypes contains duplicate sourcetype "${item}".`,
        );
      }
      seen.add(item);
      list.push(item);
    }
    out.sourcetypes = list;
  }
  if (extra.smbErrorWarnPct !== undefined) {
    out.smbErrorWarnPct = assertFiniteRange(
      extra.smbErrorWarnPct,
      "smbErrorWarnPct",
      0,
      100,
    );
  }
  if (extra.nfsLatencyWarnMs !== undefined) {
    out.nfsLatencyWarnMs = assertFiniteRange(
      extra.nfsLatencyWarnMs,
      "nfsLatencyWarnMs",
      0,
      60_000,
      { minExclusive: true },
    );
  }
  if (extra.nfsErrorWarnPct !== undefined) {
    out.nfsErrorWarnPct = assertFiniteRange(
      extra.nfsErrorWarnPct,
      "nfsErrorWarnPct",
      0,
      100,
    );
  }
  if (extra.ldapErrorWarnPct !== undefined) {
    out.ldapErrorWarnPct = assertFiniteRange(
      extra.ldapErrorWarnPct,
      "ldapErrorWarnPct",
      0,
      100,
    );
  }
  if (extra.radiusRejectWarnCount !== undefined) {
    out.radiusRejectWarnCount = assertFiniteRange(
      extra.radiusRejectWarnCount,
      "radiusRejectWarnCount",
      1,
      100_000,
      { integer: true },
    );
  }
  if (extra.voipMosWarnMin !== undefined) {
    out.voipMosWarnMin = assertFiniteRange(
      extra.voipMosWarnMin,
      "voipMosWarnMin",
      1,
      5,
    );
  }
  if (extra.voipJitterWarnMs !== undefined) {
    out.voipJitterWarnMs = assertFiniteRange(
      extra.voipJitterWarnMs,
      "voipJitterWarnMs",
      0,
      5_000,
      { minExclusive: true },
    );
  }
  if (extra.voipLossWarnPct !== undefined) {
    out.voipLossWarnPct = assertFiniteRange(
      extra.voipLossWarnPct,
      "voipLossWarnPct",
      0,
      100,
      { minExclusive: true },
    );
  }
  return Object.keys(out).length ? out : undefined;
}
