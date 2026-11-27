import type { BaseProtocolProfile } from "../../shared/contract";

export type MgmtPlaneSourceKind =
  "auto" | "stream_snmp" | "stream_ftp" | "netflow" | "syslog";

export interface MgmtPlaneExtraConfig {
  sourceKind?: MgmtPlaneSourceKind;
  receiptGapMinutes?: number;
  flagSnmpV2c?: boolean;
  flagHttpPort80?: boolean;
  mgmtIps?: string[];
}

export interface ResolvedMgmtPlaneThresholds {
  sourceKind: MgmtPlaneSourceKind;
  receiptGapMinutes: number;
  flagSnmpV2c: boolean;
  flagHttpPort80: boolean;
  mgmtIps: string[];
}

export const DEFAULT_MGMT_PLANE_THRESHOLDS: ResolvedMgmtPlaneThresholds = {
  sourceKind: "auto",
  receiptGapMinutes: 15,
  flagSnmpV2c: true,
  flagHttpPort80: true,
  mgmtIps: [],
};

const ALLOWED_SOURCE_KINDS = new Set<string>([
  "auto",
  "stream_snmp",
  "stream_ftp",
  "netflow",
  "syslog",
]);

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourceKind",
  "receiptGapMinutes",
  "flagSnmpV2c",
  "flagHttpPort80",
  "mgmtIps",
]);

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_CHARS_RE = /^[0-9a-fA-F:]{2,45}$/;

function isValidIpLiteral(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  if (IPV4_RE.test(trimmed)) {
    return trimmed.split(".").every((part) => {
      const n = Number(part);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  return trimmed.includes(":") && IPV6_CHARS_RE.test(trimmed);
}

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `mgmt_plane`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateMgmtPlaneExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported mgmt_plane profile extra configuration key "${key}".`,
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
        'mgmt_plane extra.sourceKind must be "auto", "stream_snmp", "stream_ftp", "netflow", or "syslog".',
      );
    }
    out.sourceKind = extra.sourceKind;
  }
  if (extra.receiptGapMinutes !== undefined) {
    if (
      typeof extra.receiptGapMinutes !== "number" ||
      !Number.isInteger(extra.receiptGapMinutes) ||
      extra.receiptGapMinutes < 5 ||
      extra.receiptGapMinutes > 1440
    ) {
      throw new Error(
        "mgmt_plane extra.receiptGapMinutes must be an integer between 5 and 1440.",
      );
    }
    out.receiptGapMinutes = extra.receiptGapMinutes;
  }
  if (extra.flagSnmpV2c !== undefined) {
    if (typeof extra.flagSnmpV2c !== "boolean") {
      throw new Error("mgmt_plane extra.flagSnmpV2c must be a boolean.");
    }
    out.flagSnmpV2c = extra.flagSnmpV2c;
  }
  if (extra.flagHttpPort80 !== undefined) {
    if (typeof extra.flagHttpPort80 !== "boolean") {
      throw new Error("mgmt_plane extra.flagHttpPort80 must be a boolean.");
    }
    out.flagHttpPort80 = extra.flagHttpPort80;
  }
  if (extra.mgmtIps !== undefined) {
    if (!Array.isArray(extra.mgmtIps) || extra.mgmtIps.length > 64) {
      throw new Error(
        "mgmt_plane extra.mgmtIps must be an array of up to 64 IPv4/IPv6 addresses.",
      );
    }
    const normalized: string[] = [];
    const seen = new Set<string>();
    for (const entry of extra.mgmtIps) {
      if (typeof entry !== "string" || !isValidIpLiteral(entry)) {
        throw new Error(
          "mgmt_plane extra.mgmtIps entries must be valid IPv4 or IPv6 literals.",
        );
      }
      const trimmed = entry.trim();
      if (!seen.has(trimmed)) {
        seen.add(trimmed);
        normalized.push(trimmed);
      }
    }
    out.mgmtIps = normalized;
  }
  return Object.keys(out).length ? out : undefined;
}

export function resolveMgmtPlaneThresholds(
  profile?: BaseProtocolProfile,
): ResolvedMgmtPlaneThresholds {
  const extra = profile?.extra as MgmtPlaneExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "stream_snmp" ||
      extra?.sourceKind === "stream_ftp" ||
      extra?.sourceKind === "netflow" ||
      extra?.sourceKind === "syslog" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_MGMT_PLANE_THRESHOLDS.sourceKind,
    receiptGapMinutes:
      typeof extra?.receiptGapMinutes === "number"
        ? extra.receiptGapMinutes
        : DEFAULT_MGMT_PLANE_THRESHOLDS.receiptGapMinutes,
    flagSnmpV2c:
      typeof extra?.flagSnmpV2c === "boolean"
        ? extra.flagSnmpV2c
        : DEFAULT_MGMT_PLANE_THRESHOLDS.flagSnmpV2c,
    flagHttpPort80:
      typeof extra?.flagHttpPort80 === "boolean"
        ? extra.flagHttpPort80
        : DEFAULT_MGMT_PLANE_THRESHOLDS.flagHttpPort80,
    mgmtIps: Array.isArray(extra?.mgmtIps)
      ? [...extra.mgmtIps]
      : DEFAULT_MGMT_PLANE_THRESHOLDS.mgmtIps,
  };
}
