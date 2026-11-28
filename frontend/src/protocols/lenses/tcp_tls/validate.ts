export type TcpTlsSourcetype = "stream:tcp" | "stream:netflow";

export interface TcpTlsExtraConfig {
  rttWarnMs?: number;
  retransmitWarnPct?: number;
  certExpiryWarnDays?: number;
  sourcetype?: TcpTlsSourcetype;
}

export interface ResolvedTcpTlsThresholds {
  rttWarnMs: number;
  retransmitWarnPct: number;
  certExpiryWarnDays: number;
  sourcetype: TcpTlsSourcetype;
}

export const DEFAULT_TCP_TLS_THRESHOLDS: ResolvedTcpTlsThresholds = {
  rttWarnMs: 50,
  retransmitWarnPct: 2,
  certExpiryWarnDays: 30,
  sourcetype: "stream:tcp",
};

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "rttWarnMs",
  "retransmitWarnPct",
  "certExpiryWarnDays",
  "sourcetype",
]);

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `tcp_tls`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateTcpTlsExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported tcp_tls profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.rttWarnMs !== undefined) {
    if (
      typeof extra.rttWarnMs !== "number" ||
      !Number.isFinite(extra.rttWarnMs) ||
      extra.rttWarnMs <= 0 ||
      extra.rttWarnMs > 60_000
    ) {
      throw new Error(
        "tcp_tls extra.rttWarnMs must be a positive number up to 60000 ms.",
      );
    }
    out.rttWarnMs = extra.rttWarnMs;
  }
  if (extra.retransmitWarnPct !== undefined) {
    if (
      typeof extra.retransmitWarnPct !== "number" ||
      !Number.isFinite(extra.retransmitWarnPct) ||
      extra.retransmitWarnPct < 0 ||
      extra.retransmitWarnPct > 100
    ) {
      throw new Error(
        "tcp_tls extra.retransmitWarnPct must be a number between 0 and 100.",
      );
    }
    out.retransmitWarnPct = extra.retransmitWarnPct;
  }
  if (extra.certExpiryWarnDays !== undefined) {
    if (
      typeof extra.certExpiryWarnDays !== "number" ||
      !Number.isInteger(extra.certExpiryWarnDays) ||
      extra.certExpiryWarnDays < 1 ||
      extra.certExpiryWarnDays > 365
    ) {
      throw new Error(
        "tcp_tls extra.certExpiryWarnDays must be an integer between 1 and 365.",
      );
    }
    out.certExpiryWarnDays = extra.certExpiryWarnDays;
  }
  if (extra.sourcetype !== undefined) {
    if (
      extra.sourcetype !== "stream:tcp" &&
      extra.sourcetype !== "stream:netflow"
    ) {
      throw new Error(
        'tcp_tls extra.sourcetype must be "stream:tcp" or "stream:netflow".',
      );
    }
    out.sourcetype = extra.sourcetype;
  }
  return Object.keys(out).length ? out : undefined;
}
