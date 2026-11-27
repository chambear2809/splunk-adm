export type DnsOpsSourcetype = "stream:dns" | "cilium:hubble:flow";

export interface DnsOpsExtraConfig {
  sourcetype?: DnsOpsSourcetype;
  latencyWarnMs?: number;
  nxdomainWarnPct?: number;
  servfailWarnPct?: number;
}

export interface ResolvedDnsOpsThresholds {
  sourcetype: DnsOpsSourcetype;
  latencyWarnMs: number;
  nxdomainWarnPct: number;
  servfailWarnPct: number;
}

export const DEFAULT_DNS_OPS_THRESHOLDS: ResolvedDnsOpsThresholds = {
  sourcetype: "stream:dns",
  latencyWarnMs: 50,
  nxdomainWarnPct: 10,
  servfailWarnPct: 2,
};

const ALLOWED_EXTRA_KEYS = new Set<string>([
  "sourcetype",
  "latencyWarnMs",
  "nxdomainWarnPct",
  "servfailWarnPct",
]);

/**
 * Fail-closed validator for `adm_protocol_profiles` `extra` configuration on `dns_ops`.
 * Kept in its own dependency-free module so `registry.ts` never eagerly pulls in
 * the lens adapter or React view into `protocols-core`.
 */
export function validateDnsOpsExtra(
  extra: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (extra === undefined) return undefined;
  for (const key of Object.keys(extra)) {
    if (!ALLOWED_EXTRA_KEYS.has(key)) {
      throw new Error(
        `Unsupported dns_ops profile extra configuration key "${key}".`,
      );
    }
  }
  const out: Record<string, unknown> = {};
  if (extra.sourcetype !== undefined) {
    if (
      extra.sourcetype !== "stream:dns" &&
      extra.sourcetype !== "cilium:hubble:flow"
    ) {
      throw new Error(
        'dns_ops extra.sourcetype must be "stream:dns" or "cilium:hubble:flow".',
      );
    }
    out.sourcetype = extra.sourcetype;
  }
  if (extra.latencyWarnMs !== undefined) {
    if (
      typeof extra.latencyWarnMs !== "number" ||
      !Number.isFinite(extra.latencyWarnMs) ||
      extra.latencyWarnMs <= 0 ||
      extra.latencyWarnMs > 60_000
    ) {
      throw new Error(
        "dns_ops extra.latencyWarnMs must be a positive number up to 60000 ms.",
      );
    }
    out.latencyWarnMs = extra.latencyWarnMs;
  }
  if (extra.nxdomainWarnPct !== undefined) {
    if (
      typeof extra.nxdomainWarnPct !== "number" ||
      !Number.isFinite(extra.nxdomainWarnPct) ||
      extra.nxdomainWarnPct < 0 ||
      extra.nxdomainWarnPct > 100
    ) {
      throw new Error(
        "dns_ops extra.nxdomainWarnPct must be a number between 0 and 100.",
      );
    }
    out.nxdomainWarnPct = extra.nxdomainWarnPct;
  }
  if (extra.servfailWarnPct !== undefined) {
    if (
      typeof extra.servfailWarnPct !== "number" ||
      !Number.isFinite(extra.servfailWarnPct) ||
      extra.servfailWarnPct < 0 ||
      extra.servfailWarnPct > 100
    ) {
      throw new Error(
        "dns_ops extra.servfailWarnPct must be a number between 0 and 100.",
      );
    }
    out.servfailWarnPct = extra.servfailWarnPct;
  }
  return Object.keys(out).length ? out : undefined;
}
