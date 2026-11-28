import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  ALLOWED_SYSLOG_SOURCETYPES,
  CONFIG_CHANGE_MNEMONICS,
  EXCLUDED_AUTH_CATEGORIES,
  buildSyslogStateSearch,
  normalizeSyslogRow,
  type SyslogOperationalDomain,
} from "../../shared/adapters/nxosSyslog";
import {
  MAX_INPUT_ROWS,
  type BaseProtocolProfile,
  type LensProfileValidator,
  type ProtocolConfiguration,
  type ProtocolDistributionMetric,
  type ProtocolFilter,
  type ProtocolKpi,
  type ProtocolLensId,
  type ProtocolLensSummary,
  type ProtocolMatrixCell,
  type ProtocolRequest,
  type ProtocolSourceOutcome,
  type ProtocolStatus,
  type ProtocolTimelineEvent,
} from "../../shared/contract";
import { buildAllowedFieldsClause } from "../../shared/fields";
import { formatCount } from "../../shared/format";
import {
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  DEFAULT_STATE_EVENTS_THRESHOLDS,
  validateStateEventsExtra,
  type ResolvedStateEventsThresholds,
  type StateEventsExtraConfig,
  type StateEventsSourceKind,
} from "./validate";

export {
  ALLOWED_SYSLOG_SOURCETYPES,
  CONFIG_CHANGE_MNEMONICS,
  DEFAULT_STATE_EVENTS_THRESHOLDS,
  EXCLUDED_AUTH_CATEGORIES,
  validateStateEventsExtra,
  type ResolvedStateEventsThresholds,
  type StateEventsExtraConfig,
  type StateEventsSourceKind,
};

export type StateEventDomainKey =
  "link" | "routing" | "l2" | "hsrp_vrrp" | "pim" | "aci_faults" | "other";

export const DOMAIN_LABELS: Record<StateEventDomainKey, string> = {
  link: "Link",
  routing: "BGP/OSPF/BFD",
  l2: "STP/LACP",
  hsrp_vrrp: "HSRP/VRRP",
  pim: "PIM",
  aci_faults: "ACI Faults",
  other: "Other",
};

const CANONICAL_DOMAIN_ORDER: readonly StateEventDomainKey[] = [
  "link",
  "routing",
  "l2",
  "hsrp_vrrp",
  "pim",
  "aci_faults",
  "other",
];

const SEVERITY_LABELS: Record<number, string> = {
  0: "Emergency",
  1: "Alert",
  2: "Critical",
  3: "Error",
  4: "Warning",
  5: "Notice",
  6: "Info",
  7: "Debug",
};

export const EXTRA_EXCLUDED_PRIVACY_CATEGORIES = [
  "AUDIT",
  "SESSION",
  "LOGIN",
] as const;

const CONFIG_CHANGE_SET = new Set<string>(CONFIG_CHANGE_MNEMONICS);
const EXCLUDED_AUTH_SET = new Set<string>([
  ...EXCLUDED_AUTH_CATEGORIES,
  ...EXTRA_EXCLUDED_PRIVACY_CATEGORIES,
]);

const CISCO_SYSLOG_PREFIX_RE =
  /%([A-Za-z0-9_]+)(?:-[A-Za-z0-9_]+)?-([0-7])-([A-Za-z0-9_]+):\s*(.*)/;

export const ACI_FAULT_EVENT_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "apic_host",
  "component",
  "dn",
  "code",
  "descr",
  "severity",
  "domain",
  "cause",
  "type",
  "rule",
  "lifecycle",
  "affected",
  "subject",
  "created",
  "lastTransition",
] as const;

export function resolveStateEventsThresholds(
  profile?: BaseProtocolProfile,
): ResolvedStateEventsThresholds {
  const extra = profile?.extra as StateEventsExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "auto" ||
      extra?.sourceKind === "syslog" ||
      extra?.sourceKind === "aci_faults"
        ? extra.sourceKind
        : DEFAULT_STATE_EVENTS_THRESHOLDS.sourceKind,
    burstWarnCount:
      typeof extra?.burstWarnCount === "number" &&
      Number.isInteger(extra.burstWarnCount)
        ? extra.burstWarnCount
        : DEFAULT_STATE_EVENTS_THRESHOLDS.burstWarnCount,
    maxSeverityAttention:
      typeof extra?.maxSeverityAttention === "number" &&
      Number.isInteger(extra.maxSeverityAttention)
        ? extra.maxSeverityAttention
        : DEFAULT_STATE_EVENTS_THRESHOLDS.maxSeverityAttention,
    includeAci:
      typeof extra?.includeAci === "boolean"
        ? extra.includeAci
        : DEFAULT_STATE_EVENTS_THRESHOLDS.includeAci,
  };
}

/**
 * Shortens DNS hostnames to their short label while preserving IPv4 and IPv6
 * literals completely intact (`192.0.2.11` -> `192.0.2.11`,
 * `leaf-01.dc1.local` -> `leaf-01`).
 */
export function shortenDeviceLabel(device: string): string {
  const trimmed = device.trim();
  if (!trimmed) return "unknown";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(":")) {
    return trimmed;
  }
  return trimmed.split(".")[0] || trimmed;
}

export function formatSeverityLabel(severity: number): string {
  const clamped = Math.max(0, Math.min(7, Math.trunc(severity)));
  return SEVERITY_LABELS[clamped] ?? `Sev ${clamped}`;
}

const IFACE_PREFIX_MAP: ReadonlyArray<readonly [RegExp, string]> = [
  [/^ethernet(?=\d)/i, "eth"],
  [/^gigabitethernet(?=\d)/i, "gi"],
  [/^tengigabitethernet(?=\d)/i, "te"],
  [/^fortygigabitethernet(?=\d)/i, "fo"],
  [/^hundredgig(?:abit)?ethernet(?=\d)/i, "hu"],
  [/^port-channel(?=\d)/i, "po"],
  [/^loopback(?=\d)/i, "lo"],
  [/^mgmt(?=\d)/i, "mgmt"],
  [/^vlan(?=\d)/i, "vlan"],
];

function canonicalStateInterface(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return "";
  for (const [pattern, shortPrefix] of IFACE_PREFIX_MAP) {
    if (pattern.test(trimmed)) {
      return trimmed.replace(pattern, shortPrefix);
    }
  }
  return trimmed;
}

function stateInterfaceVariants(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  const canon = canonicalStateInterface(trimmed);
  const variants = new Set<string>([trimmed, canon]);
  if (/^eth\d/i.test(canon)) {
    variants.add(`Ethernet${canon.slice(3)}`);
  } else if (/^po\d/i.test(canon)) {
    variants.add(`port-channel${canon.slice(2)}`);
  }
  return [...variants].filter(Boolean);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function matchesStateInterface(
  candidate: string | undefined,
  summary: string,
  filterIface: string,
): boolean {
  const targetCanon = canonicalStateInterface(filterIface);
  if (!targetCanon) return true;
  if (candidate) {
    if (canonicalStateInterface(candidate) === targetCanon) return true;
    const bracketMatch = candidate.match(/\[([^\]]+)\]/);
    if (
      bracketMatch?.[1] &&
      canonicalStateInterface(bracketMatch[1]) === targetCanon
    ) {
      return true;
    }
  }
  const tokenVariants = stateInterfaceVariants(filterIface).map(escapeRegExp);
  if (!tokenVariants.length) return false;
  const boundaryRe = new RegExp(
    `(?:^|[^A-Za-z0-9/_-])(?:${tokenVariants.join("|")})(?=$|[^A-Za-z0-9/._-])`,
    "i",
  );
  if (candidate && boundaryRe.test(candidate)) return true;
  return boundaryRe.test(summary);
}

/**
 * Builds a bounded SPL query for operational syslog events via the shared
 * `nxosSyslog` adapter (`CONFIG_CHANGE_MNEMONICS`, `EXCLUDED_AUTH_CATEGORIES`,
 * and ACI audit/session categories `AUDIT`, `SESSION`, `LOGIN` are excluded
 * before `| head`).
 */
export function buildStateSyslogSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  includeAci?: boolean;
  maxRows: number;
}): string {
  const baseSpl = buildSyslogStateSearch({
    index: options.index,
    device: options.filter?.device,
    includeAci: options.includeAci ?? true,
    maxRows: options.maxRows,
  });
  const extraExcluded = EXTRA_EXCLUDED_PRIVACY_CATEGORIES.map(
    (c) => `category!="${c}"`,
  ).join(" AND ");
  let spl = baseSpl.replace(
    " | head ",
    ` | where (isnull(category) OR (${extraExcluded})) | head `,
  );
  if (options.filter?.iface) {
    const terms = stateInterfaceVariants(options.filter.iface).map(
      (v) => `"${literal(v, 64)}"`,
    );
    if (terms.length > 0) {
      spl = spl.replace(" | rex ", ` (${terms.join(" OR ")}) | rex `);
    }
  }
  return spl;
}

/**
 * Builds a bounded, allowlisted SPL query for ACI `faultInst` and `eventRecord`
 * events (`cisco:dc:aci:fault`, `cisco:dc:aci:event`, or `cisco:dc:aci:class`).
 * Emits `| head <maxRows + 1>` BEFORE `| table ...` and omits post-head `| where`.
 */
export function buildAciFaultEventSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const predicates: string[] = [
    `index=${index}`,
    `((sourcetype="cisco:dc:aci:fault" OR sourcetype="cisco:dc:aci:event") OR (sourcetype="cisco:dc:aci:class" (component="faultInst" OR component="eventRecord")))`,
  ];
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(host="${dev}" OR apic_host="${dev}")`);
  }
  if (options.filter?.iface) {
    const ifaceTerms: string[] = [];
    for (const variant of stateInterfaceVariants(options.filter.iface)) {
      const safe = literal(variant, 64);
      ifaceTerms.push(
        `dn="*[${safe}]*"`,
        `affected="*[${safe}]*"`,
        `dn="*${safe}*"`,
        `affected="*${safe}*"`,
      );
    }
    if (ifaceTerms.length > 0) {
      predicates.push(`(${ifaceTerms.join(" OR ")})`);
    }
  }
  const tableClause = buildAllowedFieldsClause(
    "state_events",
    ACI_FAULT_EVENT_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a `literal()`-quoted Splunk Search URL for raw events of a selected device.
 */
export function buildStateEventsRawEventsUrl(options: {
  index: string;
  rawHosts: readonly string[];
  sourceCoverage: "syslog_only" | "aci_faults_only" | "syslog_and_aci_faults";
  includeAci: boolean;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const hosts = options.rawHosts
    .map((h) => h.trim())
    .filter(Boolean)
    .slice(0, 6);
  if (!hosts.length) {
    throw new Error("Raw events URL requires at least one literal host.");
  }
  const hostPredicates = hosts.map((h) => {
    const safeHost = literal(h, 128);
    return `(host="${safeHost}" OR apic_host="${safeHost}")`;
  });
  const hostClause =
    hostPredicates.length === 1
      ? hostPredicates[0]
      : `(${hostPredicates.join(" OR ")})`;

  const syslogSts = options.includeAci
    ? ALLOWED_SYSLOG_SOURCETYPES
    : (["cisco:ios", "cisco:dc:nexus9k:syslog"] as const);
  const syslogClause = syslogSts.map((st) => `sourcetype="${st}"`).join(" OR ");
  const aciClause = `(sourcetype="cisco:dc:aci:fault" OR sourcetype="cisco:dc:aci:event" OR (sourcetype="cisco:dc:aci:class" (component="faultInst" OR component="eventRecord")))`;

  const stClause =
    options.sourceCoverage === "syslog_only"
      ? `(${syslogClause})`
      : options.sourceCoverage === "aci_faults_only"
        ? aciClause
        : `(${syslogClause} OR ${aciClause})`;

  const q = `search index=${index} ${stClause} ${hostClause}`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedTimelineStateEvent {
  id: string;
  sourceKind: "syslog" | "aci_fault";
  timestamp: number;
  device: string;
  rawHost: string;
  domain: StateEventDomainKey;
  domainLabel: string;
  subDomain?: SyslogOperationalDomain;
  severity: number;
  severityLabel: string;
  codeOrMnemonic: string;
  category: string;
  interfaceOrDn?: string;
  summary: string;
  isHsrpVrrp: boolean;
  lifecycle?: string;
  cause?: string;
}

export interface StateEventTransitionEntry {
  id: string;
  timestamp: number;
  domain: StateEventDomainKey;
  domainLabel: string;
  severity: number;
  severityLabel: string;
  codeOrMnemonic: string;
  interfaceOrDn?: string;
  summary: string;
  sourceKind: "syslog" | "aci_fault";
}

export interface StateEventDeviceRow {
  /** URL-safe `ITEM_ID`: shortened device label sanitized for URL selection. */
  id: string;
  attention: boolean;
  device: string;
  rawHosts: string[];
  eventCount: number;
  criticalErrorCount: number;
  worstSeverity: number;
  domains: string[];
  domainKeys: StateEventDomainKey[];
  topCode: string;
  latestTime: number;
  hasHsrpVrrp: boolean;
  sourceCoverage: "syslog_only" | "aci_faults_only" | "syslog_and_aci_faults";
  transitions: StateEventTransitionEntry[];
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
}

export interface StateEventsInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: StateEventDeviceRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  timelineRowByEventId: Record<string, string>;
  distribution: ProtocolDistributionMetric[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode:
    "syslog_only" | "aci_faults_only" | "syslog_and_aci_faults" | "none";
  includeAci: boolean;
  bannerState?:
    "empty" | "partial" | "blocked" | "unavailable" | "stale_config";
  bannerReason?: string;
  checkedAt: number;
}

function asString(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function asEpochSeconds(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  if (typeof value === "string" && value.trim()) {
    const trimmed = value.trim();
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric) && numeric > 0) return Math.floor(numeric);
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed) && parsed > 0) return Math.floor(parsed / 1000);
  }
  return undefined;
}

function mapSyslogDomain(domain: SyslogOperationalDomain): StateEventDomainKey {
  switch (domain) {
    case "link":
      return "link";
    case "bgp":
    case "ospf":
    case "isis":
    case "bfd":
      return "routing";
    case "stp":
    case "port_channel":
      return "l2";
    case "hsrp_vrrp":
      return "hsrp_vrrp";
    case "pim":
      return "pim";
    case "other":
      return "other";
  }
}

function parseAciSeverity(rawSeverity: string, lifecycle: string): number {
  const s = rawSeverity.trim().toLowerCase();
  const lc = lifecycle.trim().toLowerCase();
  if (s === "cleared" || lc === "cleared") return 6;
  if (/^[0-7]$/.test(s)) return Number(s);
  if (s === "emergency") return 0;
  if (s === "alert") return 1;
  if (s === "critical") return 2;
  if (s === "major" || s === "error") return 3;
  if (s === "minor" || s === "warning" || s === "warn") return 4;
  if (s === "notice") return 5;
  if (s === "info" || s === "informational") return 6;
  if (s === "debug") return 7;
  return 4;
}

function extractAciNodeFromPath(path: string): string | undefined {
  const match = /topology\/pod-(\d+)\/node-(\d+)/i.exec(path);
  if (match) return `pod-${match[1]}/node-${match[2]}`;
  return undefined;
}

function sanitizeIdPart(raw: string): string {
  const cleaned = raw
    .replace(/[^A-Za-z0-9._:/@-]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!cleaned) return "device";
  return /^[A-Za-z0-9]/.test(cleaned) ? cleaned : `d${cleaned}`;
}

function makeSafeDeviceId(device: string, used: Set<string>): string {
  const base = sanitizeIdPart(device).slice(0, 128);
  let candidate = base;
  let n = 2;
  while (used.has(candidate)) {
    candidate = `${base.slice(0, 120)}_${n}`;
    n += 1;
  }
  used.add(candidate);
  return candidate;
}

/**
 * Normalizes a syslog row via `normalizeSyslogRow` (`nxosSyslog.ts`), preserving
 * config-change and AAA/auth exclusions and mapping into operational domains.
 */
export function normalizeStateSyslogRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedTimelineStateEvent | undefined {
  const base = normalizeSyslogRow(row, indexInBatch);
  if (!base) return undefined;
  if (CONFIG_CHANGE_SET.has(base.mnemonic.toUpperCase())) return undefined;
  if (EXCLUDED_AUTH_SET.has(base.category.toUpperCase())) return undefined;

  const domain = mapSyslogDomain(base.domain);
  const dn = asString(row.dn);
  const interfaceOrDn = base.interface || (dn ? dn : undefined);
  const codeOrMnemonic = `${base.category}-${base.severity}-${base.mnemonic}`;

  return {
    id: `syslog:${base.id}`,
    sourceKind: "syslog",
    timestamp: base.timestamp,
    device: shortenDeviceLabel(base.host),
    rawHost: base.host,
    domain,
    domainLabel: DOMAIN_LABELS[domain],
    subDomain: base.domain,
    severity: base.severity,
    severityLabel: formatSeverityLabel(base.severity),
    codeOrMnemonic,
    category: base.category,
    ...(interfaceOrDn ? { interfaceOrDn } : {}),
    summary: base.summary,
    isHsrpVrrp: base.domain === "hsrp_vrrp",
  };
}

/**
 * Normalizes an allowlist-projected ACI `faultInst` or `eventRecord` row
 * (`cisco:dc:aci:fault`, `cisco:dc:aci:event`, or `cisco:dc:aci:class`).
 * Unrelated `cisco:dc:aci:class` objects (e.g. `topSystem`, `fvCEp`) return `undefined`.
 */
export function normalizeAciFaultEventRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedTimelineStateEvent | undefined {
  const sourcetype = asString(row.sourcetype).toLowerCase();
  const component = asString(row.component);
  const compLower = component.toLowerCase();

  const isFaultEventSt =
    sourcetype === "cisco:dc:aci:fault" || sourcetype === "cisco:dc:aci:event";
  const isClassFaultEvent =
    sourcetype === "cisco:dc:aci:class" &&
    (compLower === "faultinst" || compLower === "eventrecord");
  if (!isFaultEventSt && !isClassFaultEvent) return undefined;
  if (
    isFaultEventSt &&
    component &&
    compLower !== "faultinst" &&
    compLower !== "eventrecord"
  ) {
    return undefined;
  }

  const code = asString(row.code) || asString(row.rule);
  const aciDomain = asString(row.domain).toUpperCase();
  const aciSubject = asString(row.subject).toUpperCase();
  if (code && CONFIG_CHANGE_SET.has(code.toUpperCase())) return undefined;
  if (aciDomain && EXCLUDED_AUTH_SET.has(aciDomain)) return undefined;
  if (aciSubject && EXCLUDED_AUTH_SET.has(aciSubject)) return undefined;

  const timestamp =
    asEpochSeconds(row._time) ??
    asEpochSeconds(row.lastTransition) ??
    asEpochSeconds(row.created);
  if (!timestamp) return undefined;

  const rawHost = asString(row.host) || asString(row.apic_host);
  const affected = asString(row.affected);
  const dn = asString(row.dn);
  const nodeFromPath =
    extractAciNodeFromPath(affected) ?? extractAciNodeFromPath(dn);
  const device = nodeFromPath ?? (rawHost ? shortenDeviceLabel(rawHost) : "");
  if (!device) return undefined;
  const effectiveRawHost = rawHost || device;

  const lifecycle = asString(row.lifecycle);
  const severity = parseAciSeverity(asString(row.severity), lifecycle);
  const cause = asString(row.cause);
  const subject = asString(row.subject);
  const type = asString(row.type);
  const descr = asString(row.descr);

  const codeOrMnemonic =
    code ||
    (compLower === "eventrecord" || sourcetype === "cisco:dc:aci:event"
      ? "ACI_EVENT"
      : "ACI_FAULT");
  const interfaceOrDn = affected || dn || undefined;

  const metaParts = [cause, subject, lifecycle, type].filter(Boolean);
  const summary = (
    descr ||
    metaParts.join(" · ") ||
    `${codeOrMnemonic} on ${interfaceOrDn ?? device}`
  ).slice(0, 240);

  return {
    id: `aci:${device}:${timestamp}:${codeOrMnemonic}:${indexInBatch}`,
    sourceKind: "aci_fault",
    timestamp,
    device,
    rawHost: effectiveRawHost,
    domain: "aci_faults",
    domainLabel: DOMAIN_LABELS.aci_faults,
    severity,
    severityLabel: formatSeverityLabel(severity),
    codeOrMnemonic,
    category: aciDomain || (compLower === "eventrecord" ? "EVENT" : "FAULT"),
    ...(interfaceOrDn ? { interfaceOrDn } : {}),
    summary,
    isHsrpVrrp: false,
    ...(lifecycle ? { lifecycle } : {}),
    ...(cause ? { cause } : {}),
  };
}

function matchesRequestFilter(
  ev: NormalizedTimelineStateEvent,
  filter?: ProtocolFilter,
): boolean {
  if (!filter) return true;
  if (filter.device) {
    const target = filter.device.toLowerCase();
    const shortTarget = shortenDeviceLabel(filter.device).toLowerCase();
    const matchesDevice =
      ev.device.toLowerCase() === target ||
      ev.device.toLowerCase() === shortTarget ||
      ev.rawHost.toLowerCase() === target ||
      shortenDeviceLabel(ev.rawHost).toLowerCase() === shortTarget;
    if (!matchesDevice) return false;
  }
  if (filter.src) {
    const src = filter.src.toLowerCase();
    if (
      ev.device.toLowerCase() !== src &&
      ev.rawHost.toLowerCase() !== src &&
      !(ev.interfaceOrDn ?? "").toLowerCase().includes(src)
    ) {
      return false;
    }
  }
  if (filter.dst) {
    const dst = filter.dst.toLowerCase();
    if (
      ev.device.toLowerCase() !== dst &&
      !(ev.interfaceOrDn ?? "").toLowerCase().includes(dst) &&
      !ev.summary.toLowerCase().includes(dst)
    ) {
      return false;
    }
  }
  if (filter.iface) {
    if (!matchesStateInterface(ev.interfaceOrDn, ev.summary, filter.iface)) {
      return false;
    }
  }
  return true;
}

function buildSparklineBuckets(
  events: readonly NormalizedTimelineStateEvent[],
  earliest: number,
  latest: number,
  predicate: (ev: NormalizedTimelineStateEvent) => boolean,
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const counts = Array.from({ length: buckets }, () => 0);
  let total = 0;
  for (const ev of events) {
    if (!predicate(ev)) continue;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ev.timestamp - earliest) / span) * buckets)),
    );
    counts[idx] += 1;
    total += 1;
  }
  return total > 0 ? counts : [];
}

function percentile(values: readonly number[], pct: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1),
  );
  return sorted[idx];
}

function pickTopCode(events: readonly NormalizedTimelineStateEvent[]): string {
  const counts = new Map<
    string,
    { count: number; worstSev: number; latestTs: number }
  >();
  for (const ev of events) {
    const existing = counts.get(ev.codeOrMnemonic);
    if (existing) {
      existing.count += 1;
      existing.worstSev = Math.min(existing.worstSev, ev.severity);
      existing.latestTs = Math.max(existing.latestTs, ev.timestamp);
    } else {
      counts.set(ev.codeOrMnemonic, {
        count: 1,
        worstSev: ev.severity,
        latestTs: ev.timestamp,
      });
    }
  }
  const ranked = [...counts.entries()].sort(([, a], [, b]) => {
    if (a.worstSev !== b.worstSev) return a.worstSev - b.worstSev;
    if (b.count !== a.count) return b.count - a.count;
    return b.latestTs - a.latestTs;
  });
  return ranked[0]?.[0] ?? "—";
}

function isIntentionallyExcludedSyslogRow(row: ProtocolRow): boolean {
  let category = asString(row.category || row.facility).toUpperCase();
  let mnemonic = asString(
    row.mnemonics || row.mnemonic || row.code,
  ).toUpperCase();
  const msg = asString(row.syslog_msg || row.descr);
  if ((!category || !mnemonic) && msg) {
    const match = CISCO_SYSLOG_PREFIX_RE.exec(msg);
    if (match) {
      category = category || match[1].toUpperCase();
      mnemonic = mnemonic || match[3].toUpperCase();
    }
  }
  if (mnemonic && CONFIG_CHANGE_SET.has(mnemonic)) return true;
  if (category && EXCLUDED_AUTH_SET.has(category)) return true;
  return false;
}

function isIntentionallyExcludedAciRow(row: ProtocolRow): boolean {
  const sourcetype = asString(row.sourcetype).toLowerCase();
  const component = asString(row.component).toLowerCase();
  if (
    sourcetype === "cisco:dc:aci:class" &&
    component !== "faultinst" &&
    component !== "eventrecord"
  ) {
    return true;
  }
  const code = (asString(row.code) || asString(row.rule)).toUpperCase();
  const aciDomain = asString(row.domain).toUpperCase();
  const aciSubject = asString(row.subject).toUpperCase();
  if (code && CONFIG_CHANGE_SET.has(code)) return true;
  if (aciDomain && EXCLUDED_AUTH_SET.has(aciDomain)) return true;
  if (aciSubject && EXCLUDED_AUTH_SET.has(aciSubject)) return true;
  return false;
}

/**
 * Pure aggregation of normalized operational syslog and ACI fault/event rows
 * into per-device rows, KPIs, operational domain DistributionBar,
 * Device × Domain HeatMatrix, per-device SwimlaneTimeline, and single-sentence verdict.
 */
export function buildStateEventsAnalysis(options: {
  events: readonly { event: NormalizedTimelineStateEvent; indexName: string }[];
  thresholds: ResolvedStateEventsThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  filter?: ProtocolFilter;
  unparsedRowCount?: number;
  includeAci?: boolean;
}): StateEventsInvestigationResult {
  const {
    events,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
    filter,
    unparsedRowCount = 0,
  } = options;
  const includeAci =
    options.includeAci ??
    (thresholds.includeAci ||
      events.some((e) => e.event.sourceKind === "aci_fault"));
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  const filteredEvents = events.filter(({ event }) =>
    matchesRequestFilter(event, filter),
  );

  if (!filteredEvents.length) {
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        distribution: [],
        outcomes,
        capped,
        sourceMode: "none",
        includeAci,
        bannerState: "blocked",
        bannerReason:
          outcomes.find((o) => o.state === "blocked")?.detail ??
          "Access denied for one or more state-event source indexes.",
        checkedAt: nowSec,
      };
    }
    if (anyUnavailable) {
      return {
        verdict: "One or more configured sources failed in this UTC window.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unavailable",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        distribution: [],
        outcomes,
        capped,
        sourceMode: "none",
        includeAci,
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured state-event source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (anyPartial) {
      return {
        verdict:
          "Search hit row cap before matching operational state events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        distribution: [],
        outcomes,
        capped,
        sourceMode: "none",
        includeAci,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching operational state events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    if (unparsedRowCount > 0) {
      const reason = `${unparsedRowCount} ${unparsedRowCount === 1 ? "row" : "rows"} returned but could not be normalized.`;
      return {
        verdict: reason,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unparsed rows",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        distribution: [],
        outcomes,
        capped,
        sourceMode: "none",
        includeAci,
        bannerState: "unavailable",
        bannerReason: reason,
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No operational network state changes observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      distribution: [],
      outcomes,
      capped,
      sourceMode: "none",
      includeAci,
      bannerState: "empty",
      bannerReason:
        "No matching link, routing, L2, HSRP/VRRP, PIM, or ACI fault/event transitions observed in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const deviceMap = new Map<
    string,
    {
      device: string;
      rawHosts: Set<string>;
      events: NormalizedTimelineStateEvent[];
      indexName: string;
    }
  >();

  for (const entry of filteredEvents) {
    const ev = entry.event;
    const existing = deviceMap.get(ev.device);
    if (existing) {
      existing.events.push(ev);
      existing.rawHosts.add(ev.rawHost);
    } else {
      deviceMap.set(ev.device, {
        device: ev.device,
        rawHosts: new Set([ev.rawHost]),
        events: [ev],
        indexName: entry.indexName,
      });
    }
  }

  const hasSyslogAll = filteredEvents.some(
    (e) => e.event.sourceKind === "syslog",
  );
  const hasAciAll = filteredEvents.some(
    (e) => e.event.sourceKind === "aci_fault",
  );
  const sourceMode: StateEventsInvestigationResult["sourceMode"] =
    hasSyslogAll && hasAciAll
      ? "syslog_and_aci_faults"
      : hasAciAll
        ? "aci_faults_only"
        : "syslog_only";

  const usedIds = new Set<string>();
  const rows: StateEventDeviceRow[] = [];

  for (const group of deviceMap.values()) {
    const id = makeSafeDeviceId(group.device, usedIds);
    const chronological = [...group.events].sort(
      (a, b) => a.timestamp - b.timestamp,
    );
    const hasSyslog = chronological.some((e) => e.sourceKind === "syslog");
    const hasAci = chronological.some((e) => e.sourceKind === "aci_fault");
    const sourceCoverage: StateEventDeviceRow["sourceCoverage"] =
      hasSyslog && hasAci
        ? "syslog_and_aci_faults"
        : hasAci
          ? "aci_faults_only"
          : "syslog_only";

    const criticalErrorCount = chronological.filter(
      (e) => e.severity <= thresholds.maxSeverityAttention,
    ).length;
    const worstSeverity = Math.min(...chronological.map((e) => e.severity));
    const domainKeySet = new Set(chronological.map((e) => e.domain));
    const domainKeys = CANONICAL_DOMAIN_ORDER.filter((d) =>
      domainKeySet.has(d),
    );
    const domains = domainKeys.map((d) => DOMAIN_LABELS[d]);
    const topCode = pickTopCode(chronological);
    const latestTime = chronological[chronological.length - 1].timestamp;
    const hasHsrpVrrp = chronological.some((e) => e.isHsrpVrrp);

    const reasons: string[] = [];
    if (criticalErrorCount > 0) {
      reasons.push(
        `${criticalErrorCount} severity ≤ ${thresholds.maxSeverityAttention} ${criticalErrorCount === 1 ? "event" : "events"}`,
      );
    }
    if (chronological.length >= thresholds.burstWarnCount) {
      reasons.push(
        `${chronological.length} events (≥ ${thresholds.burstWarnCount} burst threshold)`,
      );
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention ? "attention" : "ok";

    const transitions: StateEventTransitionEntry[] = [...chronological]
      .reverse()
      .slice(0, 25)
      .map((ev) => ({
        id: ev.id,
        timestamp: ev.timestamp,
        domain: ev.domain,
        domainLabel: ev.domainLabel,
        severity: ev.severity,
        severityLabel: ev.severityLabel,
        codeOrMnemonic: ev.codeOrMnemonic,
        ...(ev.interfaceOrDn ? { interfaceOrDn: ev.interfaceOrDn } : {}),
        summary: ev.summary,
        sourceKind: ev.sourceKind,
      }));

    rows.push({
      id,
      attention,
      device: group.device,
      rawHosts: [...group.rawHosts],
      eventCount: chronological.length,
      criticalErrorCount,
      worstSeverity,
      domains,
      domainKeys,
      topCode,
      latestTime,
      hasHsrpVrrp,
      sourceCoverage,
      transitions,
      status,
      reasons,
      indexName: group.indexName,
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (b.criticalErrorCount !== a.criticalErrorCount)
      return b.criticalErrorCount - a.criticalErrorCount;
    if (b.eventCount !== a.eventCount) return b.eventCount - a.eventCount;
    if (b.latestTime !== a.latestTime) return b.latestTime - a.latestTime;
    return a.device.localeCompare(b.device);
  });

  // KPI strip (<= 4 tiles with explicit units)
  const allEventsFlat = filteredEvents.map((e) => e.event);
  const totalEvents = allEventsFlat.length;
  const criticalEventsCount = allEventsFlat.filter(
    (e) => e.severity <= thresholds.maxSeverityAttention,
  ).length;
  const burstDevicesCount = rows.filter(
    (r) => r.eventCount >= thresholds.burstWarnCount,
  ).length;
  const flaggedRows = rows.filter((r) => r.attention);

  const eventSpark = buildSparklineBuckets(
    allEventsFlat,
    earliest,
    latest,
    () => true,
  );
  const critSpark = buildSparklineBuckets(
    allEventsFlat,
    earliest,
    latest,
    (e) => e.severity <= thresholds.maxSeverityAttention,
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "total-events",
      label: "State Events",
      value: formatCount(totalEvents),
      unit: totalEvents === 1 ? "event" : "events",
      status: flaggedRows.length > 0 ? "attention" : "ok",
      ...(eventSpark.length ? { sparkline: eventSpark } : {}),
    },
    {
      id: "devices",
      label: "Devices",
      value: formatCount(rows.length),
      unit: rows.length === 1 ? "device" : "devices",
      status: flaggedRows.length > 0 ? "attention" : "ok",
    },
    {
      id: "critical-events",
      label: "Critical / Error",
      value: formatCount(criticalEventsCount),
      unit: criticalEventsCount === 1 ? "event" : "events",
      status: criticalEventsCount > 0 ? "attention" : "ok",
      hint: `Syslog or ACI severity ≤ ${thresholds.maxSeverityAttention}`,
      ...(critSpark.length ? { sparkline: critSpark } : {}),
    },
    {
      id: "burst-devices",
      label: "Burst Devices",
      value: formatCount(burstDevicesCount),
      unit: burstDevicesCount === 1 ? "device" : "devices",
      status: burstDevicesCount > 0 ? "attention" : "ok",
      hint: `Devices with ≥ ${thresholds.burstWarnCount} events`,
    },
  ];

  // HeatMatrix (Device × Operational Domain)
  const observedDomainKeys = CANONICAL_DOMAIN_ORDER.filter((d) =>
    allEventsFlat.some((e) => e.domain === d),
  );
  const matrixRows = rows.map((r) => r.device);
  const matrixCols = observedDomainKeys.map((d) => DOMAIN_LABELS[d]);
  const rowByDevice = new Map<string, StateEventDeviceRow>(
    rows.map((r) => [r.device, r]),
  );

  const cellBuckets = new Map<
    string,
    {
      device: string;
      domainLabel: string;
      events: NormalizedTimelineStateEvent[];
    }
  >();
  for (const ev of allEventsFlat) {
    const key = `${ev.device}\0${ev.domainLabel}`;
    const existing = cellBuckets.get(key);
    if (existing) {
      existing.events.push(ev);
    } else {
      cellBuckets.set(key, {
        device: ev.device,
        domainLabel: ev.domainLabel,
        events: [ev],
      });
    }
  }

  const matrixCells: ProtocolMatrixCell[] = [];
  for (const bucket of cellBuckets.values()) {
    const row = rowByDevice.get(bucket.device);
    const critCount = bucket.events.filter(
      (e) => e.severity <= thresholds.maxSeverityAttention,
    ).length;
    const total = bucket.events.length;
    const isCellAttention = critCount > 0 || total >= thresholds.burstWarnCount;
    const top = pickTopCode(bucket.events);
    const value =
      critCount > 0
        ? `${total} (${critCount} crit)`
        : `${total} ${total === 1 ? "ev" : "evs"}`;
    matrixCells.push({
      row: bucket.device,
      col: bucket.domainLabel,
      status: isCellAttention ? "attention" : "ok",
      value,
      count: total,
      detail: `${top} · ${bucket.events[bucket.events.length - 1].summary}`,
      ...(row ? { itemId: row.id } : {}),
    });
  }

  // SwimlaneTimeline (one swimlane per device, chronological state changes)
  const sortedTimelineSource = [...allEventsFlat]
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(0, MAX_INPUT_ROWS);
  const timelineRowByEventId: Record<string, string> = {};
  const timelineEvents: ProtocolTimelineEvent[] = sortedTimelineSource.map(
    (ev) => {
      const row = rowByDevice.get(ev.device);
      const timelineId = `${row?.id ?? ev.device}\u001f${ev.id}`;
      if (row) {
        timelineRowByEventId[timelineId] = row.id;
      }
      const kind: ProtocolTimelineEvent["kind"] =
        ev.severity <= thresholds.maxSeverityAttention
          ? "attention"
          : ev.severity === 4
            ? "info"
            : "ok";
      return {
        id: timelineId,
        lane: ev.device,
        timestamp: ev.timestamp,
        kind,
        label: `${ev.domainLabel} · ${ev.codeOrMnemonic}`,
        detail: ev.interfaceOrDn
          ? `${ev.interfaceOrDn} — ${ev.summary}`
          : ev.summary,
      };
    },
  );

  // DistributionBar by operational domain (true domain event totals in `count`)
  const distribution: ProtocolDistributionMetric[] = observedDomainKeys
    .map((domainKey) => {
      const domainEvents = allEventsFlat.filter((e) => e.domain === domainKey);
      const perDevice = new Map<string, number>();
      for (const ev of domainEvents) {
        perDevice.set(ev.device, (perDevice.get(ev.device) ?? 0) + 1);
      }
      const counts = [...perDevice.values()];
      const hasCrit = domainEvents.some(
        (e) => e.severity <= thresholds.maxSeverityAttention,
      );
      const hasBurst = counts.some((c) => c >= thresholds.burstWarnCount);
      return {
        total: domainEvents.length,
        metric: {
          id: domainKey,
          label: DOMAIN_LABELS[domainKey],
          p50: percentile(counts, 50),
          p95: percentile(counts, 95),
          count: domainEvents.length,
          max: Math.max(...counts, 1),
          unit: "events",
          status: (hasCrit || hasBurst ? "attention" : "ok") as ProtocolStatus,
        },
      };
    })
    .sort((a, b) => b.total - a.total)
    .map((entry) => entry.metric);

  // Single-sentence plain-language verdict (keep thresholds out of the headline)
  let verdict: string;
  let verdictStatus: ProtocolStatus;
  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    if (criticalEventsCount > 0) {
      verdict = `${totalEvents} state ${totalEvents === 1 ? "change" : "changes"} across ${rows.length} ${rows.length === 1 ? "device" : "devices"}: ${criticalEventsCount} critical/error, led by ${lead.device} (${lead.topCode}).`;
    } else {
      verdict = `${totalEvents} state ${totalEvents === 1 ? "change" : "changes"} across ${rows.length} ${rows.length === 1 ? "device" : "devices"}: burst activity on ${lead.device} (${lead.eventCount} events).`;
    }
    verdictStatus = "attention";
  } else {
    verdict = `${totalEvents} operational state ${totalEvents === 1 ? "change" : "changes"} across ${rows.length} ${rows.length === 1 ? "device" : "devices"} with no critical faults or bursts.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial ? "attention" : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel = `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;
  const partialReason = anyBlocked
    ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
    : anyUnavailable
      ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
      : "Search hit row cap or partial source — narrow the UTC window or filter.";

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    kpis,
    rows,
    matrixRows,
    matrixCols,
    matrixCells,
    timelineEvents,
    timelineRowByEventId,
    distribution,
    outcomes,
    capped,
    sourceMode,
    includeAci,
    ...(anyPartial
      ? {
          bannerState: "partial" as const,
          bannerReason: partialReason,
        }
      : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateStateEventsOptions {
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand Network State-Change Timeline investigation across
 * configured `state_events` profiles (SC4S/DCN syslog and/or ACI `faultInst` /
 * `eventRecord`), rechecking the `adm_protocol_profiles` fingerprint.
 */
export async function investigateStateEvents(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateStateEventsOptions = {},
): Promise<StateEventsInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "state_events" && p.scope === request.scope,
  );
  if (!scoped.length) {
    return {
      verdict: "No active source profile covers this scope.",
      verdictStatus: "not_covered",
      coverageStatus: "not_covered",
      coverageLabel: "Not covered",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      distribution: [],
      outcomes: [],
      capped: false,
      sourceMode: "none",
      includeAci: true,
      bannerState: "unavailable",
      bannerReason: `No state_events profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: {
      event: NormalizedTimelineStateEvent;
      indexName: string;
    }[] = [];
    let capped = false;
    let unparsedRowCount = 0;
    let anyIncludeAci = false;
    const primaryThresholds = resolveStateEventsThresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const thresholds = resolveStateEventsThresholds(profile);
      if (thresholds.includeAci || thresholds.sourceKind === "aci_faults") {
        anyIncludeAci = true;
      }
      const runSyslog =
        thresholds.sourceKind === "syslog" || thresholds.sourceKind === "auto";
      const runAciFaults =
        thresholds.sourceKind === "aci_faults" ||
        (thresholds.sourceKind === "auto" && thresholds.includeAci);

      if (runSyslog) {
        const spl = buildStateSyslogSearch({
          index: profile.index,
          filter: request.filter,
          includeAci: thresholds.includeAci,
          maxRows: MAX_INPUT_ROWS,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "state_events",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          maxRows: MAX_INPUT_ROWS,
          signal,
          keySuffix: "syslog",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeStateSyslogRow(row, idx);
          if (norm) {
            collected.push({ event: norm, indexName: profile.index });
          } else if (!isIntentionallyExcludedSyslogRow(row)) {
            unparsedRowCount += 1;
          }
        });
      }

      if (runAciFaults) {
        signal.throwIfAborted();
        const spl = buildAciFaultEventSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: MAX_INPUT_ROWS,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "state_events",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          maxRows: MAX_INPUT_ROWS,
          signal,
          keySuffix: "aci_faults",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeAciFaultEventRow(row, idx);
          if (norm) {
            collected.push({ event: norm, indexName: profile.index });
          } else if (!isIntentionallyExcludedAciRow(row)) {
            unparsedRowCount += 1;
          }
        });
      }
    }

    return buildStateEventsAnalysis({
      events: collected,
      thresholds: primaryThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      filter: request.filter,
      unparsedRowCount,
      includeAci: anyIncludeAci,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    state_events: validateStateEventsExtra,
  };

  try {
    return await withProtocolConfigRecheck(
      configuration.fingerprint,
      validators,
      runProfiles,
      signal,
    );
  } catch (error) {
    if (error instanceof ProtocolConfigurationChangedError) {
      return {
        verdict: error.message,
        verdictStatus: "attention",
        coverageStatus: "unknown",
        coverageLabel: "Stale config",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        distribution: [],
        outcomes: [],
        capped: false,
        sourceMode: "none",
        includeAci: true,
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Hub "Check all" summary runner for `state_events`.
 */
export async function summarizeStateEvents(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateStateEventsOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateStateEvents(
    client,
    request,
    configuration,
    signal,
    options,
  );
  const degraded =
    result.capped ||
    result.outcomes.some(
      (o) =>
        o.state === "blocked" ||
        o.state === "unavailable" ||
        o.state === "partial",
    );
  const status: ProtocolStatus =
    degraded && result.verdictStatus === "ok"
      ? "attention"
      : degraded && result.verdictStatus === "none_observed"
        ? "unknown"
        : result.verdictStatus;
  return {
    lens: "state_events",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
