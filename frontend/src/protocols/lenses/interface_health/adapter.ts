import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  buildSyslogStateSearch,
  normalizeSyslogRow,
  type AllowedSyslogSourcetype,
  type NormalizedStateEvent,
} from "../../shared/adapters/nxosSyslog";
import type {
  BaseProtocolProfile,
  LensProfileValidator,
  ProtocolConfiguration,
  ProtocolDistributionMetric,
  ProtocolFilter,
  ProtocolKpi,
  ProtocolLensId,
  ProtocolLensSummary,
  ProtocolMatrixCell,
  ProtocolRequest,
  ProtocolSourceOutcome,
  ProtocolStatus,
  ProtocolTimelineEvent,
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
  DEFAULT_INTERFACE_HEALTH_THRESHOLDS,
  validateInterfaceHealthExtra,
  type InterfaceHealthExtraConfig,
  type InterfaceHealthSourceKind,
  type ResolvedInterfaceHealthThresholds,
} from "./validate";

export {
  DEFAULT_INTERFACE_HEALTH_THRESHOLDS,
  validateInterfaceHealthExtra,
  type InterfaceHealthExtraConfig,
  type InterfaceHealthSourceKind,
  type ResolvedInterfaceHealthThresholds,
};

export function resolveInterfaceHealthThresholds(
  profile?: BaseProtocolProfile,
): ResolvedInterfaceHealthThresholds {
  const extra = profile?.extra as InterfaceHealthExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "dme" ||
      extra?.sourceKind === "syslog" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_INTERFACE_HEALTH_THRESHOLDS.sourceKind,
    errorWarnCount:
      typeof extra?.errorWarnCount === "number"
        ? extra.errorWarnCount
        : DEFAULT_INTERFACE_HEALTH_THRESHOLDS.errorWarnCount,
    discardWarnCount:
      typeof extra?.discardWarnCount === "number"
        ? extra.discardWarnCount
        : DEFAULT_INTERFACE_HEALTH_THRESHOLDS.discardWarnCount,
    flapWarnCount:
      typeof extra?.flapWarnCount === "number"
        ? extra.flapWarnCount
        : DEFAULT_INTERFACE_HEALTH_THRESHOLDS.flapWarnCount,
    utilizationWarnPct:
      typeof extra?.utilizationWarnPct === "number"
        ? extra.utilizationWarnPct
        : DEFAULT_INTERFACE_HEALTH_THRESHOLDS.utilizationWarnPct,
  };
}

export const INTERFACE_DME_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "dn",
  "descr",
  "interface",
  "interface_name",
  "speed",
  "mtu",
  "admin_state",
  "oper_state",
  "adminSt",
  "operSt",
  "in_octets",
  "out_octets",
  "in_errors",
  "out_errors",
  "in_discards",
  "out_discards",
  "crc_errors",
  "rx_bytes",
  "tx_bytes",
  "rx_drops",
  "tx_drops",
  "utilization_pct",
  "flap_count",
] as const;

/**
 * Builds a bounded, allowlisted SPL query for Cisco DC Networking DME
 * (`cisco:dc:nexus9k:dme`, `cisco:dc:nd:*`).
 * Emits `| head <maxRows + 1>` BEFORE `buildAllowedFieldsClause` (`| table ...`)
 * so indexers cap rows before projecting and drop `_raw` server-side.
 */
export function buildInterfaceDmeSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    `(sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*")`,
    `(component="l1PhysIf" OR component="ethpmPhysIf" OR component="rmon*" OR dn="sys/intf/phys-*" OR interface=* OR interface_name=* OR interfaceName=*)`,
  ];
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`host="${dev}"`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const evalClause =
    `| eval host=coalesce(nodeName, switchName, host, device), ` +
    `interface=coalesce(interface, interface_name, interfaceName, interfaceUniqueId, 'Row_info.id'), ` +
    `dn=coalesce(dn, 'Row_info.dn'), ` +
    `descr=coalesce(descr, desc, interfaceDescription, 'Row_info.descr'), ` +
    `admin_state=coalesce(admin_state, adminStatus, adminSt, 'Row_info.adminSt'), ` +
    `oper_state=coalesce(oper_state, operStatus, operSt, 'Row_info.operSt'), ` +
    `speed=coalesce(speed, portSpeed, eth_speed, 'Row_info.speed'), ` +
    `mtu=coalesce(mtu, eth_mtu, 'Row_info.mtu'), ` +
    `in_errors=coalesce(in_errors, inErrors, eth_inerr, 'Row_info.inErrors'), ` +
    `out_errors=coalesce(out_errors, outErrors, eth_outerr, 'Row_info.outErrors'), ` +
    `crc_errors=coalesce(crc_errors, crcErrors, eth_crc, 'Row_info.crcErrors'), ` +
    `in_discards=coalesce(in_discards, inDiscards, eth_indiscard, 'Row_info.inDiscards'), ` +
    `out_discards=coalesce(out_discards, outDiscards, eth_outdiscard, 'Row_info.outDiscards'), ` +
    `rx_drops=coalesce(rx_drops, rxDrops, 'Row_info.rxDrops'), ` +
    `tx_drops=coalesce(tx_drops, txDrops, 'Row_info.txDrops'), ` +
    `in_octets=coalesce(in_octets, inOctets, rx_bytes, eth_inbytes, 'Row_info.inOctets'), ` +
    `out_octets=coalesce(out_octets, outOctets, tx_bytes, eth_outbytes, 'Row_info.outOctets'), ` +
    `utilization_pct=coalesce(utilization_pct, interfaceRateIngress), ` +
    `flap_count=coalesce(flap_count, eth_link_flapped) `;
  const tableClause = buildAllowedFieldsClause(
    "interface_health",
    INTERFACE_DME_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${evalClause}${tableClause}`;
}

/**
 * Delegates NX-OS / ACI interface syslog SPL generation to the shared
 * `nxosSyslog.ts` adapter (`buildSyslogStateSearch`).
 */
export const INTERFACE_SYSLOG_FILTER_CATEGORIES = [
  "ETHPORT",
  "ETH_PORT",
  "LINK",
  "LINEPROTO",
  "TRANSCEIVER",
  "SFP",
  "DOM",
  "ETH_PORT_CHANNEL",
  "PM",
] as const;

const INTERFACE_SYSLOG_CATEGORIES = new Set<string>(
  INTERFACE_SYSLOG_FILTER_CATEGORIES,
);

export function buildInterfaceSyslogSearch(options: {
  index: string;
  device?: string;
  sourcetypes?: readonly AllowedSyslogSourcetype[];
  maxRows: number;
}): string {
  return buildSyslogStateSearch({
    index: options.index,
    device: options.device,
    sourcetypes: options.sourcetypes,
    categories: INTERFACE_SYSLOG_FILTER_CATEGORIES,
    includeAci: true,
    maxRows: options.maxRows,
  });
}

/**
 * Builds a literal-quoted Splunk Search URL for raw events of a selected
 * `(device, interface)` row.
 */
export function buildInterfaceRawEventsUrl(options: {
  index: string;
  device: string;
  iface: string;
  sourceMode: "dme" | "syslog" | "mixed";
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const device = literal(options.device, 128);
  const iface = literal(options.iface, 128);
  const stClause =
    options.sourceMode === "syslog"
      ? `(sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog")`
      : options.sourceMode === "dme"
        ? `(sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*")`
        : `(sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*" OR sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog")`;
  const q = `search index=${index} ${stClause} host="${device}" (interface="${iface}" OR interface_name="${iface}" OR "${iface}")`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedInterfaceDmeEvent {
  sourceKind: "dme";
  timestamp: number | undefined;
  device: string;
  interface: string;
  canonKey: string;
  sourcetype: string;
  dn?: string;
  descr?: string;
  adminState?: string;
  operState?: string;
  speed?: string;
  mtu?: number;
  crcErrors?: number;
  inErrors?: number;
  outErrors?: number;
  inDiscards?: number;
  outDiscards?: number;
  rxDrops?: number;
  txDrops?: number;
  inOctets?: number;
  outOctets?: number;
  utilizationPct?: number;
  flapCount?: number;
  hasErrorCounters: boolean;
  hasDiscardCounters: boolean;
}

export interface NormalizedInterfaceSyslogEvent {
  id: string;
  sourceKind: "syslog";
  timestamp: number;
  device: string;
  interface: string;
  canonKey: string;
  category: string;
  severity: number;
  mnemonic: string;
  summary: string;
  isDown: boolean;
  isUp: boolean;
  isFlapTransition: boolean;
  isError: boolean;
  isDomWarning: boolean;
  stateEvent: NormalizedStateEvent;
}

export interface InterfaceHealthRow {
  /** URL-safe `ITEM_ID` matching `^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,191}$`. */
  id: string;
  attention: boolean;
  device: string;
  interface: string;
  descr?: string;
  adminState?: string;
  operState?: string;
  adminUpOperDown: boolean;
  speed?: string;
  mtu?: number;
  crcErrors?: number;
  inErrors?: number;
  outErrors?: number;
  totalErrors?: number;
  inDiscards?: number;
  outDiscards?: number;
  rxDrops?: number;
  txDrops?: number;
  totalDiscards?: number;
  inOctets?: number;
  outOctets?: number;
  flapCount?: number;
  utilizationPct?: number;
  hasStateCoverage: boolean;
  hasCounterCoverage: boolean;
  hasUtilizationCoverage: boolean;
  hasSyslogCoverage: boolean;
  sourceKind: "dme_only" | "syslog_only" | "dme_and_syslog";
  lastMnemonic?: string;
  recentSyslog: Array<{
    timestamp: number;
    mnemonic: string;
    severity: number;
    summary: string;
  }>;
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface InterfaceHealthInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: InterfaceHealthRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  distribution: ProtocolDistributionMetric[];
  distributionTitle: string;
  timelineEvents: ProtocolTimelineEvent[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "dme_only" | "syslog_only" | "mixed" | "none";
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

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const num = Number(value.trim());
    if (Number.isFinite(num)) return num;
  }
  return undefined;
}

function asEpochSeconds(value: unknown): number | undefined {
  const num = asFiniteNumber(value);
  if (num !== undefined && num > 0) return num;
  if (typeof value === "string" && value.trim()) {
    const parsed = Date.parse(value.trim());
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.floor(parsed / 1000);
    }
  }
  return undefined;
}

const DN_IFACE_RE = /(?:phys|intf\/[^/]+)-\[([^\]]+)\]|\[([^\]]+)\]/i;
const SYSLOG_IFACE_RE =
  /\b(?:Interface|port)\s+((?:Ethernet|Eth|GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Port-channel|port-channel|Po|Vlan|mgmt|loopback|lo)[A-Za-z0-9./:-]+)/i;

export function extractInterfaceFromDn(dn: string): string {
  if (!dn) return "";
  const match = DN_IFACE_RE.exec(dn);
  return (match?.[1] ?? match?.[2] ?? "").trim();
}

export function canonicalInterfaceKey(iface: string): string {
  const trimmed = iface.trim().toLowerCase();
  const ethShort = /^eth(\d.*)$/.exec(trimmed);
  if (ethShort) return `ethernet${ethShort[1]}`;
  const poShort = /^po(\d.*)$/.exec(trimmed);
  if (poShort) return `port-channel${poShort[1]}`;
  return trimmed;
}

function preferInterfaceDisplayName(
  current: string,
  candidate: string,
): string {
  if (!current) return candidate;
  if (/^Ethernet/i.test(candidate) && !/^Ethernet/i.test(current)) {
    return candidate;
  }
  if (/^Port-channel/i.test(candidate) && !/^Port-channel/i.test(current)) {
    return candidate;
  }
  return current;
}

function sanitizeIdPart(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._:/@-]/g, "_")
    .replace(/^[^A-Za-z0-9]+/, "");
  return cleaned || "item";
}

export function makeInterfaceRowId(device: string, iface: string): string {
  const left = sanitizeIdPart(device).slice(0, 94);
  const right = sanitizeIdPart(iface).slice(0, 94);
  return `${left}__${right}`.slice(0, 192);
}

export function formatInterfaceSpeed(raw: unknown): string | undefined {
  const s = asString(raw);
  if (!s) return undefined;
  const gbpsMatch = /^(\d+(?:\.\d+)?)\s*g(?:bps)?$/i.exec(s);
  if (gbpsMatch) return `${gbpsMatch[1]} Gbps`;
  const mbpsMatch = /^(\d+(?:\.\d+)?)\s*m(?:bps)?$/i.exec(s);
  if (mbpsMatch) return `${mbpsMatch[1]} Mbps`;
  const num = asFiniteNumber(s);
  if (num !== undefined && num > 0) {
    if (num >= 1_000_000_000) return `${Math.round(num / 1_000_000_000)} Gbps`;
    if (num >= 1_000_000) return `${Math.round(num / 1_000_000)} Mbps`;
    if (num >= 1_000) return `${Math.round(num / 1_000)} Gbps`;
    return `${Math.round(num)} Mbps`;
  }
  return s;
}

function normalizeStateValue(raw: unknown): string | undefined {
  const s = asString(raw).toLowerCase();
  if (!s) return undefined;
  if (s === "enabled" || s === "link-up") return "up";
  if (s === "disabled" || s === "link-down") return "down";
  return s;
}

const INTERFACE_SYSLOG_MNEMONIC_RE =
  /^(?:IF_DOWN|IF_UP|IF_ERROR|IF_DUPLEX|IF_SPEED|DOM_|SFP_|TRANSCEIVER|UPDOWN|ERR_DISABLE|LINK)/i;

/**
 * Normalizes a single allowlist-projected DME or ND interface event row.
 */
export function normalizeInterfaceDmeRow(
  row: ProtocolRow,
): NormalizedInterfaceDmeEvent | undefined {
  const device = asString(row.host);
  const ifaceRaw =
    asString(row.interface) ||
    asString(row.interface_name) ||
    extractInterfaceFromDn(asString(row.dn));
  if (!device || !ifaceRaw) return undefined;

  const adminState = normalizeStateValue(row.admin_state ?? row.adminSt);
  const operState = normalizeStateValue(row.oper_state ?? row.operSt);
  const speed = formatInterfaceSpeed(row.speed);
  const mtuVal = asFiniteNumber(row.mtu);
  const mtu =
    mtuVal !== undefined && mtuVal > 0 ? Math.trunc(mtuVal) : undefined;

  const crcErrors = asFiniteNumber(row.crc_errors);
  const inErrors = asFiniteNumber(row.in_errors);
  const outErrors = asFiniteNumber(row.out_errors);
  const inDiscards = asFiniteNumber(row.in_discards);
  const outDiscards = asFiniteNumber(row.out_discards);
  const rxDrops = asFiniteNumber(row.rx_drops);
  const txDrops = asFiniteNumber(row.tx_drops);
  const inOctets = asFiniteNumber(row.in_octets ?? row.rx_bytes);
  const outOctets = asFiniteNumber(row.out_octets ?? row.tx_bytes);
  const utilizationPct = asFiniteNumber(row.utilization_pct);
  const flapCount = asFiniteNumber(row.flap_count);
  const descr = asString(row.descr) || undefined;
  const dn = asString(row.dn) || undefined;

  return {
    sourceKind: "dme",
    timestamp: asEpochSeconds(row._time),
    device,
    interface: ifaceRaw,
    canonKey: canonicalInterfaceKey(ifaceRaw),
    sourcetype: asString(row.sourcetype) || "cisco:dc:nexus9k:dme",
    ...(dn ? { dn } : {}),
    ...(descr ? { descr } : {}),
    ...(adminState ? { adminState } : {}),
    ...(operState ? { operState } : {}),
    ...(speed ? { speed } : {}),
    ...(mtu !== undefined ? { mtu } : {}),
    ...(crcErrors !== undefined ? { crcErrors: Math.max(0, crcErrors) } : {}),
    ...(inErrors !== undefined ? { inErrors: Math.max(0, inErrors) } : {}),
    ...(outErrors !== undefined ? { outErrors: Math.max(0, outErrors) } : {}),
    ...(inDiscards !== undefined
      ? { inDiscards: Math.max(0, inDiscards) }
      : {}),
    ...(outDiscards !== undefined
      ? { outDiscards: Math.max(0, outDiscards) }
      : {}),
    ...(rxDrops !== undefined ? { rxDrops: Math.max(0, rxDrops) } : {}),
    ...(txDrops !== undefined ? { txDrops: Math.max(0, txDrops) } : {}),
    ...(inOctets !== undefined ? { inOctets: Math.max(0, inOctets) } : {}),
    ...(outOctets !== undefined ? { outOctets: Math.max(0, outOctets) } : {}),
    ...(utilizationPct !== undefined
      ? { utilizationPct: Math.max(0, Math.min(100, utilizationPct)) }
      : {}),
    ...(flapCount !== undefined ? { flapCount: Math.max(0, flapCount) } : {}),
    hasErrorCounters:
      crcErrors !== undefined ||
      inErrors !== undefined ||
      outErrors !== undefined,
    hasDiscardCounters:
      inDiscards !== undefined ||
      outDiscards !== undefined ||
      rxDrops !== undefined ||
      txDrops !== undefined,
  };
}

/**
 * Normalizes a syslog row via the shared `nxosSyslog.ts` adapter and filters
 * to interface link, error, and DOM transceiver events.
 */
export function normalizeInterfaceSyslogRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedInterfaceSyslogEvent | undefined {
  const ev = normalizeSyslogRow(row, indexInBatch);
  if (!ev) return undefined;
  const catUpper = ev.category.toUpperCase();
  const isInterfaceEvent =
    ev.domain === "link" ||
    INTERFACE_SYSLOG_CATEGORIES.has(catUpper) ||
    INTERFACE_SYSLOG_MNEMONIC_RE.test(ev.mnemonic);
  if (!isInterfaceEvent) return undefined;

  let iface = ev.interface
    ? extractInterfaceFromDn(ev.interface) || ev.interface
    : "";
  if (!iface && ev.summary) {
    const match = SYSLOG_IFACE_RE.exec(ev.summary);
    if (match) iface = match[1].trim();
  }
  if (!iface) return undefined;

  const mnem = ev.mnemonic.toUpperCase();
  const sumLower = ev.summary.toLowerCase();
  const isDown =
    mnem.startsWith("IF_DOWN") ||
    mnem === "ERR_DISABLE" ||
    (mnem.includes("UPDOWN") && /\bdown\b/.test(sumLower));
  const isUp =
    mnem.startsWith("IF_UP") ||
    (mnem.includes("UPDOWN") && /\bup\b/.test(sumLower));
  const isFlapTransition = isDown || isUp;
  const isDomWarning =
    catUpper === "TRANSCEIVER" ||
    mnem.startsWith("DOM_") ||
    mnem.includes("DOM_");
  const isError =
    mnem.startsWith("IF_ERROR") ||
    mnem.includes("ERR_DISABLE") ||
    (!isFlapTransition && !isDomWarning && ev.severity <= 3);

  return {
    id: ev.id,
    sourceKind: "syslog",
    timestamp: ev.timestamp,
    device: ev.host,
    interface: iface,
    canonKey: canonicalInterfaceKey(iface),
    category: ev.category,
    severity: ev.severity,
    mnemonic: ev.mnemonic,
    summary: ev.summary,
    isDown,
    isUp,
    isFlapTransition,
    isError,
    isDomWarning,
    stateEvent: ev,
  };
}

export function percentile(
  values: readonly number[],
  pct: number,
): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1),
  );
  return sorted[idx];
}

function roundMetric(val: number): number {
  return val < 10 ? Math.round(val * 10) / 10 : Math.round(val);
}

function buildSparklineBuckets(
  items: readonly { timestamp?: number; value: number | undefined }[],
  earliest: number,
  latest: number,
  mode: "max" | "sum",
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const grouped: number[][] = Array.from({ length: buckets }, () => []);
  for (const item of items) {
    if (item.value === undefined) continue;
    const ts = item.timestamp ?? earliest;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ts - earliest) / span) * buckets)),
    );
    grouped[idx].push(item.value);
  }
  const points = grouped.map((bucket) => {
    if (!bucket.length) return undefined;
    return mode === "sum"
      ? bucket.reduce((a, b) => a + b, 0)
      : Math.max(...bucket);
  });
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

function buildMatrixCellLabel(
  row: InterfaceHealthRow,
  thresholds: ResolvedInterfaceHealthThresholds,
): string {
  if (row.status === "not_covered") return "Not covered";
  if (row.attention) {
    if (row.adminUpOperDown) return "Admin up / Down";
    if ((row.crcErrors ?? 0) >= thresholds.errorWarnCount) {
      return `${formatCount(row.crcErrors)} CRC`;
    }
    if ((row.totalErrors ?? 0) >= thresholds.errorWarnCount) {
      return `${formatCount(row.totalErrors)} err`;
    }
    if ((row.totalDiscards ?? 0) >= thresholds.discardWarnCount) {
      return `${formatCount(row.totalDiscards)} disc`;
    }
    if ((row.flapCount ?? 0) >= thresholds.flapWarnCount) {
      return `${formatCount(row.flapCount)} flaps`;
    }
    if (
      row.utilizationPct !== undefined &&
      row.utilizationPct >= thresholds.utilizationWarnPct
    ) {
      return `${Math.round(row.utilizationPct)}% util`;
    }
    if (row.lastMnemonic) {
      if (row.lastMnemonic.includes("DOM_")) return "DOM warn";
      if (row.lastMnemonic.includes("IF_ERROR")) return "IF_ERROR";
      if (row.lastMnemonic.startsWith("IF_DOWN")) return "Link down";
    }
    return "Attention";
  }
  if (row.utilizationPct !== undefined) {
    return `${Math.round(row.utilizationPct)}%`;
  }
  if (row.hasCounterCoverage) {
    return `${formatCount(row.totalErrors ?? 0)} err`;
  }
  return "OK";
}

/**
 * Pure aggregation of normalized DME counter snapshots and syslog link/DOM
 * events into Overview rows, KPI tiles, HeatMatrix cells, DistributionBar,
 * SwimlaneTimeline, and a single-sentence verdict.
 */
export function buildInterfaceHealthAnalysis(options: {
  dmeEvents: readonly {
    event: NormalizedInterfaceDmeEvent;
    indexName: string;
  }[];
  syslogEvents: readonly {
    event: NormalizedInterfaceSyslogEvent;
    indexName: string;
  }[];
  thresholds: ResolvedInterfaceHealthThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
}): InterfaceHealthInvestigationResult {
  const {
    dmeEvents,
    syslogEvents,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  if (!dmeEvents.length && !syslogEvents.length) {
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
        distribution: [],
        distributionTitle: "",
        timelineEvents: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "blocked",
        bannerReason:
          outcomes.find((o) => o.state === "blocked")?.detail ??
          "Access denied for one or more source indexes.",
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
        distribution: [],
        distributionTitle: "",
        timelineEvents: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (anyPartial) {
      return {
        verdict:
          "Search hit row cap before matching interface events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        distributionTitle: "",
        timelineEvents: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching interface events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No matching interface DME counters or link syslog events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      distribution: [],
      distributionTitle: "",
      timelineEvents: [],
      outcomes,
      capped,
      sourceMode: "none",
      bannerState: "empty",
      bannerReason: "No matching interface events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  interface GroupBucket {
    device: string;
    interfaceDisplay: string;
    dme: NormalizedInterfaceDmeEvent[];
    syslog: NormalizedInterfaceSyslogEvent[];
    indexName: string;
  }

  const groups = new Map<string, GroupBucket>();

  for (const entry of dmeEvents) {
    const key = `${entry.event.device.toLowerCase()}\0${entry.event.canonKey}`;
    const existing = groups.get(key);
    if (existing) {
      existing.dme.push(entry.event);
      existing.interfaceDisplay = preferInterfaceDisplayName(
        existing.interfaceDisplay,
        entry.event.interface,
      );
      existing.indexName = entry.indexName;
    } else {
      groups.set(key, {
        device: entry.event.device,
        interfaceDisplay: entry.event.interface,
        dme: [entry.event],
        syslog: [],
        indexName: entry.indexName,
      });
    }
  }

  for (const entry of syslogEvents) {
    const key = `${entry.event.device.toLowerCase()}\0${entry.event.canonKey}`;
    const existing = groups.get(key);
    if (existing) {
      existing.syslog.push(entry.event);
      existing.interfaceDisplay = preferInterfaceDisplayName(
        existing.interfaceDisplay,
        entry.event.interface,
      );
    } else {
      groups.set(key, {
        device: entry.event.device,
        interfaceDisplay: entry.event.interface,
        dme: [],
        syslog: [entry.event],
        indexName: entry.indexName,
      });
    }
  }

  const sourceMode: InterfaceHealthInvestigationResult["sourceMode"] =
    dmeEvents.length > 0 && syslogEvents.length > 0
      ? "mixed"
      : dmeEvents.length > 0
        ? "dme_only"
        : "syslog_only";

  const rows: InterfaceHealthRow[] = [];

  for (const group of groups.values()) {
    const sortedDme = [...group.dme].sort(
      (a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0),
    );
    const sortedSyslog = [...group.syslog].sort(
      (a, b) => a.timestamp - b.timestamp,
    );

    // Take latest defined value per DME attribute so separate DME object
    // classes (l1PhysIf, ethpmPhysIf, rmonEtherStats, rmonIfIn, rmonIfOut)
    // combine cleanly without double-counting cumulative counters across polls.
    let descr: string | undefined;
    let adminState: string | undefined;
    let operState: string | undefined;
    let speed: string | undefined;
    let mtu: number | undefined;
    let crcErrors: number | undefined;
    let inErrors: number | undefined;
    let outErrors: number | undefined;
    let inDiscards: number | undefined;
    let outDiscards: number | undefined;
    let rxDrops: number | undefined;
    let txDrops: number | undefined;
    let inOctets: number | undefined;
    let outOctets: number | undefined;
    let dmeFlapCount: number | undefined;
    let peakUtilizationPct: number | undefined;
    let latestDmeTs: number | undefined;

    for (const ev of sortedDme) {
      if (ev.timestamp !== undefined) latestDmeTs = ev.timestamp;
      if (ev.descr !== undefined) descr = ev.descr;
      if (ev.adminState !== undefined) adminState = ev.adminState;
      if (ev.operState !== undefined) operState = ev.operState;
      if (ev.speed !== undefined) speed = ev.speed;
      if (ev.mtu !== undefined) mtu = ev.mtu;
      if (ev.crcErrors !== undefined) crcErrors = ev.crcErrors;
      if (ev.inErrors !== undefined) inErrors = ev.inErrors;
      if (ev.outErrors !== undefined) outErrors = ev.outErrors;
      if (ev.inDiscards !== undefined) inDiscards = ev.inDiscards;
      if (ev.outDiscards !== undefined) outDiscards = ev.outDiscards;
      if (ev.rxDrops !== undefined) rxDrops = ev.rxDrops;
      if (ev.txDrops !== undefined) txDrops = ev.txDrops;
      if (ev.inOctets !== undefined) inOctets = ev.inOctets;
      if (ev.outOctets !== undefined) outOctets = ev.outOctets;
      if (ev.flapCount !== undefined) dmeFlapCount = ev.flapCount;
      if (ev.utilizationPct !== undefined) {
        peakUtilizationPct =
          peakUtilizationPct === undefined
            ? ev.utilizationPct
            : Math.max(peakUtilizationPct, ev.utilizationPct);
      }
    }

    const hasErrorCounters =
      crcErrors !== undefined ||
      inErrors !== undefined ||
      outErrors !== undefined;
    const hasDiscardCounters =
      inDiscards !== undefined ||
      outDiscards !== undefined ||
      rxDrops !== undefined ||
      txDrops !== undefined;
    const hasCounterCoverage = hasErrorCounters || hasDiscardCounters;
    const hasUtilizationCoverage = peakUtilizationPct !== undefined;
    const hasStateCoverage = Boolean(adminState || operState);
    const hasSyslogCoverage = sortedSyslog.length > 0;

    const totalErrors = hasErrorCounters
      ? (crcErrors ?? 0) + (inErrors ?? 0) + (outErrors ?? 0)
      : undefined;
    const totalDiscards = hasDiscardCounters
      ? (inDiscards ?? 0) + (outDiscards ?? 0) + (rxDrops ?? 0) + (txDrops ?? 0)
      : undefined;

    const syslogFlaps = sortedSyslog.filter((e) => e.isFlapTransition).length;
    const hasFlapMeasurement =
      dmeFlapCount !== undefined || syslogEvents.length > 0;
    const flapCount = hasFlapMeasurement
      ? Math.max(dmeFlapCount ?? 0, syslogFlaps)
      : undefined;

    const latestSyslog = sortedSyslog[sortedSyslog.length - 1];
    const latestSyslogDown =
      latestSyslog !== undefined &&
      latestSyslog.isDown &&
      (latestDmeTs === undefined ||
        latestSyslog.timestamp >= latestDmeTs ||
        operState === "down");

    const adminUpOperDown =
      (adminState === "up" && Boolean(operState) && operState !== "up") ||
      (!adminState && operState === "down");

    const syslogErrorEvents = sortedSyslog.filter((e) => e.isError);
    const syslogDomEvents = sortedSyslog.filter((e) => e.isDomWarning);

    const reasons: string[] = [];
    if (adminUpOperDown) {
      reasons.push(
        adminState === "up"
          ? `Admin up / Oper ${operState}`
          : `Oper ${operState}`,
      );
    } else if (!hasStateCoverage && latestSyslogDown) {
      reasons.push(`Link down via syslog (${latestSyslog.mnemonic})`);
    }
    if (crcErrors !== undefined && crcErrors >= thresholds.errorWarnCount) {
      reasons.push(
        `${formatCount(crcErrors)} CRC ${crcErrors === 1 ? "error" : "errors"} (≥ ${thresholds.errorWarnCount})`,
      );
    } else if (
      totalErrors !== undefined &&
      totalErrors >= thresholds.errorWarnCount
    ) {
      reasons.push(
        `${formatCount(totalErrors)} interface ${totalErrors === 1 ? "error" : "errors"} (≥ ${thresholds.errorWarnCount})`,
      );
    }
    if (
      totalDiscards !== undefined &&
      totalDiscards >= thresholds.discardWarnCount
    ) {
      reasons.push(
        `${formatCount(totalDiscards)} discards/drops (≥ ${thresholds.discardWarnCount})`,
      );
    }
    if (flapCount !== undefined && flapCount >= thresholds.flapWarnCount) {
      reasons.push(
        `${formatCount(flapCount)} link ${flapCount === 1 ? "flap" : "flaps"} (≥ ${thresholds.flapWarnCount})`,
      );
    }
    if (
      peakUtilizationPct !== undefined &&
      peakUtilizationPct >= thresholds.utilizationWarnPct
    ) {
      reasons.push(
        `${peakUtilizationPct.toFixed(1)}% peak utilization (≥ ${thresholds.utilizationWarnPct}%)`,
      );
    }
    if (syslogErrorEvents.length > 0) {
      reasons.push(
        `Syslog error: ${syslogErrorEvents[syslogErrorEvents.length - 1].mnemonic}`,
      );
    }
    if (syslogDomEvents.length > 0) {
      reasons.push(
        `Optical DOM warning: ${syslogDomEvents[syslogDomEvents.length - 1].mnemonic}`,
      );
    }

    const isDmePresent = sortedDme.length > 0;
    const rowSourceKind: InterfaceHealthRow["sourceKind"] =
      isDmePresent && hasSyslogCoverage
        ? "dme_and_syslog"
        : isDmePresent
          ? "dme_only"
          : "syslog_only";

    const attention = reasons.length > 0;
    // Never mark a syslog-only row green `ok` when DME counters were not collected.
    const status: ProtocolStatus = attention
      ? "attention"
      : !hasCounterCoverage && !hasStateCoverage
        ? "not_covered"
        : "ok";

    const rowReasons =
      !attention && rowSourceKind === "syslog_only"
        ? [
            "Syslog link events only — DME interface error counters and utilization are not covered.",
          ]
        : reasons;

    const allTimestamps = [
      ...sortedDme
        .map((e) => e.timestamp)
        .filter((t): t is number => t !== undefined),
      ...sortedSyslog.map((e) => e.timestamp),
    ];

    rows.push({
      id: makeInterfaceRowId(group.device, group.interfaceDisplay),
      attention,
      device: group.device,
      interface: group.interfaceDisplay,
      ...(descr ? { descr } : {}),
      ...(adminState ? { adminState } : {}),
      ...(operState ? { operState } : {}),
      adminUpOperDown,
      ...(speed ? { speed } : {}),
      ...(mtu !== undefined ? { mtu } : {}),
      ...(crcErrors !== undefined ? { crcErrors } : {}),
      ...(inErrors !== undefined ? { inErrors } : {}),
      ...(outErrors !== undefined ? { outErrors } : {}),
      ...(totalErrors !== undefined ? { totalErrors } : {}),
      ...(inDiscards !== undefined ? { inDiscards } : {}),
      ...(outDiscards !== undefined ? { outDiscards } : {}),
      ...(rxDrops !== undefined ? { rxDrops } : {}),
      ...(txDrops !== undefined ? { txDrops } : {}),
      ...(totalDiscards !== undefined ? { totalDiscards } : {}),
      ...(inOctets !== undefined ? { inOctets } : {}),
      ...(outOctets !== undefined ? { outOctets } : {}),
      ...(flapCount !== undefined ? { flapCount } : {}),
      ...(peakUtilizationPct !== undefined
        ? { utilizationPct: peakUtilizationPct }
        : {}),
      hasStateCoverage,
      hasCounterCoverage,
      hasUtilizationCoverage,
      hasSyslogCoverage,
      sourceKind: rowSourceKind,
      ...(latestSyslog ? { lastMnemonic: latestSyslog.mnemonic } : {}),
      recentSyslog: [...sortedSyslog]
        .reverse()
        .slice(0, 10)
        .map((e) => ({
          timestamp: e.timestamp,
          mnemonic: e.mnemonic,
          severity: e.severity,
          summary: e.summary,
        })),
      status,
      reasons: rowReasons,
      indexName: group.indexName,
      ...(allTimestamps.length
        ? { firstSeen: Math.min(...allTimestamps) }
        : {}),
      ...(allTimestamps.length ? { lastSeen: Math.max(...allTimestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.adminUpOperDown !== b.adminUpOperDown)
      return a.adminUpOperDown ? -1 : 1;
    if ((b.totalErrors ?? -1) !== (a.totalErrors ?? -1)) {
      return (b.totalErrors ?? -1) - (a.totalErrors ?? -1);
    }
    if ((b.flapCount ?? -1) !== (a.flapCount ?? -1)) {
      return (b.flapCount ?? -1) - (a.flapCount ?? -1);
    }
    if ((b.totalDiscards ?? -1) !== (a.totalDiscards ?? -1)) {
      return (b.totalDiscards ?? -1) - (a.totalDiscards ?? -1);
    }
    if ((b.utilizationPct ?? -1) !== (a.utilizationPct ?? -1)) {
      return (b.utilizationPct ?? -1) - (a.utilizationPct ?? -1);
    }
    return a.id.localeCompare(b.id);
  });

  // 4 single-metric KPI tiles
  const downOrMismatchedCount = rows.filter(
    (r) =>
      r.adminUpOperDown ||
      (!r.hasStateCoverage &&
        r.reasons.some((reason) => reason.startsWith("Link down via syslog"))),
  ).length;
  const anyStateOrSyslogDown =
    rows.some((r) => r.hasStateCoverage) || syslogEvents.length > 0;

  const anyCounterRows = rows.some((r) => r.hasCounterCoverage);
  const totalCrcAndErrors = rows.reduce(
    (sum, r) => sum + (r.totalErrors ?? 0),
    0,
  );
  const anyErrorViolation = rows.some(
    (r) =>
      (r.crcErrors ?? 0) >= thresholds.errorWarnCount ||
      (r.totalErrors ?? 0) >= thresholds.errorWarnCount,
  );

  const anyFlapSource = rows.some((r) => r.flapCount !== undefined);
  const totalFlaps = rows.reduce((sum, r) => sum + (r.flapCount ?? 0), 0);
  const anyFlapViolation = rows.some(
    (r) => (r.flapCount ?? 0) >= thresholds.flapWarnCount,
  );

  const utilValues = rows
    .map((r) => r.utilizationPct)
    .filter((v): v is number => v !== undefined);
  const peakUtil = utilValues.length ? Math.max(...utilValues) : undefined;

  const errSpark = buildSparklineBuckets(
    dmeEvents.map((d) => ({
      timestamp: d.event.timestamp,
      value: d.event.hasErrorCounters
        ? (d.event.crcErrors ?? 0) +
          (d.event.inErrors ?? 0) +
          (d.event.outErrors ?? 0)
        : undefined,
    })),
    earliest,
    latest,
    "sum",
  );
  const flapSpark = buildSparklineBuckets(
    syslogEvents.map((s) => ({
      timestamp: s.event.timestamp,
      value: s.event.isFlapTransition ? 1 : 0,
    })),
    earliest,
    latest,
    "sum",
  );
  const utilSpark = buildSparklineBuckets(
    dmeEvents.map((d) => ({
      timestamp: d.event.timestamp,
      value: d.event.utilizationPct,
    })),
    earliest,
    latest,
    "max",
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "down-mismatched",
      label: "Down / Mismatched",
      value: anyStateOrSyslogDown
        ? formatCount(downOrMismatchedCount)
        : "Not covered",
      ...(anyStateOrSyslogDown
        ? { unit: downOrMismatchedCount === 1 ? "intf" : "intfs" }
        : {}),
      status: !anyStateOrSyslogDown
        ? "not_covered"
        : downOrMismatchedCount > 0
          ? "attention"
          : "ok",
    },
    {
      id: "crc-errors",
      label: "CRC & Errors",
      value: anyCounterRows ? formatCount(totalCrcAndErrors) : "Not covered",
      ...(anyCounterRows
        ? { unit: totalCrcAndErrors === 1 ? "error" : "errors" }
        : {}),
      status: !anyCounterRows
        ? "not_covered"
        : anyErrorViolation
          ? "attention"
          : "ok",
      ...(errSpark.length ? { sparkline: errSpark } : {}),
    },
    {
      id: "link-flaps",
      label: "Link Flaps",
      value: anyFlapSource ? formatCount(totalFlaps) : "Not covered",
      ...(anyFlapSource ? { unit: totalFlaps === 1 ? "flap" : "flaps" } : {}),
      status: !anyFlapSource
        ? "not_covered"
        : anyFlapViolation
          ? "attention"
          : "ok",
      ...(flapSpark.length ? { sparkline: flapSpark } : {}),
    },
    {
      id: "peak-utilization",
      label: "Peak Utilization",
      value:
        peakUtil !== undefined
          ? `${peakUtil < 10 ? peakUtil.toFixed(1) : Math.round(peakUtil)}%`
          : "Not covered",
      status:
        peakUtil === undefined
          ? "not_covered"
          : peakUtil >= thresholds.utilizationWarnPct
            ? "attention"
            : "ok",
      ...(utilSpark.length ? { sparkline: utilSpark } : {}),
    },
  ];

  // Compact interface-first label (`Eth1/50 · leaf2`) so sibling interfaces on
  // the same host never clip to identical prefixes; never truncate IPv4/IPv6.
  const formatCompactIntfLabel = (device: string, iface: string): string => {
    const shortHost =
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(device) || device.includes(":")
        ? device
        : device.split(".")[0] || device;
    const shortIface = iface
      .replace(/^Ethernet/i, "Eth")
      .replace(/^port-channel/i, "Po");
    return `${shortIface} · ${shortHost}`;
  };

  // Matrix: Device × Interface (flagged devices sorted first)
  const flaggedIfaceDevices = new Set(
    rows.filter((r) => r.attention).map((r) => r.device),
  );
  const matrixRows = [...new Set(rows.map((r) => r.device))].sort((a, b) => {
    const aFlag = flaggedIfaceDevices.has(a);
    const bFlag = flaggedIfaceDevices.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    return a.localeCompare(b);
  });
  const matrixCols = [...new Set(rows.map((r) => r.interface))].sort((a, b) =>
    a.localeCompare(b),
  );
  const matrixCells: ProtocolMatrixCell[] = rows.map((row) => ({
    row: row.device,
    col: row.interface,
    status: row.status,
    value: buildMatrixCellLabel(row, thresholds),
    count: (row.totalErrors ?? 0) + (row.flapCount ?? 0),
    detail: row.reasons.length
      ? row.reasons.join("; ")
      : "Interface state, counters, and flaps within bounds",
    itemId: row.id,
  }));

  // DistributionBar: Top interfaces by utilization % (or errors/discards if no util)
  let distribution: ProtocolDistributionMetric[] = [];
  let distributionTitle = "";

  if (utilValues.length > 0) {
    const utilByIntf = new Map<string, { label: string; values: number[] }>();
    for (const entry of dmeEvents) {
      if (entry.event.utilizationPct === undefined) continue;
      const id = makeInterfaceRowId(entry.event.device, entry.event.interface);
      const existing = utilByIntf.get(id);
      if (existing) {
        existing.values.push(entry.event.utilizationPct);
      } else {
        utilByIntf.set(id, {
          label: formatCompactIntfLabel(
            entry.event.device,
            entry.event.interface,
          ),
          values: [entry.event.utilizationPct],
        });
      }
    }
    distributionTitle = "Utilization (%)";
    distribution = [...utilByIntf.entries()]
      .map(([id, g]) => {
        const p50 = roundMetric(percentile(g.values, 50) ?? 0);
        const p95 = roundMetric(percentile(g.values, 95) ?? 0);
        return {
          id,
          label: g.label,
          p50,
          p95,
          max: 100,
          unit: "%",
          status: (p95 >= thresholds.utilizationWarnPct
            ? "attention"
            : "ok") as ProtocolStatus,
        };
      })
      .sort((a, b) => b.p95 - a.p95)
      .slice(0, 6);
  } else if (anyCounterRows) {
    distributionTitle = "Errors & discards";
    distribution = rows
      .filter((r) => (r.totalErrors ?? 0) + (r.totalDiscards ?? 0) > 0)
      .map((r) => {
        const err = r.totalErrors ?? 0;
        const total = err + (r.totalDiscards ?? 0);
        return {
          id: r.id,
          label: formatCompactIntfLabel(r.device, r.interface),
          p50: err,
          p95: total,
          unit: "pkts",
          status: (r.attention ? "attention" : "ok") as ProtocolStatus,
        };
      })
      .sort((a, b) => b.p95 - a.p95)
      .slice(0, 6);
  }

  // SwimlaneTimeline for syslog link flap / error events
  const timelineEvents: ProtocolTimelineEvent[] = [...syslogEvents]
    .sort((a, b) => a.event.timestamp - b.event.timestamp)
    .slice(0, 128)
    .map((entry) => ({
      id: entry.event.id,
      lane: formatCompactIntfLabel(entry.event.device, entry.event.interface),
      timestamp: entry.event.timestamp,
      kind:
        entry.event.isDown || entry.event.isError || entry.event.isDomWarning
          ? ("attention" as const)
          : entry.event.isUp
            ? ("ok" as const)
            : ("info" as const),
      label: entry.event.mnemonic,
      detail: entry.event.summary,
    }));

  // Single-sentence verdict (no threshold numbers in the headline)
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadDetail = lead.adminUpOperDown
      ? "admin up / oper down"
      : (lead.crcErrors ?? 0) >= thresholds.errorWarnCount
        ? `${formatCount(lead.crcErrors)} CRC errors`
        : (lead.totalErrors ?? 0) >= thresholds.errorWarnCount
          ? `${formatCount(lead.totalErrors)} errors`
          : (lead.flapCount ?? 0) >= thresholds.flapWarnCount
            ? `${formatCount(lead.flapCount)} link flaps`
            : (lead.totalDiscards ?? 0) >= thresholds.discardWarnCount
              ? `${formatCount(lead.totalDiscards)} discards`
              : lead.utilizationPct !== undefined &&
                  lead.utilizationPct >= thresholds.utilizationWarnPct
                ? `${Math.round(lead.utilizationPct)}% utilization`
                : (lead.lastMnemonic ?? "interface fault");
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "interface needs" : "interfaces need"} attention: ${leadDetail} on ${lead.device} ${lead.interface}.`;
    verdictStatus = "attention";
  } else if (sourceMode === "syslog_only" && !anyCounterRows) {
    verdict = `Syslog events only (${rows.length} ${rows.length === 1 ? "interface" : "interfaces"} observed) — DME error counters and utilization are not covered.`;
    verdictStatus = "not_covered";
  } else {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "interface" : "interfaces"} healthy with no counter, flap, or state exceptions.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial
    ? "attention"
    : sourceMode === "syslog_only" && !anyCounterRows
      ? "not_covered"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    sourceMode === "syslog_only"
      ? "Syslog only"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;
  const partialReason =
    anyBlocked && sourceMode === "syslog_only"
      ? `Primary DME source blocked (${blockedDetail ?? "access denied"}); showing syslog link events only.`
      : anyBlocked
        ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
        : anyUnavailable
          ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
          : "Search hit row cap or partial source — narrow the UTC window or device filter.";

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
    distribution,
    distributionTitle,
    timelineEvents,
    outcomes,
    capped,
    sourceMode,
    ...(anyPartial
      ? {
          bannerState: "partial" as const,
          bannerReason: partialReason,
        }
      : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateInterfaceHealthOptions {
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand Interface & Link Health investigation across configured
 * `interface_health` profiles (DME counters and/or NX-OS/ACI syslog), verifying
 * `adm_protocol_profiles` fingerprint to discard stale responses.
 */
export async function investigateInterfaceHealth(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateInterfaceHealthOptions = {},
): Promise<InterfaceHealthInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "interface_health" && p.scope === request.scope,
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
      distribution: [],
      distributionTitle: "",
      timelineEvents: [],
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No interface_health profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const dmeProfiles = scoped.filter(
    (p) => resolveInterfaceHealthThresholds(p).sourceKind !== "syslog",
  );
  const syslogProfiles = scoped.filter(
    (p) => resolveInterfaceHealthThresholds(p).sourceKind !== "dme",
  );

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const dmeEvents: {
      event: NormalizedInterfaceDmeEvent;
      indexName: string;
    }[] = [];
    const syslogEvents: {
      event: NormalizedInterfaceSyslogEvent;
      indexName: string;
    }[] = [];
    let capped = false;
    const chosenThresholds = resolveInterfaceHealthThresholds(
      dmeProfiles[0] ?? syslogProfiles[0],
    );

    for (const profile of dmeProfiles) {
      signal.throwIfAborted();
      const spl = buildInterfaceDmeSearch({
        index: profile.index,
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "interface_health",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "dme",
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeInterfaceDmeRow(row);
        if (norm) dmeEvents.push({ event: norm, indexName: profile.index });
      }
    }

    for (const profile of syslogProfiles) {
      signal.throwIfAborted();
      const spl = buildInterfaceSyslogSearch({
        index: profile.index,
        device: request.filter?.device,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "interface_health",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "syslog",
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      res.rows.forEach((row, idx) => {
        const norm = normalizeInterfaceSyslogRow(row, idx);
        if (norm) syslogEvents.push({ event: norm, indexName: profile.index });
      });
    }

    return buildInterfaceHealthAnalysis({
      dmeEvents,
      syslogEvents,
      thresholds: chosenThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    interface_health: validateInterfaceHealthExtra,
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
        distribution: [],
        distributionTitle: "",
        timelineEvents: [],
        outcomes: [],
        capped: false,
        sourceMode: "none",
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Hub "Check all" summary runner for `interface_health`.
 */
export async function summarizeInterfaceHealth(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateInterfaceHealthOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateInterfaceHealth(
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
    lens: "interface_health",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
