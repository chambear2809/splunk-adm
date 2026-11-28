import { literal, normalizeIp } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  buildSyslogStateSearch,
  normalizeSyslogRow,
  type AllowedSyslogSourcetype,
} from "../../shared/adapters/nxosSyslog";
import type {
  BaseProtocolProfile,
  LensProfileValidator,
  ProtocolConfiguration,
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
  selectActiveProfiles,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  checkStreamEstimateMode,
  type StreamReadinessEntry,
} from "../../shared/streamReadiness";
import {
  DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS,
  validateEndpointMobilityExtra,
  type EndpointMobilityExtraConfig,
  type EndpointMobilitySourceKind,
  type ResolvedEndpointMobilityThresholds,
} from "./validate";

export {
  DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS,
  validateEndpointMobilityExtra,
  type EndpointMobilityExtraConfig,
  type EndpointMobilitySourceKind,
  type ResolvedEndpointMobilityThresholds,
};

/**
 * Single source of truth for syslog categories queried via `buildSyslogStateSearch`
 * AND accepted by `classifyMobilitySyslogEvent` so SPL filters and client-side
 * classification cannot drift.
 */
export const MOBILITY_SYSLOG_CATEGORIES = [
  "L2FM",
  "MATM",
  "MAC_MOVE",
  "SW_MATM",
  "EPM",
  "ARP",
  "DAI",
  "SW_DAI",
  "ETHPORT",
  "ETH_PORT",
  "LINK",
  "LINEPROTO",
  "ETH_PORT_CHANNEL",
  "PM",
] as const;

const MOBILITY_SYSLOG_CATEGORY_SET = new Set<string>(
  MOBILITY_SYSLOG_CATEGORIES,
);

export const STREAM_ARP_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_mac",
  "dest_mac",
  "sender_ip",
  "sender_mac",
  "target_ip",
  "target_mac",
  "arp_opcode",
  "operation",
  "vlan",
  "vlan_id",
  "vni",
] as const;

export const ND_ENDPOINTS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "endpointId",
  "mac",
  "ip",
  "nodeName",
  "displayInterface",
  "modType",
  "createTime",
  "anomalyScore",
  "fabricName",
  "nd_host",
  "tenant",
  "displayBd",
  "displayEpg",
  "encap",
] as const;

export const ACI_FVCEP_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "dn",
  "mac",
  "ip",
  "addr",
  "encap",
  "tDn",
  "modTs",
  "status",
  "lcC",
  "apic_host",
  "component",
] as const;

export const DME_MOBILITY_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "dn",
  "descr",
  "interface",
  "interface_name",
  "mac",
  "ip",
  "addr",
  "vlan",
  "vlan_id",
  "vni",
  "encap",
  "switch",
  "leaf",
  "port",
  "device",
  "component",
  "move_count",
  "status",
  "modTs",
] as const;

export function resolveEndpointMobilityThresholds(
  profile?: BaseProtocolProfile,
): ResolvedEndpointMobilityThresholds {
  const extra = profile?.extra as EndpointMobilityExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind ?? DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS.sourceKind,
    arpSpikeWarnCount:
      typeof extra?.arpSpikeWarnCount === "number"
        ? extra.arpSpikeWarnCount
        : DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS.arpSpikeWarnCount,
    macMoveWarnCount:
      typeof extra?.macMoveWarnCount === "number"
        ? extra.macMoveWarnCount
        : DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS.macMoveWarnCount,
    portFlapWarnCount:
      typeof extra?.portFlapWarnCount === "number"
        ? extra.portFlapWarnCount
        : DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS.portFlapWarnCount,
    anomalyScoreWarn:
      typeof extra?.anomalyScoreWarn === "number"
        ? extra.anomalyScoreWarn
        : DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS.anomalyScoreWarn,
  };
}

/**
 * Bounded allowlisted SPL query for Splunk Stream ARP (`stream:arp`).
 * Emits `| head <maxRows + 1>` BEFORE `| table ...` so indexers cap rows and drop `_raw`.
 */
export function buildMobilityStreamArpSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [`index=${index}`, 'sourcetype="stream:arp"'];
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(
      `(src_ip="${src}" OR sender_ip="${src}" OR src_mac="${src}" OR sender_mac="${src}")`,
    );
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(
      `(dest_ip="${dst}" OR target_ip="${dst}" OR dest_mac="${dst}" OR target_mac="${dst}")`,
    );
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(host="${dev}" OR switch="${dev}" OR leaf="${dev}")`);
  }
  if (options.filter?.vni) {
    const vni = literal(options.filter.vni, 16);
    predicates.push(`(vni="${vni}" OR vxlan_id="${vni}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const evalClause =
    `| eval sender_ip=coalesce(sender_ip, arp_src_ip, src_ip), ` +
    `sender_mac=coalesce(sender_mac, arp_src_mac, src_mac), ` +
    `target_ip=coalesce(target_ip, arp_dest_ip, dest_ip), ` +
    `target_mac=coalesce(target_mac, arp_dest_mac, dest_mac), ` +
    `arp_opcode=coalesce(arp_opcode, operation, opcode), ` +
    `operation=coalesce(operation, arp_opcode, opcode), ` +
    `vlan=coalesce(vlan, vlan_id), ` +
    `vni=coalesce(vni, vxlan_id) `;
  const tableClause = buildAllowedFieldsClause(
    "endpoint_mobility",
    STREAM_ARP_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${evalClause}${tableClause}`;
}

/**
 * Bounded allowlisted SPL query for Cisco Nexus Dashboard Endpoints (`cisco:dc:nd:endpoints`).
 */
export function buildMobilityNdEndpointsSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    'sourcetype="cisco:dc:nd:endpoints"',
  ];
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(`(ip="${src}" OR mac="${src}" OR endpointId="${src}")`);
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(`(ip="${dst}" OR mac="${dst}")`);
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(nodeName="${dev}" OR nd_host="${dev}" OR host="${dev}")`);
  }
  if (options.filter?.vni) {
    const vni = literal(options.filter.vni, 16);
    predicates.push(`(encap="vxlan-${vni}" OR encap="${vni}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "endpoint_mobility",
    ND_ENDPOINTS_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Bounded allowlisted SPL query for Cisco ACI `fvCEp` (`cisco:dc:aci:stats`, `cisco:dc:aci:class`).
 * Filters `component="fvCEp"` BEFORE `| head` so inventory/VM rows do not crowd out endpoint history.
 */
export function buildMobilityAciSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    '(sourcetype="cisco:dc:aci:stats" OR sourcetype="cisco:dc:aci:class")',
    'component="fvCEp"',
  ];
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(`(ip="${src}" OR addr="${src}" OR mac="${src}")`);
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(`(ip="${dst}" OR addr="${dst}" OR mac="${dst}")`);
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    const leafDigits = /^(?:leaf|node|paths)-(\d+)$/i.exec(dev)?.[1];
    predicates.push(
      leafDigits
        ? `(apic_host="${dev}" OR host="${dev}" OR tDn="*paths-${leafDigits}*" OR tDn="*protpaths-*${leafDigits}*")`
        : `(apic_host="${dev}" OR host="${dev}" OR tDn="*${dev}*")`,
    );
  }
  if (options.filter?.vni) {
    const vni = literal(options.filter.vni, 16);
    predicates.push(`(encap="vxlan-${vni}" OR encap="${vni}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "endpoint_mobility",
    ACI_FVCEP_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Bounded allowlisted SPL query for Cisco Nexus 9K DME MAC/endpoint tables
 * (`cisco:dc:nexus9k:dme`). Filters DME classes BEFORE `| head` so unrelated
 * DME rows do not crowd out the cap.
 */
export function buildMobilityDmeSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    'sourcetype="cisco:dc:nexus9k:dme"',
    '(component="epmMacEp" OR component="l2MacAddressEntry" OR dn="sys/eps/*" OR dn="sys/bd/*")',
  ];
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(`(mac="${src}" OR ip="${src}" OR addr="${src}")`);
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(`(mac="${dst}" OR ip="${dst}" OR addr="${dst}")`);
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(host="${dev}" OR device="${dev}" OR switch="${dev}" OR leaf="${dev}")`,
    );
  }
  if (options.filter?.vni) {
    const vni = literal(options.filter.vni, 16);
    predicates.push(`(vni="${vni}" OR encap="vxlan-${vni}" OR encap="${vni}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const evalClause =
    `| eval dn=coalesce(dn, 'Row_info.dn'), ` +
    `mac=coalesce(mac, 'Row_info.addr', 'Row_info.mac'), ` +
    `ip=coalesce(ip, 'Row_info.ip'), ` +
    `addr=coalesce(addr, 'Row_info.addr'), ` +
    `interface=coalesce(interface, interface_name, port, 'Row_info.ifId', 'Row_info.port'), ` +
    `vlan=coalesce(vlan, vlan_id, 'Row_info.vlan'), ` +
    `vni=coalesce(vni, 'Row_info.vni'), ` +
    `move_count=coalesce(move_count, 'Row_info.moveCount'), ` +
    `descr=coalesce(descr, 'Row_info.descr', component) `;
  const tableClause = buildAllowedFieldsClause(
    "endpoint_mobility",
    DME_MOBILITY_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${evalClause}${tableClause}`;
}

export function buildMobilitySyslogSearch(options: {
  index: string;
  device?: string;
  sourcetypes?: readonly AllowedSyslogSourcetype[];
  maxRows: number;
}): string {
  return buildSyslogStateSearch({
    index: options.index,
    device: options.device,
    sourcetypes: options.sourcetypes,
    categories: MOBILITY_SYSLOG_CATEGORIES,
    includeAci: true,
    maxRows: options.maxRows,
  });
}

/**
 * Builds a `literal()`-quoted `/app/splunk_adm/search?...` raw-events link for a selected endpoint row.
 */
export function buildEndpointMobilityRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly string[];
  macs: readonly string[];
  ips: readonly string[];
  switches: readonly string[];
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const safeSourcetypes = options.sourcetypes.length
    ? options.sourcetypes.map((st) => `sourcetype="${literal(st, 64)}"`)
    : [];
  const stClause =
    safeSourcetypes.length === 1
      ? safeSourcetypes[0]
      : safeSourcetypes.length > 1
        ? `(${safeSourcetypes.join(" OR ")})`
        : "";

  const terms: string[] = [];
  for (const mac of options.macs.slice(0, 4)) {
    const m = literal(mac, 64);
    terms.push(`mac="${m}" OR src_mac="${m}" OR sender_mac="${m}" OR "${m}"`);
  }
  for (const ip of options.ips.slice(0, 4)) {
    const safeIp = literal(ip, 64);
    terms.push(
      `ip="${safeIp}" OR addr="${safeIp}" OR src_ip="${safeIp}" OR sender_ip="${safeIp}"`,
    );
  }
  if (!terms.length) {
    for (const sw of options.switches.slice(0, 4)) {
      const safeSw = literal(sw, 128);
      terms.push(`host="${safeSw}" OR nodeName="${safeSw}"`);
    }
  }
  const entityClause = terms.length ? ` (${terms.join(" OR ")})` : "";
  const q = `search index=${index}${stClause ? ` ${stClause}` : ""}${entityClause}`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export type MobilitySourceFamily =
  "stream_arp" | "nd_endpoints" | "aci_fvcep" | "dme" | "syslog";

export type MobilityEventKind =
  "arp_packet" | "endpoint_state" | "mac_move" | "arp_conflict" | "port_flap";

export interface NormalizedMobilityEvent {
  id: string;
  timestamp: number;
  sourcetype: string;
  sourceFamily: MobilitySourceFamily;
  kind: MobilityEventKind;
  mac?: string;
  secondaryMac?: string;
  ips: string[];
  switchName?: string;
  port?: string;
  canonPort?: string;
  fromPort?: string;
  toPort?: string;
  vlanVni: string;
  modType?: string;
  anomalyScore?: number;
  moveCountHint?: number;
  arpOpcode?: string;
  tenant?: string;
  displayBd?: string;
  displayEpg?: string;
  encap?: string;
  lcC?: string;
  mnemonic?: string;
  anomaly: boolean;
  summary: string;
}

export interface MobilityAttachmentTransition {
  timestamp: number;
  switchName: string;
  port: string;
  source: string;
  modType?: string;
  detail: string;
}

export interface EndpointMobilityRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` (uses `__`, never `->`). */
  id: string;
  attention: boolean;
  endpointLabel: string;
  primaryMac?: string;
  macs: string[];
  ips: string[];
  switches: string[];
  attachments: string[];
  transitions: MobilityAttachmentTransition[];
  vlanVnis: string[];
  sourcetypes: string[];
  moveCount: number;
  arpCount: number;
  portFlapCount: number;
  flappingPorts: string[];
  maxAnomalyScore?: number;
  tenant?: string;
  displayBd?: string;
  displayEpg?: string;
  lcC?: string;
  hasIpCoverage: boolean;
  hasAttachmentCoverage: boolean;
  hasMoveCoverage: boolean;
  hasArpCoverage: boolean;
  hasFlapCoverage: boolean;
  status: ProtocolStatus;
  reasons: string[];
  lastSeen: number;
  firstSeen: number;
  indexName: string;
  lastSummary: string;
}

export interface EndpointMobilityInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: EndpointMobilityRow[];
  timeline: ProtocolTimelineEvent[];
  timelineItemMap: Record<string, string>;
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: MobilitySourceFamily | "mixed" | "none";
  streamReadiness?: StreamReadinessEntry;
  bannerState?:
    | "empty"
    | "partial"
    | "blocked"
    | "unavailable"
    | "stale_config"
    | "estimate_only";
  bannerReason?: string;
  checkedAt: number;
}

function asString(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (const item of value) {
      const s = asString(item);
      if (s) out.push(s);
    }
    return out;
  }
  const s = asString(value);
  if (!s) return [];
  return [s];
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value.trim());
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function asEpochSeconds(value: unknown): number | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const parsed = asEpochSeconds(entry);
      if (parsed !== undefined) return parsed;
    }
    return undefined;
  }
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

export function normalizeMac(raw: unknown): string | undefined {
  const s = asString(raw);
  if (!s) return undefined;
  const hex = s.replace(/[:.-]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return undefined;
  const formatted = hex.match(/.{2}/g)!.join(":");
  if (formatted === "00:00:00:00:00:00" || formatted === "ff:ff:ff:ff:ff:ff") {
    return undefined;
  }
  return formatted;
}

function tryNormalizeIp(raw: unknown): string | undefined {
  const s = asString(raw);
  if (!s || s === "0.0.0.0" || s === "::" || s === "not-applicable") {
    return undefined;
  }
  try {
    const norm = normalizeIp(s);
    if (norm === "0.0.0.0" || norm === "::") return undefined;
    return norm;
  } catch {
    return undefined;
  }
}

function extractNormalizedIps(values: unknown[]): string[] {
  const seen = new Set<string>();
  for (const val of values) {
    for (const candidate of asStringList(val)) {
      const ip = tryNormalizeIp(candidate);
      if (ip) seen.add(ip);
    }
  }
  return [...seen];
}

export function canonicalPortKey(rawPort: string): string {
  const trimmed = rawPort.trim().toLowerCase();
  const ethMatch = /^(?:ethernet|eth)(\d+(?:\/\d+)*)$/.exec(trimmed);
  if (ethMatch) return `ethernet${ethMatch[1]}`;
  const poMatch = /^(?:port-channel|po)(\d+)$/.exec(trimmed);
  if (poMatch) return `port-channel${poMatch[1]}`;
  return trimmed;
}

export function shortenDeviceLabel(device: string): string {
  // Never truncate IPv4, IPv6, or MAC addresses at `.` — only strip DNS suffixes.
  if (
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(device) ||
    device.includes(":") ||
    /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(device)
  ) {
    return device;
  }
  return device.split(".")[0] || device;
}

function normalizeVlanVniLabel(options: {
  vlan?: string;
  vni?: string;
  encap?: string;
}): string {
  const encap = (options.encap ?? "").trim();
  if (encap) {
    const vxlanMatch = /^vxlan-(\d+)$/i.exec(encap);
    if (vxlanMatch) return `vni-${vxlanMatch[1]}`;
    const vlanMatch = /^vlan[-_]?(\d+)$/i.exec(encap);
    if (vlanMatch) return `vlan-${Number(vlanMatch[1])}`;
    return encap.toLowerCase();
  }
  const vni = (options.vni ?? "").trim();
  if (vni && /^\d+$/.test(vni)) return `vni-${vni}`;
  const vlan = (options.vlan ?? "").trim();
  if (vlan) {
    const digits = vlan.replace(/^vlan[-_]?/i, "");
    return /^\d+$/.test(digits) ? `vlan-${Number(digits)}` : vlan.toLowerCase();
  }
  return "default";
}

function sanitizeIdSegment(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._:/-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "unknown";
}

export function buildEndpointRowId(prefix: string, rawKey: string): string {
  const safePrefix = sanitizeIdSegment(prefix).slice(0, 16);
  const safeKey = sanitizeIdSegment(rawKey).slice(0, 108);
  return `${safePrefix}__${safeKey}`.slice(0, 128);
}

function parseAciTDn(tDn: string): { switchName?: string; port?: string } {
  const singleMatch =
    /paths-(\d+)\/pathep-\[([^\]]+)\]/i.exec(tDn) ??
    /node-(\d+)\/[^\]]*\[([^\]]+)\]/i.exec(tDn);
  if (singleMatch) {
    return {
      switchName: `leaf-${singleMatch[1]}`,
      port: singleMatch[2].trim(),
    };
  }
  const vpcMatch = /protpaths-(\d+-\d+)\/pathep-\[([^\]]+)\]/i.exec(tDn);
  if (vpcMatch) {
    return {
      switchName: `leaf-${vpcMatch[1]}`,
      port: vpcMatch[2].trim(),
    };
  }
  return {};
}

function parseAciCepDn(dn: string): {
  tenant?: string;
  displayEpg?: string;
  mac?: string;
} {
  const tenant = /\/tn-([^/]+)/i.exec(dn)?.[1];
  const displayEpg = /\/epg-([^/]+)/i.exec(dn)?.[1];
  const macRaw = /\/cep-([^/]+)/i.exec(dn)?.[1];
  return {
    ...(tenant ? { tenant } : {}),
    ...(displayEpg ? { displayEpg } : {}),
    ...(macRaw ? { mac: normalizeMac(macRaw) } : {}),
  };
}

const MAC_ANY_RE =
  /\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b/g;
const IPV4_ANY_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const SYSLOG_PORT_RE =
  /\b(?:Ethernet|Eth|Port-channel|Po|Vlan|mgmt)\d+(?:\/\d+)*\b/gi;
const SYSLOG_VLAN_RE = /\bvlan[-_\s]?(\d+)\b/i;

export function classifyMobilitySyslogEvent(
  category: string,
  mnemonic: string,
  summary: string,
  severity: number,
):
  | { kind: "mac_move" | "arp_conflict" | "port_flap"; anomaly: boolean }
  | undefined {
  const cat = category.toUpperCase();
  if (!MOBILITY_SYSLOG_CATEGORY_SET.has(cat)) {
    return undefined;
  }
  const mnem = mnemonic.toUpperCase();
  const upperMsg = summary.toUpperCase();

  if (
    cat === "L2FM" ||
    cat === "MATM" ||
    cat === "MAC_MOVE" ||
    cat === "SW_MATM" ||
    cat === "EPM"
  ) {
    const isMove =
      severity <= 4 ||
      /(MOVE|FLAP|MAC_MOVE|MACFLAP|HOST_TRACK|DUP|CONFLICT|RELEARN)/.test(
        mnem,
      ) ||
      /(MOVED|MOVING|FLAPPING|RELEARN)/.test(upperMsg);
    return { kind: "mac_move", anomaly: isMove };
  }

  if (cat === "ARP" || cat === "DAI" || cat === "SW_DAI") {
    const isConflict =
      severity <= 4 ||
      /(DUP|CONFLICT|ERR|DISABLE|DROP|VIOLATION|DENY|POISON|INVALID)/.test(
        mnem,
      ) ||
      /(DUPLICATE|CONFLICT|DROPPED|MOVED)/.test(upperMsg);
    return { kind: "arp_conflict", anomaly: isConflict };
  }

  // ETHPORT, ETH_PORT, LINK, LINEPROTO, ETH_PORT_CHANNEL, PM
  const isFlap =
    severity <= 4 ||
    /(IF_DOWN|IF_UP|UPDOWN|LINK_DOWN|LINK_UP|FLAP|ERR_DISABLE|PORT_CHANNEL_DOWN|DOWN)/.test(
      mnem,
    ) ||
    /(DOWN|UP|FLAP|ERR-DISABLE)/.test(upperMsg);
  return { kind: "port_flap", anomaly: isFlap };
}

/**
 * Normalizes one row from `stream:arp`, `cisco:dc:nd:endpoints`, `cisco:dc:aci:stats`/
 * `cisco:dc:aci:class` (`fvCEp`), `cisco:dc:nexus9k:dme`, or NX-OS/ACI syslog.
 */
export function normalizeEndpointMobilityRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedMobilityEvent | undefined {
  const sourcetype = asString(row.sourcetype).toLowerCase();
  const timestamp =
    asEpochSeconds(row._time) ??
    asEpochSeconds(row.createTime) ??
    asEpochSeconds(row.modTs);
  if (!timestamp) return undefined;

  if (sourcetype === "stream:arp") {
    const mac =
      normalizeMac(row.sender_mac) ??
      normalizeMac(row.src_mac) ??
      normalizeMac(row.mac);
    const ips = extractNormalizedIps([row.sender_ip, row.src_ip, row.ip]);
    if (!mac && !ips.length) return undefined;
    const rawOp = asString(row.arp_opcode ?? row.operation);
    const opLabel =
      rawOp === "1" || rawOp.toUpperCase() === "REQUEST"
        ? "REQUEST"
        : rawOp === "2" ||
            rawOp.toUpperCase() === "REPLY" ||
            rawOp.toUpperCase() === "RESPONSE"
          ? "REPLY"
          : rawOp || "ARP";
    const switchName =
      asString(row.switch) ||
      asString(row.leaf) ||
      asString(row.host) ||
      undefined;
    const port =
      asString(row.port) || asString(row.interface_name) || undefined;
    const vlanVni = normalizeVlanVniLabel({
      vlan: asString(row.vlan ?? row.vlan_id),
      vni: asString(row.vni),
    });
    const targetIps = extractNormalizedIps([row.target_ip, row.dest_ip]);
    const ipSummary = ips[0] ?? "?";
    const targetSummary = targetIps[0] ? ` → ${targetIps[0]}` : "";
    return {
      id: `arp:${mac ?? ipSummary}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "stream:arp",
      sourceFamily: "stream_arp",
      kind: "arp_packet",
      ...(mac ? { mac } : {}),
      ips,
      ...(switchName ? { switchName } : {}),
      ...(port ? { port, canonPort: canonicalPortKey(port) } : {}),
      vlanVni,
      arpOpcode: opLabel,
      anomaly: false,
      summary: `ARP ${opLabel} ${ipSummary} (${mac ?? "?"})${targetSummary}`,
    };
  }

  if (sourcetype === "cisco:dc:nd:endpoints") {
    const mac = normalizeMac(row.mac);
    const ips = extractNormalizedIps([row.ip, row.addr]);
    if (!mac && !ips.length) return undefined;
    const switchName =
      asString(row.nodeName) ||
      asString(row.switch) ||
      asString(row.nd_host) ||
      asString(row.host) ||
      undefined;
    const port = asStringList(row.displayInterface)[0];
    const modType = asString(row.modType).toLowerCase() || "modification";
    const anomalyScore = asFiniteNumber(row.anomalyScore);
    const encap = asString(row.encap) || undefined;
    const vlanVni = normalizeVlanVniLabel({ encap });
    const tenant = asString(row.tenant) || undefined;
    const displayBd = asString(row.displayBd) || undefined;
    const displayEpg = asString(row.displayEpg) || undefined;
    const isMove = modType.includes("move");
    return {
      id: `nd:${mac ?? ips[0]}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "cisco:dc:nd:endpoints",
      sourceFamily: "nd_endpoints",
      kind: isMove ? "mac_move" : "endpoint_state",
      ...(mac ? { mac } : {}),
      ips,
      ...(switchName ? { switchName } : {}),
      ...(port ? { port, canonPort: canonicalPortKey(port) } : {}),
      vlanVni,
      modType,
      ...(anomalyScore !== undefined ? { anomalyScore } : {}),
      ...(tenant ? { tenant } : {}),
      ...(displayBd ? { displayBd } : {}),
      ...(displayEpg ? { displayEpg } : {}),
      ...(encap ? { encap } : {}),
      anomaly: isMove,
      summary: `ND ${modType} ${mac ?? ips[0]}${switchName ? ` on ${switchName}` : ""}${port ? ` ${port}` : ""}`,
    };
  }

  if (
    sourcetype === "cisco:dc:aci:stats" ||
    sourcetype === "cisco:dc:aci:class"
  ) {
    const component = asString(row.component);
    if (component && component !== "fvCEp") return undefined;
    const dn = asString(row.dn);
    const parsedDn = parseAciCepDn(dn);
    const mac = normalizeMac(row.mac) ?? parsedDn.mac;
    const ips = extractNormalizedIps([row.ip, row.addr]);
    if (!mac && !ips.length) return undefined;
    const tDn = asStringList(row.tDn)[0] ?? "";
    const parsedTDn = parseAciTDn(tDn);
    const switchName =
      parsedTDn.switchName ??
      (asString(row.apic_host) || asString(row.host) || undefined);
    const port = parsedTDn.port;
    const encap = asString(row.encap) || undefined;
    const vlanVni = normalizeVlanVniLabel({ encap });
    const lcCList = asStringList(row.lcC);
    const lcC = lcCList.length ? lcCList.join(", ") : undefined;
    const statusList = asStringList(row.status);
    const statusVal = statusList.find(Boolean)?.toLowerCase();
    return {
      id: `aci:${mac ?? ips[0]}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype,
      sourceFamily: "aci_fvcep",
      kind: "endpoint_state",
      ...(mac ? { mac } : {}),
      ips,
      ...(switchName ? { switchName } : {}),
      ...(port ? { port, canonPort: canonicalPortKey(port) } : {}),
      vlanVni,
      ...(statusVal ? { modType: statusVal } : {}),
      ...(parsedDn.tenant ? { tenant: parsedDn.tenant } : {}),
      ...(parsedDn.displayEpg ? { displayEpg: parsedDn.displayEpg } : {}),
      ...(encap ? { encap } : {}),
      ...(lcC ? { lcC } : {}),
      anomaly: false,
      summary: `ACI fvCEp ${mac ?? ips[0]}${switchName ? ` on ${switchName}` : ""}${port ? ` ${port}` : ""}`,
    };
  }

  if (sourcetype === "cisco:dc:nexus9k:dme") {
    const mac = normalizeMac(row.mac);
    const ips = extractNormalizedIps([row.ip, row.addr]);
    if (!mac && !ips.length) return undefined;
    const switchName =
      asString(row.switch) ||
      asString(row.leaf) ||
      asString(row.host) ||
      asString(row.device) ||
      undefined;
    const port =
      asString(row.interface) ||
      asString(row.interface_name) ||
      asString(row.port) ||
      undefined;
    const vlanVni = normalizeVlanVniLabel({
      vlan: asString(row.vlan ?? row.vlan_id),
      vni: asString(row.vni),
      encap: asString(row.encap),
    });
    const moveCountHint = asFiniteNumber(row.move_count);
    const isMove = moveCountHint !== undefined && moveCountHint > 0;
    return {
      id: `dme:${mac ?? ips[0]}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "cisco:dc:nexus9k:dme",
      sourceFamily: "dme",
      kind: isMove ? "mac_move" : "endpoint_state",
      ...(mac ? { mac } : {}),
      ips,
      ...(switchName ? { switchName } : {}),
      ...(port ? { port, canonPort: canonicalPortKey(port) } : {}),
      vlanVni,
      ...(moveCountHint !== undefined
        ? { moveCountHint: Math.max(0, Math.trunc(moveCountHint)) }
        : {}),
      anomaly: isMove,
      summary: `NX-OS DME ${mac ?? ips[0]}${switchName ? ` on ${switchName}` : ""}${port ? ` ${port}` : ""}${isMove ? ` (moves=${moveCountHint})` : ""}`,
    };
  }

  // Syslog via shared nxosSyslog.ts
  const syslogEv = normalizeSyslogRow(row, indexInBatch);
  if (!syslogEv) return undefined;
  const classified = classifyMobilitySyslogEvent(
    syslogEv.category,
    syslogEv.mnemonic,
    syslogEv.summary,
    syslogEv.severity,
  );
  if (!classified) return undefined;

  const msgMacs = (syslogEv.summary.match(MAC_ANY_RE) ?? [])
    .map((m) => normalizeMac(m))
    .filter((m): m is string => Boolean(m));
  const msgIps = (syslogEv.summary.match(IPV4_ANY_RE) ?? [])
    .map((ip) => tryNormalizeIp(ip))
    .filter((ip): ip is string => Boolean(ip));
  const rowIps = extractNormalizedIps([
    row.src_ip,
    row.sender_ip,
    row.ip,
    row.addr,
    syslogEv.neighborIp,
  ]);
  const ips = [...new Set([...rowIps, ...msgIps])];
  const mac =
    normalizeMac(row.mac ?? row.src_mac ?? row.sender_mac) ?? msgMacs[0];
  const secondaryMac = msgMacs.find((m) => m !== mac);

  const msgPorts = syslogEv.summary.match(SYSLOG_PORT_RE) ?? [];
  const rowPort =
    asString(row.interface) ||
    asString(row.interface_name) ||
    asString(row.port);
  const fromPort = msgPorts.length >= 2 ? msgPorts[0] : undefined;
  const toPort =
    msgPorts.length >= 2 ? msgPorts[1] : rowPort || msgPorts[0] || undefined;
  const port = toPort ?? rowPort ?? msgPorts[0];

  const vlanMatch = SYSLOG_VLAN_RE.exec(syslogEv.summary);
  const vlanVni = normalizeVlanVniLabel({
    vlan: asString(row.vlan_id ?? row.vlan) || vlanMatch?.[1],
    vni: asString(row.vni),
    encap: asString(row.encap),
  });

  return {
    id: syslogEv.id,
    timestamp: syslogEv.timestamp,
    sourcetype: sourcetype || syslogEv.sourceKind,
    sourceFamily: "syslog",
    kind: classified.kind,
    ...(mac ? { mac } : {}),
    ...(secondaryMac ? { secondaryMac } : {}),
    ips,
    switchName: syslogEv.host,
    ...(port ? { port, canonPort: canonicalPortKey(port) } : {}),
    ...(fromPort ? { fromPort } : {}),
    ...(toPort ? { toPort } : {}),
    vlanVni,
    mnemonic: syslogEv.mnemonic,
    anomaly: classified.anomaly,
    summary: syslogEv.summary,
  };
}

function buildSparklineBuckets(
  events: readonly NormalizedMobilityEvent[],
  earliest: number,
  latest: number,
  predicate: (ev: NormalizedMobilityEvent) => boolean,
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const counts = Array.from({ length: buckets }, () => 0);
  const populated = Array.from({ length: buckets }, () => false);
  for (const ev of events) {
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ev.timestamp - earliest) / span) * buckets)),
    );
    populated[idx] = true;
    if (predicate(ev)) counts[idx] += 1;
  }
  const activeBuckets = populated.filter(Boolean).length;
  return activeBuckets >= 4 ? counts : [];
}

/**
 * Pure aggregation of normalized endpoint mobility & ARP events into
 * flagged-first endpoint rows, 4 single-metric KPIs, SwimlaneTimeline,
 * Switch/Leaf × VLAN/VNI HeatMatrix, and a plain-language verdict.
 */
export function buildEndpointMobilityAnalysis(options: {
  events: readonly { event: NormalizedMobilityEvent; indexName: string }[];
  thresholds: ResolvedEndpointMobilityThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  activeSourceKinds?: readonly EndpointMobilitySourceKind[];
  streamReadiness?: StreamReadinessEntry;
}): EndpointMobilityInvestigationResult {
  const {
    events: rawEvents,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
    activeSourceKinds,
    streamReadiness,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  if (!rawEvents.length) {
    if (streamReadiness?.state === "estimate_only") {
      return {
        verdict:
          "Stream arp is in Estimate mode (statsOnly=true); no ARP event rows are indexed.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        kpis: [],
        rows: [],
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "estimate_only",
        bannerReason: streamReadiness.detail,
        checkedAt: nowSec,
      };
    }
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        kpis: [],
        rows: [],
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
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
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
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
          "Search hit row cap before matching endpoint mobility events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching endpoint mobility events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No endpoint mobility, duplicate IP, or ARP events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      timeline: [],
      timelineItemMap: {},
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      outcomes,
      capped,
      sourceMode: "none",
      streamReadiness,
      bannerState: "empty",
      bannerReason:
        streamReadiness?.state === "enabled"
          ? "Stream arp is Enabled (statsOnly=false), but no matching ARP or mobility events were observed in this UTC window."
          : "No matching endpoint mobility events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const familiesPresent = new Set<MobilitySourceFamily>(
    rawEvents.map((e) => e.event.sourceFamily),
  );
  const sourceMode: EndpointMobilityInvestigationResult["sourceMode"] =
    familiesPresent.size > 1 ? "mixed" : ([...familiesPresent][0] ?? "none");

  const inferredKinds: readonly EndpointMobilitySourceKind[] =
    activeSourceKinds?.length
      ? activeSourceKinds
      : ([...familiesPresent] as EndpointMobilitySourceKind[]);

  const hasAuto = inferredKinds.includes("auto");
  const hasStreamArpSource =
    (hasAuto || inferredKinds.includes("stream_arp")) &&
    streamReadiness?.state !== "estimate_only";
  const hasNdSource =
    hasAuto ||
    inferredKinds.includes("nd_endpoints") ||
    familiesPresent.has("nd_endpoints");
  const hasAciSource =
    hasAuto ||
    inferredKinds.includes("aci_fvcep") ||
    familiesPresent.has("aci_fvcep");
  const hasDmeSource =
    hasAuto || inferredKinds.includes("dme") || familiesPresent.has("dme");
  const hasSyslogSource =
    hasAuto ||
    inferredKinds.includes("syslog") ||
    familiesPresent.has("syslog");

  const dupIpCovered =
    hasStreamArpSource ||
    hasNdSource ||
    hasAciSource ||
    hasDmeSource ||
    hasSyslogSource ||
    rawEvents.length > 0;
  const macMoveCovered =
    hasNdSource || hasAciSource || hasDmeSource || hasSyslogSource;
  const arpSpikeCovered =
    hasStreamArpSource || familiesPresent.has("stream_arp");
  const portFlapCovered = hasSyslogSource;
  const attachmentCovered =
    hasNdSource || hasAciSource || hasDmeSource || hasSyslogSource;

  // Step 1: Identify duplicate IPs (>= 2 distinct MACs or explicit syslog ARP conflict)
  const ipToMacs = new Map<string, Set<string>>();
  const explicitConflictIps = new Set<string>();
  const portFlapPool: { event: NormalizedMobilityEvent; indexName: string }[] =
    [];
  const endpointEntries: {
    event: NormalizedMobilityEvent;
    indexName: string;
  }[] = [];

  for (const entry of rawEvents) {
    const ev = entry.event;
    if (ev.kind === "port_flap") {
      portFlapPool.push(entry);
      continue;
    }
    endpointEntries.push(entry);
    for (const ip of ev.ips) {
      const set = ipToMacs.get(ip) ?? new Set<string>();
      if (ev.mac) set.add(ev.mac);
      if (ev.secondaryMac) set.add(ev.secondaryMac);
      ipToMacs.set(ip, set);
      if (ev.kind === "arp_conflict" && ev.anomaly) {
        explicitConflictIps.add(ip);
      }
    }
  }

  const duplicateIpSet = new Set<string>(explicitConflictIps);
  for (const [ip, macs] of ipToMacs.entries()) {
    if (macs.size >= 2) duplicateIpSet.add(ip);
  }

  // If a MAC participates in exactly one duplicate IP, route MAC-only events for that MAC to that IP conflict group.
  const macToDupIps = new Map<string, Set<string>>();
  for (const dupIp of duplicateIpSet) {
    for (const mac of ipToMacs.get(dupIp) ?? []) {
      const s = macToDupIps.get(mac) ?? new Set<string>();
      s.add(dupIp);
      macToDupIps.set(mac, s);
    }
  }

  // Step 2: Cluster endpoint events into endpoint rows
  const groups = new Map<
    string,
    {
      id: string;
      endpointLabel: string;
      events: NormalizedMobilityEvent[];
      flaps: NormalizedMobilityEvent[];
      indexName: string;
      isConflictIpGroup: boolean;
      conflictIp?: string;
    }
  >();

  for (const entry of endpointEntries) {
    const ev = entry.event;
    const dupIp = ev.ips.find((ip) => duplicateIpSet.has(ip));
    let key: string;
    let id: string;
    let endpointLabel: string;
    let isConflictIpGroup = false;
    let conflictIp: string | undefined;

    if (dupIp) {
      key = `ip:${dupIp}`;
      id = buildEndpointRowId("ip", dupIp);
      endpointLabel = dupIp;
      isConflictIpGroup = true;
      conflictIp = dupIp;
    } else if (
      ev.mac &&
      !ev.ips.length &&
      macToDupIps.get(ev.mac)?.size === 1
    ) {
      const linkedIp = [...macToDupIps.get(ev.mac)!][0];
      key = `ip:${linkedIp}`;
      id = buildEndpointRowId("ip", linkedIp);
      endpointLabel = linkedIp;
      isConflictIpGroup = true;
      conflictIp = linkedIp;
    } else if (ev.mac) {
      key = `mac:${ev.mac}`;
      id = buildEndpointRowId("mac", ev.mac);
      endpointLabel = ev.mac;
    } else if (ev.ips[0]) {
      key = `ip:${ev.ips[0]}`;
      id = buildEndpointRowId("ip", ev.ips[0]);
      endpointLabel = ev.ips[0];
    } else {
      continue;
    }

    const existing = groups.get(key);
    if (existing) {
      existing.events.push(ev);
    } else {
      groups.set(key, {
        id,
        endpointLabel,
        events: [ev],
        flaps: [],
        indexName: entry.indexName,
        isConflictIpGroup,
        conflictIp,
      });
    }
  }

  // Step 3: Correlate port flaps to endpoint attachments by (switch, canonicalPort)
  const unmatchedFlaps: {
    event: NormalizedMobilityEvent;
    indexName: string;
  }[] = [];

  for (const flapEntry of portFlapPool) {
    const flap = flapEntry.event;
    const flapSwitch = flap.switchName
      ? shortenDeviceLabel(flap.switchName).toLowerCase()
      : "";
    const flapPortKey = flap.canonPort ?? "";
    let matchedAny = false;
    if (flapSwitch && flapPortKey) {
      for (const group of groups.values()) {
        const matchesEndpoint = group.events.some(
          (ev) =>
            ev.switchName &&
            ev.canonPort &&
            shortenDeviceLabel(ev.switchName).toLowerCase() === flapSwitch &&
            ev.canonPort === flapPortKey,
        );
        if (matchesEndpoint) {
          group.flaps.push(flap);
          matchedAny = true;
        }
      }
    }
    if (!matchedAny) {
      unmatchedFlaps.push(flapEntry);
    }
  }

  // Group unmatched port flaps per (switch, port) so syslog-only port flap runs stay visible
  for (const flapEntry of unmatchedFlaps) {
    const ev = flapEntry.event;
    const sw = ev.switchName ?? "switch";
    const port = ev.port ?? "port";
    const key = `port:${sw}:${canonicalPortKey(port)}`;
    const existing = groups.get(key);
    if (existing) {
      existing.flaps.push(ev);
    } else {
      groups.set(key, {
        id: buildEndpointRowId("port", `${sw}__${port}`),
        endpointLabel: `${shortenDeviceLabel(sw)} ${port}`,
        events: [],
        flaps: [ev],
        indexName: flapEntry.indexName,
        isConflictIpGroup: false,
      });
    }
  }

  // Step 4: Build EndpointMobilityRow[] and track totals for KPIs
  const rows: EndpointMobilityRow[] = [];
  let totalDuplicateIps = 0;
  let totalMacMoves = 0;
  let totalArpSpikes = 0;
  const totalPortFlapEvents = portFlapPool.filter(
    (e) => e.event.anomaly,
  ).length;
  const rowIdByEventId = new Map<string, string>();

  for (const group of groups.values()) {
    const chronological = [...group.events].sort(
      (a, b) => a.timestamp - b.timestamp,
    );
    const allGroupEvents = [...group.events, ...group.flaps].sort(
      (a, b) => b.timestamp - a.timestamp,
    );
    for (const ev of allGroupEvents) {
      rowIdByEventId.set(ev.id, group.id);
    }

    const macs = [
      ...new Set(
        chronological
          .flatMap((e) => [e.mac, e.secondaryMac])
          .filter((m): m is string => Boolean(m)),
      ),
    ];
    const ips = [...new Set(chronological.flatMap((e) => e.ips))];
    const switches = [
      ...new Set(
        allGroupEvents
          .map((e) => e.switchName)
          .filter((s): s is string => Boolean(s)),
      ),
    ];
    const vlanVnis = [
      ...new Set(
        allGroupEvents.map((e) => e.vlanVni).filter((v) => v !== "default"),
      ),
    ];
    if (!vlanVnis.length) vlanVnis.push("default");

    const sourcetypes = [...new Set(allGroupEvents.map((e) => e.sourcetype))];

    // Build chronological attachment transitions & distinct attachments
    const transitions: MobilityAttachmentTransition[] = [];
    const attachments: string[] = [];
    let attachmentTransitions = 0;
    let prevAttachKey: string | undefined;

    for (const ev of chronological) {
      if (ev.fromPort && ev.toPort && ev.switchName) {
        const fromLabel = `${shortenDeviceLabel(ev.switchName)} ${ev.fromPort}`;
        const toLabel = `${shortenDeviceLabel(ev.switchName)} ${ev.toPort}`;
        if (!attachments.includes(fromLabel)) attachments.push(fromLabel);
        if (!attachments.includes(toLabel)) attachments.push(toLabel);
        transitions.push({
          timestamp: ev.timestamp,
          switchName: ev.switchName,
          port: `${ev.fromPort} → ${ev.toPort}`,
          source: ev.sourcetype,
          ...(ev.mnemonic ? { modType: ev.mnemonic } : {}),
          detail: ev.summary,
        });
        attachmentTransitions += 1;
        prevAttachKey = `${shortenDeviceLabel(ev.switchName).toLowerCase()}|${canonicalPortKey(ev.toPort)}`;
        continue;
      }

      if (ev.switchName && ev.port) {
        const label = `${shortenDeviceLabel(ev.switchName)} ${ev.port}`;
        if (!attachments.includes(label)) attachments.push(label);
        const attachKey = `${shortenDeviceLabel(ev.switchName).toLowerCase()}|${ev.canonPort ?? canonicalPortKey(ev.port)}`;
        if (prevAttachKey !== undefined && prevAttachKey !== attachKey) {
          attachmentTransitions += 1;
        }
        if (
          prevAttachKey !== attachKey ||
          ev.modType === "deletion" ||
          ev.modType === "move"
        ) {
          transitions.push({
            timestamp: ev.timestamp,
            switchName: ev.switchName,
            port: ev.port,
            source: ev.sourcetype,
            ...(ev.modType ? { modType: ev.modType } : {}),
            detail: ev.summary,
          });
        }
        prevAttachKey = attachKey;
      } else if (ev.switchName && ev.sourceFamily !== "stream_arp") {
        const label = shortenDeviceLabel(ev.switchName);
        if (!attachments.includes(label)) attachments.push(label);
      }
    }

    const explicitMoves = chronological.reduce(
      (max, ev) =>
        ev.moveCountHint !== undefined ? Math.max(max, ev.moveCountHint) : max,
      0,
    );
    const hasExplicitMoveEvent = chronological.some(
      (ev) => ev.kind === "mac_move" && ev.anomaly,
    );
    const moveCount = Math.max(
      attachmentTransitions,
      explicitMoves,
      hasExplicitMoveEvent ? 1 : 0,
    );

    const arpCount = chronological.filter(
      (e) => e.sourceFamily === "stream_arp",
    ).length;

    const anomalyFlaps = group.flaps.filter((f) => f.anomaly);
    const portFlapCount = anomalyFlaps.length;
    const flappingPorts = [
      ...new Set(
        anomalyFlaps
          .map((f) =>
            f.switchName && f.port
              ? `${shortenDeviceLabel(f.switchName)} ${f.port}`
              : f.port,
          )
          .filter((p): p is string => Boolean(p)),
      ),
    ];

    const anomalyScores = chronological
      .map((e) => e.anomalyScore)
      .filter((s): s is number => s !== undefined);
    const maxAnomalyScore = anomalyScores.length
      ? Math.max(...anomalyScores)
      : undefined;

    const reasons: string[] = [];
    const hasDuplicateIp =
      group.isConflictIpGroup ||
      macs.length >= 2 ||
      chronological.some((e) => e.kind === "arp_conflict" && e.anomaly);

    if (hasDuplicateIp) {
      totalDuplicateIps += 1;
      const targetIp = group.conflictIp ?? ips[0] ?? group.endpointLabel;
      const deletedMacs = new Set(
        chronological
          .filter((e) => e.modType === "deletion" && e.mac)
          .map((e) => e.mac!),
      );
      if (macs.length >= 2) {
        const macDetails = macs.map((m) =>
          deletedMacs.has(m) ? `${m} (deleted)` : m,
        );
        reasons.push(
          `Duplicate IP ${targetIp} across ${macs.length} MACs (${macDetails.join(", ")})`,
        );
      } else {
        reasons.push(`Duplicate IP / ARP conflict reported for ${targetIp}`);
      }
    }

    if (moveCount >= thresholds.macMoveWarnCount && moveCount > 0) {
      totalMacMoves += moveCount;
      reasons.push(
        attachments.length >= 2
          ? `MAC moved across ${attachments.length} attachments (${attachments.join(" → ")})`
          : `MAC move observed (${moveCount} ${moveCount === 1 ? "move" : "moves"})`,
      );
    }

    if (
      maxAnomalyScore !== undefined &&
      maxAnomalyScore >= thresholds.anomalyScoreWarn
    ) {
      reasons.push(
        `ND anomaly score ${Math.round(maxAnomalyScore)} (≥ ${thresholds.anomalyScoreWarn})`,
      );
    }

    if (arpSpikeCovered && arpCount >= thresholds.arpSpikeWarnCount) {
      totalArpSpikes += 1;
      reasons.push(
        `ARP rate spike: ${arpCount} packets in window (≥ ${thresholds.arpSpikeWarnCount})`,
      );
    }

    if (
      portFlapCount > 0 &&
      (portFlapCount >= thresholds.portFlapWarnCount ||
        moveCount > 0 ||
        hasDuplicateIp ||
        chronological.length === 0)
    ) {
      reasons.push(
        `Port flap correlation: ${portFlapCount} link ${portFlapCount === 1 ? "flap" : "flaps"}${flappingPorts.length ? ` on ${flappingPorts.join(", ")}` : ""}`,
      );
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention ? "attention" : "ok";
    const timestamps = allGroupEvents.map((e) => e.timestamp);
    const rep = allGroupEvents.find((e) => e.anomaly) ?? allGroupEvents[0];

    const rowHasIpCoverage =
      chronological.length > 0 && (dupIpCovered || ips.length > 0);
    const rowHasAttachmentCoverage =
      attachmentCovered || attachments.length > 0;
    const rowHasMoveCoverage = macMoveCovered && chronological.length > 0;
    const rowHasArpCoverage =
      (arpSpikeCovered || arpCount > 0) && chronological.length > 0;
    const rowHasFlapCoverage = portFlapCovered || portFlapCount > 0;

    rows.push({
      id: group.id,
      attention,
      endpointLabel: group.endpointLabel,
      ...(macs[0] ? { primaryMac: macs[0] } : {}),
      macs,
      ips,
      switches,
      attachments,
      transitions,
      vlanVnis,
      sourcetypes,
      moveCount,
      arpCount,
      portFlapCount,
      flappingPorts,
      ...(maxAnomalyScore !== undefined ? { maxAnomalyScore } : {}),
      ...(chronological.find((e) => e.tenant)?.tenant
        ? { tenant: chronological.find((e) => e.tenant)!.tenant }
        : {}),
      ...(chronological.find((e) => e.displayBd)?.displayBd
        ? { displayBd: chronological.find((e) => e.displayBd)!.displayBd }
        : {}),
      ...(chronological.find((e) => e.displayEpg)?.displayEpg
        ? { displayEpg: chronological.find((e) => e.displayEpg)!.displayEpg }
        : {}),
      ...(chronological.find((e) => e.lcC)?.lcC
        ? { lcC: chronological.find((e) => e.lcC)!.lcC }
        : {}),
      hasIpCoverage: rowHasIpCoverage,
      hasAttachmentCoverage: rowHasAttachmentCoverage,
      hasMoveCoverage: rowHasMoveCoverage,
      hasArpCoverage: rowHasArpCoverage,
      hasFlapCoverage: rowHasFlapCoverage,
      status,
      reasons,
      firstSeen: Math.min(...timestamps),
      lastSeen: Math.max(...timestamps),
      indexName: group.indexName,
      lastSummary: rep.summary,
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.reasons.length !== b.reasons.length) {
      return b.reasons.length - a.reasons.length;
    }
    if (a.moveCount !== b.moveCount) return b.moveCount - a.moveCount;
    if (a.arpCount !== b.arpCount) return b.arpCount - a.arpCount;
    return b.lastSeen - a.lastSeen;
  });

  // Step 5: KPIs (<= 4 single-metric tiles with clean units and sparklines)
  const allFlat = rawEvents.map((e) => e.event);
  const dupSpark = buildSparklineBuckets(
    allFlat,
    earliest,
    latest,
    (ev) =>
      ev.ips.some((ip) => duplicateIpSet.has(ip)) ||
      (ev.kind === "arp_conflict" && ev.anomaly),
  );
  const moveSpark = buildSparklineBuckets(
    allFlat,
    earliest,
    latest,
    (ev) => ev.kind === "mac_move" || (ev.moveCountHint ?? 0) > 0,
  );
  const arpSpark = buildSparklineBuckets(
    allFlat,
    earliest,
    latest,
    (ev) => ev.sourceFamily === "stream_arp",
  );
  const flapSpark = buildSparklineBuckets(
    allFlat,
    earliest,
    latest,
    (ev) => ev.kind === "port_flap" && ev.anomaly,
  );

  const observedIpCount = rows.reduce((sum, r) => sum + r.ips.length, 0);
  const dupIpHasObservedIps = dupIpCovered && observedIpCount > 0;

  const kpis: ProtocolKpi[] = [
    {
      id: "duplicate-ips",
      label: "Duplicate IPs",
      value: !dupIpCovered
        ? "Not covered"
        : observedIpCount === 0
          ? "None observed"
          : formatCount(totalDuplicateIps),
      ...(dupIpHasObservedIps
        ? { unit: totalDuplicateIps === 1 ? "IP" : "IPs" }
        : {}),
      status: !dupIpCovered
        ? "not_covered"
        : observedIpCount === 0
          ? "none_observed"
          : totalDuplicateIps > 0
            ? "attention"
            : "ok",
      ...(dupIpHasObservedIps && dupSpark.length
        ? { sparkline: dupSpark }
        : {}),
    },
    {
      id: "mac-moves",
      label: "MAC Moves",
      value: macMoveCovered ? formatCount(totalMacMoves) : "Not covered",
      ...(macMoveCovered
        ? { unit: totalMacMoves === 1 ? "move" : "moves" }
        : {}),
      status: !macMoveCovered
        ? "not_covered"
        : totalMacMoves >= thresholds.macMoveWarnCount && totalMacMoves > 0
          ? "attention"
          : "ok",
      ...(macMoveCovered && moveSpark.length ? { sparkline: moveSpark } : {}),
    },
    {
      id: "arp-spikes",
      label: "ARP Rate Spikes",
      value: arpSpikeCovered ? formatCount(totalArpSpikes) : "Not covered",
      ...(arpSpikeCovered
        ? { unit: totalArpSpikes === 1 ? "spike" : "spikes" }
        : {}),
      status: !arpSpikeCovered
        ? "not_covered"
        : totalArpSpikes > 0
          ? "attention"
          : "ok",
      ...(arpSpikeCovered && arpSpark.length ? { sparkline: arpSpark } : {}),
      ...(streamReadiness?.state === "estimate_only"
        ? { hint: streamReadiness.detail }
        : {}),
    },
    {
      id: "port-flaps",
      label: "Port Flaps",
      value: portFlapCovered ? formatCount(totalPortFlapEvents) : "Not covered",
      ...(portFlapCovered
        ? { unit: totalPortFlapEvents === 1 ? "flap" : "flaps" }
        : {}),
      status: !portFlapCovered
        ? "not_covered"
        : totalPortFlapEvents >= thresholds.portFlapWarnCount ||
            (totalPortFlapEvents > 0 &&
              rows.some((r) => r.attention && r.portFlapCount > 0))
          ? "attention"
          : "ok",
      ...(portFlapCovered && flapSpark.length ? { sparkline: flapSpark } : {}),
    },
  ];

  // Step 6: SwimlaneTimeline (preserve IPv4 & IPv6 intact via shortenDeviceLabel)
  const timelineItemMap: Record<string, string> = {};
  const rowById = new Map(rows.map((r) => [r.id, r]));
  const prioritizedRowIds = new Set(rows.slice(0, 8).map((r) => r.id));

  const timelineEventsSource = [...allFlat]
    .filter((ev) => {
      const rowId = rowIdByEventId.get(ev.id);
      return rowId ? prioritizedRowIds.has(rowId) : false;
    })
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(0, 64);

  const timeline: ProtocolTimelineEvent[] = timelineEventsSource.map((ev) => {
    const rowId = rowIdByEventId.get(ev.id)!;
    const ownerRow = rowById.get(rowId)!;
    timelineItemMap[ev.id] = rowId;
    const isDupIpEvent = ev.ips.some((ip) => duplicateIpSet.has(ip));
    const isAttentionEvent =
      ev.anomaly ||
      isDupIpEvent ||
      (ownerRow.attention &&
        ev.sourceFamily === "stream_arp" &&
        ownerRow.arpCount >= thresholds.arpSpikeWarnCount);
    const lane = shortenDeviceLabel(ownerRow.endpointLabel);
    const label =
      ev.kind === "port_flap"
        ? `${ev.mnemonic ?? "PORT_FLAP"} (${ev.port ?? "port"})`
        : ev.kind === "mac_move"
          ? `MAC move (${ev.port ?? ev.switchName ?? ownerRow.endpointLabel})`
          : isDupIpEvent
            ? `Dup IP ${ev.mac ?? ev.ips[0] ?? ""}`.trim()
            : ev.sourceFamily === "stream_arp"
              ? `ARP ${ev.arpOpcode ?? "PKT"}`
              : `${ev.modType ?? "seen"} (${ev.port ?? ev.switchName ?? "fabric"})`;
    return {
      id: ev.id,
      lane,
      timestamp: ev.timestamp,
      kind: isAttentionEvent ? "attention" : "ok",
      label,
      detail: ev.summary,
    };
  });

  // Step 7: Switch/Leaf × VLAN/VNI HeatMatrix (flagged switches sorted first)
  const switchToVlanStats = new Map<
    string,
    {
      events: number;
      attentionReasons: string[];
      itemId?: string;
    }
  >();
  const flaggedSwitches = new Set<string>();
  const allSwitches = new Set<string>();
  const allVlanVnis = new Set<string>();

  for (const ev of allFlat) {
    const sw = ev.switchName
      ? shortenDeviceLabel(ev.switchName)
      : "unattributed";
    const vlan = ev.vlanVni || "default";
    allSwitches.add(sw);
    allVlanVnis.add(vlan);

    const rowId = rowIdByEventId.get(ev.id);
    const ownerRow = rowId ? rowById.get(rowId) : undefined;
    const key = `${sw}\0${vlan}`;
    const existing = switchToVlanStats.get(key) ?? {
      events: 0,
      attentionReasons: [],
      itemId: rowId,
    };
    existing.events += 1;
    if (ownerRow?.attention) {
      flaggedSwitches.add(sw);
      if (
        ownerRow.reasons[0] &&
        !existing.attentionReasons.includes(ownerRow.reasons[0])
      ) {
        existing.attentionReasons.push(ownerRow.reasons[0]);
      }
      // Prefer linking cell to an attention row
      if (!existing.itemId || !rowById.get(existing.itemId)?.attention) {
        existing.itemId = ownerRow.id;
      }
    }
    switchToVlanStats.set(key, existing);
  }

  const matrixRows = [...allSwitches].sort((a, b) => {
    const aFlag = flaggedSwitches.has(a);
    const bFlag = flaggedSwitches.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    return a.localeCompare(b);
  });
  const matrixCols = [...allVlanVnis].sort((a, b) => a.localeCompare(b));
  const matrixCells: ProtocolMatrixCell[] = [];

  for (const sw of matrixRows) {
    for (const vlan of matrixCols) {
      const stat = switchToVlanStats.get(`${sw}\0${vlan}`);
      if (!stat) continue;
      const isAttn = stat.attentionReasons.length > 0;
      const leadReason = stat.attentionReasons[0] ?? "";
      const cellTag = leadReason.startsWith("Duplicate IP")
        ? "dup IP"
        : leadReason.startsWith("MAC move")
          ? "MAC move"
          : leadReason.startsWith("ARP rate")
            ? "ARP spike"
            : leadReason.startsWith("Port flap")
              ? "port flap"
              : "alert";
      matrixCells.push({
        row: sw,
        col: vlan,
        status: isAttn ? "attention" : "ok",
        value: isAttn ? cellTag : `${stat.events} ok`,
        count: stat.events,
        detail: isAttn
          ? stat.attentionReasons.join("; ")
          : `${stat.events} steady endpoint events on ${sw} (${vlan})`,
        ...(stat.itemId ? { itemId: stat.itemId } : {}),
      });
    }
  }

  // Step 8: Plain-language single-sentence verdict above the fold
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    // Strip threshold parenthetical `(≥ N)` from verdict text per UX contract
    const rawLeadReason = lead.reasons[0] ?? lead.lastSummary;
    const cleanLeadReason = rawLeadReason.replace(/\s*\(≥\s*\d+\)/g, "");
    const lowerLead = cleanLeadReason.startsWith("Duplicate IP")
      ? `duplicate IP${cleanLeadReason.slice("Duplicate IP".length)}`
      : cleanLeadReason.startsWith("ARP rate spike")
        ? `ARP rate spike${cleanLeadReason.slice("ARP rate spike".length)}`
        : cleanLeadReason.startsWith("Port flap")
          ? `port flap${cleanLeadReason.slice("Port flap".length)}`
          : cleanLeadReason;
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "endpoint needs" : "endpoints need"} attention: ${lowerLead}.`;
    verdictStatus = "attention";
  } else {
    const checked: string[] = [];
    const missing: string[] = [];
    if (dupIpHasObservedIps) checked.push("duplicate IPs");
    else if (!dupIpCovered) missing.push("duplicate IPs");
    if (macMoveCovered) checked.push("MAC moves");
    else missing.push("MAC moves");
    if (arpSpikeCovered) checked.push("ARP spikes");
    else missing.push("ARP spikes");
    if (portFlapCovered) checked.push("port flaps");
    else missing.push("port flaps");
    const scopePrefix = capped
      ? `First ${rows.length} ${rows.length === 1 ? "endpoint" : "endpoints"} (capped)`
      : `${rows.length} of ${rows.length} ${rows.length === 1 ? "endpoint" : "endpoints"}`;
    const checkedNote = checked.length ? ` with no ${checked.join(", ")}` : "";
    const noIpNote =
      dupIpCovered && observedIpCount === 0
        ? " (no endpoint IPs reported)"
        : "";
    const missingNote = missing.length
      ? ` — ${missing.join(", ")} not covered`
      : "";
    verdict = `${scopePrefix} steady${checkedNote}${noIpNote}${missingNote}.`;
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
      : "Sample capped at 256 rows — narrow the UTC window or filter.";

  const bannerState: EndpointMobilityInvestigationResult["bannerState"] =
    anyPartial
      ? "partial"
      : streamReadiness?.state === "estimate_only"
        ? "estimate_only"
        : undefined;
  const bannerReason = anyPartial
    ? partialReason
    : streamReadiness?.state === "estimate_only"
      ? streamReadiness.detail
      : undefined;

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    kpis,
    rows,
    timeline,
    timelineItemMap,
    matrixRows,
    matrixCols,
    matrixCells,
    outcomes,
    capped,
    sourceMode,
    streamReadiness,
    ...(bannerState ? { bannerState, bannerReason } : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateEndpointMobilityOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

function matchesEntityFilter(
  ev: NormalizedMobilityEvent,
  filter?: ProtocolFilter,
): boolean {
  if (!filter) return true;
  if (filter.src) {
    const s = filter.src.toLowerCase();
    const match =
      ev.mac?.toLowerCase() === s ||
      ev.ips.some((ip) => ip.toLowerCase() === s) ||
      ev.summary.toLowerCase().includes(s);
    if (!match) return false;
  }
  if (filter.dst) {
    const d = filter.dst.toLowerCase();
    const match =
      ev.mac?.toLowerCase() === d ||
      ev.ips.some((ip) => ip.toLowerCase() === d) ||
      ev.summary.toLowerCase().includes(d);
    if (!match) return false;
  }
  if (filter.device) {
    const dev = filter.device.toLowerCase();
    const match =
      ev.switchName?.toLowerCase() === dev ||
      shortenDeviceLabel(ev.switchName ?? "").toLowerCase() === dev ||
      ev.summary.toLowerCase().includes(dev);
    if (!match) return false;
  }
  if (filter.vni) {
    if (
      ev.vlanVni !== `vni-${filter.vni}` &&
      ev.encap !== `vxlan-${filter.vni}`
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Executes the on-demand Endpoint Mobility & Address Conflicts investigation across
 * `stream:arp`, `cisco:dc:nd:endpoints`, `cisco:dc:aci:stats`/`class` (`fvCEp`),
 * `cisco:dc:nexus9k:dme`, and NX-OS/ACI syslog (`nxosSyslog.ts`), rechecking the
 * `adm_protocol_profiles` fingerprint before surfacing results.
 */
export async function investigateEndpointMobility(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateEndpointMobilityOptions = {},
): Promise<EndpointMobilityInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "endpoint_mobility",
    request.scope,
    request.earliest,
    request.latest,
  );
  if (!scoped.length) {
    return {
      verdict: "No active source profile covers this scope.",
      verdictStatus: "not_covered",
      coverageStatus: "not_covered",
      coverageLabel: "Not covered",
      kpis: [],
      rows: [],
      timeline: [],
      timelineItemMap: {},
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No endpoint_mobility profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: {
      event: NormalizedMobilityEvent;
      indexName: string;
    }[] = [];
    const activeKinds: EndpointMobilitySourceKind[] = [];
    const streamProfiles: BaseProtocolProfile[] = [];
    let sawStreamArpComplete = false;
    let capped = false;
    const chosenThresholds = resolveEndpointMobilityThresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const thresholds = resolveEndpointMobilityThresholds(profile);
      activeKinds.push(thresholds.sourceKind);

      const runStreamArp =
        thresholds.sourceKind === "stream_arp" ||
        thresholds.sourceKind === "auto";
      const runNd =
        thresholds.sourceKind === "nd_endpoints" ||
        thresholds.sourceKind === "auto";
      const runAci =
        thresholds.sourceKind === "aci_fvcep" ||
        thresholds.sourceKind === "auto";
      const runDme =
        thresholds.sourceKind === "dme" || thresholds.sourceKind === "auto";
      const runSyslog =
        (thresholds.sourceKind === "syslog" ||
          thresholds.sourceKind === "auto") &&
        !request.filter?.vni;

      if (runStreamArp) {
        streamProfiles.push(profile);
        const spl = buildMobilityStreamArpSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "endpoint_mobility",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: "stream_arp",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        if (res.outcome.state === "complete" && res.rows.length === 0) {
          sawStreamArpComplete = true;
        }
        res.rows.forEach((row, idx) => {
          const norm = normalizeEndpointMobilityRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runNd) {
        signal.throwIfAborted();
        const spl = buildMobilityNdEndpointsSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "endpoint_mobility",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: "nd_endpoints",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeEndpointMobilityRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runAci) {
        signal.throwIfAborted();
        const spl = buildMobilityAciSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "endpoint_mobility",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: "aci_fvcep",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeEndpointMobilityRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runDme) {
        signal.throwIfAborted();
        const spl = buildMobilityDmeSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "endpoint_mobility",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: "dme",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeEndpointMobilityRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runSyslog) {
        signal.throwIfAborted();
        const spl = buildMobilitySyslogSearch({
          index: profile.index,
          device: request.filter?.device,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "endpoint_mobility",
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
          const norm = normalizeEndpointMobilityRow(row, idx);
          if (!norm) return;
          if (!matchesEntityFilter(norm, request.filter)) return;
          collected.push({ event: norm, indexName: profile.index });
        });
      }
    }

    // Check Stream Estimate mode ONLY when stream:arp completed with 0 rows
    // and an explicit investigation was requested.
    let streamReadiness: StreamReadinessEntry | undefined;
    const arpCompletedEmpty =
      streamProfiles.length > 0 &&
      sawStreamArpComplete &&
      collected.every((c) => c.event.sourceFamily !== "stream_arp");

    if (arpCompletedEmpty && !options.skipEstimateCheck) {
      const entries = await checkStreamEstimateMode(client, ["arp"], signal);
      streamReadiness =
        entries.find((e) => e.state === "estimate_only") ?? entries[0];
      if (streamReadiness?.state === "estimate_only") {
        outcomes.push({
          source: "protocol_stream_readiness",
          state: "estimate_only",
          detail: streamReadiness.detail,
        });
      }
    }

    return buildEndpointMobilityAnalysis({
      events: collected,
      thresholds: chosenThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      activeSourceKinds: activeKinds,
      streamReadiness,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    endpoint_mobility: validateEndpointMobilityExtra,
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
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
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
 * Hub "Check all" summary runner for `endpoint_mobility`.
 */
export async function summarizeEndpointMobility(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateEndpointMobilityOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateEndpointMobility(
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
    lens: "endpoint_mobility",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
