import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  buildSyslogStateSearch,
  normalizeSyslogRow,
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
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  checkStreamEstimateMode,
  type StreamReadinessEntry,
} from "../../shared/streamReadiness";
import {
  DEFAULT_L2_CONTROL_THRESHOLDS,
  validateL2ControlExtra,
  type L2ControlExtraConfig,
  type L2ControlSourceKind,
  type ResolvedL2ControlThresholds,
} from "./validate";

export {
  DEFAULT_L2_CONTROL_THRESHOLDS,
  validateL2ControlExtra,
  type L2ControlExtraConfig,
  type L2ControlSourceKind,
  type ResolvedL2ControlThresholds,
};

export type L2Subsystem = "DHCP" | "STP" | "LACP" | "ARP" | "LLDP";

export const L2_SUBSYSTEMS: readonly L2Subsystem[] = [
  "DHCP",
  "STP",
  "LACP",
  "ARP",
  "LLDP",
] as const;

export const STREAM_L2_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_mac",
  "dest_mac",
  "client_mac",
  "dhcp_message_type",
  "message_type",
  "yiaddr",
  "lease_time",
  "option_53",
  "vlan",
  "vlan_id",
  "vni",
] as const;

export const DME_L2_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "dn",
  "descr",
  "interface",
  "vlan",
  "stp_root",
  "root_bridge",
  "port_state",
  "port_role",
  "port_channel",
  "member_interface",
  "oper_state",
  "operSt",
  "lacp_state",
] as const;

export function resolveL2ControlThresholds(
  profile?: BaseProtocolProfile,
): ResolvedL2ControlThresholds {
  const extra = profile?.extra as L2ControlExtraConfig | undefined;
  return {
    sourceKind: extra?.sourceKind ?? DEFAULT_L2_CONTROL_THRESHOLDS.sourceKind,
    dhcpNakWarnCount:
      typeof extra?.dhcpNakWarnCount === "number"
        ? extra.dhcpNakWarnCount
        : DEFAULT_L2_CONTROL_THRESHOLDS.dhcpNakWarnCount,
    stpTcnWarnCount:
      typeof extra?.stpTcnWarnCount === "number"
        ? extra.stpTcnWarnCount
        : DEFAULT_L2_CONTROL_THRESHOLDS.stpTcnWarnCount,
    lacpDropWarnCount:
      typeof extra?.lacpDropWarnCount === "number"
        ? extra.lacpDropWarnCount
        : DEFAULT_L2_CONTROL_THRESHOLDS.lacpDropWarnCount,
  };
}

/**
 * Builds a bounded, allowlisted SPL query for `stream:dhcp` (and optionally `stream:arp`).
 * Emits `| head <maxRows + 1>` BEFORE `buildAllowedFieldsClause` so indexers cap rows
 * and drop `_raw` server-side.
 */
export function buildL2StreamSearch(options: {
  index: string;
  includeArp?: boolean;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const stClause = options.includeArp
    ? '(sourcetype="stream:dhcp" OR sourcetype="stream:arp")'
    : 'sourcetype="stream:dhcp"';
  const predicates: string[] = [`index=${index}`, stClause];
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(`(src_ip="${src}" OR src_mac="${src}" OR chaddr="${src}")`);
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(
      `(dest_ip="${dst}" OR yiaddr="${dst}" OR dest_mac="${dst}")`,
    );
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(host="${dev}" OR dest_ip="${dev}")`);
  }
  if (options.filter?.vni) {
    const vni = literal(options.filter.vni, 16);
    predicates.push(`(vxlan_id="${vni}" OR vni="${vni}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "l2_control",
    STREAM_L2_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval client_mac=coalesce(client_mac, chaddr, arp_src_mac, src_mac), dhcp_message_type=coalesce(dhcp_message_type, message_type, opcode), lease_time=coalesce(lease_time, ip_lease_time), vni=coalesce(vni, vxlan_id) ` +
    tableClause
  );
}

export const L2_SYSLOG_CATEGORIES = [
  "DHCP",
  "DHCP_SNOOPING",
  "STP",
  "MSTP",
  "SPANTREE",
  "LACP",
  "ETH_PORT_CHANNEL",
  "EC",
  "ARP",
  "DAI",
  "SW_DAI",
  "LLDP",
] as const;

function shortenDeviceLabel(device: string): string {
  // Never truncate IPv4 or IPv6 addresses at `.` — only strip DNS domain suffixes.
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(device) || device.includes(":")) {
    return device;
  }
  return device.split(".")[0] || device;
}

/**
 * Builds a bounded, allowlisted SPL query for optional `cisco:dc:nexus9k:dme`
 * port-channel / STP / LLDP state objects.
 */
export function buildL2DmeSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    'sourcetype="cisco:dc:nexus9k:dme"',
    '(component="pc*" OR component="stp*" OR component="lldp*" OR dn="sys/intf/aggr-*" OR dn="sys/stp/*" OR dn="sys/lldp/*" OR port_channel=* OR stp_root=*)',
  ];
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(host="${dev}" OR device="${dev}")`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "l2_control",
    DME_L2_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval dn=coalesce(dn, 'Row_info.dn'), port_channel=coalesce(port_channel, 'Row_info.pcId', if(component=="pcAggrIf", 'Row_info.id', null())), member_interface=coalesce(member_interface, 'Row_info.tSKey', if(component=="pcRsMbrIfs", 'Row_info.tDn', null())), operSt=coalesce(operSt, 'Row_info.operSt'), oper_state=coalesce(oper_state, 'Row_info.operSt', 'Row_info.state'), lacp_state=coalesce(lacp_state, 'Row_info.mode', 'Row_info.lacpState'), stp_root=coalesce(stp_root, 'Row_info.desigRoot', 'Row_info.root'), port_state=coalesce(port_state, 'Row_info.state'), port_role=coalesce(port_role, 'Row_info.role'), vlan=coalesce(vlan, 'Row_info.vlan', 'Row_info.encap'), interface=coalesce(interface, 'Row_info.id', 'Row_info.portIdV'), descr=coalesce(descr, 'Row_info.descr', 'Row_info.operStQual', component) ` +
    tableClause
  );
}

/**
 * Builds a safe `literal()`-quoted Splunk Search URL for raw events of a selected L2 item.
 */
export function buildL2ControlRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly string[];
  device: string;
  subsystem: L2Subsystem;
  subject: string;
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
  const dev = literal(options.device, 128);
  const deviceClause =
    options.subsystem === "DHCP"
      ? `(host="${dev}" OR dest_ip="${dev}")`
      : `host="${dev}"`;
  const subjectTerm =
    options.subject &&
    options.subject !== "default" &&
    options.subject !== "switch"
      ? ` "${literal(options.subject, 128)}"`
      : "";
  const q = `search index=${index}${stClause ? ` ${stClause}` : ""} ${deviceClause}${subjectTerm}`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedL2ControlEvent {
  id: string;
  timestamp: number;
  sourcetype: string;
  sourceFamily: "stream" | "syslog" | "dme";
  subsystem: L2Subsystem;
  device: string;
  subject: string;
  anomaly: boolean;
  mnemonic: string;
  severity: number;
  summary: string;
  dhcpMessageType?: string;
  clientMac?: string;
  srcIp?: string;
  destIp?: string;
  yiaddr?: string;
  leaseTimeSec?: number;
  vlan?: string;
  vni?: string;
  portChannel?: string;
  memberInterface?: string;
  operState?: string;
  lacpState?: string;
  stpRoot?: string;
  portRole?: string;
  portState?: string;
}

export interface L2DhcpDetails {
  discovers: number;
  offers: number;
  requests: number;
  acks: number;
  naks: number;
  declines: number;
  clientMacs: string[];
  assignedIps: string[];
  leaseTimesSec: number[];
}

export interface L2ControlRow {
  /** URL-safe `ITEM_ID` matching `^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,191}$` (uses `__`, never `->`). */
  id: string;
  attention: boolean;
  subsystem: L2Subsystem;
  device: string;
  subject: string;
  sourcetypes: string[];
  eventCount: number;
  anomalyCount: number;
  status: ProtocolStatus;
  reasons: string[];
  recentMnemonics: string[];
  lastEventSummary: string;
  lastSeen?: number;
  firstSeen?: number;
  indexName: string;
  dhcpDetails?: L2DhcpDetails;
  portChannel?: string;
  memberInterfaces: string[];
  operState?: string;
  lacpState?: string;
  stpRoot?: string;
  portRole?: string;
  portState?: string;
}

export interface L2ControlInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: L2ControlRow[];
  timeline: ProtocolTimelineEvent[];
  timelineItemMap: Record<string, string>;
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "stream_only" | "syslog_only" | "dme_only" | "mixed" | "none";
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

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value.trim());
    if (Number.isFinite(n)) return n;
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

function sanitizeIdSegment(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._:/@-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "unknown";
}

export function buildL2RowId(
  subsystem: L2Subsystem,
  device: string,
  subject: string,
): string {
  const raw = `${subsystem}__${sanitizeIdSegment(device)}__${sanitizeIdSegment(subject)}`;
  return raw.slice(0, 192);
}

const DHCP_OPTION53_MAP: Record<string, string> = {
  "1": "DISCOVER",
  "2": "OFFER",
  "3": "REQUEST",
  "4": "DECLINE",
  "5": "ACK",
  "6": "NAK",
  "7": "RELEASE",
  "8": "INFORM",
};

export function normalizeDhcpMessageType(raw: unknown): string {
  const s = asString(raw).toUpperCase();
  if (!s) return "EVENT";
  if (DHCP_OPTION53_MAP[s]) return DHCP_OPTION53_MAP[s];
  if (s.includes("NAK") || s.includes("NACK")) return "NAK";
  if (s.includes("DECLINE")) return "DECLINE";
  if (s.includes("ACK")) return "ACK";
  if (s.includes("DISCOVER")) return "DISCOVER";
  if (s.includes("OFFER")) return "OFFER";
  if (s.includes("REQUEST")) return "REQUEST";
  if (s.includes("RELEASE")) return "RELEASE";
  if (s.includes("INFORM")) return "INFORM";
  return s;
}

function normalizeVlanLabel(rawVlan: string, rawVni?: string): string {
  if (rawVlan) {
    const digits = rawVlan.replace(/^vlan[-_]?/i, "");
    return /^\d+$/.test(digits) ? `vlan-${Number(digits)}` : rawVlan;
  }
  if (rawVni) return `vni-${rawVni}`;
  return "default";
}

function extractSubjectFromSyslog(
  summary: string,
  row: ProtocolRow,
): string | undefined {
  const direct =
    asString(row.port_channel) ||
    asString(row.interface) ||
    asString(row.member_interface);
  if (direct) return direct;
  const vlan = asString(row.vlan_id ?? row.vlan);
  if (vlan) return normalizeVlanLabel(vlan);
  const dn = asString(row.dn);
  if (dn) {
    const pathMatch = /\[([^\]]+)\]/.exec(dn);
    if (pathMatch) return pathMatch[1];
    const vlanMatch = /(vlan-?\d+)/i.exec(dn);
    if (vlanMatch) return vlanMatch[1].toLowerCase();
  }
  const msgMatch =
    /\b(port-channel\d+|Po\d+|Ethernet\d+\/\d+(?:\/\d+)?|Eth\d+\/\d+(?:\/\d+)?|Vlan\d+|VLAN\d+)\b/i.exec(
      summary,
    );
  if (msgMatch) return msgMatch[1];
  return undefined;
}

function classifyL2SyslogEvent(
  category: string,
  mnemonic: string,
  domain: string,
  summary: string,
  severity: number,
): { subsystem: L2Subsystem; anomaly: boolean } | undefined {
  const cat = category.toUpperCase();
  const mnem = mnemonic.toUpperCase();
  const upperMsg = summary.toUpperCase();

  let subsystem: L2Subsystem | undefined;
  if (
    cat === "DHCP" ||
    cat === "DHCP_SNOOPING" ||
    mnem.includes("DHCP_SNOOP") ||
    mnem.includes("DHCP")
  ) {
    subsystem = "DHCP";
  } else if (
    domain === "stp" ||
    cat === "STP" ||
    cat === "MSTP" ||
    cat === "SPANTREE" ||
    mnem.includes("STP") ||
    mnem.includes("ROOTGUARD") ||
    mnem.includes("LOOPGUARD") ||
    mnem.includes("BPDUGUARD") ||
    mnem.includes("TCN") ||
    mnem.includes("TOPOLOGY_CHANGE")
  ) {
    subsystem = "STP";
  } else if (
    domain === "port_channel" ||
    cat === "LACP" ||
    cat === "ETH_PORT_CHANNEL" ||
    cat === "EC" ||
    mnem.includes("LACP") ||
    mnem.includes("PORT_CHANNEL") ||
    mnem.includes("FOP_") ||
    mnem.includes("BUNDLE")
  ) {
    subsystem = "LACP";
  } else if (
    cat === "ARP" ||
    cat === "DAI" ||
    cat === "SW_DAI" ||
    mnem.includes("ARP") ||
    mnem.includes("DUP_V4_ADDR") ||
    mnem.includes("DUP_ADDR") ||
    mnem.includes("DUPLICATE_IP") ||
    mnem.includes("DAI_")
  ) {
    subsystem = "ARP";
  } else if (cat === "LLDP" || mnem.includes("LLDP")) {
    subsystem = "LLDP";
  }

  if (!subsystem) return undefined;

  if (subsystem === "DHCP") {
    const isErr =
      severity <= 4 ||
      /(NAK|DENY|DROP|UNTRUSTED|VIOLATION|RATE_LIMIT|LIMIT|ERR|FAIL|SPOOF|EXHAUST)/.test(
        mnem,
      ) ||
      /(DROPPED|UNTRUSTED|RATE LIMIT|NAK)/.test(upperMsg);
    return { subsystem, anomaly: isErr };
  }

  if (subsystem === "STP") {
    const isRecoveryOnly =
      /(UNBLOCK|ROOT_OK|CLEARED|RESTORED)/.test(mnem) && severity >= 5;
    const isChange =
      !isRecoveryOnly &&
      (severity <= 4 ||
        /(TCN|TOPOLOGY|TOPO_CHANGE|ROOTGUARD|ROOT_GUARD|LOOPGUARD|LOOP_GUARD|BPDUGUARD|BPDU_GUARD|BPDU_FILTER|DISPUTE|INCONSIST|BLOCK|ERR_DISABLE|NEW_ROOT|ROOT_CHANGE|PORT_STATE)/.test(
          mnem,
        ) ||
        /(TOPOLOGY CHANGE|TCN|ROOT GUARD|INCONSISTENT|DISPUTE)/.test(upperMsg));
    return { subsystem, anomaly: isChange };
  }

  if (subsystem === "LACP") {
    const isHealthyUp =
      /(PORT_CHANNEL_UP|PORT_UP|BUNDLE_UP|ADDED|OPER_UP|LINK_UP)/.test(mnem) &&
      severity >= 5;
    const isDrop =
      !isHealthyUp &&
      (severity <= 4 ||
        /(SUSPEND|DOWN|DROP|REMOVE|DETACH|MISMATCH|TIMEOUT|EXPIRE|ERR_DISABLE|FAIL|PARTNER_TIMEOUT|NO_PARTNER|HOT_STANDBY)/.test(
          mnem,
        ) ||
        /(SUSPENDED|DOWN|TIMEOUT|DETACHED|REMOVED)/.test(upperMsg));
    return { subsystem, anomaly: isDrop };
  }

  if (subsystem === "ARP") {
    const isDupOrDrop =
      severity <= 4 ||
      /(DUP|CONFLICT|ERR|DISABLE|DROP|VIOLATION|DENY|POISON|INVALID)/.test(
        mnem,
      ) ||
      /(DUPLICATE|CONFLICT|DROPPED)/.test(upperMsg);
    return { subsystem, anomaly: isDupOrDrop };
  }

  // LLDP
  const isLldpIssue =
    severity <= 4 ||
    /(TIMEOUT|EXPIRE|DELETE|REMOVE|DOWN|MISMATCH|DUP|FAIL|CONFLICT)/.test(mnem);
  return { subsystem, anomaly: isLldpIssue };
}

/**
 * Normalizes one row from `stream:dhcp`, `stream:arp`, NX-OS/ACI syslog (`cisco:ios`,
 * `cisco:dc:nexus9k:syslog`, `cisco:aci`, `cisco:dc:aci:syslog`), or `cisco:dc:nexus9k:dme`.
 */
export function normalizeL2ControlRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedL2ControlEvent | undefined {
  const sourcetype = asString(row.sourcetype).toLowerCase();
  const timestamp = asEpochSeconds(row._time);
  if (!timestamp) return undefined;

  if (sourcetype === "stream:dhcp") {
    const msgType = normalizeDhcpMessageType(
      row.dhcp_message_type ?? row.message_type ?? row.option_53 ?? row.opcode,
    );
    const clientMac =
      asString(row.client_mac ?? row.chaddr ?? row.src_mac) || undefined;
    const srcIp = asString(row.src_ip) || undefined;
    const destIp = asString(row.dest_ip) || undefined;
    const yiaddr = asString(row.yiaddr) || undefined;
    const leaseTimeSec = asFiniteNumber(row.lease_time ?? row.ip_lease_time);
    const vlan = asString(row.vlan_id ?? row.vlan) || undefined;
    const vni = asString(row.vni ?? row.vxlan_id) || undefined;
    const host = asString(row.host) || "dhcp-sensor";
    const serverCandidate =
      destIp && destIp !== "0.0.0.0" && destIp !== "255.255.255.255"
        ? destIp
        : srcIp && srcIp !== "0.0.0.0" && msgType === "NAK"
          ? srcIp
          : host;
    const subject = normalizeVlanLabel(vlan ?? "", vni);
    const anomaly = msgType === "NAK" || msgType === "DECLINE";
    const summaryParts = [`DHCP ${msgType}`];
    if (clientMac) summaryParts.push(`client ${clientMac}`);
    if (yiaddr && yiaddr !== "0.0.0.0") summaryParts.push(`ip ${yiaddr}`);
    if (leaseTimeSec !== undefined && leaseTimeSec > 0) {
      summaryParts.push(`lease ${Math.round(leaseTimeSec)}s`);
    }

    return {
      id: `dhcp:${serverCandidate}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "stream:dhcp",
      sourceFamily: "stream",
      subsystem: "DHCP",
      device: serverCandidate,
      subject,
      anomaly,
      mnemonic: `DHCP_${msgType}`,
      severity: anomaly ? 3 : 6,
      summary: summaryParts.join(" · "),
      dhcpMessageType: msgType,
      ...(clientMac ? { clientMac } : {}),
      ...(srcIp ? { srcIp } : {}),
      ...(destIp ? { destIp } : {}),
      ...(yiaddr && yiaddr !== "0.0.0.0" ? { yiaddr } : {}),
      ...(leaseTimeSec !== undefined && leaseTimeSec >= 0
        ? { leaseTimeSec }
        : {}),
      ...(vlan ? { vlan } : {}),
      ...(vni ? { vni } : {}),
    };
  }

  if (sourcetype === "stream:arp") {
    const rawOp = asString(
      row.message_type ?? row.opcode ?? row.dhcp_message_type,
    );
    const opLabel =
      rawOp === "1" || rawOp.toUpperCase() === "REQUEST"
        ? "ARP_REQUEST"
        : rawOp === "2" ||
            rawOp.toUpperCase() === "RESPONSE" ||
            rawOp.toUpperCase() === "REPLY"
          ? "ARP_REPLY"
          : "ARP_EVENT";
    const srcIp = asString(row.src_ip) || undefined;
    const destIp = asString(row.dest_ip) || undefined;
    const clientMac =
      asString(row.client_mac ?? row.arp_src_mac ?? row.src_mac) || undefined;
    const vlan = asString(row.vlan_id ?? row.vlan) || undefined;
    const vni = asString(row.vni ?? row.vxlan_id) || undefined;
    const device = asString(row.host) || srcIp || "arp-sensor";
    const subject = normalizeVlanLabel(vlan ?? "", vni);
    return {
      id: `arp:${device}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "stream:arp",
      sourceFamily: "stream",
      subsystem: "ARP",
      device,
      subject,
      anomaly: false,
      mnemonic: opLabel,
      severity: 6,
      summary: `${opLabel.replace("_", " ")} ${srcIp ?? "?"} (${clientMac ?? "?"}) → ${destIp ?? "?"}`,
      ...(clientMac ? { clientMac } : {}),
      ...(srcIp ? { srcIp } : {}),
      ...(destIp ? { destIp } : {}),
      ...(vlan ? { vlan } : {}),
      ...(vni ? { vni } : {}),
    };
  }

  if (sourcetype === "cisco:dc:nexus9k:dme") {
    const host = asString(row.host) || "nxos-switch";
    const dn = asString(row.dn);
    const descr = asString(row.descr);
    const portChannel = asString(row.port_channel) || undefined;
    const memberInterface = asString(row.member_interface) || undefined;
    const iface = asString(row.interface) || undefined;
    const operState = asString(row.operSt ?? row.oper_state) || undefined;
    const lacpState = asString(row.lacp_state) || undefined;
    const stpRoot = asString(row.stp_root ?? row.root_bridge) || undefined;
    const portState = asString(row.port_state) || undefined;
    const portRole = asString(row.port_role) || undefined;
    const vlan = asString(row.vlan) || undefined;

    const hint = `${dn} ${descr}`.toLowerCase();
    let subsystem: L2Subsystem | undefined;
    if (
      portChannel ||
      memberInterface ||
      lacpState ||
      hint.includes("pcaggr") ||
      hint.includes("pcrsmbr") ||
      hint.includes("/pc-") ||
      hint.includes("aggr-")
    ) {
      subsystem = "LACP";
    } else if (stpRoot || portRole || portState || hint.includes("stp")) {
      subsystem = "STP";
    } else if (hint.includes("lldp")) {
      subsystem = "LLDP";
    }
    if (!subsystem) return undefined;

    const subject =
      portChannel ||
      memberInterface ||
      iface ||
      (vlan ? normalizeVlanLabel(vlan) : undefined) ||
      dn ||
      "switch";

    const stateCheck =
      `${operState ?? ""} ${lacpState ?? ""} ${portState ?? ""}`
        .trim()
        .toLowerCase();
    const anomaly =
      /(down|suspend|err-disable|broken|inconsistent|root-inconsistent|loop-inconsistent|bpdu-guard|expired|individual|timeout|unbundled)/.test(
        stateCheck,
      );
    const mnemonic =
      subsystem === "LACP"
        ? anomaly
          ? "DME_LACP_DEGRADED"
          : "DME_LACP_UP"
        : subsystem === "STP"
          ? anomaly
            ? "DME_STP_ANOMALY"
            : "DME_STP_STEADY"
          : anomaly
            ? "DME_LLDP_DOWN"
            : "DME_LLDP_UP";

    const summary = [
      descr || `DME ${subsystem}`,
      portChannel,
      memberInterface,
      operState ? `operSt=${operState}` : undefined,
      lacpState ? `lacp=${lacpState}` : undefined,
      stpRoot ? `root=${stpRoot}` : undefined,
    ]
      .filter(Boolean)
      .join(" · ");

    return {
      id: `dme:${host}:${timestamp}:${indexInBatch}`,
      timestamp,
      sourcetype: "cisco:dc:nexus9k:dme",
      sourceFamily: "dme",
      subsystem,
      device: host,
      subject,
      anomaly,
      mnemonic,
      severity: anomaly ? 3 : 6,
      summary: summary || `${subsystem} state on ${subject}`,
      ...(vlan ? { vlan } : {}),
      ...(portChannel ? { portChannel } : {}),
      ...(memberInterface ? { memberInterface } : {}),
      ...(operState ? { operState } : {}),
      ...(lacpState ? { lacpState } : {}),
      ...(stpRoot ? { stpRoot } : {}),
      ...(portRole ? { portRole } : {}),
      ...(portState ? { portState } : {}),
    };
  }

  // Otherwise delegate syslog normalization to shared nxosSyslog.ts
  const syslogEv = normalizeSyslogRow(row, indexInBatch);
  if (!syslogEv) return undefined;

  const classified = classifyL2SyslogEvent(
    syslogEv.category,
    syslogEv.mnemonic,
    syslogEv.domain,
    syslogEv.summary,
    syslogEv.severity,
  );
  if (!classified) return undefined;

  const subject = extractSubjectFromSyslog(syslogEv.summary, row) ?? "switch";
  const vlan = asString(row.vlan_id ?? row.vlan) || undefined;
  const portChannel =
    asString(row.port_channel) ||
    (/^(?:po|port-channel)/i.test(subject) ? subject : undefined);
  const memberInterface = asString(row.member_interface) || undefined;
  const stpRoot = asString(row.stp_root ?? row.root_bridge) || undefined;

  return {
    id: syslogEv.id,
    timestamp: syslogEv.timestamp,
    sourcetype: sourcetype || syslogEv.sourceKind,
    sourceFamily: "syslog",
    subsystem: classified.subsystem,
    device: syslogEv.host,
    subject,
    anomaly: classified.anomaly,
    mnemonic: syslogEv.mnemonic,
    severity: syslogEv.severity,
    summary: syslogEv.summary,
    ...(vlan ? { vlan } : {}),
    ...(portChannel ? { portChannel } : {}),
    ...(memberInterface ? { memberInterface } : {}),
    ...(stpRoot ? { stpRoot } : {}),
  };
}

function buildSparklineBuckets(
  events: readonly NormalizedL2ControlEvent[],
  earliest: number,
  latest: number,
  predicate: (ev: NormalizedL2ControlEvent) => boolean,
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
 * Pure aggregation of normalized L2 control events (`stream:dhcp`, `stream:arp`,
 * NX-OS/ACI syslog, and optional DME) into rows, KPIs, SwimlaneTimeline,
 * Device × Subsystem HeatMatrix, and a single-sentence verdict.
 */
export function buildL2ControlAnalysis(options: {
  events: readonly { event: NormalizedL2ControlEvent; indexName: string }[];
  thresholds: ResolvedL2ControlThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  activeSourceKinds?: readonly L2ControlSourceKind[];
  streamReadiness?: StreamReadinessEntry;
}): L2ControlInvestigationResult {
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

  // Detect duplicate IP->MAC ARP conflicts across stream:arp events in the same window.
  const arpIpMacs = new Map<string, Set<string>>();
  for (const entry of rawEvents) {
    const ev = entry.event;
    if (
      ev.sourcetype === "stream:arp" &&
      ev.srcIp &&
      ev.clientMac &&
      ev.clientMac !== "00:00:00:00:00:00" &&
      ev.clientMac.toLowerCase() !== "ff:ff:ff:ff:ff:ff"
    ) {
      const key = `${ev.subject}__${ev.srcIp}`;
      const set = arpIpMacs.get(key) ?? new Set<string>();
      set.add(ev.clientMac.toLowerCase());
      arpIpMacs.set(key, set);
    }
  }
  const duplicateArpIps = new Set<string>();
  for (const [key, macs] of arpIpMacs.entries()) {
    if (macs.size > 1) duplicateArpIps.add(key);
  }

  const events = rawEvents.map((entry) => {
    const ev = entry.event;
    if (
      ev.sourcetype === "stream:arp" &&
      ev.srcIp &&
      duplicateArpIps.has(`${ev.subject}__${ev.srcIp}`)
    ) {
      return {
        ...entry,
        event: {
          ...ev,
          anomaly: true,
          mnemonic: "ARP_DUPLICATE_MAC",
          severity: 3,
          summary: `Duplicate ARP MACs observed for ${ev.srcIp} (${ev.clientMac ?? "?"})`,
        },
      };
    }
    return entry;
  });

  if (!events.length) {
    if (streamReadiness?.state === "estimate_only") {
      return {
        verdict:
          "Stream dhcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        kpis: [],
        rows: [],
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [...L2_SUBSYSTEMS],
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
        matrixCols: [...L2_SUBSYSTEMS],
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
        matrixCols: [...L2_SUBSYSTEMS],
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
          "Search hit row cap before matching L2 control events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        timeline: [],
        timelineItemMap: {},
        matrixRows: [],
        matrixCols: [...L2_SUBSYSTEMS],
        matrixCells: [],
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching L2 control events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict: "No L2 control events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      timeline: [],
      timelineItemMap: {},
      matrixRows: [],
      matrixCols: [...L2_SUBSYSTEMS],
      matrixCells: [],
      outcomes,
      capped,
      sourceMode: "none",
      streamReadiness,
      bannerState: "empty",
      bannerReason:
        streamReadiness?.state === "enabled"
          ? "Stream dhcp is Enabled (statsOnly=false), but no matching L2 control events were observed in this UTC window."
          : "No matching L2 control events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const hasStreamEv = events.some((e) => e.event.sourceFamily === "stream");
  const hasSyslogEv = events.some((e) => e.event.sourceFamily === "syslog");
  const hasDmeEv = events.some((e) => e.event.sourceFamily === "dme");
  const familyCount = [hasStreamEv, hasSyslogEv, hasDmeEv].filter(
    Boolean,
  ).length;
  const sourceMode: L2ControlInvestigationResult["sourceMode"] =
    familyCount > 1
      ? "mixed"
      : hasStreamEv
        ? "stream_only"
        : hasSyslogEv
          ? "syslog_only"
          : "dme_only";

  const inferredKinds: readonly L2ControlSourceKind[] =
    activeSourceKinds?.length
      ? activeSourceKinds
      : sourceMode === "stream_only"
        ? ["stream_dhcp"]
        : sourceMode === "dme_only"
          ? ["dme"]
          : sourceMode === "syslog_only"
            ? ["syslog"]
            : ["auto"];

  const hasStreamSource =
    inferredKinds.includes("stream_dhcp") || inferredKinds.includes("auto");
  const hasSyslogSource =
    inferredKinds.includes("syslog") || inferredKinds.includes("auto");
  const hasDmeSource =
    inferredKinds.includes("dme") || inferredKinds.includes("auto");

  const dhcpCovered =
    hasStreamSource ||
    hasSyslogSource ||
    events.some((e) => e.event.subsystem === "DHCP");
  const stpCovered =
    hasSyslogSource ||
    hasDmeSource ||
    events.some((e) => e.event.subsystem === "STP");
  const lacpCovered =
    hasSyslogSource ||
    hasDmeSource ||
    events.some((e) => e.event.subsystem === "LACP");
  const arpLldpCovered =
    hasSyslogSource ||
    hasDmeSource ||
    inferredKinds.includes("auto") ||
    events.some(
      (e) => e.event.subsystem === "ARP" || e.event.subsystem === "LLDP",
    );

  const grouped = new Map<
    string,
    {
      subsystem: L2Subsystem;
      device: string;
      subject: string;
      events: NormalizedL2ControlEvent[];
      indexName: string;
    }
  >();

  for (const entry of events) {
    const id = buildL2RowId(
      entry.event.subsystem,
      entry.event.device,
      entry.event.subject,
    );
    const existing = grouped.get(id);
    if (existing) {
      existing.events.push(entry.event);
    } else {
      grouped.set(id, {
        subsystem: entry.event.subsystem,
        device: entry.event.device,
        subject: entry.event.subject,
        events: [entry.event],
        indexName: entry.indexName,
      });
    }
  }

  const rows: L2ControlRow[] = [];
  for (const [id, group] of grouped.entries()) {
    const sortedEvents = [...group.events].sort(
      (a, b) => b.timestamp - a.timestamp,
    );
    const sourcetypes = [...new Set(sortedEvents.map((e) => e.sourcetype))];
    const anomalyEvents = sortedEvents.filter((e) => e.anomaly);
    const anomalyCount = anomalyEvents.length;
    const timestamps = sortedEvents.map((e) => e.timestamp);

    let dhcpDetails: L2DhcpDetails | undefined;
    if (group.subsystem === "DHCP") {
      const discovers = sortedEvents.filter(
        (e) => e.dhcpMessageType === "DISCOVER",
      ).length;
      const offers = sortedEvents.filter(
        (e) => e.dhcpMessageType === "OFFER",
      ).length;
      const requests = sortedEvents.filter(
        (e) => e.dhcpMessageType === "REQUEST",
      ).length;
      const acks = sortedEvents.filter(
        (e) => e.dhcpMessageType === "ACK",
      ).length;
      const naks = sortedEvents.filter(
        (e) => e.dhcpMessageType === "NAK",
      ).length;
      const declines = sortedEvents.filter(
        (e) => e.dhcpMessageType === "DECLINE",
      ).length;
      const clientMacs = [
        ...new Set(
          sortedEvents
            .map((e) => e.clientMac)
            .filter((m): m is string => Boolean(m)),
        ),
      ];
      const assignedIps = [
        ...new Set(
          sortedEvents
            .map((e) => e.yiaddr)
            .filter((ip): ip is string => Boolean(ip)),
        ),
      ];
      const leaseTimesSec = [
        ...new Set(
          sortedEvents
            .map((e) => e.leaseTimeSec)
            .filter((l): l is number => l !== undefined && l > 0),
        ),
      ];
      if (
        discovers + offers + requests + acks + naks + declines > 0 ||
        clientMacs.length > 0 ||
        assignedIps.length > 0
      ) {
        dhcpDetails = {
          discovers,
          offers,
          requests,
          acks,
          naks,
          declines,
          clientMacs,
          assignedIps,
          leaseTimesSec,
        };
      }
    }

    const reasons: string[] = [];
    if (group.subsystem === "DHCP") {
      const nakCount = dhcpDetails?.naks ?? 0;
      const declineCount = dhcpDetails?.declines ?? 0;
      const snoopAnomalies = sortedEvents.filter(
        (e) => e.sourceFamily === "syslog" && e.anomaly,
      ).length;
      if (nakCount >= thresholds.dhcpNakWarnCount) {
        reasons.push(
          `${nakCount} DHCP ${nakCount === 1 ? "NAK" : "NAKs"} (≥ ${thresholds.dhcpNakWarnCount})`,
        );
      }
      if (declineCount > 0) {
        reasons.push(
          `${declineCount} DHCP ${declineCount === 1 ? "Decline" : "Declines"}`,
        );
      }
      if (snoopAnomalies > 0) {
        reasons.push(
          `${snoopAnomalies} DHCP snooping ${snoopAnomalies === 1 ? "alert" : "alerts"}`,
        );
      }
    } else if (group.subsystem === "STP") {
      if (anomalyCount >= thresholds.stpTcnWarnCount) {
        reasons.push(
          `${anomalyCount} STP ${anomalyCount === 1 ? "change" : "changes"} (≥ ${thresholds.stpTcnWarnCount})`,
        );
      }
    } else if (group.subsystem === "LACP") {
      if (anomalyCount >= thresholds.lacpDropWarnCount) {
        reasons.push(
          `${anomalyCount} LACP ${anomalyCount === 1 ? "drop" : "drops"} (≥ ${thresholds.lacpDropWarnCount})`,
        );
      }
    } else if (group.subsystem === "ARP") {
      if (anomalyCount > 0) {
        reasons.push(
          `${anomalyCount} duplicate ARP / DAI ${anomalyCount === 1 ? "alert" : "alerts"}`,
        );
      }
    } else if (group.subsystem === "LLDP") {
      if (anomalyCount > 0) {
        reasons.push(
          `${anomalyCount} LLDP neighbor ${anomalyCount === 1 ? "drop" : "drops"}`,
        );
      }
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention ? "attention" : "ok";
    const recentMnemonics = [
      ...new Set(sortedEvents.map((e) => e.mnemonic)),
    ].slice(0, 6);
    const memberInterfaces = [
      ...new Set(
        sortedEvents
          .map((e) => e.memberInterface)
          .filter((m): m is string => Boolean(m)),
      ),
    ];
    const rep = anomalyEvents[0] ?? sortedEvents[0];

    rows.push({
      id,
      attention,
      subsystem: group.subsystem,
      device: group.device,
      subject: group.subject,
      sourcetypes,
      eventCount: sortedEvents.length,
      anomalyCount,
      status,
      reasons,
      recentMnemonics,
      lastEventSummary: rep.summary,
      firstSeen: Math.min(...timestamps),
      lastSeen: Math.max(...timestamps),
      indexName: group.indexName,
      ...(dhcpDetails ? { dhcpDetails } : {}),
      ...(rep.portChannel ? { portChannel: rep.portChannel } : {}),
      memberInterfaces,
      ...(rep.operState ? { operState: rep.operState } : {}),
      ...(rep.lacpState ? { lacpState: rep.lacpState } : {}),
      ...(rep.stpRoot ? { stpRoot: rep.stpRoot } : {}),
      ...(rep.portRole ? { portRole: rep.portRole } : {}),
      ...(rep.portState ? { portState: rep.portState } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.anomalyCount !== b.anomalyCount)
      return b.anomalyCount - a.anomalyCount;
    if ((b.lastSeen ?? 0) !== (a.lastSeen ?? 0)) {
      return (b.lastSeen ?? 0) - (a.lastSeen ?? 0);
    }
    return b.eventCount - a.eventCount;
  });

  // KPI metrics (<= 4 tiles, one metric per tile, readable units)
  const allNormalized = events.map((e) => e.event);
  const dhcpNaks = allNormalized.filter(
    (e) => e.subsystem === "DHCP" && e.anomaly,
  ).length;
  const stpChanges = allNormalized.filter(
    (e) => e.subsystem === "STP" && e.anomaly,
  ).length;
  const lacpDrops = allNormalized.filter(
    (e) => e.subsystem === "LACP" && e.anomaly,
  ).length;
  const arpL2Alerts = allNormalized.filter(
    (e) => (e.subsystem === "ARP" || e.subsystem === "LLDP") && e.anomaly,
  ).length;

  const dhcpSpark = buildSparklineBuckets(
    allNormalized,
    earliest,
    latest,
    (e) => e.subsystem === "DHCP" && e.anomaly,
  );
  const stpSpark = buildSparklineBuckets(
    allNormalized,
    earliest,
    latest,
    (e) => e.subsystem === "STP" && e.anomaly,
  );
  const lacpSpark = buildSparklineBuckets(
    allNormalized,
    earliest,
    latest,
    (e) => e.subsystem === "LACP" && e.anomaly,
  );
  const arpSpark = buildSparklineBuckets(
    allNormalized,
    earliest,
    latest,
    (e) => (e.subsystem === "ARP" || e.subsystem === "LLDP") && e.anomaly,
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "dhcp-naks",
      label: "DHCP NAKs",
      value: dhcpCovered ? formatCount(dhcpNaks) : "Not covered",
      ...(dhcpCovered ? { unit: dhcpNaks === 1 ? "NAK" : "NAKs" } : {}),
      status: !dhcpCovered
        ? "not_covered"
        : dhcpNaks >= thresholds.dhcpNakWarnCount
          ? "attention"
          : "ok",
      ...(dhcpCovered && dhcpSpark.length ? { sparkline: dhcpSpark } : {}),
    },
    {
      id: "stp-changes",
      label: "STP Changes",
      value: stpCovered ? formatCount(stpChanges) : "Not covered",
      ...(stpCovered ? { unit: stpChanges === 1 ? "event" : "events" } : {}),
      status: !stpCovered
        ? "not_covered"
        : stpChanges >= thresholds.stpTcnWarnCount
          ? "attention"
          : "ok",
      ...(stpCovered && stpSpark.length ? { sparkline: stpSpark } : {}),
    },
    {
      id: "lacp-drops",
      label: "LACP Drops",
      value: lacpCovered ? formatCount(lacpDrops) : "Not covered",
      ...(lacpCovered ? { unit: lacpDrops === 1 ? "drop" : "drops" } : {}),
      status: !lacpCovered
        ? "not_covered"
        : lacpDrops >= thresholds.lacpDropWarnCount
          ? "attention"
          : "ok",
      ...(lacpCovered && lacpSpark.length ? { sparkline: lacpSpark } : {}),
    },
    {
      id: "arp-l2-alerts",
      label: "ARP / L2 Alerts",
      value: arpLldpCovered ? formatCount(arpL2Alerts) : "Not covered",
      ...(arpLldpCovered
        ? { unit: arpL2Alerts === 1 ? "alert" : "alerts" }
        : {}),
      status: !arpLldpCovered
        ? "not_covered"
        : arpL2Alerts > 0
          ? "attention"
          : "ok",
      ...(arpLldpCovered && arpSpark.length ? { sparkline: arpSpark } : {}),
    },
  ];

  // Swimlane timeline (events by subsystem / device, prioritizing attention lanes)
  const timelineItemMap: Record<string, string> = {};
  const prioritizedLanes = rows
    .slice(0, 8)
    .map((r) => `${r.subsystem} · ${r.device}`);
  const allowedLaneSet = new Set(prioritizedLanes);
  const timeline: ProtocolTimelineEvent[] = [...allNormalized]
    .filter((ev) => allowedLaneSet.has(`${ev.subsystem} · ${ev.device}`))
    .sort((a, b) => a.timestamp - b.timestamp)
    .slice(0, 64)
    .map((ev) => {
      const rowId = buildL2RowId(ev.subsystem, ev.device, ev.subject);
      timelineItemMap[ev.id] = rowId;
      return {
        id: ev.id,
        lane: `${ev.subsystem} · ${shortenDeviceLabel(ev.device)}`,
        timestamp: ev.timestamp,
        kind: ev.anomaly ? "attention" : "ok",
        label: `${ev.mnemonic} (${ev.subject})`,
        detail: ev.summary,
      };
    });

  // Device × Subsystem HeatMatrix (flagged devices sorted first)
  const flaggedL2Devices = new Set(
    rows.filter((r) => r.attention).map((r) => r.device),
  );
  const matrixRows = [...new Set(rows.map((r) => r.device))].sort((a, b) => {
    const aFlag = flaggedL2Devices.has(a);
    const bFlag = flaggedL2Devices.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    return a.localeCompare(b);
  });
  const matrixCols = [...L2_SUBSYSTEMS];
  const matrixCells: ProtocolMatrixCell[] = [];
  const subsystemCoverage: Record<L2Subsystem, boolean> = {
    DHCP: dhcpCovered,
    STP: stpCovered,
    LACP: lacpCovered,
    ARP: arpLldpCovered,
    LLDP: arpLldpCovered,
  };

  for (const device of matrixRows) {
    for (const subsystem of L2_SUBSYSTEMS) {
      const matching = rows.filter(
        (r) => r.device === device && r.subsystem === subsystem,
      );
      if (matching.length > 0) {
        const totalEvents = matching.reduce((s, r) => s + r.eventCount, 0);
        const totalAnomalies = matching.reduce((s, r) => s + r.anomalyCount, 0);
        const lead = matching[0];
        const anyAttn = matching.some((r) => r.attention);
        matrixCells.push({
          row: device,
          col: subsystem,
          status: anyAttn ? "attention" : "ok",
          value: anyAttn
            ? `${totalAnomalies} ${totalAnomalies === 1 ? "alert" : "alerts"}`
            : `${totalEvents} ok`,
          count: totalEvents,
          detail: anyAttn
            ? lead.reasons.join("; ") || lead.lastEventSummary
            : `${totalEvents} clean ${subsystem} events`,
          itemId: lead.id,
        });
      } else if (!subsystemCoverage[subsystem]) {
        matrixCells.push({
          row: device,
          col: subsystem,
          status: "not_covered",
          value: "Not covered",
          detail: `${subsystem} is not collected by the active source profile.`,
        });
      }
    }
  }

  // Plain-language single-sentence verdict above the fold
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadDetail = lead.reasons[0] ?? lead.lastEventSummary;
    verdict = `${flaggedRows.length} of ${rows.length} L2 ${rows.length === 1 ? "entity needs" : "entities need"} attention: ${leadDetail} on ${lead.device} (${lead.subject}).`;
    verdictStatus = "attention";
  } else {
    const checked: string[] = [];
    const missing: string[] = [];
    if (subsystemCoverage.DHCP) checked.push("DHCP NAKs");
    else missing.push("DHCP");
    if (subsystemCoverage.STP) checked.push("STP TCNs");
    else missing.push("STP");
    if (subsystemCoverage.LACP) checked.push("LACP drops");
    else missing.push("LACP");
    if (subsystemCoverage.ARP || subsystemCoverage.LLDP) {
      checked.push("ARP/LLDP alerts");
    } else {
      missing.push("ARP/LLDP");
    }
    const scopePrefix = capped
      ? `First ${rows.length} L2 ${rows.length === 1 ? "entity" : "entities"} (capped)`
      : `${rows.length} of ${rows.length} L2 ${rows.length === 1 ? "entity" : "entities"}`;
    const checkedNote = checked.length ? ` with no ${checked.join(", ")}` : "";
    const missingNote = missing.length
      ? ` — ${missing.join(", ")} not covered`
      : "";
    verdict = `${scopePrefix} steady${checkedNote}${missingNote}.`;
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

  const bannerState: L2ControlInvestigationResult["bannerState"] = anyPartial
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

export interface InvestigateL2ControlOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand L2 control plane investigation across configured
 * `l2_control` profiles (`stream:dhcp`/`stream:arp`, NX-OS/ACI syslog via
 * `nxosSyslog.ts`, and optional `cisco:dc:nexus9k:dme`), rechecking the
 * `adm_protocol_profiles` fingerprint before surfacing results.
 */
export async function investigateL2Control(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateL2ControlOptions = {},
): Promise<L2ControlInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "l2_control" && p.scope === request.scope,
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
      matrixCols: [...L2_SUBSYSTEMS],
      matrixCells: [],
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No l2_control profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedL2ControlEvent; indexName: string }[] =
      [];
    const activeKinds: L2ControlSourceKind[] = [];
    const streamProfiles: BaseProtocolProfile[] = [];
    let capped = false;
    const chosenThresholds = resolveL2ControlThresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const thresholds = resolveL2ControlThresholds(profile);
      activeKinds.push(thresholds.sourceKind);

      const runStream =
        thresholds.sourceKind === "stream_dhcp" ||
        thresholds.sourceKind === "auto";
      const runSyslog =
        (thresholds.sourceKind === "syslog" ||
          thresholds.sourceKind === "auto") &&
        !request.filter?.vni;
      const runDme =
        (thresholds.sourceKind === "dme" || thresholds.sourceKind === "auto") &&
        !request.filter?.vni;

      if (runStream) {
        streamProfiles.push(profile);
        const spl = buildL2StreamSearch({
          index: profile.index,
          includeArp: thresholds.sourceKind === "auto",
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "l2_control",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: "stream",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        res.rows.forEach((row, idx) => {
          const norm = normalizeL2ControlRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runSyslog) {
        signal.throwIfAborted();
        const spl = buildSyslogStateSearch({
          index: profile.index,
          device: request.filter?.device,
          categories: L2_SYSLOG_CATEGORIES,
          includeAci: true,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "l2_control",
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
          const norm = normalizeL2ControlRow(row, idx);
          if (!norm) return;
          if (
            request.filter?.src &&
            norm.subject !== request.filter.src &&
            norm.device !== request.filter.src &&
            !norm.summary.includes(request.filter.src)
          ) {
            return;
          }
          if (
            request.filter?.dst &&
            norm.subject !== request.filter.dst &&
            norm.device !== request.filter.dst &&
            !norm.summary.includes(request.filter.dst)
          ) {
            return;
          }
          collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runDme) {
        signal.throwIfAborted();
        const spl = buildL2DmeSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "l2_control",
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
          const norm = normalizeL2ControlRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }
    }

    // Check Stream Estimate mode ONLY when stream:dhcp completed with 0 rows
    // and an explicit investigation was requested.
    let streamReadiness: StreamReadinessEntry | undefined;
    const dhcpCompletedEmpty =
      streamProfiles.length > 0 &&
      collected.every((c) => c.event.sourcetype !== "stream:dhcp") &&
      outcomes.some(
        (o) =>
          streamProfiles.some((sp) => sp.id === o.profile) &&
          o.state === "complete",
      );

    if (dhcpCompletedEmpty && !options.skipEstimateCheck) {
      const entries = await checkStreamEstimateMode(
        client,
        ["dhcp", "arp"],
        signal,
      );
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

    return buildL2ControlAnalysis({
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
    l2_control: validateL2ControlExtra,
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
        matrixCols: [...L2_SUBSYSTEMS],
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
 * Hub "Check all" summary runner for `l2_control`.
 */
export async function summarizeL2Control(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateL2ControlOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateL2Control(
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
    lens: "l2_control",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
