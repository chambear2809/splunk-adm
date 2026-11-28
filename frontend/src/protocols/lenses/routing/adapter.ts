import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  buildSyslogStateSearch,
  normalizeSyslogRow,
  type NormalizedStateEvent,
} from "../../shared/adapters/nxosSyslog";
import type {
  BaseProtocolProfile,
  LensProfileValidator,
  ProtocolAdjacencyEdge,
  ProtocolAdjacencyNode,
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
  buildDmeDispatchBounds,
  buildDmeSnapshotWindowPredicate,
  dmePreDedupLimit,
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  selectActiveProfiles,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  DEFAULT_ROUTING_THRESHOLDS,
  validateRoutingExtra,
  type ResolvedRoutingThresholds,
  type RoutingExtraConfig,
  type RoutingProtocolFilter,
  type RoutingSourceKind,
} from "./validate";

export {
  DEFAULT_ROUTING_THRESHOLDS,
  validateRoutingExtra,
  type ResolvedRoutingThresholds,
  type RoutingExtraConfig,
  type RoutingProtocolFilter,
  type RoutingSourceKind,
};

export type RoutingProtocol = "BGP" | "OSPF" | "BFD" | "ISIS" | "HSRP" | "VRRP";

export const ROUTING_DME_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "dn",
  "vrf",
  "vrf_name",
  "peer_ip",
  "neighbor_ip",
  "peer_asn",
  "local_asn",
  "state",
  "oper_state",
  "operSt",
  "peer_state",
  "prefixes_received",
  "flap_count",
  "uptime",
  "protocol",
  "area",
  "interface",
  "descr",
] as const;

export function resolveRoutingThresholds(
  profile?: BaseProtocolProfile,
): ResolvedRoutingThresholds {
  const extra = profile?.extra as RoutingExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "syslog" ||
      extra?.sourceKind === "dme" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_ROUTING_THRESHOLDS.sourceKind,
    flapWarnCount:
      typeof extra?.flapWarnCount === "number" &&
      Number.isInteger(extra.flapWarnCount)
        ? extra.flapWarnCount
        : DEFAULT_ROUTING_THRESHOLDS.flapWarnCount,
    protocolFilter:
      extra?.protocolFilter === "bgp" ||
      extra?.protocolFilter === "ospf" ||
      extra?.protocolFilter === "bfd" ||
      extra?.protocolFilter === "all"
        ? extra.protocolFilter
        : DEFAULT_ROUTING_THRESHOLDS.protocolFilter,
  };
}

/**
 * Builds a bounded, allowlisted SPL query for NX-OS DME (`cisco:dc:nexus9k:dme`)
 * and Nexus Dashboard (`cisco:dc:nd:*`) routing state events.
 * Emits `| head` BEFORE `buildAllowedFieldsClause` (`| table ...`) so indexers
 * cap rows early and drop `_raw` server-side.
 */
export function buildRoutingDmeSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
  earliest?: number;
  latest?: number;
  componentFilter?: "all" | "ospf";
}): string {
  const index = literal(options.index, 80);
  const componentClause =
    options.componentFilter === "ospf"
      ? `(component="ospfAdjEp" OR component="ospf*" OR dn="sys/ospf/*")`
      : `(component="bgp*" OR component="ospf*" OR component="bfd*" OR dn="sys/bgp/*" OR dn="sys/ospf/*" OR dn="sys/bfd/*" OR peer_ip=* OR neighbor_ip=*)`;
  const windowPred = buildDmeSnapshotWindowPredicate(
    options.earliest,
    options.latest,
  );
  const e =
    options.earliest !== undefined ? Math.trunc(options.earliest) : undefined;
  const l =
    options.latest !== undefined ? Math.trunc(options.latest) : undefined;
  const hasNdWindow =
    e !== undefined &&
    l !== undefined &&
    Number.isFinite(e) &&
    Number.isFinite(l) &&
    l > e;
  const sourcetypeClause =
    options.componentFilter === "ospf"
      ? windowPred
        ? `(sourcetype="cisco:dc:nexus9k:dme" ${windowPred})`
        : `sourcetype="cisco:dc:nexus9k:dme"`
      : windowPred && hasNdWindow
        ? `((sourcetype="cisco:dc:nexus9k:dme" ${windowPred}) OR (sourcetype="cisco:dc:nd:*" ("bgp" OR "ospf" OR "bfd") earliest=${e} latest=${l}))`
        : `(sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*")`;
  const predicates: string[] = [
    `index=${index}`,
    sourcetypeClause,
    componentClause,
  ];
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(host="${dev}" OR device="${dev}" OR nodeName="${dev}" OR switchName="${dev}" OR exporter_ip="${dev}")`,
    );
  }
  if (options.filter?.src) {
    const src = literal(options.filter.src, 128);
    predicates.push(
      `(host="${src}" OR device="${src}" OR peer_ip="${src}" OR neighbor_ip="${src}" OR Row_info.addr="${src}" OR Row_info.peerIp="${src}" OR Row_info.destAddr="${src}" OR ipAddress="${src}" OR src_ip="${src}")`,
    );
  }
  if (options.filter?.dst) {
    const dst = literal(options.filter.dst, 128);
    predicates.push(
      `(peer_ip="${dst}" OR neighbor_ip="${dst}" OR Row_info.addr="${dst}" OR Row_info.peerIp="${dst}" OR Row_info.destAddr="${dst}" OR ipAddress="${dst}" OR dest_ip="${dst}")`,
    );
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const preDedupLimit = dmePreDedupLimit(options.maxRows);
  const tableClause = buildAllowedFieldsClause("routing", [
    ...ROUTING_DME_FIELDS,
    "_pre_dedup_count",
  ]);
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${preDedupLimit} ` +
    `| eventstats count AS _pre_dedup_count ` +
    `| eval _dk_host=coalesce(device, nodeName, switchName, host, "none"), _dk_comp=coalesce(component, sourcetype, "none"), _dk_dn=coalesce(dn, 'Row_info.dn', peer_ip, neighbor_ip, 'Row_info.addr', 'Row_info.peerIp', 'Row_info.destAddr', ipAddress, "none") ` +
    `| dedup _dk_host _dk_comp _dk_dn ` +
    `| head ${headLimit} ` +
    `| eval host=coalesce(device, nodeName, switchName, host), ` +
    `dn=coalesce(dn, 'Row_info.dn'), ` +
    `vrf=coalesce(vrf, vrf_name, 'Row_info.vrfName', 'Row_info.vrf'), ` +
    `vrf_name=coalesce(vrf_name, vrf, 'Row_info.vrfName'), ` +
    `peer_ip=coalesce(peer_ip, neighbor_ip, 'Row_info.addr', 'Row_info.peerIp', 'Row_info.destAddr', ipAddress), ` +
    `peer_asn=coalesce(peer_asn, 'Row_info.asn', 'Row_info.peerAsn'), ` +
    `local_asn=coalesce(local_asn, 'Row_info.localAsn'), ` +
    `operSt=coalesce(operSt, 'Row_info.operSt', operStatus, status), ` +
    `oper_state=coalesce(oper_state, operSt, 'Row_info.operSt', operStatus), ` +
    `prefixes_received=coalesce(prefixes_received, prefix_count, 'Row_info.rcvPfx', 'Row_info.pfxRcvd', 'Row_info.prefixesReceived'), ` +
    `flap_count=coalesce(flap_count, flaps, 'Row_info.flapCnt', 'Row_info.flapCount'), ` +
    `uptime=coalesce(uptime, 'Row_info.upTs', 'Row_info.uptime'), ` +
    `protocol=coalesce(protocol, component, sourceName), ` +
    `area=coalesce(area, 'Row_info.area'), ` +
    `interface=coalesce(interface, 'Row_info.ifId', 'Row_info.ifName', interfaceUniqueId), ` +
    `descr=coalesce(descr, 'Row_info.descr', 'Row_info.name') ` +
    tableClause
  );
}

export const ROUTING_SYSLOG_CATEGORIES = [
  "BGP",
  "OSPF",
  "OSPFV3",
  "BFD",
  "ISIS",
  "HSRP",
  "VRRP",
] as const;

/**
 * Builds a bounded SPL query for SC4S (`cisco:ios`, `cisco:aci`) and DCN TA
 * (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`) operational routing syslog
 * rows via the shared `nxosSyslog` adapter (`categories` are filtered in `where`
 * after SC4S `rex` extraction).
 */
export function buildRoutingSyslogSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  return buildSyslogStateSearch({
    index: options.index,
    device: options.filter?.device,
    categories: ROUTING_SYSLOG_CATEGORIES,
    includeAci: true,
    maxRows: options.maxRows,
  });
}

/**
 * Builds a safe Splunk Search URL for raw events of a selected routing peer.
 */
export function buildRoutingRawEventsUrl(options: {
  index: string;
  device: string;
  peerIp: string;
  sourceCoverage: "syslog_only" | "dme_only" | "syslog_and_dme";
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const device = literal(options.device, 128);
  const peerIp = literal(options.peerIp, 128);
  const sourcetypes =
    options.sourceCoverage === "dme_only"
      ? `(sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*")`
      : options.sourceCoverage === "syslog_only"
        ? `(sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog")`
        : `(sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog" OR sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*")`;
  const q = `search index=${index} ${sourcetypes} (host="${device}" OR device="${device}" OR nodeName="${device}" OR switchName="${device}") (peer_ip="${peerIp}" OR neighbor_ip="${peerIp}" OR Row_info.addr="${peerIp}" OR Row_info.peerIp="${peerIp}" OR Row_info.destAddr="${peerIp}" OR ipAddress="${peerIp}" OR "${peerIp}")`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedRoutingEvent {
  id: string;
  sourceKind: "syslog" | "dme";
  timestamp?: number;
  device: string;
  vrf: string;
  peerIp: string;
  protocol: RoutingProtocol;
  stateLabel?: string;
  isDown?: boolean;
  isTransition: boolean;
  peerAsn?: number;
  localAsn?: number;
  prefixesReceived?: number;
  flapCount?: number;
  uptime?: string;
  area?: string;
  iface?: string;
  mnemonic?: string;
  summary?: string;
}

export interface RoutingPeerRow {
  /** URL-safe `ITEM_ID`: `${device}__${protocol}__${peerIp}` (disambiguated with `__${vrf}` only on collision). */
  id: string;
  attention: boolean;
  device: string;
  vrf: string;
  peerIp: string;
  protocol: RoutingProtocol;
  currentState: string;
  isDown: boolean;
  flapCount: number;
  syslogTransitions: number;
  dmeFlapCount?: number;
  peerAsn?: number;
  localAsn?: number;
  prefixesReceived?: number;
  uptime?: string;
  area?: string;
  iface?: string;
  lastTransitionTime?: number;
  lastMnemonic?: string;
  recentMnemonics: string[];
  sourceCoverage: "syslog_only" | "dme_only" | "syslog_and_dme";
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
}

export interface RoutingInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: RoutingPeerRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  adjacencyNodes: ProtocolAdjacencyNode[];
  adjacencyEdges: ProtocolAdjacencyEdge[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "syslog_only" | "dme_only" | "syslog_and_dme" | "none";
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
  if (num !== undefined && num > 0) return Math.floor(num);
  if (typeof value === "string" && value.trim()) {
    const parsed = Date.parse(value.trim());
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.floor(parsed / 1000);
    }
  }
  return undefined;
}

function sanitizeIdPart(raw: string): string {
  const cleaned = raw
    .replace(/[^A-Za-z0-9._:/@-]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!cleaned) return "item";
  return /^[A-Za-z0-9]/.test(cleaned) ? cleaned : `r${cleaned}`;
}

function makeSafePeerId(
  device: string,
  protocol: string,
  peerIp: string,
  vrf: string,
  used: Set<string>,
): string {
  const base = `${sanitizeIdPart(device)}__${sanitizeIdPart(protocol)}__${sanitizeIdPart(peerIp)}`;
  let candidate = base.slice(0, 128);
  if (!used.has(candidate)) {
    used.add(candidate);
    return candidate;
  }
  const withVrf = `${base}__${sanitizeIdPart(vrf)}`.slice(0, 128);
  candidate = withVrf;
  let n = 2;
  while (used.has(candidate)) {
    candidate = `${withVrf.slice(0, 120)}_${n}`;
    n += 1;
  }
  used.add(candidate);
  return candidate;
}

function extractVrfFromDn(dn: string | undefined): string | undefined {
  if (!dn) return undefined;
  const dom = /\/dom-([^/\]]+)/i.exec(dn);
  if (dom?.[1]) return dom[1];
  const vrf = /\/vrf-\[?([^/\]]+)\]?/i.exec(dn);
  if (vrf?.[1]) return vrf[1];
  return undefined;
}

function extractPeerFromDn(dn: string | undefined): string | undefined {
  if (!dn) return undefined;
  const peer = /\/(?:peer|ent)-\[([^\]]+)\]/i.exec(dn);
  if (peer?.[1]) return peer[1];
  const adj = /\/adj-([0-9a-fA-F.:]+)/i.exec(dn);
  if (adj?.[1]) return adj[1];
  return undefined;
}

function parseProtocolFromHints(hints: string[]): RoutingProtocol | undefined {
  const joined = hints.join(" ").toUpperCase();
  if (!joined.trim()) return undefined;
  if (/\bBFD/.test(joined)) return "BFD";
  if (/\bOSPF/.test(joined)) return "OSPF";
  if (/\bBGP/.test(joined)) return "BGP";
  if (/\bISIS\b|\bIS-IS\b/.test(joined)) return "ISIS";
  if (/\bHSRP\b/.test(joined)) return "HSRP";
  if (/\bVRRP\b/.test(joined)) return "VRRP";
  return undefined;
}

function canonicalizeState(
  protocol: RoutingProtocol,
  rawState: string,
  mnemonic?: string,
): { label: string; isDown: boolean } | undefined {
  const s = rawState.trim();
  const u = s.toUpperCase();
  const m = (mnemonic ?? "").toUpperCase();

  if (!s && !m) return undefined;

  if (m.includes("SESSION_STATE_DOWN") || m.includes("SESS_DOWN")) {
    return { label: "Down", isDown: true };
  }
  if (m.includes("SESSION_STATE_UP") || m.includes("SESS_UP")) {
    return { label: "Up", isDown: false };
  }
  if (m.includes("NBR_RESET") || m.includes("NOTIFICATION")) {
    return { label: "Reset", isDown: true };
  }

  if (protocol === "BGP") {
    if (/\bESTABLISHED\b|\bUP\b/.test(u))
      return { label: "Established", isDown: false };
    if (/\bIDLE\b/.test(u)) return { label: "Idle", isDown: true };
    if (/\bACTIVE\b/.test(u)) return { label: "Active", isDown: true };
    if (/\bCONNECT\b/.test(u)) return { label: "Connect", isDown: true };
    if (/\bOPENSENT\b/.test(u)) return { label: "OpenSent", isDown: true };
    if (/\bOPENCONFIRM\b/.test(u))
      return { label: "OpenConfirm", isDown: true };
    if (/\bRESET\b/.test(u)) return { label: "Reset", isDown: true };
    if (/\bSHUT\b|\bADMINDOWN\b|\bDOWN\b/.test(u))
      return { label: "Down", isDown: true };
  }

  if (protocol === "OSPF") {
    if (/\bFULL\b/.test(u)) return { label: "Full", isDown: false };
    if (/\bDOWN\b/.test(u)) return { label: "Down", isDown: true };
    if (/\bLOADING\b/.test(u)) return { label: "Loading", isDown: true };
    if (/\bEXCHANGE\b/.test(u)) return { label: "Exchange", isDown: true };
    if (/\bEXSTART\b/.test(u)) return { label: "ExStart", isDown: true };
    if (/\b2-?WAY\b|\bTWOWAY\b/.test(u))
      return { label: "2-Way", isDown: true };
    if (/\bINIT\b/.test(u)) return { label: "Init", isDown: true };
    if (/\bUP\b/.test(u)) return { label: "Full", isDown: false };
  }

  if (protocol === "BFD" || protocol === "ISIS") {
    if (/\bUP\b/.test(u)) return { label: "Up", isDown: false };
    if (/\bADMINDOWN\b/.test(u)) return { label: "AdminDown", isDown: true };
    if (/\bINIT\b/.test(u)) return { label: "Init", isDown: true };
    if (/\bDOWN\b/.test(u)) return { label: "Down", isDown: true };
  }

  if (protocol === "HSRP" || protocol === "VRRP") {
    if (/\bACTIVE\b/.test(u)) return { label: "Active", isDown: false };
    if (/\bMASTER\b/.test(u)) return { label: "Master", isDown: false };
    if (/\bSTANDBY\b/.test(u)) return { label: "Standby", isDown: false };
    if (/\bBACKUP\b/.test(u)) return { label: "Backup", isDown: false };
    if (/\bUP\b/.test(u)) return { label: "Up", isDown: false };
    if (/\bDOWN\b|\bINIT\b/.test(u)) return { label: "Down", isDown: true };
  }

  if (s) {
    const downMatch = /\b(DOWN|IDLE|RESET|FAIL|EXPIRED|SHUT)\b/i.test(s);
    const upMatch = /\b(ESTABLISHED|FULL|UP)\b/i.test(s);
    if (upMatch && !downMatch) return { label: s, isDown: false };
    if (downMatch) return { label: s, isDown: true };
    return { label: s, isDown: false };
  }

  return undefined;
}

function parseSyslogRoutingFields(
  ev: NormalizedStateEvent,
  rawRow: ProtocolRow,
):
  | {
      protocol: RoutingProtocol;
      peerIp?: string;
      vrf: string;
      localAsn?: number;
      peerAsn?: number;
      area?: string;
      iface?: string;
      stateLabel?: string;
      isDown?: boolean;
      isTransition: boolean;
    }
  | undefined {
  let protocol: RoutingProtocol | undefined;
  if (ev.domain === "bgp") protocol = "BGP";
  else if (ev.domain === "ospf") protocol = "OSPF";
  else if (ev.domain === "bfd") protocol = "BFD";
  else if (ev.domain === "isis") protocol = "ISIS";
  else if (ev.domain === "hsrp_vrrp") {
    protocol =
      ev.category.includes("VRRP") || ev.mnemonic.includes("VRRP")
        ? "VRRP"
        : "HSRP";
  }
  if (!protocol) return undefined;

  const summary = ev.summary;
  const dn = asString(rawRow.dn);

  // VRF extraction: explicit field -> bracketed `[default]` / `[vrf-prod]` -> `vrf <name>` -> DN
  let vrf = ev.vrf || asString(rawRow.vrf_name) || extractVrfFromDn(dn) || "";
  if (!vrf) {
    const bracketVrf = /bgp-\d+\s+\[([A-Za-z0-9._-]+)\]/i.exec(summary);
    if (bracketVrf?.[1]) vrf = bracketVrf[1];
    else {
      const kwVrf = /\b(?:in\s+)?VRF\s+([A-Za-z0-9._-]+)/i.exec(summary);
      if (kwVrf?.[1]) vrf = kwVrf[1];
    }
  }
  if (!vrf) vrf = "default";

  // Local ASN from NX-OS `bgp-65001`
  let localAsn = asFiniteNumber(rawRow.local_asn);
  if (localAsn === undefined) {
    const asnMatch = /\bbgp-(\d+)\b/i.exec(summary);
    if (asnMatch?.[1]) localAsn = Number(asnMatch[1]);
  }
  const peerAsn = asFiniteNumber(rawRow.peer_asn);

  // Peer IP extraction
  let peerIp =
    ev.neighborIp || asString(rawRow.peer_ip) || extractPeerFromDn(dn) || "";
  if (!peerIp) {
    const nbrMatch =
      /\b(?:neighbor|nbr|to\s+neighbor|from\s+neighbor|adjacency\s+to)\s+([0-9a-fA-F.:]+)/i.exec(
        summary,
      );
    if (nbrMatch?.[1]) peerIp = nbrMatch[1];
  }
  if (!peerIp && (protocol === "HSRP" || protocol === "VRRP")) {
    const grpMatch = /([A-Za-z]+\d+(?:\/\d+)?)\s+Grp\s+(\d+)/i.exec(summary);
    if (grpMatch) peerIp = `${grpMatch[1]}-grp${grpMatch[2]}`;
  }
  if (!peerIp) {
    const anyIp =
      /\b((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}:[0-9a-fA-F:]+)\b/.exec(
        summary,
      );
    if (anyIp?.[1]) peerIp = anyIp[1];
  }
  if (!peerIp && ev.interface) {
    peerIp = ev.interface;
  }
  if (!peerIp) return undefined;

  // Interface extraction
  let iface = ev.interface;
  if (!iface) {
    const ifMatch =
      /\bon\s+(?:interface\s+)?([A-Za-z]+[0-9]+(?:\/[0-9]+)*(?:\.[0-9]+)?)/i.exec(
        summary,
      );
    if (ifMatch?.[1]) iface = ifMatch[1];
  }

  // Area extraction for OSPF
  let area = asString(rawRow.area) || undefined;
  if (!area && protocol === "OSPF") {
    const areaMatch = /\barea\s+([0-9.]+)/i.exec(summary);
    if (areaMatch?.[1]) area = areaMatch[1];
  }

  // State extraction
  let rawState = asString(
    rawRow.peer_state ?? rawRow.state ?? rawRow.oper_state,
  );
  if (!rawState) {
    const fromTo = /\bfrom\s+\S+\s+to\s+([A-Za-z0-9_-]+)/i.exec(summary);
    if (fromTo?.[1]) {
      rawState = fromTo[1];
    } else {
      const stateArrow = /\bstate\s+\S+\s*->\s*([A-Za-z0-9_-]+)/i.exec(summary);
      if (stateArrow?.[1]) {
        rawState = stateArrow[1];
      } else if (/\bhas\s+gone\s+down\b|\bis\s+going\s+DOWN\b/i.test(summary)) {
        rawState = "Down";
      } else if (/\bhas\s+come\s+up\b|\bis\s+UP\b/i.test(summary)) {
        rawState = "Up";
      } else {
        const bgpNbrState =
          /\b(?:neighbor|nbr)\s+\S+(?:\s+vrf\s+\S+)?\s+(Up|Down|Reset|Idle|Active|Connect|Established)\b/i.exec(
            summary,
          );
        if (bgpNbrState?.[1]) rawState = bgpNbrState[1];
      }
    }
  }

  const state = canonicalizeState(protocol, rawState, ev.mnemonic);
  const isTransition =
    /ADJCHG|ADJCHANGE|STATE|RESET|NOTIFICATION|DOWN|UP/i.test(ev.mnemonic) ||
    Boolean(state);

  return {
    protocol,
    peerIp,
    vrf,
    ...(localAsn !== undefined ? { localAsn } : {}),
    ...(peerAsn !== undefined ? { peerAsn } : {}),
    ...(area ? { area } : {}),
    ...(iface ? { iface } : {}),
    ...(state ? { stateLabel: state.label, isDown: state.isDown } : {}),
    isTransition,
  };
}

/**
 * Normalizes a syslog row via `normalizeSyslogRow` (`nxosSyslog.ts`) and parses
 * routing protocol, peer IP, VRF, ASN, and adjacency state.
 */
export function normalizeRoutingSyslogRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedRoutingEvent | undefined {
  const base = normalizeSyslogRow(row, indexInBatch);
  if (!base) return undefined;
  const parsed = parseSyslogRoutingFields(base, row);
  if (!parsed || !parsed.peerIp) return undefined;

  return {
    id: base.id,
    sourceKind: "syslog",
    timestamp: base.timestamp,
    device: base.host,
    vrf: parsed.vrf,
    peerIp: parsed.peerIp,
    protocol: parsed.protocol,
    ...(parsed.stateLabel ? { stateLabel: parsed.stateLabel } : {}),
    ...(parsed.isDown !== undefined ? { isDown: parsed.isDown } : {}),
    isTransition: parsed.isTransition,
    ...(parsed.peerAsn !== undefined ? { peerAsn: parsed.peerAsn } : {}),
    ...(parsed.localAsn !== undefined ? { localAsn: parsed.localAsn } : {}),
    ...(parsed.area ? { area: parsed.area } : {}),
    ...(parsed.iface ? { iface: parsed.iface } : {}),
    mnemonic: `${base.category}-${base.severity}-${base.mnemonic}`,
    summary: base.summary,
  };
}

/**
 * Normalizes an allowlist-projected DME (`cisco:dc:nexus9k:dme` / `cisco:dc:nd:*`)
 * routing state row. Unrelated DME classes (e.g., `topSystem`, `l1PhysIf`) return `undefined`.
 */
export function normalizeRoutingDmeRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedRoutingEvent | undefined {
  const device = asString(row.host);
  if (!device) return undefined;
  const dn = asString(row.dn);
  const descr = asString(row.descr);
  const rawProto = asString(row.protocol);
  const protocol = parseProtocolFromHints([rawProto, dn, descr]);
  const peerIp =
    asString(row.peer_ip || row.neighbor_ip) || extractPeerFromDn(dn) || "";
  if (!protocol || !peerIp) return undefined;

  const rawState = asString(
    row.operSt ?? row.oper_state ?? row.peer_state ?? row.state,
  );
  const state = canonicalizeState(protocol, rawState);
  const vrf =
    asString(row.vrf || row.vrf_name) || extractVrfFromDn(dn) || "default";
  const peerAsn = asFiniteNumber(row.peer_asn);
  const localAsn = asFiniteNumber(row.local_asn);
  const prefixesReceived = asFiniteNumber(row.prefixes_received);
  const flapCount = asFiniteNumber(row.flap_count);
  const uptime = asString(row.uptime) || undefined;
  const area = asString(row.area) || undefined;
  const iface = asString(row.interface) || undefined;
  const timestamp = asEpochSeconds(row._time);

  return {
    id: `${device}:dme:${protocol}:${peerIp}:${indexInBatch}`,
    sourceKind: "dme",
    ...(timestamp !== undefined ? { timestamp } : {}),
    device,
    vrf,
    peerIp,
    protocol,
    ...(state ? { stateLabel: state.label, isDown: state.isDown } : {}),
    isTransition: false,
    ...(peerAsn !== undefined ? { peerAsn } : {}),
    ...(localAsn !== undefined ? { localAsn } : {}),
    ...(prefixesReceived !== undefined
      ? { prefixesReceived: Math.max(0, Math.trunc(prefixesReceived)) }
      : {}),
    ...(flapCount !== undefined
      ? { flapCount: Math.max(0, Math.trunc(flapCount)) }
      : {}),
    ...(uptime ? { uptime } : {}),
    ...(area ? { area } : {}),
    ...(iface ? { iface } : {}),
    ...(descr ? { summary: descr } : {}),
  };
}

function matchesProtocolFilter(
  protocol: RoutingProtocol,
  filter: RoutingProtocolFilter,
): boolean {
  if (filter === "all") return true;
  return protocol.toLowerCase() === filter;
}

function matchesRequestFilter(
  ev: NormalizedRoutingEvent,
  filter?: ProtocolFilter,
): boolean {
  if (!filter) return true;
  if (
    filter.device &&
    ev.device.toLowerCase() !== filter.device.toLowerCase()
  ) {
    return false;
  }
  if (
    filter.src &&
    ev.device.toLowerCase() !== filter.src.toLowerCase() &&
    ev.peerIp.toLowerCase() !== filter.src.toLowerCase()
  ) {
    return false;
  }
  if (filter.dst && ev.peerIp.toLowerCase() !== filter.dst.toLowerCase()) {
    return false;
  }
  return true;
}

function buildSparklineBuckets(
  events: readonly NormalizedRoutingEvent[],
  earliest: number,
  latest: number,
  predicate: (ev: NormalizedRoutingEvent) => boolean,
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const counts = Array.from({ length: buckets }, () => 0);
  let total = 0;
  for (const ev of events) {
    if (!predicate(ev)) continue;
    const ts = ev.timestamp ?? earliest;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ts - earliest) / span) * buckets)),
    );
    counts[idx] += 1;
    total += 1;
  }
  return total > 0 ? counts : [];
}

/**
 * Pure aggregation of normalized routing syslog and DME events into peer rows,
 * KPI tiles, Matrix cells, SwimlaneTimeline events, AdjacencyOverlay graph, and
 * a single-sentence verdict.
 */
export function buildRoutingAnalysis(options: {
  events: readonly { event: NormalizedRoutingEvent; indexName: string }[];
  thresholds: ResolvedRoutingThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  filter?: ProtocolFilter;
}): RoutingInvestigationResult {
  const { events, thresholds, earliest, latest, outcomes, capped, filter } =
    options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  const filteredEvents = events.filter(
    ({ event }) =>
      matchesProtocolFilter(event.protocol, thresholds.protocolFilter) &&
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
        adjacencyNodes: [],
        adjacencyEdges: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "blocked",
        bannerReason:
          outcomes.find((o) => o.state === "blocked")?.detail ??
          "Access denied for one or more routing source indexes.",
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
        adjacencyNodes: [],
        adjacencyEdges: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured routing source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (anyPartial) {
      return {
        verdict:
          "Search hit row cap before matching routing events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        adjacencyNodes: [],
        adjacencyEdges: [],
        outcomes,
        capped,
        sourceMode: "none",
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching routing events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No routing adjacency transitions or peer states observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      adjacencyNodes: [],
      adjacencyEdges: [],
      outcomes,
      capped,
      sourceMode: "none",
      bannerState: "empty",
      bannerReason:
        "No matching BGP, OSPF, or BFD events observed in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const peerMap = new Map<
    string,
    {
      device: string;
      vrf: string;
      peerIp: string;
      protocol: RoutingProtocol;
      events: NormalizedRoutingEvent[];
      indexName: string;
    }
  >();

  for (const entry of filteredEvents) {
    const ev = entry.event;
    const key = `${ev.device}\0${ev.vrf}\0${ev.peerIp}\0${ev.protocol}`;
    const existing = peerMap.get(key);
    if (existing) {
      existing.events.push(ev);
      if (ev.sourceKind === "dme") {
        existing.indexName = entry.indexName;
      }
    } else {
      peerMap.set(key, {
        device: ev.device,
        vrf: ev.vrf,
        peerIp: ev.peerIp,
        protocol: ev.protocol,
        events: [ev],
        indexName: entry.indexName,
      });
    }
  }

  const hasSyslogAll = filteredEvents.some(
    (e) => e.event.sourceKind === "syslog",
  );
  const hasDmeAll = filteredEvents.some((e) => e.event.sourceKind === "dme");
  const sourceMode: RoutingInvestigationResult["sourceMode"] =
    hasSyslogAll && hasDmeAll
      ? "syslog_and_dme"
      : hasDmeAll
        ? "dme_only"
        : "syslog_only";

  const usedIds = new Set<string>();
  const rows: RoutingPeerRow[] = [];

  for (const group of peerMap.values()) {
    const id = makeSafePeerId(
      group.device,
      group.protocol,
      group.peerIp,
      group.vrf,
      usedIds,
    );
    const ordered = [...group.events].sort(
      (a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0),
    );
    const syslogEvents = ordered.filter((e) => e.sourceKind === "syslog");
    const dmeEvents = ordered.filter((e) => e.sourceKind === "dme");

    const sourceCoverage: RoutingPeerRow["sourceCoverage"] =
      syslogEvents.length > 0 && dmeEvents.length > 0
        ? "syslog_and_dme"
        : dmeEvents.length > 0
          ? "dme_only"
          : "syslog_only";

    // Latest state-bearing event determines current state (prefer newer timestamp,
    // break equal-timestamp ties in favor of authoritative DME operSt).
    const stateEvents = ordered.filter((e) => e.stateLabel !== undefined);
    const latestStateEvent = stateEvents.sort((a, b) => {
      const dt = (a.timestamp ?? 0) - (b.timestamp ?? 0);
      if (dt !== 0) return dt;
      return a.sourceKind === "dme" ? 1 : -1;
    })[stateEvents.length - 1];

    const currentState = latestStateEvent?.stateLabel ?? "Unknown";
    const isDown = Boolean(latestStateEvent?.isDown);

    const syslogTransitions = syslogEvents.filter((e) => e.isTransition).length;
    const dmeFlapsList = dmeEvents
      .map((e) => e.flapCount)
      .filter((n): n is number => n !== undefined);
    const dmeFlapCount = dmeFlapsList.length
      ? Math.max(...dmeFlapsList)
      : undefined;
    const flapCount = Math.max(syslogTransitions, dmeFlapCount ?? 0);

    const peerAsn = [...ordered]
      .reverse()
      .find((e) => e.peerAsn !== undefined)?.peerAsn;
    const localAsn = [...ordered]
      .reverse()
      .find((e) => e.localAsn !== undefined)?.localAsn;
    const prefixesReceived = [...dmeEvents]
      .reverse()
      .find((e) => e.prefixesReceived !== undefined)?.prefixesReceived;
    const uptime = [...dmeEvents]
      .reverse()
      .find((e) => e.uptime !== undefined)?.uptime;
    const area = [...ordered].reverse().find((e) => e.area !== undefined)?.area;
    const iface = [...ordered]
      .reverse()
      .find((e) => e.iface !== undefined)?.iface;

    const latestSyslog = syslogEvents[syslogEvents.length - 1];
    const lastTransitionTime = latestSyslog?.timestamp;
    const lastMnemonic = latestSyslog?.mnemonic;
    const recentMnemonics = syslogEvents
      .slice(-5)
      .reverse()
      .map((e) =>
        e.mnemonic && e.summary
          ? `${e.mnemonic}: ${e.summary}`
          : (e.mnemonic ?? e.summary ?? "Transition"),
      );

    const reasons: string[] = [];
    if (isDown) {
      reasons.push(`${group.protocol} state ${currentState}`);
    }
    if (flapCount >= thresholds.flapWarnCount) {
      reasons.push(
        `${flapCount} ${flapCount === 1 ? "flap" : "flaps"} (≥ ${thresholds.flapWarnCount})`,
      );
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention
      ? "attention"
      : latestStateEvent
        ? "ok"
        : "unknown";

    rows.push({
      id,
      attention,
      device: group.device,
      vrf: group.vrf,
      peerIp: group.peerIp,
      protocol: group.protocol,
      currentState,
      isDown,
      flapCount,
      syslogTransitions,
      ...(dmeFlapCount !== undefined ? { dmeFlapCount } : {}),
      ...(peerAsn !== undefined ? { peerAsn } : {}),
      ...(localAsn !== undefined ? { localAsn } : {}),
      ...(prefixesReceived !== undefined ? { prefixesReceived } : {}),
      ...(uptime ? { uptime } : {}),
      ...(area ? { area } : {}),
      ...(iface ? { iface } : {}),
      ...(lastTransitionTime !== undefined ? { lastTransitionTime } : {}),
      ...(lastMnemonic ? { lastMnemonic } : {}),
      recentMnemonics,
      sourceCoverage,
      status,
      reasons,
      indexName: group.indexName,
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.isDown !== b.isDown) return a.isDown ? -1 : 1;
    if (b.flapCount !== a.flapCount) return b.flapCount - a.flapCount;
    const devCmp = a.device.localeCompare(b.device);
    if (devCmp !== 0) return devCmp;
    return a.peerIp.localeCompare(b.peerIp);
  });

  // KPI strip (<=4 tiles, one metric per tile, readable units)
  const downPeersCount = rows.filter((r) => r.isDown).length;
  const totalFlaps = rows.reduce((sum, r) => sum + r.flapCount, 0);
  const affectedDevices = new Set(
    rows.filter((r) => r.attention).map((r) => r.device),
  );
  const anyFlapWarning = rows.some(
    (r) => r.flapCount >= thresholds.flapWarnCount,
  );
  const allEventsFlat = filteredEvents.map((e) => e.event);
  const downSpark = buildSparklineBuckets(
    allEventsFlat,
    earliest,
    latest,
    (e) => Boolean(e.isDown && e.isTransition),
  );
  const flapSpark = buildSparklineBuckets(
    allEventsFlat,
    earliest,
    latest,
    (e) => e.isTransition,
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "down-peers",
      label: "Down Sessions",
      value: formatCount(downPeersCount),
      unit: downPeersCount === 1 ? "session" : "sessions",
      status: downPeersCount > 0 ? "attention" : "ok",
      ...(downSpark.length ? { sparkline: downSpark } : {}),
    },
    {
      id: "total-flaps",
      label: "Total Flaps",
      value: formatCount(totalFlaps),
      unit: totalFlaps === 1 ? "flap" : "flaps",
      status: anyFlapWarning || downPeersCount > 0 ? "attention" : "ok",
      ...(flapSpark.length ? { sparkline: flapSpark } : {}),
    },
    {
      id: "tracked-peers",
      label: "Tracked Sessions",
      value: formatCount(rows.length),
      unit: rows.length === 1 ? "session" : "sessions",
      status: "ok",
    },
    {
      id: "affected-devices",
      label: "Affected Devices",
      value: formatCount(affectedDevices.size),
      unit: affectedDevices.size === 1 ? "device" : "devices",
      status: affectedDevices.size > 0 ? "attention" : "ok",
    },
  ];

  // Matrix (device x peer_ip), sorted flagged devices first and keeping highest-severity row per cell.
  const flaggedDeviceSet = new Set(
    rows.filter((r) => r.attention).map((r) => r.device),
  );
  const matrixRows = [...new Set(rows.map((r) => r.device))].sort((a, b) => {
    const aFlag = flaggedDeviceSet.has(a);
    const bFlag = flaggedDeviceSet.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    return a.localeCompare(b);
  });
  const matrixCols = [...new Set(rows.map((r) => r.peerIp))].sort((a, b) =>
    a.localeCompare(b),
  );
  const groupedByPair = new Map<string, RoutingPeerRow[]>();
  for (const row of rows) {
    const key = `${row.device}\0${row.peerIp}`;
    const list = groupedByPair.get(key);
    if (list) list.push(row);
    else groupedByPair.set(key, [row]);
  }
  const matrixCells: ProtocolMatrixCell[] = [];
  for (const group of groupedByPair.values()) {
    // `rows` is already sorted with flagged/down/flapping sessions first, so
    // group[0] carries the worst status for this (device, peerIp) pair.
    const lead = group[0];
    const baseLabel = lead.isDown
      ? `${lead.protocol} ${lead.currentState}`
      : lead.flapCount >= thresholds.flapWarnCount
        ? `${lead.flapCount} flaps`
        : `${lead.protocol} ${lead.currentState}`;
    const label =
      group.length > 1 ? `${baseLabel} +${group.length - 1}` : baseLabel;
    const totalFlaps = group.reduce((acc, r) => acc + r.flapCount, 0);
    const detail = group
      .map((r) =>
        r.reasons.length
          ? `${r.protocol} (${r.vrf}): ${r.reasons.join("; ")}`
          : `${r.protocol} (${r.vrf}) ${r.currentState}`,
      )
      .join(" · ");
    matrixCells.push({
      row: lead.device,
      col: lead.peerIp,
      status: lead.status,
      value: label,
      count: totalFlaps,
      detail,
      itemId: lead.id,
    });
  }

  // SwimlaneTimeline events (per-device adjacency transitions across UTC window)
  const rowIdByPeerKey = new Map<string, string>();
  for (const r of rows) {
    rowIdByPeerKey.set(
      `${r.device}\0${r.vrf}\0${r.peerIp}\0${r.protocol}`,
      r.id,
    );
  }
  const timelineEvents: ProtocolTimelineEvent[] = filteredEvents
    .map((entry) => entry.event)
    .filter((ev) => ev.sourceKind === "syslog" && ev.timestamp !== undefined)
    .sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))
    .slice(0, 128)
    .map((ev) => {
      const peerRowId =
        rowIdByPeerKey.get(
          `${ev.device}\0${ev.vrf}\0${ev.peerIp}\0${ev.protocol}`,
        ) ?? ev.id;
      return {
        id: `${peerRowId}\u001f${ev.id}`,
        lane: ev.device,
        timestamp: ev.timestamp!,
        kind: ev.isDown ? "attention" : "ok",
        label:
          `${ev.protocol} ${ev.peerIp} ${ev.stateLabel ?? ev.mnemonic ?? ""}`.trim(),
        detail: ev.summary,
      };
    });

  // AdjacencyOverlay graph (devices <-> peers)
  const devStatus = new Map<string, ProtocolStatus>();
  const peerStatus = new Map<string, ProtocolStatus>();
  for (const row of rows) {
    const curDev = devStatus.get(row.device);
    if (row.attention || !curDev) {
      devStatus.set(row.device, row.attention ? "attention" : row.status);
    }
    const curPeer = peerStatus.get(row.peerIp);
    if (row.attention || !curPeer) {
      peerStatus.set(row.peerIp, row.attention ? "attention" : row.status);
    }
  }
  const adjacencyNodes: ProtocolAdjacencyNode[] = [
    ...[...devStatus.entries()].map(([dev, status]) => ({
      id: `dev:${dev}`,
      label: dev,
      role: "device",
      status,
    })),
    ...[...peerStatus.entries()].map(([peerIp, status]) => ({
      id: `peer:${peerIp}`,
      label: peerIp,
      role: "peer",
      status,
    })),
  ];
  const adjacencyEdges: ProtocolAdjacencyEdge[] = rows.map((row) => ({
    id: row.id,
    from: `dev:${row.device}`,
    to: `peer:${row.peerIp}`,
    label: `${row.protocol} (${row.vrf}) · ${row.currentState}`,
    status: row.status,
    detail: row.reasons.join("; ") || row.currentState,
  }));

  // Single-sentence plain-language verdict (keep thresholds in tooltips, not the headline).
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadSummary = lead.isDown
      ? `${lead.protocol} ${lead.currentState} to ${lead.peerIp} on ${lead.device}`
      : `${lead.flapCount} ${lead.flapCount === 1 ? "flap" : "flaps"} on ${lead.device} (${lead.protocol} ${lead.peerIp})`;
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "session needs" : "sessions need"} attention: ${leadSummary}.`;
    verdictStatus = "attention";
  } else {
    verdict = `${rows.length} of ${rows.length} routing ${rows.length === 1 ? "session is" : "sessions are"} healthy with no excessive flaps.`;
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
    adjacencyNodes,
    adjacencyEdges,
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

export interface InvestigateRoutingOptions {
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand Routing Control Plane investigation across configured
 * `routing` profiles (SC4S/DCN syslog and/or NX-OS DME/ND state), rechecking
 * the `adm_protocol_profiles` fingerprint to discard stale results.
 */
export async function investigateRouting(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateRoutingOptions = {},
): Promise<RoutingInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "routing",
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
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      adjacencyNodes: [],
      adjacencyEdges: [],
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No routing profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedRoutingEvent; indexName: string }[] =
      [];
    let capped = false;
    const primaryThresholds = resolveRoutingThresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const thresholds = resolveRoutingThresholds(profile);
      const runSyslog =
        thresholds.sourceKind === "syslog" || thresholds.sourceKind === "auto";
      const runDme =
        thresholds.sourceKind === "dme" || thresholds.sourceKind === "auto";

      if (runSyslog) {
        const spl = buildRoutingSyslogSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "routing",
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
          const norm = normalizeRoutingSyslogRow(row, idx);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        });
      }

      if (runDme) {
        signal.throwIfAborted();
        const dispatchBounds = buildDmeDispatchBounds(
          profile,
          request.earliest,
          request.latest,
        );
        const spl = buildRoutingDmeSearch({
          index: profile.index,
          filter: request.filter,
          maxRows: 256,
          earliest: request.earliest,
          latest: request.latest,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "routing",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          preDedupLimit: dmePreDedupLimit(256),
          ...dispatchBounds,
          signal,
          keySuffix: "dme",
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        let sawOspf = false;
        res.rows.forEach((row, idx) => {
          const norm = normalizeRoutingDmeRow(row, idx);
          if (norm) {
            if (norm.protocol === "OSPF") sawOspf = true;
            collected.push({ event: norm, indexName: profile.index });
          }
        });
        if (
          res.capped &&
          !sawOspf &&
          (thresholds.protocolFilter === "all" ||
            thresholds.protocolFilter === "ospf")
        ) {
          signal.throwIfAborted();
          const ospfSpl = buildRoutingDmeSearch({
            index: profile.index,
            filter: request.filter,
            maxRows: 256,
            earliest: request.earliest,
            latest: request.latest,
            componentFilter: "ospf",
          });
          const ospfRes = await runBoundedProtocolSearch(client, {
            lens: "routing",
            profile,
            spl: ospfSpl,
            earliest: request.earliest,
            latest: request.latest,
            preDedupLimit: dmePreDedupLimit(256),
            ...dispatchBounds,
            signal,
            keySuffix: "dme_ospf",
          });
          if (
            ospfRes.outcome.state === "blocked" ||
            ospfRes.outcome.state === "unavailable"
          ) {
            outcomes.push(ospfRes.outcome);
          }
          if (ospfRes.capped) capped = true;
          ospfRes.rows.forEach((row, idx) => {
            const norm = normalizeRoutingDmeRow(row, idx);
            if (norm) collected.push({ event: norm, indexName: profile.index });
          });
        }
      }
    }

    return buildRoutingAnalysis({
      events: collected,
      thresholds: primaryThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      filter: request.filter,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    routing: validateRoutingExtra,
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
        adjacencyNodes: [],
        adjacencyEdges: [],
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
 * Hub "Check all" summary runner for `routing`.
 */
export async function summarizeRouting(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateRoutingOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateRouting(
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
    lens: "routing",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
