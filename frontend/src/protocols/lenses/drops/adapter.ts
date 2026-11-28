import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
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
import { buildFlowEndpointPredicates } from "../../shared/filterSpl";
import { formatBytes, formatCount } from "../../shared/format";
import {
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  DEFAULT_DROPS_THRESHOLDS,
  validateDropsExtra,
  type DropsExtraConfig,
  type DropsSourceKind,
  type ResolvedDropsThresholds,
} from "./validate";

export {
  DEFAULT_DROPS_THRESHOLDS,
  validateDropsExtra,
  type DropsExtraConfig,
  type DropsSourceKind,
  type ResolvedDropsThresholds,
};

export type DropsEnforcerKind = "ftd" | "hubble" | "nd" | "aci" | "firewall";

export const ENFORCER_LABELS: Record<DropsEnforcerKind, string> = {
  ftd: "FTD",
  hubble: "Hubble",
  nd: "Nexus Dashboard",
  aci: "ACI",
  firewall: "Firewall",
};

export function resolveDropsThresholds(
  profile?: BaseProtocolProfile,
): ResolvedDropsThresholds {
  const extra = profile?.extra as DropsExtraConfig | undefined;
  const sourceKind: DropsSourceKind =
    extra?.sourceKind === "ftd" ||
    extra?.sourceKind === "hubble" ||
    extra?.sourceKind === "nd" ||
    extra?.sourceKind === "aci" ||
    extra?.sourceKind === "firewall" ||
    extra?.sourceKind === "auto"
      ? extra.sourceKind
      : DEFAULT_DROPS_THRESHOLDS.sourceKind;
  const dropWarnCount =
    typeof extra?.dropWarnCount === "number" &&
    Number.isInteger(extra.dropWarnCount) &&
    extra.dropWarnCount >= 1
      ? extra.dropWarnCount
      : DEFAULT_DROPS_THRESHOLDS.dropWarnCount;
  return {
    sourceKind,
    ...(typeof extra?.sourcetype === "string" && extra.sourcetype.trim()
      ? { sourcetype: extra.sourcetype.trim() }
      : {}),
    dropWarnCount,
  };
}

export const FTD_DROPS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "InitiatorIP",
  "InitiatorPort",
  "ResponderIP",
  "ResponderPort",
  "Protocol",
  "AC_RuleAction",
  "AccessControlRuleName",
  "Device",
  "DeviceIP",
  "IngressZone",
  "EgressZone",
  "Application",
  "InitiatorBytes",
  "ResponderBytes",
  "InitiatorPackets",
  "ResponderPackets",
] as const;

export const HUBBLE_DROPS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "verdict",
  "drop_reason_desc",
  "drop_reason",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protocol",
  "transport",
  "src_namespace",
  "dest_namespace",
  "src_pod",
  "dest_pod",
  "namespace",
  "pod_name",
  "node",
  "device",
] as const;

export const ND_DROPS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "srcIp",
  "dstIp",
  "srcPort",
  "dstPort",
  "protocolName",
  "dropPktCount",
  "dropReasons",
  "fabricName",
  "nd_host",
  "node",
  "device",
] as const;

export const ACI_DROPS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protocol",
  "drop_reason",
  "contract_name",
  "tenant",
  "vrf",
  "dn",
  "descr",
  "node",
  "device",
  "bytes",
] as const;

export const FIREWALL_DROPS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "transport",
  "protocol",
  "action",
  "reason",
  "drop_reason",
  "rule_name",
  "acl_name",
  "policy_name",
  "packets",
  "bytes",
  "device",
  "exporter_ip",
] as const;

/**
 * Never truncate IPv4 or IPv6 addresses at `.` — only strip DNS domain suffixes.
 */
export function shortenDeviceLabel(device: string): string {
  const trimmed = device.trim();
  if (!trimmed) return "unknown";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(":")) {
    return trimmed;
  }
  return trimmed.split(".")[0] || trimmed;
}

/**
 * Produces a URL-safe row ID matching `^[A-Za-z0-9._:/-]{1,128}$` (and `ITEM_ID`),
 * using `__` as separator and never `->`.
 */
export function makeDropRowId(
  srcIp: string,
  destIp: string,
  enforcerKind: DropsEnforcerKind,
  serviceKey: string,
): string {
  const cleanPart = (val: string) =>
    val.replace(/[^A-Za-z0-9._:/-]/g, "_") || "unknown";
  const sanitized = `${cleanPart(srcIp)}__${cleanPart(destIp)}__${enforcerKind}__${cleanPart(serviceKey)}`;
  const base = /^[A-Za-z0-9]/.test(sanitized) ? sanitized : `d_${sanitized}`;
  if (base.length <= 128) return base;
  let hash = 2166136261;
  for (let i = 0; i < base.length; i += 1) {
    hash = Math.imul(hash ^ base.charCodeAt(i), 16777619);
  }
  const suffix = `__${(hash >>> 0).toString(36)}`;
  return `${base.slice(0, 128 - suffix.length)}${suffix}`;
}

export function buildDropsFtdSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="cisco:sfw:estreamer"`,
    `(AC_RuleAction="*Block*" OR AC_RuleAction="*Drop*" OR AC_RuleAction="*Deny*" OR AC_RuleAction="Reset")`,
    `NOT AC_RuleAction="Allow*"`,
  ];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["InitiatorIP", "src_ip"],
      dstFields: ["ResponderIP", "dest_ip"],
      portFields: ["ResponderPort", "InitiatorPort", "dest_port", "src_port"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(Device="${dev}" OR DeviceIP="${dev}" OR host="${dev}")`);
  }
  const tableClause = buildAllowedFieldsClause(
    "drops",
    FTD_DROPS_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

export function buildDropsHubbleSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="cilium:hubble:flow"`,
    `(flow.verdict="DROPPED" OR verdict="DROPPED")`,
  ];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip", "flow.IP.source"],
      dstFields: ["dest_ip", "flow.IP.destination"],
      portFields: [
        "dest_port",
        "src_port",
        "flow.l4.TCP.destination_port",
        "flow.l4.TCP.source_port",
        "flow.l4.UDP.destination_port",
        "flow.l4.UDP.source_port",
      ],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(host="${dev}" OR node="${dev}" OR node_name="${dev}" OR flow.node_name="${dev}")`,
    );
  }
  const tableClause = buildAllowedFieldsClause(
    "drops",
    HUBBLE_DROPS_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| spath path=flow.verdict output=hubble_verdict ` +
    `| spath path=flow.drop_reason_desc output=hubble_drop_reason_desc ` +
    `| spath path=flow.drop_reason output=hubble_drop_reason ` +
    `| spath path=flow.IP.source output=hubble_src_ip ` +
    `| spath path=flow.IP.destination output=hubble_dest_ip ` +
    `| spath path=flow.l4.TCP.source_port output=hubble_tcp_sport ` +
    `| spath path=flow.l4.TCP.destination_port output=hubble_tcp_dport ` +
    `| spath path=flow.l4.UDP.source_port output=hubble_udp_sport ` +
    `| spath path=flow.l4.UDP.destination_port output=hubble_udp_dport ` +
    `| spath path=flow.source.namespace output=hubble_src_ns ` +
    `| spath path=flow.destination.namespace output=hubble_dst_ns ` +
    `| spath path=flow.source.pod_name output=hubble_src_pod ` +
    `| spath path=flow.destination.pod_name output=hubble_dst_pod ` +
    `| spath path=flow.node_name output=hubble_node_name ` +
    `| eval verdict=coalesce(verdict, hubble_verdict, 'flow.verdict'), ` +
    `drop_reason_desc=coalesce(drop_reason_desc, hubble_drop_reason_desc, 'flow.drop_reason_desc'), ` +
    `drop_reason=coalesce(drop_reason, hubble_drop_reason, 'flow.drop_reason'), ` +
    `src_ip=coalesce(src_ip, hubble_src_ip, 'flow.IP.source'), ` +
    `dest_ip=coalesce(dest_ip, hubble_dest_ip, 'flow.IP.destination'), ` +
    `src_port=coalesce(src_port, hubble_tcp_sport, hubble_udp_sport, 'flow.l4.TCP.source_port', 'flow.l4.UDP.source_port'), ` +
    `dest_port=coalesce(dest_port, hubble_tcp_dport, hubble_udp_dport, 'flow.l4.TCP.destination_port', 'flow.l4.UDP.destination_port'), ` +
    `transport=coalesce(transport, if(isnotnull(hubble_tcp_dport) OR isnotnull('flow.l4.TCP.destination_port'), "TCP", if(isnotnull(hubble_udp_dport) OR isnotnull('flow.l4.UDP.destination_port'), "UDP", null()))), ` +
    `src_namespace=coalesce(src_namespace, hubble_src_ns, 'flow.source.namespace'), ` +
    `dest_namespace=coalesce(dest_namespace, hubble_dst_ns, 'flow.destination.namespace'), ` +
    `src_pod=coalesce(src_pod, hubble_src_pod, 'flow.source.pod_name'), ` +
    `dest_pod=coalesce(dest_pod, hubble_dst_pod, 'flow.destination.pod_name'), ` +
    `node=coalesce(node, hubble_node_name, 'flow.node_name', host) ` +
    tableClause
  );
}

export function buildDropsNdSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="cisco:dc:nd:flows"`,
    `(stats{}.dropPktCount>0 OR (stats{}.dropReasons{}=* AND stats{}.dropReasons{}!="0" AND stats{}.dropReasons{}!="[]") OR dropPktCount>0)`,
  ];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["srcIp"],
      dstFields: ["dstIp"],
      portFields: ["dstPort", "srcPort"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(host="${dev}" OR nd_host="${dev}" OR fabricName="${dev}" OR stats{}.nodeNames{}="${dev}")`,
    );
  }
  const tableClause = buildAllowedFieldsClause(
    "drops",
    ND_DROPS_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| spath path=srcIp output=nd_src_ip ` +
    `| spath path=dstIp output=nd_dst_ip ` +
    `| spath path=srcPort output=nd_src_port ` +
    `| spath path=dstPort output=nd_dst_port ` +
    `| spath path=protocolName output=nd_proto ` +
    `| spath path=fabricName output=nd_fabric ` +
    `| spath path=nd_host output=nd_host_ext ` +
    `| spath path=stats{}.dropPktCount output=nd_drop_pkt ` +
    `| spath path=stats{}.dropReasons{} output=nd_drop_reasons ` +
    `| spath path=stats{}.nodeNames{} output=nd_nodes ` +
    `| eval srcIp=coalesce(srcIp, nd_src_ip), ` +
    `dstIp=coalesce(dstIp, nd_dst_ip), ` +
    `srcPort=coalesce(srcPort, nd_src_port), ` +
    `dstPort=coalesce(dstPort, nd_dst_port), ` +
    `protocolName=coalesce(protocolName, nd_proto), ` +
    `fabricName=coalesce(fabricName, nd_fabric), ` +
    `nd_host=coalesce(nd_host, nd_host_ext), ` +
    `dropPktCount=coalesce(dropPktCount, mvindex(nd_drop_pkt, 0), 'stats{}.dropPktCount'), ` +
    `dropReasons=coalesce(dropReasons, nd_drop_reasons, 'stats{}.dropReasons{}'), ` +
    `node=coalesce(node, mvindex(nd_nodes, 0), 'stats{}.nodeNames{}') ` +
    tableClause
  );
}

export function buildDropsAciSearch(options: {
  index: string;
  sourcetype?: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const stClause =
    options.sourcetype === "cisco:dc:aci:class"
      ? `sourcetype="cisco:dc:aci:class" component="acllogDropL3Pkt"`
      : options.sourcetype === "cisco:dc:aci:syslog"
        ? `sourcetype="cisco:dc:aci:syslog" (drop_reason=* OR "drop" OR "deny" OR "acllog")`
        : `((sourcetype="cisco:dc:aci:class" component="acllogDropL3Pkt") OR (sourcetype="cisco:dc:aci:syslog" (drop_reason=* OR "drop" OR "deny" OR "acllog")))`;
  const predicates: string[] = [`index=${index}`, stClause];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip", "srcIp"],
      dstFields: ["dest_ip", "dstIp"],
      portFields: ["dest_port", "src_port", "dstPort", "srcPort"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(device="${dev}" OR node="${dev}" OR host="${dev}" OR apic_host="${dev}")`,
    );
  }
  const tableClause = buildAllowedFieldsClause(
    "drops",
    ACI_DROPS_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval src_ip=coalesce(src_ip, srcIp), ` +
    `dest_ip=coalesce(dest_ip, dstIp), ` +
    `src_port=coalesce(src_port, srcPort), ` +
    `dest_port=coalesce(dest_port, dstPort), ` +
    `bytes=coalesce(bytes, pktLen), ` +
    `node=coalesce(node, if(match(dn, "topology/pod-[0-9]+/node-[0-9]+"), replace(dn, "^.*topology/(pod-[0-9]+/node-[0-9]+)/.*$", "\\1"), null())), ` +
    `device=coalesce(device, apic_host, host), ` +
    `tenant=coalesce(tenant, if(match(dn, "/tn-[^/]+"), replace(dn, "^.*/tn-([^/]+)/.*$", "\\1"), null())), ` +
    `vrf=coalesce(vrf, if(match(dn, "/ctx-[^/]+"), replace(dn, "^.*/ctx-([^/]+)/.*$", "\\1"), vrfEncap)), ` +
    `descr=coalesce(descr, if(isnotnull(srcEpgName) OR isnotnull(dstEpgName), coalesce(srcEpgName, "?")." -> ".coalesce(dstEpgName, "?"), null())), ` +
    `drop_reason=coalesce(drop_reason, if(component=="acllogDropL3Pkt", "acllogDropL3Pkt", null())) ` +
    tableClause
  );
}

export function buildDropsFirewallSearch(options: {
  index: string;
  sourcetype?: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const stClause = options.sourcetype
    ? `sourcetype="${literal(options.sourcetype, 80)}"`
    : `(sourcetype!="cisco:sfw:estreamer" sourcetype!="cilium:hubble:flow" sourcetype!="cisco:dc:nd:flows" sourcetype!="cisco:dc:aci:class" sourcetype!="cisco:dc:aci:syslog")`;
  const predicates: string[] = [
    `index=${index}`,
    stClause,
    `(action IN ("block", "blocked", "deny", "denied", "drop", "dropped", "reject", "rejected", "reset", "reset-client", "reset-server", "reset-both", "client-rst", "server-rst") OR disposition="DROPPED")`,
  ];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip", "srcip", "srcaddr"],
      dstFields: ["dest_ip", "dstip", "dstaddr"],
      portFields: ["dest_port", "src_port", "dstport", "srcport"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(device="${dev}" OR devname="${dev}" OR exporter_ip="${dev}" OR host="${dev}")`,
    );
  }
  const tableClause = buildAllowedFieldsClause(
    "drops",
    FIREWALL_DROPS_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval action=coalesce(action, disposition), ` +
    `reason=coalesce(reason, drop_reason), ` +
    `src_ip=coalesce(src_ip, srcip, srcaddr), ` +
    `dest_ip=coalesce(dest_ip, dstip, dstaddr), ` +
    `src_port=coalesce(src_port, srcport), ` +
    `dest_port=coalesce(dest_port, dstport), ` +
    `transport=coalesce(transport, protocol, proto), ` +
    `policy_name=coalesce(policy_name, policyid), ` +
    `device=coalesce(device, devname, exporter_ip, host) ` +
    tableClause
  );
}

/**
 * Builds a `literal()`-quoted `/app/splunk_adm/search?...` link for raw drop events.
 */
export function buildDropsRawEventsUrl(options: {
  index: string;
  enforcerKind: DropsEnforcerKind;
  sourcetypes: readonly string[];
  srcIp: string;
  destIp: string;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const src = literal(options.srcIp, 128);
  const dst = literal(options.destIp, 128);

  let q: string;
  if (options.enforcerKind === "ftd") {
    q = `search index=${index} sourcetype="cisco:sfw:estreamer" (AC_RuleAction="*Block*" OR AC_RuleAction="*Drop*" OR AC_RuleAction="*Deny*" OR AC_RuleAction="Reset") NOT AC_RuleAction="Allow*" (InitiatorIP="${src}" OR src_ip="${src}") (ResponderIP="${dst}" OR dest_ip="${dst}")`;
  } else if (options.enforcerKind === "hubble") {
    q = `search index=${index} sourcetype="cilium:hubble:flow" (flow.verdict="DROPPED" OR verdict="DROPPED") (src_ip="${src}" OR flow.IP.source="${src}") (dest_ip="${dst}" OR flow.IP.destination="${dst}")`;
  } else if (options.enforcerKind === "nd") {
    q = `search index=${index} sourcetype="cisco:dc:nd:flows" (stats{}.dropPktCount>0 OR stats{}.dropReasons{}=* OR dropPktCount>0) srcIp="${src}" dstIp="${dst}"`;
  } else if (options.enforcerKind === "aci") {
    q = `search index=${index} (sourcetype="cisco:dc:aci:class" OR sourcetype="cisco:dc:aci:syslog") (src_ip="${src}" OR srcIp="${src}") (dest_ip="${dst}" OR dstIp="${dst}")`;
  } else {
    const sts = options.sourcetypes.filter(Boolean);
    const stFilter = sts.length
      ? `(${sts.map((s) => `sourcetype="${literal(s, 80)}"`).join(" OR ")}) `
      : "";
    q = `search index=${index} ${stFilter}(src_ip="${src}" OR srcip="${src}" OR srcaddr="${src}") (dest_ip="${dst}" OR dstip="${dst}" OR dstaddr="${dst}")`;
  }

  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedDropEvent {
  enforcerKind: DropsEnforcerKind;
  enforcerLabel: string;
  sourcetype: string;
  timestamp: number;
  device: string;
  srcIp: string;
  destIp: string;
  srcPort?: number;
  destPort?: number;
  protocol?: string;
  serviceKey: string;
  serviceLabel?: string;
  nativeReason: string;
  shortReason: string;
  attributed: boolean;
  packets?: number;
  bytes?: number;
  dedupKey?: string;
  srcPodLabel?: string;
  destPodLabel?: string;
  nativeDetails: string[];
}

export interface DropsPairRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` using `__` (never `->`). */
  id: string;
  attention: boolean;
  srcIp: string;
  destIp: string;
  serviceKey: string;
  serviceLabel?: string;
  enforcerKind: DropsEnforcerKind;
  enforcerLabel: string;
  primaryReason: string;
  attributed: boolean;
  eventCount: number;
  packetCount?: number;
  byteCount?: number;
  devices: string[];
  sourcetypes: string[];
  nativeDetails: string[];
  srcPods: string[];
  destPods: string[];
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface DropsInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: DropsPairRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
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

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((v) => asStringArray(v));
  if (typeof value === "string") {
    const t = value.trim();
    return t ? [t] : [];
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return [String(value)];
  }
  return [];
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const num = Number(value.trim());
    if (Number.isFinite(num)) return num;
  }
  return undefined;
}

function asPort(value: unknown): number | undefined {
  const num = asFiniteNumber(value);
  if (num !== undefined && Number.isInteger(num) && num > 0 && num <= 65535) {
    return num;
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

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function normalizeProtocolName(value: unknown): string | undefined {
  const raw = asString(value).toUpperCase();
  if (!raw || raw === "0") return undefined;
  if (raw === "6") return "TCP";
  if (raw === "17") return "UDP";
  if (raw === "1") return "ICMP";
  if (raw === "58") return "IPV6-ICMP";
  if (raw === "132") return "SCTP";
  return raw;
}

function buildServiceDescriptor(
  protocol?: string,
  destPort?: number,
): { serviceKey: string; serviceLabel?: string } {
  if (protocol && destPort !== undefined) {
    return {
      serviceKey: `${protocol.toLowerCase()}_${destPort}`,
      serviceLabel: `${protocol}/${destPort}`,
    };
  }
  if (destPort !== undefined) {
    return {
      serviceKey: `port_${destPort}`,
      serviceLabel: String(destPort),
    };
  }
  if (protocol) {
    return {
      serviceKey: protocol.toLowerCase(),
      serviceLabel: protocol,
    };
  }
  return { serviceKey: "any" };
}

function isFtdDenyAction(action: string): boolean {
  const lower = action.trim().toLowerCase();
  if (!lower) return false;
  if (/^(allow|trust|monitor)\b/.test(lower)) return false;
  return /\b(block|drop|reset|deny|reject)\b/.test(lower);
}

const GENERIC_DENY_RE =
  /^(?:block(?:ed)?|deny|denied|drop(?:ped)?|reject(?:ed)?|reset(?:-client|-server|-both)?|client-rst|server-rst)$/i;

function detectSourceKind(
  row: ProtocolRow,
  hint?: DropsEnforcerKind,
): DropsEnforcerKind {
  const st = asString(row.sourcetype).toLowerCase();
  if (st === "cisco:sfw:estreamer") return "ftd";
  if (st === "cilium:hubble:flow") return "hubble";
  if (st === "cisco:dc:nd:flows") return "nd";
  if (st.startsWith("cisco:dc:aci")) return "aci";
  if (hint) return hint;
  if (row.AC_RuleAction !== undefined || row.InitiatorIP !== undefined) {
    return "ftd";
  }
  if (
    row.flow !== undefined ||
    row["flow.verdict"] !== undefined ||
    row.drop_reason_desc !== undefined
  ) {
    return "hubble";
  }
  if (
    row.dropPktCount !== undefined ||
    row.dropReasons !== undefined ||
    row.stats !== undefined
  ) {
    return "nd";
  }
  if (
    row.component === "acllogDropL3Pkt" ||
    (typeof row.dn === "string" && row.dn.includes("acllog"))
  ) {
    return "aci";
  }
  return "firewall";
}

/**
 * Normalizes one drop/deny row from any of the 5 supported source families
 * (FTD eStreamer, Cilium Hubble, Nexus Dashboard, ACI ACL drops, Generic Firewall/Cloud flow logs)
 * preserving native vendor reasons without conflating policy semantics.
 */
export function normalizeDropsRow(
  row: ProtocolRow,
  hintKind?: DropsEnforcerKind,
): NormalizedDropEvent | undefined {
  const kind = detectSourceKind(row, hintKind);
  const timestamp = asEpochSeconds(row._time) ?? 0;
  const host = asString(row.host);

  if (kind === "ftd") {
    const action = asString(row.AC_RuleAction ?? row.action);
    if (!isFtdDenyAction(action)) return undefined;
    const srcIp = asString(row.InitiatorIP ?? row.src_ip);
    const destIp = asString(row.ResponderIP ?? row.dest_ip);
    if (!srcIp || !destIp) return undefined;

    const srcPort = asPort(row.InitiatorPort ?? row.src_port);
    const destPort = asPort(row.ResponderPort ?? row.dest_port);
    const protocol = normalizeProtocolName(row.Protocol ?? row.protocol);
    const { serviceKey, serviceLabel } = buildServiceDescriptor(
      protocol,
      destPort,
    );

    const ruleName = asString(row.AccessControlRuleName ?? row.rule_name);
    const device =
      asString(row.Device) || asString(row.DeviceIP) || host || "ftd";
    const deviceIp = asString(row.DeviceIP);
    const ingressZone = asString(row.IngressZone);
    const egressZone = asString(row.EgressZone);
    const app = asString(row.Application);

    const initPkts = asFiniteNumber(row.InitiatorPackets);
    const respPkts = asFiniteNumber(row.ResponderPackets);
    const packets =
      initPkts !== undefined || respPkts !== undefined
        ? (initPkts ?? 0) + (respPkts ?? 0)
        : undefined;
    const initBytes = asFiniteNumber(row.InitiatorBytes);
    const respBytes = asFiniteNumber(row.ResponderBytes);
    const bytes =
      initBytes !== undefined || respBytes !== undefined
        ? (initBytes ?? 0) + (respBytes ?? 0)
        : undefined;

    const nativeReason = ruleName ? `${action} (${ruleName})` : action;
    const nativeDetails: string[] = [`AC_RuleAction: ${action}`];
    if (ruleName) nativeDetails.push(`AccessControlRuleName: ${ruleName}`);
    if (ingressZone || egressZone) {
      nativeDetails.push(`Zones: ${ingressZone || "?"} → ${egressZone || "?"}`);
    }
    if (app) nativeDetails.push(`Application: ${app}`);
    if (device) {
      nativeDetails.push(
        deviceIp && deviceIp !== device
          ? `Device: ${device} (${deviceIp})`
          : `Device: ${device}`,
      );
    }

    return {
      enforcerKind: "ftd",
      enforcerLabel: ENFORCER_LABELS.ftd,
      sourcetype: asString(row.sourcetype) || "cisco:sfw:estreamer",
      timestamp,
      device,
      srcIp,
      destIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      ...(protocol ? { protocol } : {}),
      serviceKey,
      ...(serviceLabel ? { serviceLabel } : {}),
      nativeReason,
      shortReason: action,
      attributed: Boolean(ruleName || action),
      ...(packets !== undefined ? { packets } : {}),
      ...(bytes !== undefined ? { bytes } : {}),
      nativeDetails,
    };
  }

  if (kind === "hubble") {
    const flow = asObject(row.flow);
    const ipObj = asObject(flow?.IP);
    const l4Obj = asObject(flow?.l4);
    const tcpObj = asObject(l4Obj?.TCP);
    const udpObj = asObject(l4Obj?.UDP);
    const srcObj = asObject(flow?.source);
    const dstObj = asObject(flow?.destination);

    const verdict = asString(
      row.verdict ?? row["flow.verdict"] ?? flow?.verdict,
    ).toUpperCase();
    if (verdict !== "DROPPED") return undefined;

    const srcIp = asString(
      row.src_ip ?? row["flow.IP.source"] ?? ipObj?.source,
    );
    const destIp = asString(
      row.dest_ip ?? row["flow.IP.destination"] ?? ipObj?.destination,
    );
    if (!srcIp || !destIp) return undefined;

    const srcPort = asPort(
      row.src_port ??
        tcpObj?.source_port ??
        udpObj?.source_port ??
        row["flow.l4.TCP.source_port"] ??
        row["flow.l4.UDP.source_port"],
    );
    const destPort = asPort(
      row.dest_port ??
        tcpObj?.destination_port ??
        udpObj?.destination_port ??
        row["flow.l4.TCP.destination_port"] ??
        row["flow.l4.UDP.destination_port"],
    );
    const inferredProto =
      tcpObj || row["flow.l4.TCP.destination_port"] !== undefined
        ? "TCP"
        : udpObj || row["flow.l4.UDP.destination_port"] !== undefined
          ? "UDP"
          : undefined;
    const protocol = normalizeProtocolName(
      row.transport ?? row.protocol ?? inferredProto,
    );
    const { serviceKey, serviceLabel } = buildServiceDescriptor(
      protocol,
      destPort,
    );

    const dropReasonDesc = asString(
      row.drop_reason_desc ??
        row["flow.drop_reason_desc"] ??
        flow?.drop_reason_desc,
    );
    const dropReasonCode = asString(
      row.drop_reason ?? row["flow.drop_reason"] ?? flow?.drop_reason,
    );

    const rawNode =
      asString(row.node) ||
      asString(flow?.node_name) ||
      asString(row.node_name) ||
      asString(row.device) ||
      host ||
      "cilium-node";
    const device = rawNode.includes("/")
      ? rawNode.split("/").pop() || rawNode
      : rawNode;

    const srcNs = asString(
      row.src_namespace ?? row.namespace ?? srcObj?.namespace,
    );
    const srcPod = asString(row.src_pod ?? row.pod_name ?? srcObj?.pod_name);
    const destNs = asString(row.dest_namespace ?? dstObj?.namespace);
    const destPod = asString(row.dest_pod ?? dstObj?.pod_name);

    const srcPodLabel =
      srcNs && srcPod ? `${srcNs}/${srcPod}` : srcPod || undefined;
    const destPodLabel =
      destNs && destPod ? `${destNs}/${destPod}` : destPod || undefined;

    const attributed = Boolean(
      dropReasonDesc || (dropReasonCode && dropReasonCode !== "0"),
    );
    const nativeReason =
      dropReasonDesc ||
      (dropReasonCode && dropReasonCode !== "0"
        ? `drop_reason ${dropReasonCode}`
        : "DROPPED (unattributed)");

    const nativeDetails: string[] = [`verdict: ${verdict}`];
    if (dropReasonDesc)
      nativeDetails.push(`drop_reason_desc: ${dropReasonDesc}`);
    if (dropReasonCode) nativeDetails.push(`drop_reason: ${dropReasonCode}`);
    if (srcPodLabel) nativeDetails.push(`source pod: ${srcPodLabel}`);
    if (destPodLabel) nativeDetails.push(`dest pod: ${destPodLabel}`);
    if (device) nativeDetails.push(`node: ${device}`);

    const flowTs = timestamp || asEpochSeconds(flow?.time) || 0;

    return {
      enforcerKind: "hubble",
      enforcerLabel: ENFORCER_LABELS.hubble,
      sourcetype: asString(row.sourcetype) || "cilium:hubble:flow",
      timestamp: flowTs,
      device,
      srcIp,
      destIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      ...(protocol ? { protocol } : {}),
      serviceKey,
      ...(serviceLabel ? { serviceLabel } : {}),
      nativeReason,
      shortReason: dropReasonDesc || "DROPPED",
      attributed,
      ...(srcPodLabel ? { srcPodLabel } : {}),
      ...(destPodLabel ? { destPodLabel } : {}),
      nativeDetails,
    };
  }

  if (kind === "nd") {
    const srcIp = asString(row.srcIp ?? row.src_ip);
    const destIp = asString(row.dstIp ?? row.dest_ip);
    if (!srcIp || !destIp) return undefined;

    let dropPktCount = asFiniteNumber(row.dropPktCount) ?? 0;
    const reasonSet = new Set<string>();
    for (const r of asStringArray(row.dropReasons)) {
      if (r && r !== "0" && r.toLowerCase() !== "none" && r !== "N/A") {
        reasonSet.add(r);
      }
    }

    let statsNode = "";
    if (Array.isArray(row.stats)) {
      let statsDropSum = 0;
      for (const entry of row.stats) {
        const obj = asObject(entry);
        if (!obj) continue;
        const cnt = asFiniteNumber(obj.dropPktCount);
        if (cnt !== undefined && cnt > 0) statsDropSum += cnt;
        for (const r of asStringArray(obj.dropReasons)) {
          if (r && r !== "0" && r.toLowerCase() !== "none" && r !== "N/A") {
            reasonSet.add(r);
          }
        }
        if (!statsNode) {
          const nodes = asStringArray(obj.nodeNames);
          if (nodes.length) statsNode = nodes[0];
        }
      }
      if (dropPktCount === 0 && statsDropSum > 0) {
        dropPktCount = statsDropSum;
      }
    }

    const dropReasons = [...reasonSet];
    if (dropPktCount <= 0 && dropReasons.length === 0) return undefined;

    const srcPort = asPort(row.srcPort ?? row.src_port);
    const destPort = asPort(row.dstPort ?? row.dest_port);
    const protocol = normalizeProtocolName(
      row.protocolName ?? row.protocol ?? row.transport,
    );
    const { serviceKey, serviceLabel } = buildServiceDescriptor(
      protocol,
      destPort,
    );

    const fabricName = asString(row.fabricName);
    const ndHost = asString(row.nd_host);
    const node = asString(row.node) || statsNode;
    const device =
      node || fabricName || ndHost || asString(row.device) || host || "nd";

    const attributed = dropReasons.length > 0;
    const nativeReason = attributed
      ? dropReasons.join(", ")
      : `${dropPktCount} dropped packets (no reason reported)`;
    const shortReason = attributed
      ? dropReasons[0]
      : `${dropPktCount} dropped pkts`;

    const nativeDetails: string[] = [];
    if (dropReasons.length) {
      nativeDetails.push(`dropReasons: ${dropReasons.join(", ")}`);
    }
    if (dropPktCount > 0) {
      nativeDetails.push(`dropPktCount: ${dropPktCount}`);
    }
    if (fabricName) nativeDetails.push(`fabricName: ${fabricName}`);
    if (ndHost) nativeDetails.push(`nd_host: ${ndHost}`);
    if (node) nativeDetails.push(`node: ${node}`);

    return {
      enforcerKind: "nd",
      enforcerLabel: ENFORCER_LABELS.nd,
      sourcetype: asString(row.sourcetype) || "cisco:dc:nd:flows",
      timestamp: timestamp || asEpochSeconds(row.ts) || 0,
      device,
      srcIp,
      destIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      ...(protocol ? { protocol } : {}),
      serviceKey,
      ...(serviceLabel ? { serviceLabel } : {}),
      nativeReason,
      shortReason,
      attributed,
      ...(dropPktCount > 0 ? { packets: dropPktCount } : {}),
      nativeDetails,
    };
  }

  if (kind === "aci") {
    const stLower = asString(row.sourcetype).toLowerCase();
    const component = asString(row.component);
    const dn = asString(row.dn);
    const dropReasonRaw = asString(row.drop_reason);
    const contractName = asString(row.contract_name);
    const descr = asString(row.descr);
    const isAclDropL3 =
      component === "acllogDropL3Pkt" ||
      dropReasonRaw.toLowerCase() === "acllogdropl3pkt" ||
      /dropl3pkt/i.test(dn);

    if (stLower === "cisco:dc:aci:syslog") {
      const actionRaw = asString(row.action);
      const looksLikeDrop =
        Boolean(dropReasonRaw) ||
        isAclDropL3 ||
        /\b(drop|deny|block)\b/i.test(`${actionRaw} ${descr}`);
      if (!looksLikeDrop) return undefined;
    } else if (
      stLower === "cisco:dc:aci:class" &&
      !isAclDropL3 &&
      !dropReasonRaw
    ) {
      return undefined;
    }

    const srcIp = asString(row.src_ip ?? row.srcIp);
    const destIp = asString(row.dest_ip ?? row.dstIp);
    if (!srcIp || !destIp) return undefined;

    const srcPort = asPort(row.src_port ?? row.srcPort);
    const destPort = asPort(row.dest_port ?? row.dstPort);
    const protocol = normalizeProtocolName(row.protocol ?? row.transport);
    const { serviceKey, serviceLabel } = buildServiceDescriptor(
      protocol,
      destPort,
    );

    const dnNodeMatch = /topology\/(pod-\d+\/node-\d+)/i.exec(dn);
    const dnTenantMatch = /\/tn-([^/]+)/i.exec(dn);
    const dnVrfMatch = /\/ctx-([^/]+)/i.exec(dn);

    const node = asString(row.node) || (dnNodeMatch ? dnNodeMatch[1] : "");
    const tenant =
      asString(row.tenant) || (dnTenantMatch ? dnTenantMatch[1] : "");
    const vrf =
      asString(row.vrf) ||
      (dnVrfMatch ? dnVrfMatch[1] : asString(row.vrfEncap));
    const device =
      node || asString(row.device) || asString(row.apic_host) || host || "apic";

    const reasonText = dropReasonRaw || (isAclDropL3 ? "acllogDropL3Pkt" : "");
    const attributed = Boolean(reasonText || contractName || descr);
    const nativeReason =
      reasonText && contractName
        ? `${reasonText} (contract ${contractName})`
        : reasonText ||
          (contractName ? `Contract ${contractName}` : "") ||
          descr ||
          "ACI ACL drop";
    const shortReason = contractName || reasonText || "ACL drop";

    const bytes = asFiniteNumber(row.bytes ?? row.pktLen);
    const explicitPackets = asFiniteNumber(row.packets);
    const packets =
      explicitPackets !== undefined
        ? explicitPackets
        : isAclDropL3
          ? 1
          : undefined;

    const nativeDetails: string[] = [];
    if (reasonText) nativeDetails.push(`drop_reason: ${reasonText}`);
    if (contractName) nativeDetails.push(`contract_name: ${contractName}`);
    if (tenant) nativeDetails.push(`tenant: ${tenant}`);
    if (vrf) nativeDetails.push(`vrf: ${vrf}`);
    if (node) nativeDetails.push(`node: ${node}`);
    if (descr) nativeDetails.push(`descr: ${descr}`);
    if (dn) nativeDetails.push(`dn: ${dn}`);

    return {
      enforcerKind: "aci",
      enforcerLabel: ENFORCER_LABELS.aci,
      sourcetype: asString(row.sourcetype) || "cisco:dc:aci:class",
      timestamp: timestamp || asEpochSeconds(row.timeStamp) || 0,
      device,
      srcIp,
      destIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      ...(protocol ? { protocol } : {}),
      serviceKey,
      ...(serviceLabel ? { serviceLabel } : {}),
      nativeReason,
      shortReason,
      attributed,
      ...(packets !== undefined ? { packets } : {}),
      ...(bytes !== undefined ? { bytes } : {}),
      ...(isAclDropL3 && dn ? { dedupKey: `aci:${dn}` } : {}),
      nativeDetails,
    };
  }

  // Generic Firewall / Cloud Flow-Log Denies
  const action = asString(row.action ?? row.verdict);
  if (!GENERIC_DENY_RE.test(action)) return undefined;

  const srcIp = asString(row.src_ip ?? row.srcip ?? row.srcaddr);
  const destIp = asString(row.dest_ip ?? row.dstip ?? row.dstaddr);
  if (!srcIp || !destIp) return undefined;

  const srcPort = asPort(row.src_port ?? row.srcport);
  const destPort = asPort(row.dest_port ?? row.dstport);
  const protocol = normalizeProtocolName(
    row.transport ?? row.protocol ?? row.proto,
  );
  const { serviceKey, serviceLabel } = buildServiceDescriptor(
    protocol,
    destPort,
  );

  const reason = asString(row.reason ?? row.drop_reason);
  const ruleName = asString(row.rule_name);
  const aclName = asString(row.acl_name);
  const policyName = asString(row.policy_name);
  const policyRef = ruleName || aclName || policyName;
  const device =
    asString(row.device) || asString(row.exporter_ip) || host || "firewall";
  const exporterIp = asString(row.exporter_ip);
  const sourcetype = asString(row.sourcetype) || "firewall:deny";

  const attributed = Boolean(policyRef || reason);
  const nativeReason =
    policyRef && reason
      ? `${action} · ${policyRef} (${reason})`
      : policyRef
        ? `${action} (${policyRef})`
        : reason
          ? `${action} (${reason})`
          : action;
  const shortReason = policyRef || reason || action;

  const packets = asFiniteNumber(row.packets);
  const bytes = asFiniteNumber(row.bytes);

  const nativeDetails: string[] = [`action: ${action}`];
  if (reason) nativeDetails.push(`reason: ${reason}`);
  if (ruleName) nativeDetails.push(`rule_name: ${ruleName}`);
  if (aclName) nativeDetails.push(`acl_name: ${aclName}`);
  if (policyName) nativeDetails.push(`policy_name: ${policyName}`);
  if (device) nativeDetails.push(`device: ${device}`);
  if (exporterIp && exporterIp !== device) {
    nativeDetails.push(`exporter_ip: ${exporterIp}`);
  }
  if (sourcetype) nativeDetails.push(`sourcetype: ${sourcetype}`);

  return {
    enforcerKind: "firewall",
    enforcerLabel: ENFORCER_LABELS.firewall,
    sourcetype,
    timestamp,
    device,
    srcIp,
    destIp,
    ...(srcPort !== undefined ? { srcPort } : {}),
    ...(destPort !== undefined ? { destPort } : {}),
    ...(protocol ? { protocol } : {}),
    serviceKey,
    ...(serviceLabel ? { serviceLabel } : {}),
    nativeReason,
    shortReason,
    attributed,
    ...(packets !== undefined ? { packets } : {}),
    ...(bytes !== undefined ? { bytes } : {}),
    nativeDetails,
  };
}

function buildSparklineBuckets(
  events: readonly NormalizedDropEvent[],
  earliest: number,
  latest: number,
  extract: (ev: NormalizedDropEvent) => number | undefined,
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const sums = new Array<number>(buckets).fill(0);
  const seen = new Array<boolean>(buckets).fill(false);
  for (const ev of events) {
    const val = extract(ev);
    if (val === undefined) continue;
    const ts = ev.timestamp || earliest;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ts - earliest) / span) * buckets)),
    );
    sums[idx] += val;
    seen[idx] = true;
  }
  const activeBuckets = seen.filter(Boolean).length;
  return activeBuckets >= 2 ? sums : [];
}

/**
 * Pure aggregation of normalized multi-vendor drop events into Overview rows,
 * KPI tiles, Source × Destination HeatMatrix, SwimlaneTimeline, and plain-language verdict.
 */
export function buildDropsAnalysis(options: {
  events: readonly { event: NormalizedDropEvent; indexName: string }[];
  thresholds: ResolvedDropsThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
}): DropsInvestigationResult {
  const { events, thresholds, earliest, latest, outcomes, capped } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyPartialOutcome = outcomes.some((o) => o.state === "partial");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial = anyPartialOutcome || capped || anyDegraded;

  // Deduplicate ACI acllogDropL3Pkt repolls across APIC polls by DN.
  const deduped: { event: NormalizedDropEvent; indexName: string }[] = [];
  const seenDedupKeys = new Set<string>();
  for (const entry of events) {
    if (entry.event.dedupKey) {
      if (seenDedupKeys.has(entry.event.dedupKey)) continue;
      seenDedupKeys.add(entry.event.dedupKey);
    }
    deduped.push(entry);
  }

  if (!deduped.length) {
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
        outcomes,
        capped,
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
        timelineEvents: [],
        outcomes,
        capped,
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (capped || anyPartialOutcome) {
      return {
        verdict:
          "Search hit row cap before matching drop events could be confirmed.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        outcomes,
        capped: true,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap with zero matching drop events; narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict: "No drops observed in configured sources.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      outcomes,
      capped: false,
      bannerState: "empty",
      bannerReason:
        "No matching deny or drop events observed in configured sources for this UTC window.",
      checkedAt: nowSec,
    };
  }

  // Group by (srcIp, destIp, enforcerKind, serviceKey)
  interface GroupBucket {
    id: string;
    srcIp: string;
    destIp: string;
    enforcerKind: DropsEnforcerKind;
    enforcerLabel: string;
    serviceKey: string;
    serviceLabel?: string;
    indexName: string;
    events: NormalizedDropEvent[];
  }
  const groups = new Map<string, GroupBucket>();

  for (const entry of deduped) {
    const ev = entry.event;
    const id = makeDropRowId(
      ev.srcIp,
      ev.destIp,
      ev.enforcerKind,
      ev.serviceKey,
    );
    const existing = groups.get(id);
    if (existing) {
      existing.events.push(ev);
      if (!existing.serviceLabel && ev.serviceLabel) {
        existing.serviceLabel = ev.serviceLabel;
      }
    } else {
      groups.set(id, {
        id,
        srcIp: ev.srcIp,
        destIp: ev.destIp,
        enforcerKind: ev.enforcerKind,
        enforcerLabel: ev.enforcerLabel,
        serviceKey: ev.serviceKey,
        ...(ev.serviceLabel ? { serviceLabel: ev.serviceLabel } : {}),
        indexName: entry.indexName,
        events: [ev],
      });
    }
  }

  const rows: DropsPairRow[] = [];
  for (const group of groups.values()) {
    const eventCount = group.events.length;
    const packetEvents = group.events
      .map((e) => e.packets)
      .filter((p): p is number => p !== undefined);
    const byteEvents = group.events
      .map((e) => e.bytes)
      .filter((b): b is number => b !== undefined);
    const packetCount = packetEvents.length
      ? packetEvents.reduce((a, b) => a + b, 0)
      : undefined;
    const byteCount = byteEvents.length
      ? byteEvents.reduce((a, b) => a + b, 0)
      : undefined;

    const reasonCounts = new Map<string, number>();
    let anyAttributed = false;
    for (const ev of group.events) {
      if (ev.attributed) anyAttributed = true;
      reasonCounts.set(
        ev.nativeReason,
        (reasonCounts.get(ev.nativeReason) ?? 0) + 1,
      );
    }
    const primaryReason =
      [...reasonCounts.entries()].sort(
        (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
      )[0]?.[0] ?? "Drop observed";

    const devices = [...new Set(group.events.map((e) => e.device))];
    const sourcetypes = [...new Set(group.events.map((e) => e.sourcetype))];
    const nativeDetails = [
      ...new Set(group.events.flatMap((e) => e.nativeDetails)),
    ].slice(0, 12);
    const srcPods = [
      ...new Set(
        group.events
          .map((e) => e.srcPodLabel)
          .filter((v): v is string => Boolean(v)),
      ),
    ];
    const destPods = [
      ...new Set(
        group.events
          .map((e) => e.destPodLabel)
          .filter((v): v is string => Boolean(v)),
      ),
    ];
    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t) => t > 0);

    const attention = eventCount >= thresholds.dropWarnCount;
    const status: ProtocolStatus = attention ? "attention" : "ok";
    const rowReasons: string[] = [];
    if (attention) {
      rowReasons.push(
        `${group.enforcerLabel}: ${primaryReason} (${eventCount} ${eventCount === 1 ? "event" : "events"})`,
      );
      if (!anyAttributed) {
        rowReasons.push(
          "Drop reported without a native rule, contract, or reason description.",
        );
      }
    } else {
      rowReasons.push(
        `${eventCount} ${eventCount === 1 ? "drop" : "drops"} below warn threshold (${thresholds.dropWarnCount}).`,
      );
    }

    rows.push({
      id: group.id,
      attention,
      srcIp: group.srcIp,
      destIp: group.destIp,
      serviceKey: group.serviceKey,
      ...(group.serviceLabel ? { serviceLabel: group.serviceLabel } : {}),
      enforcerKind: group.enforcerKind,
      enforcerLabel: group.enforcerLabel,
      primaryReason,
      attributed: anyAttributed,
      eventCount,
      ...(packetCount !== undefined ? { packetCount } : {}),
      ...(byteCount !== undefined ? { byteCount } : {}),
      devices,
      sourcetypes,
      nativeDetails,
      srcPods,
      destPods,
      status,
      reasons: rowReasons,
      indexName: group.indexName,
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.attributed !== b.attributed) return a.attributed ? -1 : 1;
    if (a.eventCount !== b.eventCount) return b.eventCount - a.eventCount;
    return (
      a.srcIp.localeCompare(b.srcIp) ||
      a.destIp.localeCompare(b.destIp) ||
      a.enforcerLabel.localeCompare(b.enforcerLabel)
    );
  });

  // KPI strip (<= 4 tiles, one metric per tile, readable units)
  const allEvents = deduped.map((d) => d.event);
  const totalEvents = allEvents.length;
  const distinctPairs = new Set(rows.map((r) => `${r.srcIp}\0${r.destIp}`))
    .size;

  const enforcerCounts = new Map<
    DropsEnforcerKind,
    { label: string; count: number }
  >();
  for (const ev of allEvents) {
    const prev = enforcerCounts.get(ev.enforcerKind);
    if (prev) {
      prev.count += 1;
    } else {
      enforcerCounts.set(ev.enforcerKind, {
        label: ev.enforcerLabel,
        count: 1,
      });
    }
  }
  const topEnforcerEntry = [...enforcerCounts.entries()].sort(
    (a, b) => b[1].count - a[1].count || a[1].label.localeCompare(b[1].label),
  )[0];

  const packetValues = allEvents
    .map((e) => e.packets)
    .filter((p): p is number => p !== undefined);
  const hasPacketCounts = packetValues.length > 0;
  const totalPackets = packetValues.reduce((a, b) => a + b, 0);

  const flaggedRows = rows.filter((r) => r.attention);
  const dropSpark = buildSparklineBuckets(allEvents, earliest, latest, () => 1);
  const topEnforcerSpark = topEnforcerEntry
    ? buildSparklineBuckets(allEvents, earliest, latest, (ev) =>
        ev.enforcerKind === topEnforcerEntry[0] ? 1 : 0,
      )
    : [];
  const packetSpark = hasPacketCounts
    ? buildSparklineBuckets(allEvents, earliest, latest, (ev) => ev.packets)
    : [];

  const kpis: ProtocolKpi[] = [
    {
      id: "drop-events",
      label: "Drop Events",
      value: formatCount(totalEvents),
      unit: totalEvents === 1 ? "event" : "events",
      status: flaggedRows.length > 0 ? "attention" : "ok",
      ...(dropSpark.length ? { sparkline: dropSpark } : {}),
    },
    {
      id: "blocked-pairs",
      label: "Blocked Pairs",
      value: formatCount(distinctPairs),
      unit: distinctPairs === 1 ? "pair" : "pairs",
      status: flaggedRows.length > 0 ? "attention" : "ok",
      ...(dropSpark.length ? { sparkline: dropSpark } : {}),
    },
    {
      id: "top-enforcer",
      label: "Top Enforcer",
      value: topEnforcerEntry ? topEnforcerEntry[1].label : "Not covered",
      ...(topEnforcerEntry
        ? {
            unit: `${formatCount(topEnforcerEntry[1].count)} ${topEnforcerEntry[1].count === 1 ? "drop" : "drops"}`,
          }
        : {}),
      status: topEnforcerEntry
        ? flaggedRows.length > 0
          ? "attention"
          : "ok"
        : "not_covered",
      ...(topEnforcerSpark.length ? { sparkline: topEnforcerSpark } : {}),
    },
    {
      id: "dropped-packets",
      label: "Dropped Packets",
      value: hasPacketCounts ? formatCount(totalPackets) : "Not covered",
      ...(hasPacketCounts ? { unit: totalPackets === 1 ? "pkt" : "pkts" } : {}),
      status: !hasPacketCounts
        ? "not_covered"
        : flaggedRows.length > 0
          ? "attention"
          : "ok",
      ...(packetSpark.length ? { sparkline: packetSpark } : {}),
    },
  ];

  // Matrix: Source × Destination (rows sorted flagged-first)
  const srcOrder = new Map<string, { attention: boolean; count: number }>();
  const dstOrder = new Map<string, { count: number }>();
  for (const r of rows) {
    const s = srcOrder.get(r.srcIp) ?? { attention: false, count: 0 };
    s.attention = s.attention || r.attention;
    s.count += r.eventCount;
    srcOrder.set(r.srcIp, s);

    const d = dstOrder.get(r.destIp) ?? { count: 0 };
    d.count += r.eventCount;
    dstOrder.set(r.destIp, d);
  }
  const matrixRows = [...srcOrder.entries()]
    .sort(
      (a, b) =>
        (a[1].attention === b[1].attention ? 0 : a[1].attention ? -1 : 1) ||
        b[1].count - a[1].count ||
        a[0].localeCompare(b[0]),
    )
    .map(([src]) => src);
  const matrixCols = [...dstOrder.entries()]
    .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .map(([dst]) => dst);

  const cellGroups = new Map<string, DropsPairRow[]>();
  for (const r of rows) {
    const key = `${r.srcIp}\0${r.destIp}`;
    const list = cellGroups.get(key) ?? [];
    list.push(r);
    cellGroups.set(key, list);
  }
  const matrixCells: ProtocolMatrixCell[] = [];
  for (const groupRows of cellGroups.values()) {
    const lead = groupRows[0];
    const sumEvents = groupRows.reduce((acc, r) => acc + r.eventCount, 0);
    const anyCellAttention = groupRows.some((r) => r.attention);
    const enforcers = [...new Set(groupRows.map((r) => r.enforcerLabel))];
    const cellValue =
      enforcers.length === 1
        ? `${lead.enforcerLabel} (${formatCount(sumEvents)})`
        : `${enforcers.length} enforcers (${formatCount(sumEvents)})`;
    matrixCells.push({
      row: lead.srcIp,
      col: lead.destIp,
      status: anyCellAttention ? "attention" : "ok",
      value: cellValue,
      count: sumEvents,
      detail: groupRows
        .map((r) => `${r.enforcerLabel}: ${r.primaryReason}`)
        .join("; "),
      itemId: lead.id,
    });
  }

  // SwimlaneTimeline grouped by enforcement point / native source
  const timelineEvents: ProtocolTimelineEvent[] = deduped
    .filter(({ event }) => event.timestamp > 0)
    .slice(0, 64)
    .map(({ event }, idx) => {
      const rowId = makeDropRowId(
        event.srcIp,
        event.destIp,
        event.enforcerKind,
        event.serviceKey,
      );
      const matchingRow = rows.find((r) => r.id === rowId);
      const kind: ProtocolTimelineEvent["kind"] =
        matchingRow && !matchingRow.attention ? "info" : "attention";
      const lanePrefix =
        event.enforcerKind === "nd" ? "ND" : event.enforcerLabel;
      return {
        id: `${rowId}\u001f${idx}`,
        lane: `${lanePrefix} · ${shortenDeviceLabel(event.device)}`,
        timestamp: event.timestamp,
        kind,
        label: `${event.srcIp} → ${event.destIp} (${event.shortReason})`,
        detail: `${event.enforcerLabel}: ${event.nativeReason}`,
      };
    });

  // Plain-language single-sentence verdict above the fold
  const attributedRows = rows.filter((r) => r.attributed);
  const topReasons: string[] = [];
  const seenSummaries = new Set<string>();
  for (const r of rows) {
    if (!r.attributed) continue;
    const snippet = `${r.enforcerLabel} ${r.primaryReason}`;
    if (!seenSummaries.has(snippet)) {
      seenSummaries.add(snippet);
      topReasons.push(snippet);
    }
    if (topReasons.length >= 2) break;
  }

  let verdict: string;
  let verdictStatus: ProtocolStatus;
  const flowNoun = rows.length === 1 ? "blocked flow" : "blocked flows";

  if (flaggedRows.length === 0) {
    verdict = `${rows.length} low-volume ${flowNoun} observed below alert threshold (${thresholds.dropWarnCount}).`;
    verdictStatus = "ok";
  } else if (attributedRows.length > 0) {
    const reasonsPhrase = topReasons.join(" and ");
    const unattributedCount = rows.length - attributedRows.length;
    const unattributedNote =
      unattributedCount > 0 ? ` (${unattributedCount} unattributed)` : "";
    verdict = `${attributedRows.length} of ${rows.length} ${flowNoun} attributed: ${reasonsPhrase}${unattributedNote}.`;
    verdictStatus = "attention";
  } else {
    verdict = `${rows.length} ${flowNoun} observed without native rule or drop reason.`;
    verdictStatus = "attention";
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
    ? `One or more sources denied access (${blockedDetail ?? "access denied"}); drop visibility is incomplete.`
    : anyUnavailable
      ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); drop visibility is incomplete.`
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
    outcomes,
    capped,
    ...(anyPartial
      ? {
          bannerState: "partial" as const,
          bannerReason: partialReason,
        }
      : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateDropsOptions {
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

function resolveSourcesForProfile(
  thresholds: ResolvedDropsThresholds,
): DropsEnforcerKind[] {
  if (thresholds.sourceKind !== "auto") {
    return [thresholds.sourceKind];
  }
  if (thresholds.sourcetype) {
    const st = thresholds.sourcetype.toLowerCase();
    if (st === "cisco:sfw:estreamer") return ["ftd"];
    if (st === "cilium:hubble:flow") return ["hubble"];
    if (st === "cisco:dc:nd:flows") return ["nd"];
    if (st.startsWith("cisco:dc:aci")) return ["aci"];
    return ["firewall"];
  }
  return ["ftd", "hubble", "nd", "aci", "firewall"];
}

function buildSearchForKind(options: {
  kind: DropsEnforcerKind;
  index: string;
  sourcetype?: string;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  switch (options.kind) {
    case "ftd":
      return buildDropsFtdSearch(options);
    case "hubble":
      return buildDropsHubbleSearch(options);
    case "nd":
      return buildDropsNdSearch(options);
    case "aci":
      return buildDropsAciSearch(options);
    case "firewall":
      return buildDropsFirewallSearch(options);
  }
}

/**
 * Executes the on-demand Blocked Traffic & Drop Reasons investigation across
 * configured `drops` profiles, rechecking the `adm_protocol_profiles` fingerprint
 * so stale configuration cannot pass.
 */
export async function investigateDrops(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateDropsOptions = {},
): Promise<DropsInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "drops" && p.scope === request.scope,
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
      outcomes: [],
      capped: false,
      bannerState: "unavailable",
      bannerReason: `No drops profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedDropEvent; indexName: string }[] = [];
    let capped = false;
    const primaryThresholds = resolveDropsThresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const thresholds = resolveDropsThresholds(profile);
      const kinds = resolveSourcesForProfile(thresholds);

      for (const kind of kinds) {
        signal.throwIfAborted();
        const spl = buildSearchForKind({
          kind,
          index: profile.index,
          sourcetype: thresholds.sourcetype,
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "drops",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: kind,
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        for (const row of res.rows) {
          const norm = normalizeDropsRow(row, kind);
          if (norm) collected.push({ event: norm, indexName: profile.index });
        }
      }
    }

    return buildDropsAnalysis({
      events: collected,
      thresholds: primaryThresholds,
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
    drops: validateDropsExtra,
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
        outcomes: [],
        capped: false,
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Hub "Check all" summary runner for `drops`.
 * Downgrades degraded/capped summaries: `ok` -> `attention`, `none_observed` -> `unknown`.
 */
export async function summarizeDrops(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateDropsOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateDrops(
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
    lens: "drops",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}

export function formatDropVolume(packets?: number, bytes?: number): string {
  const parts: string[] = [];
  if (packets !== undefined) {
    parts.push(`${formatCount(packets)} ${packets === 1 ? "pkt" : "pkts"}`);
  }
  if (bytes !== undefined) {
    parts.push(formatBytes(bytes));
  }
  return parts.join(" · ");
}
