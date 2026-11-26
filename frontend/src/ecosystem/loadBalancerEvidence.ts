import type { Row } from "../rows";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import {
  EVIDENCE_LIMITS,
  normalizeIp,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "../data/evidence";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "../data/supplementalEvidence";
import type { SearchClient } from "../data/searchClient";
import {
  assertActiveSource,
  baseSearch,
  cidrPredicate,
  first,
  isoSeconds,
  lateWindow,
  matchedFields,
  parseInteger,
  recordOrigin,
  reported,
  slashNaiveSeconds,
  socketValue,
  splRex,
  supplementalTail,
  verifiedAuthorities,
  type Endpoint,
  type SourceIdentity,
} from "./shared";

export type LoadBalancerSource = "f5_ltm_http" | "aws_elb_access";

/** Access logs are written when a request or connection completes. */
export const LB_LATE_LOG_SECONDS = 3600;
const INPUT_LIMIT = EVIDENCE_LIMITS.input;
const MAX_ZONE_OFFSET = 14 * 3600;

export interface LoadBalancerContract extends SourceIdentity {
  source: LoadBalancerSource;
  producer: string;
  /** Projection lines after the base search; every column is allowlisted. */
  projection: readonly string[];
  /** SPL predicate for rows the adapter can read; others are kept and rejected. */
  parseOk: string;
  columns: readonly string[];
  addressColumns: readonly string[];
}

/**
 * Splunk Add-on for F5 BIG-IP 7.0.x, "Configure iRules for LTM": the
 * documented `Splunk-iRule-HTTP` and `Splunk-iRule-LB_FAILED` HSL messages,
 * in their published key order. Atlas extracts the keys itself. Quoted values
 * (User-Agent, Referer, cookie names, LB::server) are client- or
 * configuration-controlled; the anchored pattern plus an exact quote count
 * keeps an injected `,key=` from being read as a field. URI, cookie, user and
 * User-Agent are matched but never projected.
 */
export const F5_IRULE_PATTERN =
  '^(?:<\\d{1,3}>)?[^,"]{0,128}?,f5_irule=(?<f5_irule>Splunk-iRule-(?:HTTP|LB_FAILED))' +
  ",src_ip=(?<f5_client_ip>[0-9A-Fa-f:.]{2,45})(?:%(?<f5_client_rd>\\d{1,5}))?" +
  ",vip=(?<f5_vip>[0-9A-Fa-f:.]{2,45})(?:%(?<f5_vip_rd>\\d{1,5}))?" +
  ",http_method=(?<f5_method>[A-Z]{0,16})" +
  ',http_host=[^,"]{0,300}?:(?<f5_vip_port>\\d{1,5})' +
  ',http_uri=[^,"]{0,8192},http_url=[^,"]{0,8192}' +
  ",http_version=(?<f5_http_version>[0-9.]{0,8})" +
  ',http_user_agent="[^"]{0,8192}",http_content_type=[^,"]{0,256},http_referrer="[^"]{0,8192}"' +
  ",req_start_time=(?<f5_req_start>[0-9/: ]{19})" +
  ',cookie="[^"]{0,8192}",user=[^,"]{0,256}' +
  ',virtual_server="(?<f5_pool>[^" ]{0,255})(?: [^"]{0,128})?"' +
  ",bytes_in=(?<f5_bytes_in>\\d{0,19})" +
  "(?:,res_start_time=(?<f5_res_start>[0-9/: ]{19})" +
  ",node=(?<f5_node>[0-9A-Fa-f:.]{2,45})(?:%(?<f5_node_rd>\\d{1,5}))?" +
  ",node_port=(?<f5_node_port>\\d{1,5}),http_status=(?<f5_status>\\d{3})" +
  ",req_elapsed_time=(?<f5_elapsed_ms>\\d{1,19}),bytes_out=(?<f5_bytes_out>\\d{0,19}))?" +
  "\\s*$";
/** Four quoted values in both documented messages. */
export const F5_QUOTE_COUNT = 8;

const F5_COLUMNS = [
  "f5_irule",
  "f5_client_ip",
  "f5_client_rd",
  "f5_vip",
  "f5_vip_rd",
  "f5_vip_port",
  "f5_method",
  "f5_http_version",
  "f5_req_start",
  "f5_pool",
  "f5_bytes_in",
  "f5_res_start",
  "f5_node",
  "f5_node_rd",
  "f5_node_port",
  "f5_status",
  "f5_elapsed_ms",
  "f5_bytes_out",
] as const;

export const F5_LTM_HTTP: LoadBalancerContract = {
  source: "f5_ltm_http",
  label: "F5 BIG-IP LTM request legs",
  producer: "Splunk Add-on for F5 BIG-IP (iRule HSL)",
  observerKind: "f5_bigip",
  // The add-on documents f5:bigip:ltm:lb:failed:irule; SC4S documents
  // f5:bigip:ltm:failed:irule for the same message.
  sourcetypes: [
    "f5:bigip:ltm:http:irule",
    "f5:bigip:ltm:lb:failed:irule",
    "f5:bigip:ltm:failed:irule",
  ],
  projection: [
    splRex(F5_IRULE_PATTERN),
    '| eval f5_quotes=len(_raw)-len(replace(_raw,"\\"",""))',
  ],
  parseOk: "isnotnull(f5_irule) AND f5_quotes=" + F5_QUOTE_COUNT,
  columns: F5_COLUMNS,
  addressColumns: ["f5_client_ip", "f5_vip", "f5_node"],
};

/**
 * AWS "Access logs for your Application Load Balancer", fields 1-36 in
 * order. Fields 31-36 are optional (older logs end at 29 or 30); anything
 * after the last documented field is ignored, as AWS instructs.
 */
export const ALB_PATTERN =
  "^(?<alb_type>https?|h2|grpcs|wss?) (?<alb_time>[0-9T:.Z-]{20,32}) (?<alb_elb>[A-Za-z0-9/._-]{1,256})" +
  " (?<alb_client>[0-9A-Fa-f:.\\[\\]]{3,64}) (?<alb_target>[0-9A-Fa-f:.\\[\\]-]{1,64})" +
  " (?<alb_request_s>-?[0-9.]{1,16}) (?<alb_target_s>-?[0-9.]{1,16}) (?<alb_response_s>-?[0-9.]{1,16})" +
  " (?<alb_status>\\d{3}|-) (?<alb_target_status>\\d{3}|-) (?<alb_received>\\d{1,19}) (?<alb_sent>\\d{1,19})" +
  ' "[^"]*" "[^"]*" \\S+ \\S+ (?<alb_target_group>\\S{1,512}) "[^"]*" "[^"]*" "[^"]*"' +
  " (?<alb_rule_priority>-?\\d{1,5}|-) (?<alb_created>[0-9T:.Z-]{20,32})" +
  ' "(?<alb_actions>[a-z,-]{0,128})" "[^"]*" "(?<alb_error_reason>[A-Za-z]{0,64}|-)"' +
  ' "(?<alb_target_list>[^"]{0,256})" "[^"]*" "[^"]*" "[^"]*"' +
  '(?: (?<alb_conn_trace>\\S{1,128}) "[^"]*" "[^"]*" "[^"]*" (?<alb_node_ip>[0-9A-Fa-f:.]{2,45})(?: \\S+ \\S+)?)?' +
  "(?: .*)?$";
/** Twelve quoted fields through position 29; fifteen once 31-33 are present. */
export const ALB_QUOTE_COUNTS = [24, 30] as const;

/**
 * AWS "Access logs for your Network Load Balancer" (TLS listeners only),
 * version 3.0 fields 1-23. Later fields (client certificate subject and
 * validity) can contain spaces and are not read.
 */
export const NLB_PATTERN =
  "^tls (?<nlb_version>\\d{1,2}\\.\\d{1,2}) (?<nlb_time>[0-9T:.Z-]{19,32}) (?<nlb_elb>[A-Za-z0-9/._-]{1,256})" +
  " (?<nlb_listener>[A-Za-z0-9/._-]{1,256}) (?<nlb_client>[0-9A-Fa-f:.\\[\\]]{3,64}) (?<nlb_destination>[0-9A-Fa-f:.\\[\\]]{3,64})" +
  " (?<nlb_connection_ms>\\d{1,19}) (?<nlb_handshake_ms>\\d{1,19}|-) (?<nlb_received>\\d{1,19}) (?<nlb_sent>\\d{1,19})" +
  " (?<nlb_tls_alert>\\S{1,16})(?: \\S+){9} (?<nlb_created>[0-9T:.Z-]{19,32}) (?<nlb_verify>Success|Failed:[A-Za-z]{1,64})" +
  "(?: .*)?$";

const SOCKET_IP = '"^\\[?(?<IP>[0-9A-Fa-f:.]{2,45}?)\\]?:\\d{1,5}$"';
function socketIp(field: string, ip: string): string {
  return "| rex field=" + field + " " + SOCKET_IP.replace("IP", ip);
}

const ELB_COLUMNS = [
  "alb_type",
  "alb_time",
  "alb_elb",
  "alb_client",
  "alb_target",
  "alb_request_s",
  "alb_target_s",
  "alb_response_s",
  "alb_status",
  "alb_target_status",
  "alb_received",
  "alb_sent",
  "alb_target_group",
  "alb_rule_priority",
  "alb_created",
  "alb_actions",
  "alb_error_reason",
  "alb_target_list",
  "alb_node_ip",
  "nlb_version",
  "nlb_time",
  "nlb_elb",
  "nlb_listener",
  "nlb_client",
  "nlb_destination",
  "nlb_connection_ms",
  "nlb_handshake_ms",
  "nlb_received",
  "nlb_sent",
  "nlb_tls_alert",
  "nlb_created",
  "nlb_verify",
] as const;

export const AWS_ELB_ACCESS: LoadBalancerContract = {
  source: "aws_elb_access",
  label: "AWS ALB/NLB access legs",
  producer: "Splunk Add-on for Amazon Web Services (ELB access logs)",
  observerKind: "aws_elb",
  sourcetypes: ["aws:elb:accesslogs"],
  projection: [
    splRex(ALB_PATTERN),
    splRex(NLB_PATTERN),
    '| eval elb_quotes=len(_raw)-len(replace(_raw,"\\"",""))',
    socketIp("alb_client", "alb_client_ip"),
    socketIp("alb_target", "alb_target_ip"),
    socketIp("nlb_client", "nlb_client_ip"),
    socketIp("nlb_destination", "nlb_destination_ip"),
  ],
  parseOk:
    "(isnotnull(alb_type) AND isnull(nlb_version) AND (" +
    ALB_QUOTE_COUNTS.map((count) => "elb_quotes=" + count).join(" OR ") +
    ")) OR (isnotnull(nlb_version) AND isnull(alb_type))",
  columns: ELB_COLUMNS,
  addressColumns: [
    "alb_client_ip",
    "alb_target_ip",
    "alb_node_ip",
    "nlb_client_ip",
    "nlb_destination_ip",
  ],
};

export const LOAD_BALANCER_CONTRACTS: Record<
  LoadBalancerSource,
  LoadBalancerContract
> = { f5_ltm_http: F5_LTM_HTTP, aws_elb_access: AWS_ELB_ACCESS };

export type LegRole =
  | "client"
  | "virtual_server_address"
  | "load_balancer_node"
  | "listener_or_endpoint"
  | "load_balancer_source"
  | "pool_member"
  | "target";

/** A leg endpoint is either reported (address, optional port) or explicitly not reported. */
export interface LegEndpoint {
  role: LegRole;
  ip?: string;
  port?: number;
  routeDomain?: number;
  /** Why the producer does not report this address or port. */
  notReported?: string;
}

export interface TransportLeg {
  source: LegEndpoint;
  destination: LegEndpoint;
}

export type LegField =
  "client_source" | "client_destination" | "server_destination";

export interface LoadBalancerObservation {
  schemaVersion: 1;
  source: LoadBalancerSource;
  sourcetype: string;
  /** Splunk host mapped to one verified observer; not a device identity proof. */
  authority: string;
  observerKind: string;
  scope: string;
  recordType: "f5_http" | "f5_lb_failed" | "alb_request" | "nlb_tls";
  /** F5 pool (from LB::server), ALB/NLB resource ID. */
  balancer?: string;
  targetGroup?: string;
  listener?: string;
  protocol: string;
  /** Client to the balancer, as reported. */
  clientLeg: TransportLeg;
  /** Balancer to the server, or the reason no server leg is reported. */
  serverLeg: TransportLeg | { notReported: string };
  outcome: "forwarded" | "not_forwarded" | "lb_failed" | "tls_connection";
  outcomeText: string;
  status: { balancer?: string; server?: string };
  counters: { requestBytes?: number; responseBytes?: number; basis: string };
  interval: EvidenceWindow;
  intervalBasis:
    | "request_start_to_response"
    | "request_start_only"
    | "request_received_to_response_sent"
    | "connection_start_to_end";
  eventTime: number;
  rowTime: number;
  indexedTime: number;
  inferredZoneOffsetSeconds?: number;
  index: string;
  eventFingerprint: string;
  matchedAddressFields: LegField[];
  attribution: "context_only";
  attributionReason: string;
  limitations: string[];
}

export const LOAD_BALANCER_COVERAGE = [
  "Each record is one request or connection at one load balancer. The client-side and server-side legs come from the same record and are shown separately; they are never merged into one flow.",
  "Virtual server, listener and load balancer node addresses belong to the balancer, not to an endpoint. A selected address matched there identifies the service entry point, not a workload.",
  "Server-side source addresses (SNAT, automap self IP, ALB node address) are not in these logs, so the server leg's source is shown as not reported.",
  "Records are context only. They do not create dependency or blocked-flow edges and do not change graph counters.",
  "No visible records does not prove traffic was absent: iRule attachment, access-log enablement, best-effort delivery and caller permissions limit coverage.",
];

export function loadBalancerSearchWindow(
  selection: EvidenceSelection,
): EvidenceWindow {
  return lateWindow(selection, LB_LATE_LOG_SECONDS);
}

export function buildLoadBalancerSearch(
  contract: LoadBalancerContract,
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const authorities = assertActiveSource(contract, config, selection);
  return [
    baseSearch(contract, config, authorities),
    ...contract.projection,
    "| eval lb_parse_ok=if(" + contract.parseOk + ",1,0)",
    "| where lb_parse_ok=0 OR (" +
      cidrPredicate(selection.addresses, contract.addressColumns) +
      ")",
    ...supplementalTail([...contract.columns, "lb_parse_ok"]),
  ].join("\n");
}

function address(row: Row, column: string): string | undefined {
  const value = reported(row, column);
  return value === undefined ? undefined : normalizeIp(value);
}

function int(row: Row, column: string, maximum: number): number | undefined {
  return parseInteger(reported(row, column), maximum);
}

function socket(row: Row, column: string): Endpoint | undefined {
  const value = reported(row, column);
  return value === undefined ? undefined : socketValue(value);
}

function seconds(row: Row, column: string): number {
  const value = first(row, column);
  if (value === undefined || value === "-1") return -1;
  if (!/^\d{1,6}(?:\.\d{1,6})?$/.test(value))
    throw new Error("Invalid processing time.");
  return Number(value);
}

interface Parsed {
  recordType: LoadBalancerObservation["recordType"];
  balancer?: string;
  targetGroup?: string;
  listener?: string;
  protocol: string;
  clientLeg: TransportLeg;
  serverLeg: LoadBalancerObservation["serverLeg"];
  outcome: LoadBalancerObservation["outcome"];
  outcomeText: string;
  status: LoadBalancerObservation["status"];
  counters: LoadBalancerObservation["counters"];
  interval: EvidenceWindow;
  intervalBasis: LoadBalancerObservation["intervalBasis"];
  eventTime: number;
  inferredZoneOffsetSeconds?: number;
  candidates: [LegField, Endpoint | undefined][];
  limitations: string[];
}

/**
 * The iRule formats `[clock seconds]` in the BIG-IP's local zone and the
 * add-on does not document how `_time` is assigned. Atlas infers a
 * quarter-hour zone offset from `_time` and accepts at most two minutes of
 * transport delay; anything else is rejected.
 */
export function f5ZoneOffset(
  rowTime: number,
  naive: readonly number[],
): number {
  const offsets = new Set<number>();
  for (const value of naive) {
    const offset = Math.round((rowTime - value) / 900) * 900;
    const residual = rowTime - value - offset;
    if (
      Math.abs(offset) <= MAX_ZONE_OFFSET &&
      residual >= -2 &&
      residual <= 120
    )
      offsets.add(offset);
  }
  if (offsets.size !== 1)
    throw new Error("Splunk event time does not derive from the iRule time.");
  return [...offsets][0];
}

function routeDomain(row: Row, column: string): number | undefined {
  return int(row, column, 65534);
}

function parseF5(row: Row, rowTime: number): Parsed {
  const rule = reported(row, "f5_irule");
  const http = rule === "Splunk-iRule-HTTP";
  if (!http && rule !== "Splunk-iRule-LB_FAILED")
    throw new Error("Unsupported iRule message.");
  if (http !== (reported(row, "f5_res_start") !== undefined))
    throw new Error("iRule message fields do not match its type.");
  const requestNaive = slashNaiveSeconds(reported(row, "f5_req_start")!);
  const responseNaive = http
    ? slashNaiveSeconds(reported(row, "f5_res_start")!)
    : requestNaive;
  if (responseNaive < requestNaive || responseNaive - requestNaive > 3600)
    throw new Error("iRule request and response times are inconsistent.");
  const offset = f5ZoneOffset(rowTime, [requestNaive, responseNaive]);
  const elapsed = int(row, "f5_elapsed_ms", 3_600_000);
  const client = address(row, "f5_client_ip");
  const vip = address(row, "f5_vip");
  const vipPort = int(row, "f5_vip_port", 65535);
  const pool = reported(row, "f5_pool");
  if (!client || !vip || vipPort === undefined || !pool)
    throw new Error("iRule client leg is incomplete.");
  if (!/^[A-Za-z0-9/._:-]{1,255}$/.test(pool))
    throw new Error("Invalid pool name.");
  const clientRd = routeDomain(row, "f5_client_rd");
  const vipRd = routeDomain(row, "f5_vip_rd");
  const clientLeg: TransportLeg = {
    source: {
      role: "client",
      ip: client,
      ...(clientRd !== undefined ? { routeDomain: clientRd } : {}),
      notReported: "The iRule does not log the client port.",
    },
    destination: {
      role: "virtual_server_address",
      ip: vip,
      port: vipPort,
      ...(vipRd !== undefined ? { routeDomain: vipRd } : {}),
    },
  };
  const limitations = [
    "client_port_not_logged",
    "virtual_server_address_is_balancer_not_identity",
    "byte_counts_are_content_length_headers",
    "f5_time_zone_inferred_from_splunk",
    "host_mapping_does_not_prove_device_identity",
  ];
  const method = reported(row, "f5_method");
  const version = reported(row, "f5_http_version");
  const protocol = "http" + (version ? "/" + version : "");
  const requestBytes = int(row, "f5_bytes_in", Number.MAX_SAFE_INTEGER);
  const start = requestNaive + offset;
  if (!http) {
    return {
      recordType: "f5_lb_failed",
      balancer: pool,
      protocol,
      clientLeg,
      serverLeg: {
        notReported:
          "Load balancing failed; no pool member connection was made or logged.",
      },
      outcome: "lb_failed",
      outcomeText:
        "LB_FAILED: the BIG-IP could not select or connect to a pool member" +
        (method ? " for " + method : "") +
        ".",
      status: {},
      counters: {
        ...(requestBytes !== undefined ? { requestBytes } : {}),
        basis: "Request Content-Length header",
      },
      interval: { start, end: start },
      intervalBasis: "request_start_only",
      eventTime: start,
      inferredZoneOffsetSeconds: offset,
      candidates: [
        ["client_source", { ip: client }],
        ["client_destination", { ip: vip, port: vipPort }],
      ],
      limitations,
    };
  }
  const node = address(row, "f5_node");
  const nodePort = int(row, "f5_node_port", 65535);
  if (!node || nodePort === undefined)
    throw new Error("iRule server leg is incomplete.");
  const nodeRd = routeDomain(row, "f5_node_rd");
  const status = reported(row, "f5_status");
  const responseBytes = int(row, "f5_bytes_out", Number.MAX_SAFE_INTEGER);
  const end = responseNaive + offset;
  limitations.push("server_side_source_not_logged");
  return {
    recordType: "f5_http",
    balancer: pool,
    protocol,
    clientLeg,
    serverLeg: {
      source: {
        role: "load_balancer_source",
        notReported:
          "The iRule does not log the server-side source (SNAT pool, automap self IP or preserved client address).",
      },
      destination: {
        role: "pool_member",
        ip: node,
        port: nodePort,
        ...(nodeRd !== undefined ? { routeDomain: nodeRd } : {}),
      },
    },
    outcome: "forwarded",
    outcomeText:
      (method ? method + " " : "") +
      "forwarded to a pool member" +
      (elapsed !== undefined
        ? "; " + elapsed + " ms from request to response headers"
        : "") +
      ".",
    status: { ...(status ? { server: status } : {}) },
    counters: {
      ...(requestBytes !== undefined ? { requestBytes } : {}),
      ...(responseBytes !== undefined ? { responseBytes } : {}),
      basis: "Request and response Content-Length headers",
    },
    interval: { start, end },
    intervalBasis: "request_start_to_response",
    eventTime: end,
    inferredZoneOffsetSeconds: offset,
    candidates: [
      ["client_source", { ip: client }],
      ["client_destination", { ip: vip, port: vipPort }],
      ["server_destination", { ip: node, port: nodePort }],
    ],
    limitations,
  };
}

const ALB_ACTIONS = new Set([
  "authenticate",
  "fixed-response",
  "forward",
  "redirect",
  "rewrite",
  "waf",
  "waf-failed",
]);

function timeBounds(rowTime: number, created: number, completed: number): void {
  if (
    created > completed + 1 ||
    completed - created > 86400 ||
    rowTime < created - 1 ||
    rowTime > completed + 1
  )
    throw new Error("Splunk event time is outside the logged request.");
}

function parseAlb(row: Row, rowTime: number): Parsed {
  const elb = reported(row, "alb_elb");
  if (!elb || !elb.startsWith("app/"))
    throw new Error("Unexpected ALB resource ID.");
  const completed = isoSeconds(first(row, "alb_time") ?? "");
  const created = isoSeconds(first(row, "alb_created") ?? "");
  timeBounds(rowTime, created, completed);
  const client = socket(row, "alb_client");
  if (!client) throw new Error("ALB client is missing.");
  const target = socket(row, "alb_target");
  const targetList = reported(row, "alb_target_list");
  if (
    targetList !== undefined &&
    (!target || targetList !== first(row, "alb_target"))
  )
    throw new Error("ALB target list does not match the target.");
  const actionsText = reported(row, "alb_actions");
  const actions = actionsText ? actionsText.split(",") : [];
  if (actions.some((action) => !ALB_ACTIONS.has(action)))
    throw new Error("Unsupported ALB action.");
  const node = address(row, "alb_node_ip");
  const balancerStatus = reported(row, "alb_status");
  const targetStatus = reported(row, "alb_target_status");
  const errorReason = reported(row, "alb_error_reason");
  const targetGroup = reported(row, "alb_target_group");
  for (const column of ["alb_request_s", "alb_target_s", "alb_response_s"])
    seconds(row, column);
  const clientLeg: TransportLeg = {
    source: { role: "client", ...client },
    destination: node
      ? {
          role: "load_balancer_node",
          ip: node,
          notReported: "The listener port is not a separate access-log field.",
        }
      : {
          role: "load_balancer_node",
          notReported:
            "This log version does not include the load balancer node address (field 34).",
        },
  };
  const limitations = [
    "load_balancer_node_is_balancer_not_identity",
    "server_side_source_not_logged",
    "aws_best_effort_logging",
    "host_mapping_does_not_prove_device_identity",
  ];
  if (!node) limitations.push("load_balancer_node_not_logged");
  const last = actions[actions.length - 1];
  const outcomeText = target
    ? "Forwarded to a target" +
      (targetStatus ? "; target status " + targetStatus : "") +
      "."
    : last === "waf"
      ? "Not forwarded: AWS WAF was the final action."
      : "Not forwarded to a target" +
        (errorReason ? " (" + errorReason + ")" : "") +
        (actions.length ? "; actions " + actions.join(", ") : "") +
        ".";
  return {
    recordType: "alb_request",
    balancer: elb,
    ...(targetGroup ? { targetGroup } : {}),
    protocol: first(row, "alb_type")!,
    clientLeg,
    serverLeg: target
      ? {
          source: {
            role: "load_balancer_source",
            notReported:
              "ALB access logs do not record the address the load balancer uses toward the target.",
          },
          destination: { role: "target", ...target },
        }
      : {
          notReported:
            "No target connection is logged for this request (target is '-').",
        },
    outcome: target ? "forwarded" : "not_forwarded",
    outcomeText,
    status: {
      ...(balancerStatus ? { balancer: balancerStatus } : {}),
      ...(targetStatus ? { server: targetStatus } : {}),
    },
    counters: {
      requestBytes: int(row, "alb_received", Number.MAX_SAFE_INTEGER),
      responseBytes: int(row, "alb_sent", Number.MAX_SAFE_INTEGER),
      basis:
        "Bytes received from and sent to the client, including HTTP headers",
    },
    interval: { start: created, end: completed },
    intervalBasis: "request_received_to_response_sent",
    eventTime: completed,
    candidates: [
      ["client_source", client],
      ["client_destination", node ? { ip: node } : undefined],
      ["server_destination", target],
    ],
    limitations,
  };
}

function parseNlb(row: Row, rowTime: number): Parsed {
  if (first(row, "nlb_version") !== "3.0")
    throw new Error("Unsupported NLB access-log version.");
  const elb = reported(row, "nlb_elb");
  if (!elb || !elb.startsWith("net/"))
    throw new Error("Unexpected NLB resource ID.");
  const completed = isoSeconds(first(row, "nlb_time") ?? "", true);
  const created = isoSeconds(first(row, "nlb_created") ?? "", true);
  timeBounds(rowTime, created, completed);
  const client = socket(row, "nlb_client");
  const destination = socket(row, "nlb_destination");
  if (!client || !destination) throw new Error("NLB client leg is incomplete.");
  const verify = first(row, "nlb_verify")!;
  const listener = reported(row, "nlb_listener");
  int(row, "nlb_connection_ms", Number.MAX_SAFE_INTEGER);
  return {
    recordType: "nlb_tls",
    balancer: elb,
    ...(listener ? { listener } : {}),
    protocol: "tls",
    clientLeg: {
      source: { role: "client", ...client },
      destination: { role: "listener_or_endpoint", ...destination },
    },
    serverLeg: {
      notReported:
        "NLB access logs cover TLS listeners only and do not report the target.",
    },
    outcome: "tls_connection",
    outcomeText:
      verify === "Success"
        ? "TLS connection established."
        : "TLS connection failed: " + verify.slice("Failed:".length) + ".",
    status: { balancer: verify },
    counters: {
      requestBytes: int(row, "nlb_received", Number.MAX_SAFE_INTEGER),
      responseBytes: int(row, "nlb_sent", Number.MAX_SAFE_INTEGER),
      basis:
        "Bytes from and to the client, after decryption and before encryption",
    },
    interval: { start: created, end: completed },
    intervalBasis: "connection_start_to_end",
    eventTime: completed,
    candidates: [
      ["client_source", client],
      ["client_destination", destination],
    ],
    limitations: [
      "listener_or_endpoint_is_balancer_not_identity",
      "nlb_target_not_logged",
      "nlb_time_zone_assumed_utc",
      "aws_best_effort_logging",
      "host_mapping_does_not_prove_device_identity",
    ],
  };
}

/** Normalize only projected columns; `_raw` is never returned or read. */
export function normalizeLoadBalancerEvidence(
  contract: LoadBalancerContract,
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: LoadBalancerObservation[]; rejected: number } {
  const selection = validateSelection(input);
  if (config.source !== contract.source || rows.length > INPUT_LIMIT + 1)
    throw new Error("Invalid load balancer normalization input.");
  const authorities = verifiedAuthorities(contract, config, selection.scope);
  const selected = new Set(selection.addresses.map(normalizeIp));
  const dispatch = loadBalancerSearchWindow(selection);
  const records: LoadBalancerObservation[] = [];
  let rejected = 0;
  for (const row of rows) {
    try {
      if (Number(row.lb_parse_ok) !== 1)
        throw new Error("Unparsed load balancer record.");
      const origin = recordOrigin(contract, config, authorities, row);
      const parsed =
        contract.source === "f5_ltm_http"
          ? parseF5(row, origin.rowTime)
          : reported(row, "alb_type")
            ? parseAlb(row, origin.rowTime)
            : parseNlb(row, origin.rowTime);
      if (
        parsed.eventTime < dispatch.start ||
        parsed.eventTime >= dispatch.end ||
        parsed.interval.start >= selection.window.end ||
        parsed.interval.end < selection.window.start
      )
        throw new Error("Record is outside the selection.");
      const { candidates, ...observation } = parsed;
      const matchedAddressFields = matchedFields(selected, candidates);
      if (!matchedAddressFields.length)
        throw new Error("Record does not match a selected address.");
      const limitations = [...parsed.limitations];
      if (
        matchedAddressFields.length === 1 &&
        matchedAddressFields[0] === "client_destination"
      )
        limitations.push("selected_address_matched_balancer_address_only");
      records.push({
        schemaVersion: 1,
        source: contract.source,
        sourcetype: origin.sourcetype,
        authority: origin.authority,
        observerKind: contract.observerKind,
        scope: origin.scope,
        ...observation,
        rowTime: origin.rowTime,
        indexedTime: origin.indexedTime,
        index: origin.index,
        eventFingerprint: origin.eventFingerprint,
        matchedAddressFields,
        attribution: "context_only",
        attributionReason:
          "Address match on one leg at one host-mapped load balancer observer; balancer-owned addresses are not endpoint identity.",
        limitations,
      });
    } catch {
      rejected++;
    }
  }
  return { records, rejected };
}

export function loadLoadBalancerEvidence(
  client: SearchClient,
  source: LoadBalancerSource,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<SupplementalResult<LoadBalancerObservation>> {
  const contract = LOAD_BALANCER_CONTRACTS[source];
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    source,
    (config, input) => buildLoadBalancerSearch(contract, config, input),
    (rows, input, config) =>
      normalizeLoadBalancerEvidence(contract, rows, input, config),
    configurationClient,
    false,
    loadBalancerSearchWindow,
    LOAD_BALANCER_COVERAGE,
  );
}
