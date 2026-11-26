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
  isLowerBound,
  lateWindow,
  matchedFields,
  parseInteger,
  recordOrigin,
  slashNaiveSeconds,
  supplementalTail,
  verifiedAuthorities,
  type Endpoint,
} from "./shared";

export type FirewallSource = "pan_traffic" | "fortigate_traffic";

/**
 * Firewalls write a traffic log when a session starts, ends or is denied. A
 * session that overlaps the selection can be logged after it, so the dispatch
 * window extends this far past the selected end.
 */
export const FIREWALL_LATE_LOG_SECONDS = 3600;
export const FIREWALL_MAX_SESSION_SECONDS = 31 * 86400;
const INPUT_LIMIT = EVIDENCE_LIMITS.input;

export type FirewallAddressField =
  | "original_source"
  | "original_destination"
  | "translated_source"
  | "translated_destination";

/** Projected column → meaning. Each vendor maps its own grounded field names onto these. */
const COLUMNS = [
  "fw_type",
  "fw_subtype",
  "fw_log_time",
  "fw_session_start",
  "fw_duration",
  "fw_serial",
  "fw_device_name",
  "fw_virtual_system",
  "fw_session_id",
  "fw_rule",
  "fw_application",
  "fw_src_ip",
  "fw_src_port",
  "fw_dest_ip",
  "fw_dest_port",
  "fw_nat_disposition",
  "fw_nat_src_ip",
  "fw_nat_src_port",
  "fw_nat_dest_ip",
  "fw_nat_dest_port",
  "fw_protocol",
  "fw_action",
  "fw_session_end_reason",
  "fw_session_flags",
  "fw_ingress_interface",
  "fw_egress_interface",
  "fw_src_zone",
  "fw_dest_zone",
  "fw_repeat_count",
  "fw_bytes",
  "fw_bytes_sent",
  "fw_bytes_received",
  "fw_packets",
  "fw_packets_sent",
  "fw_packets_received",
] as const;
type Column = (typeof COLUMNS)[number];

export interface FirewallSourceContract {
  source: FirewallSource;
  label: string;
  producer: string;
  observerKind: string;
  sourcetypes: readonly string[];
  /** Vendor field (TA search-time name or FortiOS log key) for each projected column. */
  fields: Partial<Record<Column, string>>;
  /** Columns whose absence makes a row unparseable; such rows are returned and rejected. */
  required: readonly Column[];
}

/**
 * Palo Alto Networks: field names are the `extract_traffic` DELIMS list in
 * Splunk_TA_paloalto 6.2.0 transforms.conf. `vendor_action` is the TA's
 * `EVAL-vendor_action = action`, evaluated before its CIM lookup rewrites
 * `action`. The search therefore depends on the TA's search-time extraction.
 */
export const PAN_TRAFFIC: FirewallSourceContract = {
  source: "pan_traffic",
  label: "Palo Alto Networks traffic",
  producer: "Palo Alto Networks add-on for Splunk",
  observerKind: "pan_firewall",
  sourcetypes: ["pan:traffic"],
  fields: {
    fw_type: "type",
    fw_subtype: "log_subtype",
    fw_log_time: "generated_time",
    fw_session_start: "start_time",
    fw_duration: "duration",
    fw_serial: "serial_number",
    fw_device_name: "dvc_name",
    fw_virtual_system: "vsys",
    fw_session_id: "session_id",
    fw_rule: "rule",
    fw_application: "app",
    fw_src_ip: "src_ip",
    fw_src_port: "src_port",
    fw_dest_ip: "dest_ip",
    fw_dest_port: "dest_port",
    fw_nat_src_ip: "src_translated_ip",
    fw_nat_src_port: "src_translated_port",
    fw_nat_dest_ip: "dest_translated_ip",
    fw_nat_dest_port: "dest_translated_port",
    fw_protocol: "transport",
    fw_action: "vendor_action",
    fw_session_end_reason: "session_end_reason",
    fw_session_flags: "session_flags",
    fw_ingress_interface: "src_interface",
    fw_egress_interface: "dest_interface",
    fw_src_zone: "src_zone",
    fw_dest_zone: "dest_zone",
    fw_repeat_count: "repeat_count",
    fw_bytes: "bytes",
    fw_bytes_sent: "bytes_out",
    fw_bytes_received: "bytes_in",
    fw_packets: "packets",
    fw_packets_sent: "packets_out",
    fw_packets_received: "packets_in",
  },
  required: [
    "fw_type",
    "fw_subtype",
    "fw_log_time",
    "fw_src_ip",
    "fw_dest_ip",
    "fw_protocol",
    "fw_action",
  ],
};

/**
 * FortiGate: raw FortiOS traffic log keys (FortiOS 7.6 Log Message Reference,
 * LOG_ID_TRAFFIC_STAT). Fortinet's add-on writes `fgt_traffic` (up to 1.5.x)
 * or `fortigate_traffic` (1.6.x and later); its search-time extraction and
 * action lookup differ by version, so Atlas extracts the keys itself.
 */
export const FORTIGATE_TRAFFIC: FirewallSourceContract = {
  source: "fortigate_traffic",
  label: "FortiGate traffic",
  producer: "Fortinet FortiGate Add-on for Splunk",
  observerKind: "fortigate_firewall",
  sourcetypes: ["fgt_traffic", "fortigate_traffic"],
  fields: {
    fw_type: "type",
    fw_subtype: "subtype",
    fw_log_time: "eventtime",
    fw_duration: "duration",
    fw_serial: "devid",
    fw_device_name: "devname",
    fw_virtual_system: "vd",
    fw_session_id: "sessionid",
    fw_rule: "policyid",
    fw_src_ip: "srcip",
    fw_src_port: "srcport",
    fw_dest_ip: "dstip",
    fw_dest_port: "dstport",
    fw_nat_disposition: "trandisp",
    fw_nat_src_ip: "transip",
    fw_nat_src_port: "transport",
    fw_nat_dest_ip: "tranip",
    fw_nat_dest_port: "tranport",
    fw_protocol: "proto",
    fw_action: "action",
    fw_ingress_interface: "srcintf",
    fw_egress_interface: "dstintf",
    fw_bytes_sent: "sentbyte",
    fw_bytes_received: "rcvdbyte",
    fw_packets_sent: "sentpkt",
    fw_packets_received: "rcvdpkt",
  },
  required: [
    "fw_type",
    "fw_subtype",
    "fw_log_time",
    "fw_src_ip",
    "fw_dest_ip",
    "fw_protocol",
    "fw_action",
  ],
};

export const FIREWALL_CONTRACTS: Record<
  FirewallSource,
  FirewallSourceContract
> = { pan_traffic: PAN_TRAFFIC, fortigate_traffic: FORTIGATE_TRAFFIC };

export type FirewallPolicyDecision = "allow" | "deny" | "not_reported";

/** Vendor action values with their documented meaning; anything else is rejected. */
const PAN_ACTIONS: Record<string, [FirewallPolicyDecision, string]> = {
  allow: ["allow", "Allowed by security policy."],
  deny: ["deny", "Denied by security policy."],
  drop: ["deny", "Dropped silently by the firewall."],
  "reset-both": [
    "deny",
    "Terminated by the firewall with a TCP reset to both sides.",
  ],
  "reset-client": [
    "deny",
    "Terminated by the firewall with a TCP reset to the client.",
  ],
  "reset-server": [
    "deny",
    "Terminated by the firewall with a TCP reset to the server.",
  ],
};
const FORTIGATE_ACTIONS: Record<string, [FirewallPolicyDecision, string]> = {
  accept: ["allow", "Allowed forward session."],
  close: ["allow", "Session ended normally."],
  timeout: ["allow", "Allowed session timed out."],
  deny: ["deny", "Session was denied."],
  start: [
    "not_reported",
    "Session start log; no policy decision is stated by this value.",
  ],
  "client-rst": [
    "not_reported",
    "Session reset by the client endpoint, not by firewall policy.",
  ],
  "server-rst": [
    "not_reported",
    "Session reset by the server endpoint, not by firewall policy.",
  ],
  "ip-conn": ["not_reported", "Failed connection attempt."],
  dns: ["not_reported", "DNS query returned an error."],
};
const PAN_SUBTYPES = new Set(["start", "end", "drop", "deny"]);
const FORTIGATE_SUBTYPES = new Set(["forward", "local"]);
const PROTOCOL_NAMES: Record<number, string> = {
  1: "icmp",
  6: "tcp",
  17: "udp",
  58: "ipv6-icmp",
};

export type FirewallEndpoint = Endpoint;

export interface FirewallTrafficObservation {
  schemaVersion: 1;
  source: FirewallSource;
  sourcetype: string;
  /** Splunk host mapped to one verified observer; not a device identity proof. */
  authority: string;
  observerKind: string;
  /** Operator-attested routing scope; not an access-control boundary. */
  scope: string;
  device: { serial?: string; name?: string; virtualSystem?: string };
  logType: string;
  logSubtype: string;
  sessionId?: string;
  /** PAN rule name or FortiGate policy ID, as reported. */
  rule?: string;
  application?: string;
  protocol: string;
  /** Reported (pre-NAT) tuple. Original source is the session initiator as logged. */
  original: { source: FirewallEndpoint; destination: FirewallEndpoint };
  /**
   * Same-event translation evidence. A translated address is never used as
   * the identity of the endpoint and is not a separate packet hop.
   */
  translated?: {
    source?: FirewallEndpoint;
    destination?: FirewallEndpoint;
    disposition?: string;
    /** PAN session flag 0x00400000 ("nat"), decoded as the TA does. */
    natFlag?: boolean;
  };
  interfaces: {
    ingress?: string;
    egress?: string;
    sourceZone?: string;
    destinationZone?: string;
  };
  vendorAction: string;
  policyDecision: FirewallPolicyDecision;
  actionMeaning: string;
  sessionEndReason?: string;
  /** Session counters belong to this record; never summed across observers. */
  counters: {
    bytes?: number;
    bytesSent?: number;
    bytesReceived?: number;
    packets?: number;
    packetsSent?: number;
    packetsReceived?: number;
  };
  repeatCount?: number;
  interval: EvidenceWindow;
  intervalBasis:
    | "reported_session_start_and_elapsed"
    | "log_time_minus_duration"
    | "log_time_only";
  /** Producer log time as UTC epoch seconds. */
  eventTime: number;
  rowTime: number;
  indexedTime: number;
  /** PAN only: offset between Generated Time (no zone) and Splunk `_time`. */
  inferredZoneOffsetSeconds?: number;
  index: string;
  eventFingerprint: string;
  matchedAddressFields: FirewallAddressField[];
  attribution: "context_only";
  attributionReason: string;
  limitations: string[];
}

export const FIREWALL_COVERAGE = [
  "Each record is one firewall traffic log at one observer. Records are not joined across firewalls, and none creates a dependency edge or changes graph counters.",
  "Allow and deny are this firewall's reported policy decision. They do not prove the application outcome or the decision of any other policy point.",
  "NAT fields are same-event translation evidence. A translated address is not an endpoint identity, and the reported and translated tuples are not separate hops.",
  "No visible records does not prove that traffic was absent or allowed: logging profiles, log forwarding, rule logging settings and caller permissions limit coverage.",
  `Sessions are found through logs written up to ${FIREWALL_LATE_LOG_SECONDS} seconds after the selection; longer sessions without an earlier log in the window can be missed.`,
];

export function verifiedFirewallAuthorities(
  contract: FirewallSourceContract,
  config: SupplementalSourceConfiguration,
  scope?: string,
): string[] {
  return verifiedAuthorities(contract, config, scope);
}

/** FortiOS `key=value` or `key="value"`; spaces or commas separate pairs. */
function fortiRex(key: string, column: string): string {
  if (!/^[a-z]{2,16}$/.test(key) || !/^fw_[a-z_]{2,32}$/.test(column))
    throw new Error("Invalid FortiOS projection.");
  return (
    '| rex field=_raw max_match=2 "(?:^|[ ,])' +
    key +
    '=\\"?(?<' +
    column +
    '>[^\\" ,]{1,255})\\"?(?=[ ,]|$)"'
  );
}

/** Vendor-specific projection onto the fixed column allowlist. */
export function firewallProjection(contract: FirewallSourceContract): string[] {
  const entries = COLUMNS.filter((column) => contract.fields[column]).map(
    (column) => [column, contract.fields[column]!] as const,
  );
  if (contract.source === "fortigate_traffic")
    return entries.map(([column, key]) => fortiRex(key, column));
  for (const [, field] of entries)
    if (!/^[a-z][a-z_]{0,40}$/.test(field))
      throw new Error("Invalid firewall projection.");
  return [
    "| eval " +
      entries.map(([column, field]) => column + "=" + field).join(", "),
  ];
}

function requiredPresent(contract: FirewallSourceContract): string {
  return contract.required
    .map((column) => "isnotnull(" + column + ")")
    .join(" AND ");
}

const ADDRESS_COLUMNS: readonly [FirewallAddressField, Column][] = [
  ["original_source", "fw_src_ip"],
  ["original_destination", "fw_dest_ip"],
  ["translated_source", "fw_nat_src_ip"],
  ["translated_destination", "fw_nat_dest_ip"],
];

export function firewallSearchWindow(
  selection: EvidenceSelection,
): EvidenceWindow {
  return lateWindow(selection, FIREWALL_LATE_LOG_SECONDS);
}

/**
 * Rows that fail extraction are retained so the normalizer counts them as
 * rejected; dropping them in SPL would make missing TA extraction look like
 * an absence of traffic.
 */
export function buildFirewallSearch(
  contract: FirewallSourceContract,
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const authorities = assertActiveSource(contract, config, selection);
  return [
    baseSearch(contract, config, authorities),
    ...firewallProjection(contract),
    "| eval fw_parse_ok=if(" + requiredPresent(contract) + ",1,0)",
    "| where fw_parse_ok=0 OR (" +
      cidrPredicate(
        selection.addresses,
        ADDRESS_COLUMNS.map(([, column]) => column),
      ) +
      ")",
    ...supplementalTail([
      ...COLUMNS.filter((column) => contract.fields[column]),
      "fw_parse_ok",
    ]),
  ].join("\n");
}

function text(row: Row, column: Column): string | undefined {
  const value = first(row, column);
  return value === undefined || value === "-" ? undefined : value;
}

function integer(
  row: Row,
  column: Column,
  maximum: number,
): number | undefined {
  return parseInteger(text(row, column), maximum);
}

/** Unspecified, wildcard and missing translated values are not translation evidence. */
function endpoint(
  row: Row,
  ipColumn: Column,
  portColumn: Column,
  required: boolean,
): FirewallEndpoint | undefined {
  const value = text(row, ipColumn);
  if (value === undefined) {
    if (required) throw new Error("Firewall address is missing.");
    return undefined;
  }
  const ip = normalizeIp(value);
  const port = integer(row, portColumn, 65535);
  if (!required && (ip === "0.0.0.0" || ip === "::")) return undefined;
  return port === undefined || (!required && port === 0)
    ? { ip }
    : { ip, port };
}

/** "YYYY/MM/DD HH:MM:SS" with no zone, read as a naive clock value. */
export const panNaiveSeconds = slashNaiveSeconds;

/** FortiOS `eventtime` is epoch seconds in older releases and nanoseconds in 7.6. */
export function fortiEventSeconds(value: string): number {
  if (/^\d{10}$/.test(value)) return Number(value);
  if (/^\d{19}$/.test(value))
    return Number(value.slice(0, 10)) + Number(value.slice(10)) / 1e9;
  throw new Error("Unsupported FortiOS eventtime precision.");
}

const MAX_ZONE_OFFSET = 14 * 3600;

interface TimeBasis {
  eventTime: number;
  interval: EvidenceWindow;
  intervalBasis: FirewallTrafficObservation["intervalBasis"];
  inferredZoneOffsetSeconds?: number;
}

function panTimes(row: Row, rowTime: number, duration?: number): TimeBasis {
  const generated = panNaiveSeconds(text(row, "fw_log_time")!);
  const offset = Math.round(rowTime) - generated;
  if (
    !Number.isInteger(rowTime) ||
    Math.abs(offset) > MAX_ZONE_OFFSET ||
    offset % 900 !== 0
  )
    throw new Error("Splunk event time does not derive from Generated Time.");
  const startText = text(row, "fw_session_start");
  if (startText !== undefined && duration !== undefined) {
    const start = panNaiveSeconds(startText) + offset;
    if (start > rowTime || start + duration > rowTime + 1)
      throw new Error("PAN-OS session interval is inconsistent.");
    return {
      eventTime: rowTime,
      interval: { start, end: start + duration },
      intervalBasis: "reported_session_start_and_elapsed",
      inferredZoneOffsetSeconds: offset,
    };
  }
  return {
    eventTime: rowTime,
    interval: { start: rowTime, end: rowTime },
    intervalBasis: "log_time_only",
    inferredZoneOffsetSeconds: offset,
  };
}

function fortiTimes(row: Row, rowTime: number, duration?: number): TimeBasis {
  const eventTime = fortiEventSeconds(text(row, "fw_log_time")!);
  if (Math.abs(eventTime - rowTime) > 1)
    throw new Error("Splunk event time does not match FortiOS eventtime.");
  return duration === undefined
    ? {
        eventTime,
        interval: { start: eventTime, end: eventTime },
        intervalBasis: "log_time_only",
      }
    : {
        eventTime,
        interval: { start: eventTime - duration, end: eventTime },
        intervalBasis: "log_time_minus_duration",
      };
}

function protocolName(contract: FirewallSourceContract, value: string): string {
  if (contract.source === "fortigate_traffic") {
    if (!/^\d{1,3}$/.test(value) || Number(value) > 255)
      throw new Error("Invalid FortiOS protocol number.");
    return PROTOCOL_NAMES[Number(value)] ?? "ip-" + Number(value);
  }
  if (!/^[a-z0-9-]{1,32}$/.test(value))
    throw new Error("Invalid PAN-OS protocol.");
  return value;
}

/** Normalize only projected columns; `_raw` is never returned or read. */
export function normalizeFirewallEvidence(
  contract: FirewallSourceContract,
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: FirewallTrafficObservation[]; rejected: number } {
  const selection = validateSelection(input);
  if (config.source !== contract.source || rows.length > INPUT_LIMIT + 1)
    throw new Error("Invalid firewall traffic normalization input.");
  const authorities = verifiedAuthorities(contract, config, selection.scope);
  const selected = new Set(selection.addresses.map(normalizeIp));
  const dispatch = firewallSearchWindow(selection);
  const records: FirewallTrafficObservation[] = [];
  let rejected = 0;
  for (const row of rows) {
    try {
      if (Number(row.fw_parse_ok) !== 1)
        throw new Error("Unparsed firewall record.");
      const {
        authority,
        sourcetype,
        scope,
        index,
        eventFingerprint,
        rowTime,
        indexedTime,
      } = recordOrigin(contract, config, authorities, row);
      const pan = contract.source === "pan_traffic";
      const logType = text(row, "fw_type");
      const logSubtype = text(row, "fw_subtype");
      if (
        logType !== (pan ? "TRAFFIC" : "traffic") ||
        !logSubtype ||
        !(pan ? PAN_SUBTYPES : FORTIGATE_SUBTYPES).has(logSubtype)
      )
        throw new Error("Unsupported firewall log type.");
      const vendorAction = text(row, "fw_action") ?? "";
      const actions = pan ? PAN_ACTIONS : FORTIGATE_ACTIONS;
      if (!Object.prototype.hasOwnProperty.call(actions, vendorAction))
        throw new Error("Unsupported firewall action.");
      const mapped = actions[vendorAction];
      const duration = integer(
        row,
        "fw_duration",
        FIREWALL_MAX_SESSION_SECONDS,
      );
      const times = pan
        ? panTimes(row, rowTime, duration)
        : fortiTimes(row, rowTime, duration);
      if (
        times.eventTime < dispatch.start ||
        times.eventTime >= dispatch.end ||
        times.interval.start >= selection.window.end ||
        times.interval.end < selection.window.start
      )
        throw new Error("Firewall session is outside the selection.");
      const original = {
        source: endpoint(row, "fw_src_ip", "fw_src_port", true)!,
        destination: endpoint(row, "fw_dest_ip", "fw_dest_port", true)!,
      };
      const translatedSource = endpoint(
        row,
        "fw_nat_src_ip",
        "fw_nat_src_port",
        false,
      );
      const translatedDestination = endpoint(
        row,
        "fw_nat_dest_ip",
        "fw_nat_dest_port",
        false,
      );
      const disposition = text(row, "fw_nat_disposition");
      if (disposition !== undefined && !/^[a-z+-]{1,16}$/.test(disposition))
        throw new Error("Invalid FortiOS NAT disposition.");
      const flags = text(row, "fw_session_flags");
      if (flags !== undefined && !/^0x[0-9a-fA-F]{1,8}$/.test(flags))
        throw new Error("Invalid PAN-OS session flags.");
      const natFlag =
        flags === undefined
          ? undefined
          : Math.floor(parseInt(flags, 16) / 2 ** 22) % 2 === 1;
      const matchedAddressFields = matchedFields(selected, [
        ["original_source", original.source],
        ["original_destination", original.destination],
        ["translated_source", translatedSource],
        ["translated_destination", translatedDestination],
      ] as const);
      if (!matchedAddressFields.length)
        throw new Error("Record does not match a selected address.");
      const repeatCount = integer(row, "fw_repeat_count", 1_000_000);
      const big = Number.MAX_SAFE_INTEGER;
      const counters = {
        bytes: integer(row, "fw_bytes", big),
        bytesSent: integer(row, "fw_bytes_sent", big),
        bytesReceived: integer(row, "fw_bytes_received", big),
        packets: integer(row, "fw_packets", big),
        packetsSent: integer(row, "fw_packets_sent", big),
        packetsReceived: integer(row, "fw_packets_received", big),
      };
      const limitations = [
        "policy_decision_is_this_observer_only",
        "nat_fields_are_translation_evidence_not_identity",
        "per_record_counters_not_aggregated",
        "host_mapping_does_not_prove_device_identity",
      ];
      if (pan) limitations.push("pan_generated_time_zone_inferred_from_splunk");
      if (repeatCount !== undefined && repeatCount > 1)
        limitations.push("repeat_count_summarizes_multiple_sessions");
      if (matchedAddressFields.some((field) => field.startsWith("translated")))
        limitations.push("selected_address_matched_translated_field");
      if (mapped[0] === "not_reported")
        limitations.push("vendor_action_states_no_policy_decision");
      const translated =
        translatedSource ||
        translatedDestination ||
        disposition !== undefined ||
        natFlag !== undefined
          ? {
              ...(translatedSource ? { source: translatedSource } : {}),
              ...(translatedDestination
                ? { destination: translatedDestination }
                : {}),
              ...(disposition !== undefined ? { disposition } : {}),
              ...(natFlag !== undefined ? { natFlag } : {}),
            }
          : undefined;
      const device = {
        ...(text(row, "fw_serial") ? { serial: text(row, "fw_serial") } : {}),
        ...(text(row, "fw_device_name")
          ? { name: text(row, "fw_device_name") }
          : {}),
        ...(text(row, "fw_virtual_system")
          ? { virtualSystem: text(row, "fw_virtual_system") }
          : {}),
      };
      const interfaces = {
        ...(text(row, "fw_ingress_interface")
          ? { ingress: text(row, "fw_ingress_interface") }
          : {}),
        ...(text(row, "fw_egress_interface")
          ? { egress: text(row, "fw_egress_interface") }
          : {}),
        ...(text(row, "fw_src_zone")
          ? { sourceZone: text(row, "fw_src_zone") }
          : {}),
        ...(text(row, "fw_dest_zone")
          ? { destinationZone: text(row, "fw_dest_zone") }
          : {}),
      };
      records.push({
        schemaVersion: 1,
        source: contract.source,
        sourcetype,
        authority,
        observerKind: contract.observerKind,
        scope,
        device,
        logType: logType!,
        logSubtype,
        ...(text(row, "fw_session_id")
          ? { sessionId: text(row, "fw_session_id") }
          : {}),
        ...(text(row, "fw_rule") ? { rule: text(row, "fw_rule") } : {}),
        ...(text(row, "fw_application")
          ? { application: text(row, "fw_application") }
          : {}),
        protocol: protocolName(contract, text(row, "fw_protocol")!),
        original,
        ...(translated ? { translated } : {}),
        interfaces,
        vendorAction,
        policyDecision: mapped[0],
        actionMeaning: mapped[1],
        ...(text(row, "fw_session_end_reason")
          ? { sessionEndReason: text(row, "fw_session_end_reason") }
          : {}),
        counters: Object.fromEntries(
          Object.entries(counters).filter(([, value]) => value !== undefined),
        ),
        ...(repeatCount !== undefined ? { repeatCount } : {}),
        interval: times.interval,
        intervalBasis: times.intervalBasis,
        eventTime: times.eventTime,
        rowTime,
        indexedTime,
        ...(times.inferredZoneOffsetSeconds !== undefined
          ? { inferredZoneOffsetSeconds: times.inferredZoneOffsetSeconds }
          : {}),
        index,
        eventFingerprint,
        matchedAddressFields,
        attribution: "context_only",
        attributionReason:
          "Address match at one host-mapped firewall observer; no time-valid device or workload binding was supplied.",
        limitations,
      });
    } catch {
      rejected++;
    }
  }
  return { records, rejected };
}

export interface FirewallDecisionSummary {
  allow: number;
  deny: number;
  notReported: number;
  /** Visible records only; a capped or partial result is a lower bound. */
  lowerBound: boolean;
}

export function firewallDecisionSummary(
  result: SupplementalResult<FirewallTrafficObservation>,
): FirewallDecisionSummary {
  const summary = { allow: 0, deny: 0, notReported: 0 };
  for (const record of result.records)
    if (record.policyDecision === "allow") summary.allow++;
    else if (record.policyDecision === "deny") summary.deny++;
    else summary.notReported++;
  return {
    ...summary,
    lowerBound: isLowerBound(result),
  };
}

export function loadFirewallTrafficEvidence(
  client: SearchClient,
  source: FirewallSource,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<SupplementalResult<FirewallTrafficObservation>> {
  const contract = FIREWALL_CONTRACTS[source];
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    source,
    (config, input) => buildFirewallSearch(contract, config, input),
    (rows, input, config) =>
      normalizeFirewallEvidence(contract, rows, input, config),
    configurationClient,
    false,
    firewallSearchWindow,
    FIREWALL_COVERAGE,
  );
}
