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
  RECORD_BYTES,
  assertActiveSource,
  baseSearch,
  cidrPredicate,
  first,
  ianaProtocol,
  isoSeconds,
  lateWindow,
  matchedFields,
  parseInteger,
  recordOrigin,
  supplementalTail,
  verifiedAuthorities,
  type Endpoint,
  type SourceIdentity,
} from "./shared";

export type CloudFlowSource = "gcp_vpc_flow" | "azure_vnet_flow";

/** Flow logs are aggregated and exported after the interval they describe. */
export const FLOW_LATE_LOG_SECONDS = 3600;
const INPUT_LIMIT = EVIDENCE_LIMITS.input;
const BIG = Number.MAX_SAFE_INTEGER;

export interface CloudFlowContract extends SourceIdentity {
  source: CloudFlowSource;
  producer: string;
  projection: readonly string[];
  columns: readonly string[];
  addressColumns: readonly string[];
  oversized: string;
  fingerprint?: string;
}

/**
 * Google "VPC Flow Logs records" base fields and metadata annotations used
 * here, as LogEntry paths. Splunk's CIM Network Traffic mapping documents
 * them under `data.` for google:gcp:compute:vpc_flows; a bare LogEntry
 * (no Pub/Sub wrapper) is also accepted. Each event must have exactly one shape.
 */
export const GCP_PATHS: readonly (readonly [string, string])[] = [
  ["gcp_log_name", "logName"],
  ["gcp_src_ip", "jsonPayload.connection.src_ip"],
  ["gcp_src_port", "jsonPayload.connection.src_port"],
  ["gcp_dest_ip", "jsonPayload.connection.dest_ip"],
  ["gcp_dest_port", "jsonPayload.connection.dest_port"],
  ["gcp_protocol", "jsonPayload.connection.protocol"],
  ["gcp_nat_ip", "jsonPayload.connection.nat_ip"],
  ["gcp_nat_port", "jsonPayload.connection.nat_port"],
  ["gcp_reporter", "jsonPayload.reporter"],
  ["gcp_start", "jsonPayload.start_time"],
  ["gcp_end", "jsonPayload.end_time"],
  ["gcp_bytes_sent", "jsonPayload.bytes_sent"],
  ["gcp_packets_sent", "jsonPayload.packets_sent"],
  ["gcp_disposition", "jsonPayload.disposition"],
  ["gcp_drop_reason", "jsonPayload.drop_reason"],
  ["gcp_bytes_dropped", "jsonPayload.bytes_dropped"],
  ["gcp_packets_dropped", "jsonPayload.packets_dropped"],
  ["gcp_src_project", "jsonPayload.src_instance.project_id"],
  ["gcp_src_vm", "jsonPayload.src_instance.vm_name"],
  ["gcp_dest_project", "jsonPayload.dest_instance.project_id"],
  ["gcp_dest_vm", "jsonPayload.dest_instance.vm_name"],
  ["gcp_src_vpc", "jsonPayload.src_vpc.vpc_name"],
  ["gcp_dest_vpc", "jsonPayload.dest_vpc.vpc_name"],
];
const GCP_LOG_NAME =
  /^projects\/[a-z0-9-]{1,64}\/logs\/compute\.googleapis\.com%2Fvpc_flows$/;

export const GCP_VPC_FLOW: CloudFlowContract = {
  source: "gcp_vpc_flow",
  label: "GCP VPC flow logs",
  producer: "Splunk Add-on for Google Cloud Platform",
  observerKind: "gcp_vpc_flow",
  sourcetypes: ["google:gcp:compute:vpc_flows"],
  projection: [
    '| eval gcp_shape=case(isnotnull(spath(_raw,"data.jsonPayload.connection.src_ip")) AND isnull(spath(_raw,"jsonPayload")),"pubsub_data",isnotnull(spath(_raw,"jsonPayload.connection.src_ip")) AND isnull(spath(_raw,"data")),"log_entry",true(),null())',
    "| eval " +
      GCP_PATHS.map(
        ([column, path]) =>
          column +
          '=case(gcp_shape="pubsub_data",spath(_raw,"data.' +
          path +
          '"),gcp_shape="log_entry",spath(_raw,"' +
          path +
          '"))',
      ).join(", "),
    '| eval flow_parse_ok=if(isnotnull(gcp_shape) AND match(gcp_log_name,"/logs/compute[.]googleapis[.]com%2Fvpc_flows$"),1,0)',
  ],
  columns: ["gcp_shape", ...GCP_PATHS.map(([column]) => column)],
  addressColumns: ["gcp_src_ip", "gcp_dest_ip", "gcp_nat_ip"],
  oversized: "len(_raw)>" + RECORD_BYTES,
};

/**
 * Microsoft "Virtual network flow logs" log format. The Splunk event boundary
 * for mscs:vnet:flow is not documented, so an event must be exactly one
 * record: either the record object or a `records` array with one element.
 * Tuples are expanded in SPL so each row carries its own ACL and rule.
 */
/** Record-level extraction, shared with the receipt probe (which never expands tuples). */
export const AZURE_RECORD_PROJECTION: readonly string[] = [
  '| eval az_records=spath(_raw,"records{}"), atlas_oversized=if(len(_raw)>' +
    RECORD_BYTES +
    ",1,0)",
  '| eval az_shape=case(isnull(az_records) AND isnotnull(spath(_raw,"flowRecords")),"single_record",mvcount(az_records)=1,"records_array",true(),null())',
  '| eval az_record=case(az_shape="single_record",_raw,az_shape="records_array",az_records,true(),null())',
  '| eval az_time=spath(az_record,"time"), az_version=spath(az_record,"flowLogVersion"), az_category=spath(az_record,"category"), az_mac=spath(az_record,"macAddress"), az_target=spath(az_record,"targetResourceID"), az_flows=coalesce(spath(az_record,"flowRecords.flows{}"),"-")',
];

export const AZURE_VNET_FLOW: CloudFlowContract = {
  source: "azure_vnet_flow",
  label: "Azure VNet flow logs",
  producer: "Splunk Add-on for Microsoft Cloud Services",
  observerKind: "azure_vnet_flow",
  sourcetypes: ["mscs:vnet:flow", "mscs:storage:blob:json"],
  projection: [
    ...AZURE_RECORD_PROJECTION,
    "| fields - _raw az_records az_record",
    "| mvexpand az_flows",
    '| eval az_acl=spath(az_flows,"aclID"), az_groups=coalesce(spath(az_flows,"flowGroups{}"),"-")',
    "| fields - az_flows",
    "| mvexpand az_groups",
    '| eval az_rule=spath(az_groups,"rule"), az_tuple=coalesce(spath(az_groups,"flowTuples{}"),"-")',
    "| fields - az_groups",
    "| mvexpand az_tuple",
    '| eval az_parts=split(az_tuple,","), az_src_ip=mvindex(az_parts,1), az_dest_ip=mvindex(az_parts,2), az_nat_ip=mvindex(az_parts,14)',
    "| fields - az_parts",
    '| eval flow_parse_ok=if(isnotnull(az_shape) AND az_category="FlowLogFlowEvent" AND isnotnull(az_time) AND isnotnull(az_acl) AND isnotnull(az_rule) AND az_tuple!="-" AND len(az_tuple)<=255,1,0)',
  ],
  columns: [
    "az_shape",
    "az_time",
    "az_version",
    "az_category",
    "az_mac",
    "az_target",
    "az_acl",
    "az_rule",
    "az_tuple",
  ],
  addressColumns: ["az_src_ip", "az_dest_ip", "az_nat_ip"],
  oversized: "atlas_oversized=1",
  fingerprint:
    "if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd,az_acl,az_rule,az_tuple)),null())",
};

export const CLOUD_FLOW_CONTRACTS: Record<CloudFlowSource, CloudFlowContract> =
  { gcp_vpc_flow: GCP_VPC_FLOW, azure_vnet_flow: AZURE_VNET_FLOW };

export type FlowAddressField =
  "original_source" | "original_destination" | "translated_source";

export interface CloudFlowObservation {
  schemaVersion: 1;
  source: CloudFlowSource;
  sourcetype: string;
  authority: string;
  observerKind: string;
  scope: string;
  recordShape: string;
  protocol: string;
  /** Tuple as reported by the capture point. */
  original: { source: Endpoint; destination: Endpoint };
  /** Same-record translation evidence (Cloud NAT, Private Link SNAT); never identity. */
  translated?: { source: Endpoint; kind: "cloud_nat" | "private_link_snat" };
  /** GCP reporter or Azure direction relative to the captured interface. */
  vantage: string;
  rule?: string;
  policyDecision: "allow" | "deny" | "not_reported";
  actionMeaning: string;
  flowState?: string;
  encryption?: string;
  counters: {
    bytesSent?: number;
    packetsSent?: number;
    bytesReceived?: number;
    packetsReceived?: number;
    bytesDropped?: number;
    packetsDropped?: number;
  };
  countersBasis: string;
  /** Producer metadata annotations; approximations, not identity proofs. */
  context: { label: string; value: string }[];
  interval: EvidenceWindow;
  intervalBasis: "aggregation_interval" | "tuple_time";
  eventTime: number;
  rowTime: number;
  indexedTime: number;
  index: string;
  eventFingerprint: string;
  matchedAddressFields: FlowAddressField[];
  attribution: "context_only";
  attributionReason: string;
  limitations: string[];
}

export const CLOUD_FLOW_COVERAGE = [
  "Each record is one flow-log entry at one capture point. Entries are not joined across reporters, interfaces or clouds, and none creates a dependency or blocked-flow edge.",
  "GCP records state only drops (disposition DROPPED); other records are observed packets with no stated allow decision. Azure states B/C/E (permitted) and D (denied) per rule.",
  "NAT addresses (Cloud NAT, Private Link SNAT) are same-record translation evidence, not endpoint identity or a separate hop.",
  "Counters are the producer's per-record values (GCP sampled estimates, Azure deltas since the previous tuple). They are never summed across records.",
  "No visible records does not prove traffic was absent or allowed: sampling, aggregation, export filters, delivery lag and caller permissions limit coverage.",
];

export function cloudFlowSearchWindow(
  selection: EvidenceSelection,
): EvidenceWindow {
  return lateWindow(selection, FLOW_LATE_LOG_SECONDS);
}

export function buildCloudFlowSearch(
  contract: CloudFlowContract,
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const authorities = assertActiveSource(contract, config, selection);
  return [
    baseSearch(contract, config, authorities),
    ...contract.projection,
    "| where flow_parse_ok=0 OR (" +
      cidrPredicate(selection.addresses, contract.addressColumns) +
      ")",
    ...supplementalTail(
      [...contract.columns, "flow_parse_ok"],
      contract.oversized,
      contract.fingerprint,
    ),
  ].join("\n");
}

function value(row: Row, column: string): string | undefined {
  return first(row, column);
}

function count(row: Row, column: string): number | undefined {
  return parseInteger(value(row, column), BIG);
}

function optionalPort(text: string | undefined): number | undefined {
  return parseInteger(text, 65535);
}

interface Parsed extends Omit<
  CloudFlowObservation,
  | "schemaVersion"
  | "source"
  | "sourcetype"
  | "authority"
  | "observerKind"
  | "scope"
  | "rowTime"
  | "indexedTime"
  | "index"
  | "eventFingerprint"
  | "matchedAddressFields"
  | "attribution"
  | "attributionReason"
> {
  recordTime: number;
}

const GCP_REPORTERS = new Set(["SRC", "DEST", "SRC_GATEWAY", "DEST_GATEWAY"]);

function parseGcp(row: Row): Parsed {
  const shape = value(row, "gcp_shape");
  if (shape !== "pubsub_data" && shape !== "log_entry")
    throw new Error("Unsupported GCP event shape.");
  if (!GCP_LOG_NAME.test(value(row, "gcp_log_name") ?? ""))
    throw new Error("Not a VPC Flow Logs entry.");
  const reporter = value(row, "gcp_reporter") ?? "";
  if (!GCP_REPORTERS.has(reporter)) throw new Error("Unsupported reporter.");
  const start = isoSeconds(value(row, "gcp_start") ?? "");
  const end = isoSeconds(value(row, "gcp_end") ?? "");
  if (end < start || end - start > 86400)
    throw new Error("Flow interval is inconsistent.");
  const src = value(row, "gcp_src_ip");
  const dest = value(row, "gcp_dest_ip");
  if (!src || !dest) throw new Error("Flow addresses are missing.");
  const srcPort = optionalPort(value(row, "gcp_src_port"));
  const destPort = optionalPort(value(row, "gcp_dest_port"));
  const protocolText = value(row, "gcp_protocol");
  const natIp = value(row, "gcp_nat_ip");
  const natPort = optionalPort(value(row, "gcp_nat_port"));
  if ((natIp || natPort !== undefined) && reporter !== "SRC")
    throw new Error("Cloud NAT fields are only reported by the source.");
  const disposition = value(row, "gcp_disposition");
  const dropReason = value(row, "gcp_drop_reason");
  if (disposition !== undefined && disposition !== "DROPPED")
    throw new Error("Unsupported disposition.");
  if (
    dropReason !== undefined &&
    (disposition !== "DROPPED" || !/^[A-Z0-9_]{1,64}$/.test(dropReason))
  )
    throw new Error("Invalid drop reason.");
  const dropped = disposition === "DROPPED";
  const counters = {
    bytesSent: count(row, "gcp_bytes_sent"),
    packetsSent: count(row, "gcp_packets_sent"),
    bytesDropped: count(row, "gcp_bytes_dropped"),
    packetsDropped: count(row, "gcp_packets_dropped"),
  };
  if (
    !dropped &&
    (counters.bytesDropped !== undefined ||
      counters.packetsDropped !== undefined)
  )
    throw new Error("Drop counters without a drop disposition.");
  const context: CloudFlowObservation["context"] = [];
  for (const [column, label] of [
    ["gcp_src_project", "Source project"],
    ["gcp_src_vm", "Source VM"],
    ["gcp_src_vpc", "Source VPC"],
    ["gcp_dest_project", "Destination project"],
    ["gcp_dest_vm", "Destination VM"],
    ["gcp_dest_vpc", "Destination VPC"],
  ] as const) {
    const item = value(row, column);
    if (item !== undefined) context.push({ label, value: item });
  }
  const limitations = [
    "counters_are_sampled_estimates",
    "metadata_annotations_are_approximations",
    "gcp_splunk_time_basis_inferred",
    "host_mapping_does_not_prove_device_identity",
  ];
  if (!dropped) limitations.push("no_allow_decision_reported");
  return {
    recordShape: shape,
    protocol:
      protocolText === undefined ? "not reported" : ianaProtocol(protocolText),
    original: {
      source: {
        ip: normalizeIp(src),
        ...(srcPort !== undefined ? { port: srcPort } : {}),
      },
      destination: {
        ip: normalizeIp(dest),
        ...(destPort !== undefined ? { port: destPort } : {}),
      },
    },
    ...(natIp
      ? {
          translated: {
            source: {
              ip: normalizeIp(natIp),
              ...(natPort !== undefined ? { port: natPort } : {}),
            },
            kind: "cloud_nat" as const,
          },
        }
      : {}),
    vantage: "Reporter " + reporter,
    policyDecision: dropped ? "deny" : "not_reported",
    actionMeaning: dropped
      ? "Dropped" + (dropReason ? " (" + dropReason + ")" : "") + "."
      : "Observed packets; this record states no allow or deny decision.",
    counters: Object.fromEntries(
      Object.entries(counters).filter(([, item]) => item !== undefined),
    ),
    countersBasis:
      "Sampled estimates from source to destination for this aggregation interval",
    context,
    interval: { start, end },
    intervalBasis: "aggregation_interval",
    eventTime: end,
    recordTime: end,
    limitations,
  };
}

const AZURE_STATES: Record<string, string> = {
  B: "Begin",
  C: "Continuing",
  E: "End",
  D: "Deny",
};
const AZURE_ENCRYPTION = new Set([
  "X",
  "NX",
  "NX_HW_NOT_SUPPORTED",
  "NX_SW_NOT_READY",
  "NX_NOT_ACCEPTED",
  "NX_NOT_SUPPORTED",
  "NX_LOCAL_DST",
  "NX_FALLBACK",
]);
/** Encryption statuses Microsoft documents as dropping the packet. */
const AZURE_ENCRYPTION_DROPS = new Set([
  "NX_SW_NOT_READY",
  "NX_NOT_ACCEPTED",
  "NX_NOT_SUPPORTED",
]);
/**
 * Tuple field count by flowLogVersion. Microsoft's samples pair version 4
 * records with the 13-field "Version 2" tuple and version 5 records with the
 * 16-field tuple; Atlas accepts only those pairings.
 */
const AZURE_TUPLE_FIELDS: Record<string, number> = { "4": 13, "5": 16 };

/** Tuple time is UNIX epoch; Microsoft's samples use seconds and milliseconds. */
export function azureTupleSeconds(text: string): number {
  if (/^\d{10}$/.test(text)) return Number(text);
  if (/^\d{13}$/.test(text)) return Number(text) / 1000;
  throw new Error("Unsupported tuple time precision.");
}

function parseAzure(row: Row): Parsed {
  const shape = value(row, "az_shape");
  if (shape !== "single_record" && shape !== "records_array")
    throw new Error("Unsupported Azure event shape.");
  const version = value(row, "az_version") ?? "";
  const width = AZURE_TUPLE_FIELDS[version];
  const tuple = value(row, "az_tuple") ?? "";
  const parts = tuple.split(",");
  if (!width || parts.length !== width)
    throw new Error("Tuple does not match its flow log version.");
  const recordTime = isoSeconds(value(row, "az_time") ?? "");
  const tupleTime = azureTupleSeconds(parts[0]);
  if (tupleTime > recordTime + 60 || recordTime - tupleTime > 3600)
    throw new Error("Tuple time is inconsistent with the record time.");
  const direction = parts[6];
  const state = parts[7];
  const encryption = parts[8];
  if (
    (direction !== "I" && direction !== "O") ||
    !AZURE_STATES[state] ||
    !AZURE_ENCRYPTION.has(encryption)
  )
    throw new Error("Unsupported tuple state.");
  const rule = value(row, "az_rule");
  if (!rule || !/^[A-Za-z0-9_.-]{1,128}$/.test(rule))
    throw new Error("Invalid rule name.");
  const counter = (index: number) =>
    parts[index] === "" ? undefined : parseInteger(parts[index], BIG);
  const natIp = width === 16 && parts[14] !== "" ? parts[14] : undefined;
  const natPort =
    width === 16 ? optionalPort(parts[15] || undefined) : undefined;
  const denied = state === "D";
  const encryptionDrop = AZURE_ENCRYPTION_DROPS.has(encryption);
  const mac = value(row, "az_mac");
  const target = first(row, "az_target", 512);
  const context: CloudFlowObservation["context"] = [];
  if (mac && /^[0-9A-Fa-f]{12}$/.test(mac))
    context.push({ label: "Captured interface MAC", value: mac });
  if (target) context.push({ label: "Flow log target", value: target });
  const limitations = [
    "decision_is_this_capture_point_only",
    "counters_are_deltas_since_previous_tuple",
    "azure_event_boundary_inferred",
    "host_mapping_does_not_prove_device_identity",
  ];
  if (natIp) limitations.push("private_link_snat_is_translation_not_identity");
  return {
    recordShape: shape,
    protocol: ianaProtocol(parts[5]),
    original: {
      source: { ip: normalizeIp(parts[1]), ...portOf(parts[3]) },
      destination: { ip: normalizeIp(parts[2]), ...portOf(parts[4]) },
    },
    ...(natIp
      ? {
          translated: {
            source: {
              ip: normalizeIp(natIp),
              ...(natPort !== undefined ? { port: natPort } : {}),
            },
            kind: "private_link_snat" as const,
          },
        }
      : {}),
    vantage:
      direction === "I"
        ? "Inbound at the captured interface"
        : "Outbound at the captured interface",
    rule,
    policyDecision: denied || encryptionDrop ? "deny" : "allow",
    actionMeaning: denied
      ? "Denied by rule " + rule + "."
      : encryptionDrop
        ? "Dropped by virtual network encryption (" + encryption + ")."
        : "Permitted under rule " +
          rule +
          " (" +
          AZURE_STATES[state] +
          "); the rule may be a platform rule.",
    flowState: AZURE_STATES[state],
    encryption,
    counters: Object.fromEntries(
      Object.entries({
        packetsSent: counter(9),
        bytesSent: counter(10),
        packetsReceived: counter(11),
        bytesReceived: counter(12),
      }).filter(([, item]) => item !== undefined),
    ),
    countersBasis: "Packets and bytes since the previous tuple of this flow",
    context,
    interval: { start: tupleTime, end: tupleTime },
    intervalBasis: "tuple_time",
    eventTime: tupleTime,
    recordTime,
    limitations,
  };
}

function portOf(text: string): { port?: number } {
  const port = optionalPort(text === "" ? undefined : text);
  return port === undefined ? {} : { port };
}

/** Normalize only projected columns; `_raw` is never returned or read. */
export function normalizeCloudFlowEvidence(
  contract: CloudFlowContract,
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: CloudFlowObservation[]; rejected: number } {
  const selection = validateSelection(input);
  if (config.source !== contract.source || rows.length > INPUT_LIMIT + 1)
    throw new Error("Invalid flow log normalization input.");
  const authorities = verifiedAuthorities(contract, config, selection.scope);
  const selected = new Set(selection.addresses.map(normalizeIp));
  const dispatch = cloudFlowSearchWindow(selection);
  const records: CloudFlowObservation[] = [];
  let rejected = 0;
  for (const row of rows) {
    try {
      if (Number(row.flow_parse_ok) !== 1)
        throw new Error("Unparsed flow log record.");
      const origin = recordOrigin(contract, config, authorities, row);
      const { recordTime, ...parsed } =
        contract.source === "gcp_vpc_flow" ? parseGcp(row) : parseAzure(row);
      // The add-ons do not document which producer timestamp becomes `_time`;
      // it must not precede the record and may trail it by the late window.
      if (
        origin.rowTime < recordTime - 1 ||
        origin.rowTime > recordTime + FLOW_LATE_LOG_SECONDS
      )
        throw new Error("Splunk event time is inconsistent with the record.");
      if (
        origin.rowTime < dispatch.start ||
        origin.rowTime >= dispatch.end ||
        parsed.interval.start >= selection.window.end ||
        parsed.interval.end < selection.window.start
      )
        throw new Error("Record is outside the selection.");
      const matchedAddressFields = matchedFields(selected, [
        ["original_source", parsed.original.source],
        ["original_destination", parsed.original.destination],
        ["translated_source", parsed.translated?.source],
      ] as const);
      if (!matchedAddressFields.length)
        throw new Error("Record does not match a selected address.");
      if (matchedAddressFields.includes("translated_source"))
        parsed.limitations.push("selected_address_matched_translated_field");
      records.push({
        schemaVersion: 1,
        source: contract.source,
        sourcetype: origin.sourcetype,
        authority: origin.authority,
        observerKind: contract.observerKind,
        scope: origin.scope,
        ...parsed,
        rowTime: origin.rowTime,
        indexedTime: origin.indexedTime,
        index: origin.index,
        eventFingerprint: origin.eventFingerprint,
        matchedAddressFields,
        attribution: "context_only",
        attributionReason:
          "Address match at one host-mapped flow-log source; no time-valid workload binding was supplied.",
        limitations: parsed.limitations,
      });
    } catch {
      rejected++;
    }
  }
  return { records, rejected };
}

export function loadCloudFlowEvidence(
  client: SearchClient,
  source: CloudFlowSource,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<SupplementalResult<CloudFlowObservation>> {
  const contract = CLOUD_FLOW_CONTRACTS[source];
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    source,
    (config, input) => buildCloudFlowSearch(contract, config, input),
    (rows, input, config) =>
      normalizeCloudFlowEvidence(contract, rows, input, config),
    configurationClient,
    false,
    cloudFlowSearchWindow,
    CLOUD_FLOW_COVERAGE,
  );
}
