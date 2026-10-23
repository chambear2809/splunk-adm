import type { Row } from "../rows";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  literal,
  normalizeIp,
  routingScope,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "./evidence";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "./supplementalEvidence";
import type { SearchClient } from "./searchClient";

export const CLOUD_FLOW_SOURCE = "aws_vpc_flow" as const;
export const CLOUD_FLOW_SOURCETYPE = "aws:vpcflow:v5";
export const CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS = 60;
export const CLOUD_FLOW_MAX_AGGREGATION_SECONDS = 600;
export const CLOUD_FLOW_LOOKBACK_SECONDS =
  CLOUD_FLOW_MAX_AGGREGATION_SECONDS + CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS;
export const CLOUD_FLOW_RECORD_LIMIT = 64;
export const CLOUD_FLOW_INPUT_LIMIT = 10000;
export const CLOUD_FLOW_RECORD_BYTES = 1048576;
const MAX_EPOCH = 253402300799;

/** One supported producer contract: AWS custom version-5, fixed whitespace order. */
export const CLOUD_FLOW_PROJECTION = [
  ["version", "flow_version"],
  ["srcaddr", "flow_srcaddr"],
  ["dstaddr", "flow_dstaddr"],
  ["srcport", "flow_srcport"],
  ["dstport", "flow_dstport"],
  ["protocol", "flow_protocol"],
  ["start", "flow_start"],
  ["end", "flow_end"],
  ["type", "flow_type"],
  ["packets", "flow_packets"],
  ["bytes", "flow_bytes"],
  ["account-id", "flow_account_id"],
  ["vpc-id", "flow_vpc_id"],
  ["subnet-id", "flow_subnet_id"],
  ["instance-id", "flow_instance_id"],
  ["interface-id", "flow_interface_id"],
  ["region", "flow_region"],
  ["az-id", "flow_az_id"],
  ["sublocation-type", "flow_sublocation_type"],
  ["sublocation-id", "flow_sublocation_id"],
  ["action", "flow_action"],
  ["tcp-flags", "flow_tcp_flags"],
  ["pkt-srcaddr", "flow_pkt_srcaddr"],
  ["pkt-dstaddr", "flow_pkt_dstaddr"],
  ["pkt-src-aws-service", "flow_pkt_src_aws_service"],
  ["pkt-dst-aws-service", "flow_pkt_dst_aws_service"],
  ["traffic-path", "flow_traffic_path"],
  ["flow-direction", "flow_direction"],
  ["log-status", "flow_log_status"],
] as const;

export const CLOUD_FLOW_FIELDS = CLOUD_FLOW_PROJECTION.map(([field]) => field);
export const CLOUD_FLOW_LOG_FORMAT = CLOUD_FLOW_FIELDS.map(
  (field) => "$" + "{" + field + "}",
).join(" ");

export type CloudFlowLogStatus = "OK" | "NODATA" | "SKIPDATA";
export type CloudFlowAddressField =
  "srcaddr" | "dstaddr" | "pkt-srcaddr" | "pkt-dstaddr";
type FlowRawFields = Record<(typeof CLOUD_FLOW_PROJECTION)[number][0], string>;

export interface CloudFlowObservation {
  schemaVersion: 1;
  source: typeof CLOUD_FLOW_SOURCE;
  /** Splunk host mapped to one verified AWS capture authority. */
  authority: string;
  /** Operator-attested routing scope; this is not an access-control boundary. */
  scope: string;
  accountId?: string;
  region?: string;
  vpcId?: string;
  subnetId?: string;
  /** Producer-reported attributes only; these do not establish historical ownership. */
  instanceId?: string;
  interfaceId?: string;
  availabilityZoneId?: string;
  sublocationType?: string;
  sublocationId?: string;
  recordType: "IPv4" | "IPv6" | "EFA" | "unknown";
  interfaceAddresses: { source?: string; destination?: string };
  packetAddresses: { source?: string; destination?: string };
  sourcePort?: number;
  destinationPort?: number;
  protocol?: number;
  /** AWS Flow Logs counters belong to this source record and are not summed. */
  packets?: number;
  bytes?: number;
  tcpFlags?: number;
  packetSourceAwsService?: string;
  packetDestinationAwsService?: string;
  trafficPath?: number;
  flowDirection: "ingress" | "egress" | "unknown";
  action: "ACCEPT" | "REJECT" | "unknown";
  logStatus: CloudFlowLogStatus;
  recordClass: "flow" | "capture_status";
  interval: EvidenceWindow;
  /** Fields whose values exactly matched one selected IP. Empty for capture status. */
  matchedAddressFields: CloudFlowAddressField[];
  index: string;
  eventFingerprint: string;
  eventTime: number;
  rowTime: number;
  indexedTime: number;
  attribution: "context_only";
  attributionReason: string;
  limitations: string[];
}

const COVERAGE = [
  "AWS VPC Flow Logs are best-effort, per-network-interface observations over an aggregation interval; a quiet result does not prove no traffic.",
  "ACCEPT is a network-policy observation, not proof of application success; REJECT does not identify a specific rule or application outcome.",
  "NODATA and SKIPDATA are capture-scope status records, not evidence that the selected endpoint was absent.",
  "Packets and bytes remain per-record counters. Records are not summed or deduplicated across interfaces, subscriptions, directions or re-deliveries.",
  "Interface and packet addresses are kept separate. NAT, secondary addresses, proxies and service paths can make them differ.",
  "ENI and instance IDs are producer facts. This source does not infer historical resource ownership from current AWS state or an IP-only binding.",
  "Flow Logs omit documented classes of traffic and can arrive late; the result is independent of the application graph snapshot.",
];

function selector(indexes: readonly string[]): string {
  if (
    !indexes.length ||
    indexes.length > 16 ||
    indexes.some((index) => !/^[a-z][a-z0-9_-]{0,79}$/.test(index)) ||
    new Set(indexes).size !== indexes.length
  )
    throw new Error("Invalid AWS VPC Flow Logs index configuration.");
  const terms = indexes.map((index) => "index=" + index).join(" OR ");
  return indexes.length === 1 ? terms : "(" + terms + ")";
}

interface QualifiedAuthority {
  observer: string;
  scope: string;
  accountId: string;
  region: string;
  vpcId: string;
}

function authoritiesFor(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): QualifiedAuthority[] {
  if (
    config.source !== CLOUD_FLOW_SOURCE ||
    config.state !== "active" ||
    config.error ||
    config.schemaQualified !== true ||
    !config.indexes.length ||
    config.indexes.includes("unconfigured_optional") ||
    !config.authorities.length ||
    config.authorities.length > 32
  )
    throw new Error("AWS VPC Flow Logs source is not active and verified.");
  selector(config.indexes);
  const mappings = config.mappings.filter(
    (mapping) =>
      mapping.observer_kind === CLOUD_FLOW_SOURCE &&
      config.authorities.includes(mapping.observer),
  );
  if (
    mappings.length !== config.authorities.length ||
    new Set(mappings.map((mapping) => mapping.observer)).size !==
      config.authorities.length
  )
    throw new Error("AWS VPC Flow Logs authority mapping is ambiguous.");
  const result = mappings.map((mapping) => {
    let observer: string;
    let scope: string;
    try {
      observer = literal(mapping.observer);
      scope = routingScope(mapping.scope);
    } catch {
      throw new Error("AWS VPC Flow Logs authority mapping is invalid.");
    }
    if (
      observer !== observer.toLowerCase() ||
      scope !== selection.scope ||
      mapping.mapping_status !== "verified" ||
      !mapping.account_id ||
      !/^\d{12}$/.test(mapping.account_id) ||
      !mapping.region ||
      !/^[a-z0-9-]{3,32}$/.test(mapping.region) ||
      !mapping.vpc_id ||
      !/^vpc-[0-9a-f]+$/.test(mapping.vpc_id)
    )
      throw new Error(
        "AWS VPC Flow Logs requires a verified host, account, Region and VPC mapping.",
      );
    return {
      observer,
      scope,
      accountId: mapping.account_id,
      region: mapping.region,
      vpcId: mapping.vpc_id,
    };
  });
  if (
    result.some((mapping) => mapping.scope !== selection.scope) ||
    config.authorities.some(
      (authority) => !result.some((mapping) => mapping.observer === authority),
    )
  )
    throw new Error(
      "AWS VPC Flow Logs authority is outside the selected scope.",
    );
  return result;
}

const ADDRESS_COLUMNS: readonly [CloudFlowAddressField, string][] = [
  ["srcaddr", "flow_srcaddr"],
  ["dstaddr", "flow_dstaddr"],
  ["pkt-srcaddr", "flow_pkt_srcaddr"],
  ["pkt-dstaddr", "flow_pkt_dstaddr"],
];

function addressPredicate(addresses: readonly string[]): string {
  if (!addresses.length || addresses.length > 8)
    throw new Error("Narrow the AWS VPC Flow Logs addresses.");
  const ips = [...new Set(addresses.map(normalizeIp))];
  return ips
    .flatMap((address) => {
      const candidates = address.includes(":")
        ? [address]
        : [address, "::ffff:" + address];
      return ADDRESS_COLUMNS.map(([, column]) => {
        const clauses = candidates.map((candidate) => {
          const width = candidate.includes(":") ? 128 : 32;
          return 'cidrmatch("' + candidate + "/" + width + '",' + column + ")";
        });
        return "(" + clauses.join(" OR ") + ")";
      });
    })
    .join(" OR ");
}

/** Search for selected address matches plus capture-scope NODATA/SKIPDATA status. */
export function buildCloudFlowSearch(
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const authorities = authoritiesFor(config, selection);
  const hostTerms = authorities
    .map((mapping) => '"' + literal(mapping.observer) + '"')
    .join(",");
  const matchingAddress = addressPredicate(selection.addresses);
  const statusPredicate = 'flow_log_status IN ("NODATA","SKIPDATA")';
  const intervalPredicate =
    "flow_start<=" +
    Math.ceil(selection.window.end + CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS) +
    " AND flow_end>=" +
    Math.max(
      0,
      Math.floor(selection.window.start - CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS),
    );
  const projection = CLOUD_FLOW_PROJECTION.map(
    ([, column], index) => column + "=mvindex(_cloud_fields," + index + ")",
  ).join(", ");
  const projectedFields = [
    ...CLOUD_FLOW_PROJECTION.map(([, column]) => column),
    "host",
    "index",
    "event_fingerprint",
    "event_time_epoch",
    "_time",
    "_indextime",
    "input_count",
    "oversized_count",
    "oversized",
    "flow_field_count",
  ].join(" ");
  return [
    "search " +
      selector(config.indexes) +
      ' sourcetype="' +
      CLOUD_FLOW_SOURCETYPE +
      '" host IN (' +
      hostTerms +
      ")",
    "| eval oversized=if(len(_raw)>" +
      CLOUD_FLOW_RECORD_BYTES +
      ',1,0), _cloud_line=if(oversized=1,"",replace(trim(_raw),"\\s+"," ")), _cloud_fields=split(_cloud_line," "), flow_field_count=coalesce(mvcount(_cloud_fields),0)',
    "| eval " + projection,
    "| eval event_time_epoch=tonumber(_time), event_fingerprint=if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd)),null())",
    "| where flow_field_count!=29 OR ((" +
      intervalPredicate +
      ") AND ((" +
      matchingAddress +
      ") OR (" +
      statusPredicate +
      ")))",
    "| head " + (CLOUD_FLOW_INPUT_LIMIT + 1),
    "| eventstats count AS input_count sum(oversized) AS oversized_count",
    "| sort 0 - _time index host event_fingerprint",
    "| head " + CLOUD_FLOW_RECORD_LIMIT,
    "| fields " + projectedFields,
    '| eval kind="supplemental_record"',
    '| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(oversized_count) AS oversized | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(coalesce(input_count,0)>' +
      CLOUD_FLOW_INPUT_LIMIT +
      ",1,0),oversized=coalesce(oversized,0)]",
  ].join("\n");
}

export function cloudFlowSearchWindow(
  selection: EvidenceSelection,
): EvidenceWindow {
  return {
    start: Math.max(0, selection.window.start - CLOUD_FLOW_LOOKBACK_SECONDS),
    end: Math.min(
      MAX_EPOCH,
      selection.window.end + CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS,
    ),
  };
}

function projectedValue(row: Row, column: string): string {
  const value = row[column];
  if (typeof value === "string" && value.length <= 4096) return value;
  if (
    Array.isArray(value) &&
    value.length === 1 &&
    typeof value[0] === "string" &&
    value[0].length <= 4096
  )
    return value[0];
  throw new Error("Projected AWS VPC Flow Logs field is missing or invalid.");
}

/** Strictly parse the supported 29-token AWS custom v5 record. */
export function parseCloudFlowLine(line: string): FlowRawFields {
  if (
    typeof line !== "string" ||
    line.length > CLOUD_FLOW_RECORD_BYTES ||
    Array.from(line).some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("AWS VPC Flow Logs record contains invalid text.");
  const values = line.trim().split(/\s+/);
  if (values.length !== CLOUD_FLOW_PROJECTION.length || values[0] !== "5")
    throw new Error(
      "Expected exactly the fixed 29-field AWS custom v5 record.",
    );
  return Object.fromEntries(
    CLOUD_FLOW_PROJECTION.map(([field], index) => [field, values[index]]),
  ) as FlowRawFields;
}

function parseProjected(row: Row): FlowRawFields {
  const values = CLOUD_FLOW_PROJECTION.map(([, column]) =>
    projectedValue(row, column),
  );
  return parseCloudFlowLine(values.join(" "));
}

function optionalText(value: string, maximum = 255): string | undefined {
  if (value === "-") return undefined;
  if (
    !value ||
    value.length > maximum ||
    Array.from(value).some((char) => {
      const code = char.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("Invalid AWS VPC Flow Logs text field.");
  return value;
}

function optionalInteger(value: string, maximum: number): number | undefined {
  if (value === "-") return undefined;
  if (!/^\d+$/.test(value))
    throw new Error("Invalid AWS VPC Flow Logs number.");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum)
    throw new Error("AWS VPC Flow Logs number exceeds its supported range.");
  return parsed;
}

function requiredEpoch(value: string): number {
  const parsed = optionalInteger(value, MAX_EPOCH);
  if (parsed === undefined)
    throw new Error("AWS VPC Flow Logs time is missing.");
  return parsed;
}

function optionalEpoch(value: unknown): number | undefined {
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    String(value) === "" ||
    !/^\d+(?:\.\d+)?$/.test(String(value))
  )
    return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_EPOCH
    ? parsed
    : undefined;
}

function optionalAddress(value: string): string | undefined {
  if (value === "-") return undefined;
  return normalizeIp(value);
}

function matchesEventScope(
  fields: FlowRawFields,
  mapping: QualifiedAuthority,
): boolean {
  const account = fields["account-id"];
  const region = fields.region;
  const vpc = fields["vpc-id"];
  return (
    (account === "-" ||
      account === "unknown" ||
      account === mapping.accountId) &&
    (region === "-" || region === mapping.region) &&
    (vpc === "-" || vpc === mapping.vpcId)
  );
}

function findMapping(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
  authority: string,
): QualifiedAuthority | undefined {
  const matches = authoritiesFor(config, selection).filter(
    (mapping) => mapping.observer === authority,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function countInWindow(interval: EvidenceWindow, selection: EvidenceSelection) {
  return (
    interval.start <=
      selection.window.end + CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS &&
    interval.end >=
      Math.max(0, selection.window.start - CLOUD_FLOW_TIME_UNCERTAINTY_SECONDS)
  );
}

/** Normalize only explicitly projected source columns; never reads _raw. */
export function normalizeCloudFlowEvidence(
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: CloudFlowObservation[]; rejected: number } {
  const selection = validateSelection(input);
  if (
    config.source !== CLOUD_FLOW_SOURCE ||
    rows.length > CLOUD_FLOW_INPUT_LIMIT + 1
  )
    throw new Error("Invalid AWS VPC Flow Logs normalization input.");
  const records: CloudFlowObservation[] = [];
  let rejected = 0;
  const selected = new Set(selection.addresses.map(normalizeIp));
  for (const row of rows) {
    try {
      if (
        row.oversized === 1 ||
        row.oversized === "1" ||
        row.oversized === true
      )
        throw new Error("Oversized record is not normalized.");
      if (Number(row.flow_field_count) !== CLOUD_FLOW_PROJECTION.length)
        throw new Error("Record does not have the exact 29-field contract.");
      const fields = parseProjected(row);
      const authority = typeof row.host === "string" ? row.host : "";
      if (!config.authorities.includes(authority))
        throw new Error("Record authority is outside source configuration.");
      const mapping = findMapping(config, selection, authority);
      if (!mapping || !matchesEventScope(fields, mapping))
        throw new Error(
          "Record account, Region or VPC is outside its mapping.",
        );
      if (
        typeof row.index !== "string" ||
        !config.indexes.includes(row.index) ||
        typeof row.event_fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/.test(row.event_fingerprint)
      )
        throw new Error("Record origin fingerprint is invalid.");
      const indexedTime = optionalEpoch(row._indextime);
      const rowTime = optionalEpoch(row.event_time_epoch);
      if (indexedTime === undefined || rowTime === undefined)
        throw new Error("Record event or index time is missing or invalid.");
      const start = requiredEpoch(fields.start);
      const end = requiredEpoch(fields.end);
      if (Math.abs(rowTime - start) > 1)
        throw new Error(
          "Indexed event time does not match the producer start.",
        );
      if (end < start || !countInWindow({ start, end }, selection))
        throw new Error("Record interval does not overlap the selection.");
      if (
        fields.type !== "-" &&
        fields.type !== "IPv4" &&
        fields.type !== "IPv6" &&
        fields.type !== "EFA"
      )
        throw new Error("Unsupported AWS VPC Flow Logs address type.");
      const interfaceSource = optionalAddress(fields.srcaddr);
      const interfaceDestination = optionalAddress(fields.dstaddr);
      const packetSource = optionalAddress(fields["pkt-srcaddr"]);
      const packetDestination = optionalAddress(fields["pkt-dstaddr"]);
      const addressValues: [CloudFlowAddressField, string | undefined][] = [
        ["srcaddr", interfaceSource],
        ["dstaddr", interfaceDestination],
        ["pkt-srcaddr", packetSource],
        ["pkt-dstaddr", packetDestination],
      ];
      const status = fields["log-status"];
      if (!["OK", "NODATA", "SKIPDATA"].includes(status))
        throw new Error("Unsupported AWS VPC Flow Logs status.");
      const statusRecord = status === "NODATA" || status === "SKIPDATA";
      const matchedAddressFields = statusRecord
        ? []
        : addressValues
            .filter(
              ([, address]) => address !== undefined && selected.has(address),
            )
            .map(([field]) => field);
      if (!statusRecord && !matchedAddressFields.length)
        throw new Error("Record does not match a selected IP field.");
      const sourcePort = optionalInteger(fields.srcport, 65535);
      const destinationPort = optionalInteger(fields.dstport, 65535);
      const protocol = optionalInteger(fields.protocol, 255);
      const packets = optionalInteger(fields.packets, Number.MAX_SAFE_INTEGER);
      const bytes = optionalInteger(fields.bytes, Number.MAX_SAFE_INTEGER);
      const tcpFlags = optionalInteger(fields["tcp-flags"], 511);
      const trafficPath = optionalInteger(fields["traffic-path"], 255);
      const actionValue = fields.action;
      if (!["ACCEPT", "REJECT", "-"].includes(actionValue))
        throw new Error("Unsupported AWS VPC Flow Logs action.");
      const directionValue = fields["flow-direction"];
      if (!["ingress", "egress", "-"].includes(directionValue))
        throw new Error("Unsupported AWS VPC Flow Logs flow direction.");
      const recordType =
        fields.type === "IPv4" ||
        fields.type === "IPv6" ||
        fields.type === "EFA"
          ? fields.type
          : "unknown";
      const limitations = [
        "best_effort_delivery_and_coverage",
        "network_action_does_not_prove_application_outcome",
        "per_record_counters_not_aggregated",
        "producer_ids_do_not_establish_historical_owner",
      ];
      if (statusRecord) limitations.push("capture_status_not_endpoint_absence");
      if (!config.schemaQualified)
        limitations.push("producer_schema_not_qualified");
      records.push({
        schemaVersion: 1,
        source: CLOUD_FLOW_SOURCE,
        authority,
        scope: mapping.scope,
        ...(fields["account-id"] !== "-"
          ? { accountId: fields["account-id"] }
          : {}),
        ...(fields.region !== "-" ? { region: fields.region } : {}),
        ...(fields["vpc-id"] !== "-" ? { vpcId: fields["vpc-id"] } : {}),
        ...(optionalText(fields["subnet-id"]) !== undefined
          ? { subnetId: optionalText(fields["subnet-id"]) }
          : {}),
        ...(optionalText(fields["instance-id"]) !== undefined
          ? { instanceId: optionalText(fields["instance-id"]) }
          : {}),
        ...(optionalText(fields["interface-id"]) !== undefined
          ? { interfaceId: optionalText(fields["interface-id"]) }
          : {}),
        ...(optionalText(fields["az-id"]) !== undefined
          ? { availabilityZoneId: optionalText(fields["az-id"]) }
          : {}),
        ...(optionalText(fields["sublocation-type"]) !== undefined
          ? { sublocationType: optionalText(fields["sublocation-type"]) }
          : {}),
        ...(optionalText(fields["sublocation-id"]) !== undefined
          ? { sublocationId: optionalText(fields["sublocation-id"]) }
          : {}),
        recordType,
        interfaceAddresses: {
          ...(interfaceSource ? { source: interfaceSource } : {}),
          ...(interfaceDestination
            ? { destination: interfaceDestination }
            : {}),
        },
        packetAddresses: {
          ...(packetSource ? { source: packetSource } : {}),
          ...(packetDestination ? { destination: packetDestination } : {}),
        },
        ...(sourcePort !== undefined ? { sourcePort } : {}),
        ...(destinationPort !== undefined ? { destinationPort } : {}),
        ...(protocol !== undefined ? { protocol } : {}),
        ...(packets !== undefined ? { packets } : {}),
        ...(bytes !== undefined ? { bytes } : {}),
        ...(tcpFlags !== undefined ? { tcpFlags } : {}),
        ...(optionalText(fields["pkt-src-aws-service"]) !== undefined
          ? {
              packetSourceAwsService: optionalText(
                fields["pkt-src-aws-service"],
              ),
            }
          : {}),
        ...(optionalText(fields["pkt-dst-aws-service"]) !== undefined
          ? {
              packetDestinationAwsService: optionalText(
                fields["pkt-dst-aws-service"],
              ),
            }
          : {}),
        ...(trafficPath !== undefined ? { trafficPath } : {}),
        flowDirection:
          directionValue === "ingress" || directionValue === "egress"
            ? directionValue
            : "unknown",
        action:
          actionValue === "ACCEPT" || actionValue === "REJECT"
            ? actionValue
            : "unknown",
        logStatus: status as CloudFlowLogStatus,
        recordClass: statusRecord ? "capture_status" : "flow",
        interval: { start, end },
        matchedAddressFields,
        index: row.index,
        eventFingerprint: row.event_fingerprint,
        eventTime: start,
        rowTime,
        indexedTime,
        attribution: "context_only",
        attributionReason: statusRecord
          ? "Capture status has no endpoint-level meaning."
          : "Address match is scoped to an attested AWS capture authority; no time-valid ENI-to-resource binding was supplied.",
        limitations,
      });
    } catch {
      rejected++;
    }
  }
  return { records, rejected };
}

export function loadCloudFlowEvidence(
  client: SearchClient,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<SupplementalResult<CloudFlowObservation>> {
  return loadSupplementalEvidence(
    client,
    selection,
    signal,
    CLOUD_FLOW_SOURCE,
    buildCloudFlowSearch,
    normalizeCloudFlowEvidence,
    configurationClient,
    false,
    cloudFlowSearchWindow,
    COVERAGE,
  );
}
