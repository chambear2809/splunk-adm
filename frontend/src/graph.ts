import { isoTime } from "./time";
import { sameNatIp, usableNatIp } from "./ip";
export type NodeKind = "service" | "workload" | "endpoint" | "client";
export type Relationship =
  | "calls"
  | "communicates_with"
  | "runs_on"
  | "forwards_to"
  | "traffic_observation";
export type EndpointKind =
  | "k8s_node"
  | "vm"
  | "external"
  | "unresolved"
  | "ambiguous"
  | "k8s_service"
  | "k8s_node_proxy"
  | "network_client";
export type TrafficObservation = {
  source?: string;
  source_authority?: string;
  routing_domain?: string;
  observation_domain_id?: string;
  exporter_ip?: string;
  flow_id?: string;
  record_fingerprint?: string;
  sequence?: string;
  first_seen?: number;
  last_seen?: number;
  collected_time?: number;
  direction?: string;
  observation_point?: string;
  ingress_interface?: string;
  egress_interface?: string;
  bytes_in?: number;
  bytes_out?: number;
  packets_in?: number;
  packets_out?: number;
  exporter_sampling_mode?: string;
  exporter_sampling_interval?: number;
  vpn_id?: string;
  ingress_overlay_session_id?: string;
  egress_overlay_session_id?: string;
  quality_status?: "accepted" | "accepted_with_warning" | "excluded";
  quality_errors?: string;
  quality_warnings?: string;
  counter_semantics?: string;
  metrics_authoritative?: boolean;
  records?: number;
  observation_domain_present?: number | string;
  received_time?: number | string;
  source_mac?: string;
  destination_mac?: string;
  source_port?: number;
  destination_port?: number;
  raw_bytes?: number;
  raw_packets?: number;
  raw_sampling?: string | number;
  interface_in?: string;
  interface_out?: string;
  raw_bytes_in?: number;
  raw_bytes_out?: number;
  raw_packets_in?: number;
  raw_packets_out?: number;
  domain_kind?: string;
  scope?: string;
  cluster?: string;
  profile?: string;
  mapping_status?: string;
  source_ip?: string;
  destination_ip?: string;
  server_port?: number;
  transport?: string;
  event_identity_status?: string;
};
export interface AttachmentEvidence {
  basis?: string;
  status?: string;
  event_time?: number | string;
  received_time?: number | string;
  collected_time?: number | string;
  device_id?: string;
  device_name?: string;
  device_mac?: string;
  device_serial?: string;
  ssid_number?: string | number;
  client_source?: string;
  client_authority?: string;
  client_native_id?: string;
}
/** How a Service frontend was linked to the backend pod that served it. */
export type HandoffBasis =
  "hubble_client_tuple" | "hubble_xlate" | "time_inferred" | "l7_forwarded_for";
export const HANDOFF_BASES: readonly HandoffBasis[] = [
  "hubble_client_tuple",
  "hubble_xlate",
  "time_inferred",
  "l7_forwarded_for",
];
export type ClientHandoffCoverage =
  "complete" | "partial" | "unresolved" | "incomplete";
export const CLIENT_HANDOFF_COVERAGES: readonly ClientHandoffCoverage[] = [
  "complete",
  "partial",
  "unresolved",
  "incomplete",
];
export interface ClientHandoffRecord {
  target: string;
  basis: HandoffBasis;
  connections: number;
  receiving_nodes: string[];
  observers: string[];
}
export type ContractBasis = "intent" | "intra_epg" | "not_evaluated" | "none";
export const CONTRACT_BASES: readonly ContractBasis[] = [
  "intent",
  "intra_epg",
  "not_evaluated",
  "none",
];
export type AclAction = "permit" | "drop";
export type DirectionBasis = "initiator" | "port_rule" | "unknown";
export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  endpoint_kind?: EndpointKind;
  namespace?: string;
  cluster?: string;
  addresses?: string[];
  reason?: string;
  attributes?: Record<string, string>;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: Relationship;
  evidence: string[];
  confidence: "observed" | "correlated" | "unresolved" | "inferred";
  count: number;
  bytes?: number;
  reason?: string;
  observers?: string[];
  sources?: string[];
  span_ids?: string[];
  server_port?: number;
  transport?: string;
  direction_basis?: DirectionBasis;
  encapsulation?: string;
  evidence_truncated?: boolean;
  /** forwards_to only. */
  handoff_basis?: HandoffBasis;
  /** V2 per-client handoff evidence; aggregate Service edges are not a substitute. */
  client_handoff_coverage?: ClientHandoffCoverage;
  client_handoff_connections?: number;
  client_handoff_determined?: number;
  client_handoff_unresolved?: number;
  client_handoffs?: ClientHandoffRecord[];
  /** Kubernetes node that received the frontend traffic, when known. */
  /** Kubernetes nodes that received the frontend traffic (one or several). */
  via_node?: string[];
  /** Why the collected ACI policy was not evaluated, when the search says. */
  contract_reason?: string;
  contract?: string;
  contract_subject?: string;
  contract_filter?: string;
  /** e.g. "tcp 443". */
  contract_entry?: string;
  contract_basis?: ContractBasis;
  acl_action?: AclAction;
  acl_leaf?: string;
  acl_permits?: number;
  acl_drops?: number;
  /** NetFlow VLAN observations, serialized as one JSON array in Splunk rows. */
  vlan_observations?: VlanObservation[];
  /** NetFlow discarded additional VLAN contexts for this edge. */
  vlan_observations_truncated?: boolean;
  /** Cisco FTD eStreamer translation evidence contained in the same event. */
  nat_observations?: NatObservation[];
  /** More same-event translation observations existed than were returned. */
  nat_observations_truncated?: boolean;
  /** Flow observations are evidence at observation points, not adjacency or packet routes. */
  traffic_observations?: TrafficObservation[];
  attachment_evidence?: AttachmentEvidence[];
  counter_semantics?: string;
  metrics_authoritative?: boolean;
  raw_bytes?: number;
  raw_packets?: number;
  records?: number;
  source_port?: number;
  destination_port?: number;
  source_mac?: string;
  source_ip?: string;
  destination_ip?: string;
  traffic_observation_id?: string;
  link_kind?: string;
  link_source?: string;
  /** Explicit routing scope carried by edge-level collection evidence. */
  scope?: string;
  cluster?: string;
  source_authority?: string;
}
export interface VlanObservation {
  vlan: number;
  position: "ingress" | "egress";
  exporter: string;
  interface_index?: string;
  interface?: string;
  src_ip: string;
  dest_ip: string;
  first_seen: number;
  last_seen: number;
}
export interface NatObservation {
  source_authority: "cisco:sfw:estreamer";
  event_type: "ConnectionEvent";
  scope: string;
  scope_mapping_verified: true;
  device_ip: string;
  event_fingerprint: string;
  event_time: number;
  received_time: number;
  protocol: "tcp" | "udp" | "sctp";
  direction: "initiator_to_responder";
  reported_initiator_ip: string;
  reported_initiator_port: number;
  reported_responder_ip: string;
  reported_responder_port: number;
  translated_initiator_ip: string;
  translated_initiator_port: number;
  translated_responder_ip: string;
  translated_responder_port: number;
  reported_original_initiator_ip?: string;
}
export interface Graph {
  schema_version: 1;
  snapshot_id: string;
  generated_at: string;
  demo: boolean;
  window: { start: string; end: string };
  /** Exact Splunk event-time bounds for NAT evidence; omitted on older/no-NAT snapshots. */
  nat_event_window?: { start: number; end: number };
  boundary: {
    id: string;
    service: string;
    environment: string;
    cluster: string;
    namespace: string;
    root_node_id: string;
  };
  nodes: GraphNode[];
  edges: GraphEdge[];
  coverage: {
    spans: number;
    conversations: number;
    matched_conversations: number;
    unresolved_conversations: number;
    ambiguous_conversations: number;
    warnings: string[];
  };
}
const COVERAGE_COUNTS = [
  "spans",
  "conversations",
  "matched_conversations",
  "unresolved_conversations",
  "ambiguous_conversations",
] as const;
export const ENDPOINT_KINDS: readonly EndpointKind[] = [
  "k8s_node",
  "vm",
  "external",
  "unresolved",
  "ambiguous",
  "k8s_service",
  "k8s_node_proxy",
  "network_client",
];
export const RELATIONSHIPS: readonly Relationship[] = [
  "calls",
  "communicates_with",
  "runs_on",
  "forwards_to",
  "traffic_observation",
];
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const strings = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");
const number = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0;
const id = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= 4096;
const date = isoTime;
const allowedEdges: Record<Relationship, [NodeKind[], NodeKind[]]> = {
  calls: [["service"], ["service"]],
  runs_on: [["service"], ["workload"]],
  communicates_with: [
    ["workload", "endpoint", "client"],
    ["workload", "endpoint"],
  ],
  forwards_to: [["endpoint"], ["workload"]],
  traffic_observation: [
    ["client", "endpoint"],
    ["endpoint", "workload"],
  ],
};
const optionalText = (v: unknown) => v === undefined || typeof v === "string";
const optionalCount = (v: unknown) => v === undefined || number(v);
const ATTACHMENT_TEXT_FIELDS = [
  "basis",
  "status",
  "device_id",
  "device_name",
  "device_mac",
  "device_serial",
  "client_source",
  "client_authority",
  "client_native_id",
] as const;
const ATTACHMENT_TIME_FIELDS = [
  "event_time",
  "received_time",
  "collected_time",
] as const;
const ATTACHMENT_FIELDS = [
  ...ATTACHMENT_TEXT_FIELDS,
  ...ATTACHMENT_TIME_FIELDS,
  "ssid_number",
] as const;
const validAttachmentTime = (value: unknown) => {
  if (typeof value === "number") return validEpochSeconds(value);
  if (typeof value !== "string" || !/^\d+(?:\.\d+)?$/.test(value)) return false;
  return validEpochSeconds(Number(value));
};
export const validAttachmentEvidence = (
  value: unknown,
): value is AttachmentEvidence => {
  if (!object(value)) return false;
  if (
    Object.keys(value).some(
      (field) => !ATTACHMENT_FIELDS.includes(field as never),
    )
  )
    return false;
  return (
    ATTACHMENT_TEXT_FIELDS.every(
      (field) => value[field] === undefined || typeof value[field] === "string",
    ) &&
    ATTACHMENT_TIME_FIELDS.every(
      (field) =>
        value[field] === undefined || validAttachmentTime(value[field]),
    ) &&
    (value.ssid_number === undefined ||
      typeof value.ssid_number === "string" ||
      (typeof value.ssid_number === "number" &&
        Number.isFinite(value.ssid_number) &&
        value.ssid_number >= 0))
  );
};
export const validVlan = (v: unknown): v is number =>
  typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 4094;
export const validVlanString = (v: unknown): v is string =>
  typeof v === "string" &&
  /^\d+$/.test(v) &&
  String(Number(v)) === v &&
  validVlan(Number(v));
export const validEpochSeconds = (v: unknown): v is number =>
  typeof v === "number" &&
  Number.isFinite(v) &&
  v >= 0 &&
  v <= 8_640_000_000_000;
export const validVlanObservation = (v: unknown): v is VlanObservation => {
  if (!object(v)) return false;
  const text = (x: unknown) =>
    typeof x === "string" && x.length > 0 && x.length <= 4096;
  const interfaceIndex = v.interface_index;
  return (
    validVlan(v.vlan) &&
    (v.position === "ingress" || v.position === "egress") &&
    text(v.exporter) &&
    text(v.src_ip) &&
    text(v.dest_ip) &&
    (interfaceIndex === undefined ||
      (typeof interfaceIndex === "string" &&
        /^\d+$/.test(interfaceIndex) &&
        interfaceIndex.length <= 20)) &&
    (v.interface === undefined || text(v.interface)) &&
    validEpochSeconds(v.first_seen) &&
    validEpochSeconds(v.last_seen) &&
    v.last_seen >= v.first_seen
  );
};
export const validNatObservation = (v: unknown): v is NatObservation => {
  if (!object(v)) return false;
  const allowed = new Set([
    "source_authority",
    "event_type",
    "scope",
    "scope_mapping_verified",
    "device_ip",
    "event_fingerprint",
    "event_time",
    "received_time",
    "protocol",
    "direction",
    "reported_initiator_ip",
    "reported_initiator_port",
    "reported_responder_ip",
    "reported_responder_port",
    "translated_initiator_ip",
    "translated_initiator_port",
    "translated_responder_ip",
    "translated_responder_port",
    "reported_original_initiator_ip",
  ]);
  const text = (x: unknown, limit = 2048): x is string =>
    typeof x === "string" && x.length > 0 && x.length <= limit;
  const port = (x: unknown) =>
    Number.isInteger(x) && (x as number) >= 1 && (x as number) <= 65535;
  if (Object.keys(v).some((key) => !allowed.has(key))) return false;
  if (
    v.source_authority !== "cisco:sfw:estreamer" ||
    v.event_type !== "ConnectionEvent" ||
    !text(v.scope) ||
    !v.scope.trim() ||
    v.scope.trim().toLowerCase().startsWith("unmapped:") ||
    v.scope_mapping_verified !== true ||
    !usableNatIp(v.device_ip) ||
    typeof v.event_fingerprint !== "string" ||
    !/^[0-9a-f]{64}$/.test(v.event_fingerprint) ||
    !validEpochSeconds(v.event_time) ||
    !Number.isInteger(v.event_time) ||
    !validEpochSeconds(v.received_time) ||
    !Number.isInteger(v.received_time) ||
    !["tcp", "udp", "sctp"].includes(v.protocol as string) ||
    v.direction !== "initiator_to_responder" ||
    !usableNatIp(v.reported_initiator_ip) ||
    !port(v.reported_initiator_port) ||
    !usableNatIp(v.reported_responder_ip) ||
    !port(v.reported_responder_port) ||
    !usableNatIp(v.translated_initiator_ip) ||
    !port(v.translated_initiator_port) ||
    !usableNatIp(v.translated_responder_ip) ||
    !port(v.translated_responder_port) ||
    (v.reported_original_initiator_ip !== undefined &&
      !usableNatIp(v.reported_original_initiator_ip))
  )
    return false;
  return (
    !sameNatIp(
      v.reported_initiator_ip as string,
      v.translated_initiator_ip as string,
    ) ||
    v.reported_initiator_port !== v.translated_initiator_port ||
    !sameNatIp(
      v.reported_responder_ip as string,
      v.translated_responder_ip as string,
    ) ||
    v.reported_responder_port !== v.translated_responder_port
  );
};
export const validNatObservations = (v: unknown): v is NatObservation[] =>
  Array.isArray(v) &&
  v.length <= 32 &&
  v.every(validNatObservation) &&
  new Set(v.map((observation) => observation.event_fingerprint)).size ===
    v.length;
const TRAFFIC_TEXT_FIELDS = [
  "source",
  "source_authority",
  "routing_domain",
  "observation_domain_id",
  "exporter_ip",
  "flow_id",
  "record_fingerprint",
  "sequence",
  "direction",
  "observation_point",
  "ingress_interface",
  "egress_interface",
  "exporter_sampling_mode",
  "vpn_id",
  "ingress_overlay_session_id",
  "egress_overlay_session_id",
  "counter_semantics",
  "source_mac",
  "destination_mac",
  "interface_in",
  "interface_out",
  "domain_kind",
  "scope",
  "cluster",
  "profile",
  "mapping_status",
  "source_ip",
  "destination_ip",
  "transport",
  "event_identity_status",
] as const;
const TRAFFIC_QUALITY_TEXT_FIELDS = [
  "quality_errors",
  "quality_warnings",
] as const;
const TRAFFIC_NUMBER_FIELDS = [
  "first_seen",
  "last_seen",
  "collected_time",
  "bytes_in",
  "bytes_out",
  "packets_in",
  "packets_out",
  "exporter_sampling_interval",
  "records",
  "source_port",
  "destination_port",
  "raw_bytes",
  "raw_packets",
  "raw_bytes_in",
  "raw_bytes_out",
  "raw_packets_in",
  "raw_packets_out",
  "server_port",
] as const;
const TRAFFIC_SCALAR_FIELDS = [
  "observation_domain_present",
  "received_time",
  "raw_sampling",
] as const;
export const validTrafficObservation = (
  v: unknown,
): v is TrafficObservation => {
  if (!object(v)) return false;
  if (
    Object.keys(v).some(
      (k) =>
        ![
          ...TRAFFIC_TEXT_FIELDS,
          ...TRAFFIC_QUALITY_TEXT_FIELDS,
          ...TRAFFIC_NUMBER_FIELDS,
          ...TRAFFIC_SCALAR_FIELDS,
          "metrics_authoritative",
          "quality_status",
        ].includes(k as never),
    )
  )
    return false;
  if (
    TRAFFIC_TEXT_FIELDS.some(
      (k) => v[k] !== undefined && typeof v[k] !== "string",
    )
  )
    return false;
  if (
    TRAFFIC_QUALITY_TEXT_FIELDS.some(
      (k) => v[k] !== undefined && typeof v[k] !== "string",
    ) ||
    (v.quality_status !== undefined &&
      (typeof v.quality_status !== "string" ||
        !["accepted", "accepted_with_warning", "excluded"].includes(
          v.quality_status,
        )))
  )
    return false;
  if (TRAFFIC_NUMBER_FIELDS.some((k) => v[k] !== undefined && !number(v[k])))
    return false;
  if (
    v.observation_domain_present !== undefined &&
    typeof v.observation_domain_present !== "string" &&
    typeof v.observation_domain_present !== "number"
  )
    return false;
  if (
    v.received_time !== undefined &&
    typeof v.received_time !== "string" &&
    typeof v.received_time !== "number"
  )
    return false;
  if (
    v.raw_sampling !== undefined &&
    typeof v.raw_sampling !== "string" &&
    !number(v.raw_sampling)
  )
    return false;
  if (
    v.observation_domain_present !== undefined &&
    typeof v.observation_domain_present !== "string" &&
    typeof v.observation_domain_present !== "number"
  )
    return false;
  if (
    v.received_time !== undefined &&
    typeof v.received_time !== "string" &&
    typeof v.received_time !== "number"
  )
    return false;
  if (
    v.metrics_authoritative !== undefined &&
    typeof v.metrics_authoritative !== "boolean"
  )
    return false;
  if (
    typeof v.first_seen === "number" &&
    typeof v.last_seen === "number" &&
    v.last_seen < v.first_seen
  )
    return false;
  return true;
};

export function validClientHandoffRecord(v: unknown): v is ClientHandoffRecord {
  return (
    object(v) &&
    Object.keys(v).every((key) =>
      [
        "target",
        "basis",
        "connections",
        "receiving_nodes",
        "observers",
      ].includes(key),
    ) &&
    typeof v.target === "string" &&
    /^pod:[^/]+\/.+$/.test(v.target) &&
    HANDOFF_BASES.includes(v.basis as HandoffBasis) &&
    Number.isSafeInteger(v.connections) &&
    (v.connections as number) > 0 &&
    strings(v.receiving_nodes) &&
    v.receiving_nodes.length <= 64 &&
    strings(v.observers) &&
    v.observers.length <= 64
  );
}

export function validClientHandoffMetadata(
  edge: Partial<GraphEdge>,
  targetIsPod?: (id: string) => boolean,
): edge is GraphEdge & {
  client_handoff_coverage: ClientHandoffCoverage;
  client_handoff_connections: number;
  client_handoff_determined: number;
  client_handoff_unresolved: number;
  client_handoffs: ClientHandoffRecord[];
} {
  if (
    !CLIENT_HANDOFF_COVERAGES.includes(
      edge.client_handoff_coverage as ClientHandoffCoverage,
    ) ||
    !Number.isSafeInteger(edge.client_handoff_connections) ||
    !Number.isSafeInteger(edge.client_handoff_determined) ||
    !Number.isSafeInteger(edge.client_handoff_unresolved) ||
    (edge.client_handoff_connections as number) < 0 ||
    (edge.client_handoff_determined as number) < 0 ||
    (edge.client_handoff_unresolved as number) < 0 ||
    !Array.isArray(edge.client_handoffs) ||
    edge.client_handoffs.length > 64 ||
    !edge.client_handoffs.every(validClientHandoffRecord)
  )
    return false;
  const records = edge.client_handoffs;
  const keys = records.map((r) => JSON.stringify([r.target, r.basis]));
  if (new Set(keys).size !== keys.length) return false;
  if (targetIsPod && records.some((r) => !targetIsPod(r.target))) return false;
  const { client_handoff_coverage: coverage } = edge;
  const total = edge.client_handoff_connections as number;
  const determined = edge.client_handoff_determined as number;
  const unresolved = edge.client_handoff_unresolved as number;
  const recordConnections = records.reduce((sum, r) => sum + r.connections, 0);
  if (!Number.isSafeInteger(recordConnections)) return false;
  if (total !== determined + unresolved) return false;
  if (
    coverage === "incomplete"
      ? records.length !== 0
      : recordConnections !== determined
  )
    return false;
  if (coverage === "partial" && (determined === 0 || unresolved === 0))
    return false;
  if (coverage === "unresolved" && determined !== 0) return false;
  return coverage !== "complete" || (total > 0 && determined === total);
}
/**
 * Node-to-node tunnel of a conversation. Cilium DSR forwards to remote
 * backends over IPIP, which flow records report as transport `ipip`.
 */
export function tunnelOf(e: GraphEdge): string | undefined {
  return (
    e.encapsulation ??
    (e.transport?.toLowerCase() === "ipip" ? "ipip" : undefined)
  );
}
export const tunnelLabel = (t: string) =>
  t === "ipip" ? "IPIP (DSR)" : t.toUpperCase();
/** Reject malformed snapshots before using untrusted indexed content in the UI. */
export function parseGraph(value: unknown): Graph {
  if (
    !object(value) ||
    value.schema_version !== 1 ||
    typeof value.demo !== "boolean" ||
    !id(value.snapshot_id) ||
    !date(value.generated_at)
  )
    throw new Error("Unsupported or invalid graph snapshot.");
  const b = value.boundary,
    w = value.window,
    c = value.coverage;
  if (
    !object(b) ||
    ![
      "id",
      "service",
      "environment",
      "cluster",
      "namespace",
      "root_node_id",
    ].every((k) => id(b[k])) ||
    !object(w) ||
    !date(w.start) ||
    !date(w.end) ||
    Date.parse(w.start) >= Date.parse(w.end)
  )
    throw new Error("Snapshot boundary or time window is invalid.");
  if (
    !object(c) ||
    !COVERAGE_COUNTS.every((k) => number(c[k])) ||
    !strings(c.warnings)
  )
    throw new Error("Snapshot coverage is invalid.");
  const natWindow = value.nat_event_window;
  let exactNatWindow: { start: number; end: number } | undefined;
  if (natWindow !== undefined) {
    if (!object(natWindow))
      throw new Error("Snapshot NAT evidence time window is invalid.");
    const start = natWindow.start;
    const end = natWindow.end;
    if (
      !number(start) ||
      !number(end) ||
      start >= end ||
      Math.floor(start) !== Date.parse(w.start as string) / 1000 ||
      Math.floor(end) !== Date.parse(w.end as string) / 1000
    )
      throw new Error("Snapshot NAT evidence time window is invalid.");
    exactNatWindow = {
      start,
      end,
    };
  }
  const windowStart =
    exactNatWindow?.start ?? Date.parse(w.start as string) / 1000;
  const windowEnd = exactNatWindow?.end ?? Date.parse(w.end as string) / 1000;
  if (
    !Array.isArray(value.nodes) ||
    value.nodes.length > 500 ||
    !Array.isArray(value.edges) ||
    value.edges.length > 2000
  )
    throw new Error(
      "Graph exceeds the pilot limit (500 nodes / 2,000 edges). Narrow the time range or namespace.",
    );
  const natObservationsInWindow = (v: unknown) =>
    validNatObservations(v) &&
    v.every(
      (observation) =>
        observation.event_time >= windowStart &&
        observation.event_time < windowEnd,
    );
  const kinds = new Map<string, NodeKind>();
  const endpointKinds = new Map<string, unknown>();
  const clusters = new Map<string, string | undefined>();
  const serviceHandoffMarkers = new Map<string, boolean>();
  for (const n of value.nodes) {
    if (
      !object(n) ||
      !id(n.id) ||
      typeof n.label !== "string" ||
      typeof n.kind !== "string" ||
      !["service", "workload", "endpoint", "client"].includes(n.kind) ||
      (n.addresses !== undefined && !strings(n.addresses)) ||
      kinds.has(n.id)
    )
      throw new Error("Snapshot contains invalid or duplicate nodes.");
    for (const k of ["namespace", "cluster", "reason"])
      if (n[k] !== undefined && typeof n[k] !== "string")
        throw new Error("Invalid node metadata.");
    if (
      (n.endpoint_kind !== undefined &&
        !(
          (n.kind === "endpoint" ||
            (n.kind === "client" && n.endpoint_kind === "network_client")) &&
          ENDPOINT_KINDS.includes(n.endpoint_kind as EndpointKind)
        )) ||
      (n.attributes !== undefined &&
        (!object(n.attributes) ||
          !Object.values(n.attributes).every((v) => typeof v === "string")))
    )
      throw new Error("Invalid node metadata.");
    if (n.attributes?.vlan !== undefined && !validVlanString(n.attributes.vlan))
      throw new Error("Invalid node VLAN metadata.");
    for (const k of ["vlan_status", "bridge_domain_status"])
      if (
        n.attributes?.[k] !== undefined &&
        (typeof n.attributes[k] !== "string" ||
          !["varies", "incomplete"].includes(n.attributes[k]))
      )
        throw new Error("Invalid node network metadata.");
    kinds.set(n.id, n.kind as NodeKind);
    endpointKinds.set(n.id, n.endpoint_kind);
    clusters.set(n.id, n.cluster as string | undefined);
    serviceHandoffMarkers.set(
      n.id,
      n.attributes?.handoff_coverage !== undefined,
    );
  }
  const isClientHandoffSource = (nodeId: string) =>
    kinds.get(nodeId) === "workload" ||
    (kinds.get(nodeId) === "endpoint" &&
      endpointKinds.get(nodeId) !== undefined &&
      endpointKinds.get(nodeId) !== "k8s_service") ||
    (kinds.get(nodeId) === "client" &&
      endpointKinds.get(nodeId) === "network_client");
  if (value.nodes.length && kinds.get(String(b.root_node_id)) !== "service")
    throw new Error("Snapshot root is missing or is not a service.");
  const edgeIds = new Set<string>();
  for (const e of value.edges) {
    if (
      !object(e) ||
      !id(e.id) ||
      edgeIds.has(e.id) ||
      typeof e.source !== "string" ||
      typeof e.target !== "string" ||
      !kinds.has(e.source) ||
      !kinds.has(e.target) ||
      typeof e.relationship !== "string" ||
      typeof e.confidence !== "string" ||
      !RELATIONSHIPS.includes(e.relationship as Relationship) ||
      !["observed", "correlated", "unresolved", "inferred"].includes(
        e.confidence,
      ) ||
      !strings(e.evidence) ||
      !number(e.count) ||
      (e.bytes !== undefined && !number(e.bytes)) ||
      (e.observers !== undefined && !strings(e.observers)) ||
      (e.sources !== undefined && !strings(e.sources)) ||
      (e.span_ids !== undefined && !strings(e.span_ids)) ||
      (e.server_port !== undefined &&
        !(
          Number.isInteger(e.server_port) &&
          (e.server_port as number) >= 0 &&
          (e.server_port as number) <= 65535
        )) ||
      (e.transport !== undefined && typeof e.transport !== "string") ||
      (e.direction_basis !== undefined &&
        (typeof e.direction_basis !== "string" ||
          !["initiator", "port_rule", "unknown"].includes(
            e.direction_basis,
          ))) ||
      (e.encapsulation !== undefined && typeof e.encapsulation !== "string") ||
      (e.reason !== undefined && typeof e.reason !== "string") ||
      (e.evidence_truncated !== undefined &&
        typeof e.evidence_truncated !== "boolean") ||
      (e.vlan_observations !== undefined &&
        (!Array.isArray(e.vlan_observations) ||
          e.vlan_observations.length > 32 ||
          !e.vlan_observations.every(validVlanObservation))) ||
      (e.vlan_observations_truncated !== undefined &&
        typeof e.vlan_observations_truncated !== "boolean") ||
      ((e.nat_observations !== undefined ||
        e.nat_observations_truncated !== undefined) &&
        e.relationship !== "communicates_with") ||
      (e.nat_observations !== undefined &&
        !natObservationsInWindow(e.nat_observations)) ||
      (e.nat_observations_truncated !== undefined &&
        typeof e.nat_observations_truncated !== "boolean") ||
      (e.traffic_observations !== undefined &&
        (!Array.isArray(e.traffic_observations) ||
          e.traffic_observations.length > 64 ||
          !e.traffic_observations.every(validTrafficObservation))) ||
      (e.via_node !== undefined && !strings(e.via_node)) ||
      (e.client_handoff_coverage !== undefined &&
        !CLIENT_HANDOFF_COVERAGES.includes(
          e.client_handoff_coverage as ClientHandoffCoverage,
        )) ||
      (
        [
          "client_handoff_connections",
          "client_handoff_determined",
          "client_handoff_unresolved",
        ] as const
      ).some(
        (k) =>
          e[k] !== undefined &&
          (!Number.isSafeInteger(e[k]) || (e[k] as number) < 0),
      ) ||
      (e.client_handoffs !== undefined &&
        (!Array.isArray(e.client_handoffs) ||
          e.client_handoffs.length > 64 ||
          !e.client_handoffs.every(validClientHandoffRecord))) ||
      (e.counter_semantics !== undefined &&
        typeof e.counter_semantics !== "string") ||
      (e.metrics_authoritative !== undefined &&
        typeof e.metrics_authoritative !== "boolean") ||
      (
        [
          "raw_bytes",
          "raw_packets",
          "records",
          "source_port",
          "destination_port",
        ] as const
      ).some((k) => e[k] !== undefined && !number(e[k])) ||
      (
        [
          "source_mac",
          "source_ip",
          "destination_ip",
          "traffic_observation_id",
          "link_kind",
          "link_source",
        ] as const
      ).some((k) => e[k] !== undefined && typeof e[k] !== "string") ||
      (e.attachment_evidence !== undefined &&
        (!Array.isArray(e.attachment_evidence) ||
          !e.attachment_evidence.every(validAttachmentEvidence))) ||
      !optionalText(e.contract_reason) ||
      !optionalText(e.contract) ||
      !optionalText(e.contract_subject) ||
      !optionalText(e.contract_filter) ||
      !optionalText(e.contract_entry) ||
      !optionalText(e.acl_leaf) ||
      !optionalCount(e.acl_permits) ||
      !optionalCount(e.acl_drops) ||
      (e.contract_basis !== undefined &&
        !CONTRACT_BASES.includes(e.contract_basis as ContractBasis)) ||
      (e.acl_action !== undefined &&
        e.acl_action !== "permit" &&
        e.acl_action !== "drop")
    )
      throw new Error("Snapshot contains invalid relationships.");
    const forward = e.relationship === "forwards_to";
    const trafficObservation = e.relationship === "traffic_observation";
    if (
      forward !== (e.handoff_basis !== undefined) ||
      (forward &&
        (!HANDOFF_BASES.includes(e.handoff_basis as HandoffBasis) ||
          !["observed", "inferred"].includes(e.confidence) ||
          endpointKinds.get(e.source) !== "k8s_service")) ||
      (!forward && e.confidence === "inferred") ||
      // Contract and ACL-log annotations describe network conversations only.
      (e.relationship !== "communicates_with" &&
        [
          "contract",
          "contract_basis",
          "acl_action",
          "acl_leaf",
          "acl_permits",
          "acl_drops",
        ].some((k) => e[k] !== undefined)) ||
      // A contract is named for intent (permit) or, with basis none, a deny.
      (e.contract !== undefined &&
        e.contract_basis !== "intent" &&
        e.contract_basis !== "none") ||
      (e.contract_basis === "intent" && e.contract === undefined) ||
      (trafficObservation &&
        (e.bytes !== undefined ||
          e.confidence === "inferred" ||
          e.handoff_basis !== undefined)) ||
      (e.traffic_observation_id !== undefined &&
        (typeof e.traffic_observation_id !== "string" ||
          !/^[0-9a-f]{64}$/.test(e.traffic_observation_id) ||
          e.relationship !== "traffic_observation" ||
          e.id !== `traffic-observation:${e.traffic_observation_id}`))
    )
      throw new Error("Snapshot contains an invalid handoff or policy field.");
    const clientMetadataKeys = [
      "client_handoff_coverage",
      "client_handoff_connections",
      "client_handoff_determined",
      "client_handoff_unresolved",
      "client_handoffs",
    ] as const;
    const hasClientMetadata = clientMetadataKeys.some(
      (k) => e[k] !== undefined,
    );
    const clientToService =
      e.relationship === "communicates_with" &&
      isClientHandoffSource(e.source) &&
      endpointKinds.get(e.target) === "k8s_service";
    if (
      (hasClientMetadata || clientToService) &&
      (e.relationship !== "communicates_with" ||
        !isClientHandoffSource(e.source) ||
        endpointKinds.get(e.target) !== "k8s_service" ||
        (hasClientMetadata &&
          !validClientHandoffMetadata(
            e as unknown as GraphEdge,
            (target) =>
              kinds.get(target) === "workload" &&
              typeof clusters.get(String(e.target)) === "string" &&
              clusters.get(target) === clusters.get(String(e.target)) &&
              target.startsWith(`pod:${clusters.get(String(e.target))}/`),
          )))
    )
      throw new Error("Snapshot contains invalid client handoff metadata.");
    const [sources, targets] = allowedEdges[e.relationship as Relationship];
    if (
      !sources.includes(kinds.get(e.source)!) ||
      !targets.includes(kinds.get(e.target)!)
    )
      throw new Error(
        "Snapshot relationship connects incompatible node kinds.",
      );
    edgeIds.add(e.id);
  }
  return value as unknown as Graph;
}
export interface GraphIndex {
  node: Map<string, GraphNode>;
  edge: Map<string, GraphEdge>;
  incident: Map<string, GraphEdge[]>;
  outgoing: Map<string, GraphEdge[]>;
}
export function indexGraph(graph: Graph): GraphIndex {
  const node = new Map(graph.nodes.map((n) => [n.id, n]));
  const edge = new Map(graph.edges.map((e) => [e.id, e]));
  const incident = new Map<string, GraphEdge[]>(),
    outgoing = new Map<string, GraphEdge[]>();
  const push = (m: Map<string, GraphEdge[]>, k: string, e: GraphEdge) => {
    const list = m.get(k);
    if (list) list.push(e);
    else m.set(k, [e]);
  };
  for (const e of graph.edges) {
    push(outgoing, e.source, e);
    push(incident, e.source, e);
    if (e.target !== e.source) push(incident, e.target, e);
  }
  return { node, edge, incident, outgoing };
}
/** Case-insensitive match on label, address or attribute; empty query matches all. */
export function matchesQuery(node: GraphNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  return (
    !q ||
    [
      node.label,
      ...(node.addresses ?? []),
      ...Object.values(node.attributes ?? {}),
    ]
      .join(" ")
      .toLowerCase()
      .includes(q)
  );
}
