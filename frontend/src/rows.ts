import {
  CONTRACT_BASES,
  ENDPOINT_KINDS,
  HANDOFF_BASES,
  CLIENT_HANDOFF_COVERAGES,
  parseGraph,
  validVlanString,
  validNatObservations,
  validTrafficObservation,
  RELATIONSHIPS,
  type AclAction,
  type ContractBasis,
  type DirectionBasis,
  type EndpointKind,
  type Graph,
  type GraphEdge,
  type GraphNode,
  type VlanObservation,
  type NatObservation,
  type TrafficObservation,
  type HandoffBasis,
  type ClientHandoffCoverage,
  type ClientHandoffRecord,
  type NodeKind,
  type Relationship,
} from "./graph";

export type Row = Record<string, unknown>;
export interface GraphArgs {
  service: string;
  environment: string;
  cluster: string;
  namespace: string;
}
export const MAX_NODES = 500;
export const MAX_EDGES = 2000;
/** All nodes, all edges and the meta row; anything larger is over the pilot limit. */
export const MAX_ROWS = MAX_NODES + MAX_EDGES + 1;

const fail = (message: string): never => {
  throw new Error(`Invalid graph search result: ${message}`);
};
/** A single Splunk value: a string, or a one-element multivalue. */
export function one(row: Row, key: string): string | undefined {
  const v = row[key];
  if (v === undefined || v === null || v === "" || v === "Null")
    return undefined;
  if (typeof v === "string") return v;
  if (Array.isArray(v) && v.length === 1 && typeof v[0] === "string")
    return v[0];
  return fail(`${key} must be a single value`);
}
/** Splunk multivalue fields arrive as arrays, single values as strings. */
export function many(row: Row, key: string): string[] | undefined {
  const v = row[key];
  if (v === undefined || v === null || v === "" || v === "Null")
    return undefined;
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === "string"))
    return (v as string[]).filter((x) => x !== "" && x !== "Null");
  return fail(`${key} must be text`);
}
export function count(row: Row, key: string): number | undefined {
  const v = one(row, key);
  if (v === undefined) return undefined;
  if (!/^\d+(\.\d+)?$/.test(v)) return fail(`${key} must be a number`);
  return Number(v);
}
function epochIso(row: Row, key: string): string {
  const n = count(row, key);
  if (n === undefined) return fail(`meta ${key} is missing`);
  return new Date(Math.round(n * 1000)).toISOString();
}
function oneOf<T extends string>(
  row: Row,
  key: string,
  allowed: readonly T[],
): T | undefined {
  const v = one(row, key);
  if (v !== undefined && !allowed.includes(v as T))
    return fail(`${key} has unsupported value ${JSON.stringify(v)}`);
  return v as T | undefined;
}
const required = (row: Row, key: string) =>
  one(row, key) ?? fail(`${String(row.row_type)} row is missing ${key}`);

export const serviceNodeId = (a: GraphArgs) =>
  `service:${a.cluster}/${a.namespace}/${a.service}/${a.environment}`;

function toNode(row: Row): GraphNode {
  const attributes: Record<string, string> = {};
  for (const key of Object.keys(row).sort())
    if (key.startsWith("attr_")) {
      const v = one(row, key);
      if (v !== undefined) attributes[key.slice(5)] = v;
    }
  if (attributes.vlan !== undefined && !validVlanString(attributes.vlan))
    fail(
      `node ${String(row.id)} attr_vlan must be a decimal VLAN between 1 and 4094`,
    );
  for (const key of ["vlan_status", "bridge_domain_status"])
    if (
      attributes[key] !== undefined &&
      !["varies", "incomplete"].includes(attributes[key])
    )
      fail(`node ${String(row.id)} attr_${key} has unsupported value`);
  const node: GraphNode = {
    id: required(row, "id"),
    label: one(row, "label") ?? required(row, "id"),
    kind: oneOf<NodeKind>(row, "kind", [
      "service",
      "workload",
      "endpoint",
      "client",
    ])!,
  };
  if (!node.kind) fail(`node ${node.id} is missing kind`);
  const endpointKind = oneOf<EndpointKind>(
    row,
    "endpoint_kind",
    ENDPOINT_KINDS,
  );
  if (endpointKind) node.endpoint_kind = endpointKind;
  for (const key of ["namespace", "cluster", "reason"] as const) {
    const v = one(row, key);
    if (v !== undefined) node[key] = v;
  }
  const addresses = many(row, "addresses");
  if (addresses) node.addresses = addresses;
  if (Object.keys(attributes).length) node.attributes = attributes;
  return node;
}

function toEdge(row: Row): GraphEdge {
  const edge: GraphEdge = {
    id: required(row, "id"),
    source: required(row, "source"),
    target: required(row, "target"),
    relationship: oneOf<Relationship>(row, "relationship", RELATIONSHIPS)!,
    confidence: oneOf<GraphEdge["confidence"]>(row, "confidence", [
      "observed",
      "correlated",
      "unresolved",
      "inferred",
    ])!,
    evidence: many(row, "evidence") ?? [],
    count: count(row, "count") ?? fail(`edge ${String(row.id)} has no count`),
  };
  if (!edge.relationship || !edge.confidence)
    fail(`edge ${edge.id} is missing relationship or confidence`);
  const bytes = count(row, "bytes");
  if (bytes !== undefined) edge.bytes = bytes;
  const vlanRaw = one(row, "vlan_observations");
  if (vlanRaw !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(vlanRaw);
    } catch {
      fail(`edge ${edge.id} vlan_observations must be valid JSON`);
    }
    if (!Array.isArray(parsed))
      fail(`edge ${edge.id} vlan_observations must be an array`);
    edge.vlan_observations = parsed as VlanObservation[];
  }
  const natRaw = one(row, "nat_observations");
  if (natRaw !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(natRaw);
    } catch {
      fail(`edge ${edge.id} nat_observations must be valid JSON`);
    }
    const normalized = Array.isArray(parsed)
      ? parsed.map((item) => {
          if (!item || typeof item !== "object" || Array.isArray(item))
            return item;
          return Object.fromEntries(
            Object.entries(item).filter(
              ([, value]) => value !== null && value !== "Null" && value !== "",
            ),
          );
        })
      : parsed;
    if (!validNatObservations(normalized))
      fail(`edge ${edge.id} nat_observations has an invalid observation`);
    edge.nat_observations = normalized as NatObservation[];
  }
  const trafficRaw = one(row, "traffic_observations");
  if (trafficRaw !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trafficRaw);
    } catch {
      fail(`edge ${String(row.id)} traffic_observations must be valid JSON`);
    }
    const normalized = Array.isArray(parsed)
      ? parsed.map((item) => {
          if (!item || typeof item !== "object" || Array.isArray(item))
            return item;
          const clean: Record<string, unknown> = {};
          for (const [key, value] of Object.entries(item)) {
            if (value === null || value === "Null" || value === "") continue;
            clean[key] =
              [
                "source_authority",
                "routing_domain",
                "observation_domain_id",
                "flow_id",
                "sequence",
                "vpn_id",
                "ingress_overlay_session_id",
                "egress_overlay_session_id",
              ].includes(key) && typeof value === "number"
                ? String(value)
                : value;
          }
          if (clean.metrics_authoritative === "0")
            clean.metrics_authoritative = false;
          if (clean.metrics_authoritative === "1")
            clean.metrics_authoritative = true;
          return clean;
        })
      : parsed;
    if (
      !Array.isArray(normalized) ||
      !normalized.every(validTrafficObservation)
    )
      fail(
        `edge ${String(row.id)} traffic_observations has an invalid observation`,
      );
    edge.traffic_observations = normalized as TrafficObservation[];
  }
  const attachmentRaw = one(row, "attachment_evidence");
  if (attachmentRaw !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(attachmentRaw);
    } catch {
      fail(`edge ${String(row.id)} attachment_evidence must be valid JSON`);
    }
    const normalized = Array.isArray(parsed)
      ? parsed.map((entry) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry))
            return entry;
          return Object.fromEntries(
            Object.entries(entry).filter(
              ([, value]) => value !== null && value !== "Null" && value !== "",
            ),
          );
        })
      : parsed;
    if (
      !Array.isArray(normalized) ||
      normalized.some(
        (entry) => !entry || typeof entry !== "object" || Array.isArray(entry),
      )
    )
      fail(
        `edge ${String(row.id)} attachment_evidence must be an array of objects`,
      );
    edge.attachment_evidence = normalized as GraphEdge["attachment_evidence"];
  }
  const vlanTruncated = oneOf(row, "vlan_observations_truncated", ["0", "1"]);
  if (vlanTruncated !== undefined)
    edge.vlan_observations_truncated = vlanTruncated === "1";
  const natTruncated = oneOf(row, "nat_observations_truncated", ["0", "1"]);
  if (natTruncated !== undefined)
    edge.nat_observations_truncated = natTruncated === "1";
  const port = count(row, "server_port");
  if (port !== undefined) edge.server_port = port;
  const transport = one(row, "transport");
  if (transport !== undefined) edge.transport = transport;
  for (const key of [
    "counter_semantics",
    "link_kind",
    "link_source",
    "scope",
    "cluster",
    "source_authority",
  ] as const) {
    const value = one(row, key);
    if (value !== undefined) edge[key] = value;
  }
  const metricFlag = oneOf(row, "metrics_authoritative", [
    "0",
    "1",
    "true",
    "false",
  ]);
  if (metricFlag !== undefined)
    edge.metrics_authoritative = metricFlag === "1" || metricFlag === "true";
  for (const key of [
    "raw_bytes",
    "raw_packets",
    "records",
    "source_port",
    "destination_port",
  ] as const) {
    const value = count(row, key);
    if (value !== undefined) edge[key] = value;
  }
  for (const key of ["source_mac", "source_ip", "destination_ip"] as const) {
    const value = one(row, key);
    if (value !== undefined) edge[key] = value;
  }
  const observationId = one(row, "traffic_observation_id");
  if (observationId !== undefined) edge.traffic_observation_id = observationId;
  const basis = oneOf<DirectionBasis>(row, "direction_basis", [
    "initiator",
    "port_rule",
    "unknown",
  ]);
  if (basis) edge.direction_basis = basis;
  const encapsulation = oneOf(row, "encapsulation", [
    "vxlan",
    "geneve",
    "ipip",
  ]);
  if (encapsulation) edge.encapsulation = encapsulation;
  for (const key of ["observers", "sources", "span_ids"] as const) {
    const v = many(row, key);
    if (v) edge[key] = v;
  }
  const handoff = oneOf<HandoffBasis>(row, "handoff_basis", HANDOFF_BASES);
  if (handoff) edge.handoff_basis = handoff;
  const via = many(row, "via_node");
  if (via) edge.via_node = via;
  const clientCoverage = oneOf<ClientHandoffCoverage>(
    row,
    "client_handoff_coverage",
    CLIENT_HANDOFF_COVERAGES,
  );
  if (clientCoverage !== undefined)
    edge.client_handoff_coverage = clientCoverage;
  for (const key of [
    "client_handoff_connections",
    "client_handoff_determined",
    "client_handoff_unresolved",
  ] as const) {
    const value = count(row, key);
    if (value !== undefined) edge[key] = value;
  }
  const clientHandoffs = one(row, "client_handoffs");
  if (clientHandoffs !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(clientHandoffs);
    } catch {
      return fail("client_handoffs must be valid JSON");
    }
    if (!Array.isArray(parsed)) return fail("client_handoffs must be an array");
    edge.client_handoffs = parsed as ClientHandoffRecord[];
  }
  const clientHandoffFields = [
    "client_handoff_coverage",
    "client_handoff_connections",
    "client_handoff_determined",
    "client_handoff_unresolved",
    "client_handoffs",
  ] as const;
  if (
    clientHandoffFields.some((key) => Object.hasOwn(row, key)) &&
    clientHandoffFields.some((key) => one(row, key) === undefined)
  )
    return fail("client handoff metadata must include every field");
  for (const key of [
    "contract_reason",
    "contract",
    "contract_subject",
    "contract_filter",
    "contract_entry",
    "acl_leaf",
  ] as const) {
    const v = one(row, key);
    if (v !== undefined) edge[key] = v;
  }
  const contractBasis = oneOf<ContractBasis>(
    row,
    "contract_basis",
    CONTRACT_BASES,
  );
  if (contractBasis) edge.contract_basis = contractBasis;
  const acl = oneOf<AclAction>(row, "acl_action", ["permit", "drop"]);
  if (acl) edge.acl_action = acl;
  for (const key of ["acl_permits", "acl_drops"] as const) {
    const v = count(row, key);
    if (v !== undefined) edge[key] = v;
  }
  return edge;
}

/**
 * Assembles `adm_graph` result rows (row_type node, edge, meta) into a graph
 * and validates it. Rows are untrusted indexed content.
 */
export function rowsToGraph(
  rows: unknown,
  args: GraphArgs,
  options: { demo?: boolean } = {},
): Graph {
  if (!Array.isArray(rows)) return fail("rows must be an array");
  if (rows.length > MAX_ROWS)
    throw new Error(
      `Graph exceeds the pilot limit (${MAX_NODES} nodes / ${MAX_EDGES} edges). Narrow the time range or namespace.`,
    );
  const nodes: GraphNode[] = [],
    edges: GraphEdge[] = [],
    metas: Row[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      fail("each row must be an object");
    const row = raw as Row;
    const type = one(row, "row_type");
    if (type === "node") nodes.push(toNode(row));
    else if (type === "edge") edges.push(toEdge(row));
    else if (type === "meta") metas.push(row);
    else fail(`unknown row_type ${JSON.stringify(type)}`);
  }
  if (metas.length !== 1) fail("expected exactly one meta row");
  const meta = metas[0];
  const warnings = many(meta, "warnings") ?? [];
  const metaCount = (key: string) => count(meta, key) ?? 0;
  if (metaCount("nodes") > MAX_NODES || metaCount("edges") > MAX_EDGES)
    throw new Error(
      warnings.find((w) => w.startsWith("Graph exceeds")) ??
        `Graph exceeds the pilot limit (${MAX_NODES} nodes / ${MAX_EDGES} edges).`,
    );
  const boundaryId = `${args.cluster}/${args.namespace}/${args.service}/${args.environment}`;
  const window = {
    start: epochIso(meta, "window_start"),
    end: epochIso(meta, "window_end"),
  };
  const natWindowStart = count(meta, "nat_window_start");
  const natWindowEnd = count(meta, "nat_window_end");
  if (
    (natWindowStart === undefined) !== (natWindowEnd === undefined) ||
    (natWindowStart !== undefined &&
      natWindowEnd !== undefined &&
      natWindowStart >= natWindowEnd)
  )
    fail("meta NAT evidence time window is incomplete or invalid");
  const generatedAt = epochIso(meta, "generated_at");
  return parseGraph({
    schema_version: 1,
    snapshot_id: `adm_graph:${boundaryId}:${window.start}/${window.end}:${generatedAt}`,
    generated_at: generatedAt,
    demo: options.demo ?? false,
    window,
    ...(natWindowStart !== undefined && natWindowEnd !== undefined
      ? { nat_event_window: { start: natWindowStart, end: natWindowEnd } }
      : {}),
    boundary: {
      id: boundaryId,
      ...args,
      root_node_id: serviceNodeId(args),
    },
    nodes,
    edges,
    coverage: {
      spans: metaCount("spans"),
      conversations: metaCount("conversations_in_scope"),
      matched_conversations: metaCount("matched_conversations"),
      unresolved_conversations: metaCount("unresolved_conversations"),
      ambiguous_conversations: metaCount("ambiguous_conversations"),
      warnings,
    },
  });
}
