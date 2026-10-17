import type { GraphEdge, GraphIndex } from "./graph";
import type { TrafficObservation } from "./graph";
import { csvRow } from "./csv";
import { contractSummary } from "./glossary";

export interface SearchWindow {
  start: string;
  end: string;
}
export interface FlowTuple {
  client: string;
  server: string;
  port: number;
  transport: string;
}
const full = (pattern: RegExp, value: string) =>
  pattern.exec(value)?.[0] === value;
const ipv4 = (value: string) =>
  full(/(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}/, value) &&
  value.split(".").every((part) => Number(part) <= 255);
function ipv6(value: string): boolean {
  let normalized = value.toLowerCase();
  if (normalized.includes(".")) {
    const tail = /^(.*:)([^:]+)$/.exec(normalized);
    if (!tail || !ipv4(tail[2])) return false;
    const octets = tail[2].split(".").map(Number);
    normalized = `${tail[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const pieces = normalized.split("::");
  if (pieces.length > 2) return false;
  const validSide = (side: string) =>
    !side || side.split(":").every((part) => full(/[0-9a-f]{1,4}/, part));
  if (!pieces.every(validSide)) return false;
  const units = pieces.reduce(
    (sum, side) => sum + (side ? side.split(":").length : 0),
    0,
  );
  return pieces.length === 2 ? units < 8 : units === 8;
}
export const strictIp = (value: string): boolean =>
  typeof value === "string" &&
  value.length >= 2 &&
  value.length <= 45 &&
  (ipv4(value) || ipv6(value));
const epoch = (value: string): string => {
  if (
    typeof value !== "string" ||
    !full(/0|[1-9]\d{0,11}/, value) ||
    Number(value) > 253402300799
  )
    throw new Error("Evidence windows require bounded integer epochs.");
  return value;
};
export function buildFlowSearch(input: FlowTuple): string {
  if (!strictIp(input.client) || !strictIp(input.server))
    throw new Error("Evidence search needs valid IPv4 or IPv6 addresses.");
  if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535)
    throw new Error("Evidence search needs a port from 1 to 65535.");
  if (
    typeof input.transport !== "string" ||
    !full(/tcp|udp|sctp/, input.transport.toLowerCase())
  )
    throw new Error("Evidence search supports TCP, UDP or SCTP.");
  return `| \`adm_flow_evidence("${input.client.toLowerCase()}","${input.server.toLowerCase()}",${input.port},"${input.transport.toLowerCase()}")\``;
}
export function buildTrafficObservationSearch(
  observation: TrafficObservation,
  observationId: string,
): string {
  if (!full(/[0-9a-f]{64}/, observationId))
    throw new Error("Traffic evidence needs an exact observation identifier.");
  if (!observation.source_ip || !observation.destination_ip)
    throw new Error(
      "Traffic evidence needs an exact source and destination IP.",
    );
  if (observation.server_port === undefined || !observation.transport)
    throw new Error("Traffic evidence needs a destination port and transport.");
  const tuple = buildFlowSearch({
    client: observation.source_ip,
    server: observation.destination_ip,
    port: observation.server_port,
    transport: observation.transport,
  });
  const args =
    /^\| `adm_flow_evidence\(("[^"\r\n]+"),("[^"\r\n]+"),([0-9]+),("[^"\r\n]+")\)`$/.exec(
      tuple,
    );
  if (!args) throw new Error("Traffic evidence tuple could not be normalized.");
  return `| \`adm_traffic_evidence_v2(${args[1]},${args[2]},${args[3]},${args[4]},"${observationId}")\``;
}
export function buildTraceSearch(trace: string, span?: string): string {
  if (
    typeof trace !== "string" ||
    !full(/[0-9a-f]{16,32}/, trace) ||
    (span !== undefined &&
      (typeof span !== "string" || !full(/[0-9a-f]{16,32}/, span)))
  )
    throw new Error("Evidence search needs a valid trace and span identifier.");
  return `| \`adm_trace_evidence("${trace}")\``;
}
export function searchUrl(
  search: string,
  window: SearchWindow,
  locationLike: { href: string } = location,
): string {
  // Rebuild the invocation through the argument validators. Never accept free-form SPL.
  const flow =
    /^\| `adm_flow_evidence\("([^"\r\n]+)","([^"\r\n]+)",([0-9]+),"([^"\r\n]+)"\)`$/.exec(
      search,
    );
  const trace = /^\| `adm_trace_evidence\("([0-9a-f]+)"\)`$/.exec(search);
  const traffic =
    /^\| `adm_traffic_evidence_v2\("([^"\r\n]+)","([^"\r\n]+)",([0-9]+),"([^"\r\n]+)","([0-9a-f]{64})"\)`$/.exec(
      search,
    );
  const canonical = traffic
    ? buildTrafficObservationSearch(
        {
          source_ip: traffic[1],
          destination_ip: traffic[2],
          server_port: Number(traffic[3]),
          transport: traffic[4],
        },
        traffic[5],
      )
    : flow
      ? buildFlowSearch({
          client: flow[1],
          server: flow[2],
          port: Number(flow[3]),
          transport: flow[4],
        })
      : trace
        ? buildTraceSearch(trace[1])
        : undefined;
  if (canonical !== search)
    throw new Error("Only validated evidence macros can be opened in Search.");
  const start = epoch(window.start),
    end = epoch(window.end);
  if (Number(start) >= Number(end))
    throw new Error("Evidence window start must be before its end.");
  const url = new URL(locationLike.href);
  const marker = url.pathname.lastIndexOf("/app/");
  url.pathname = `${marker >= 0 ? url.pathname.slice(0, marker) : ""}/app/splunk_adm/search`;
  url.hash = "";
  url.search = new URLSearchParams({
    q: search,
    earliest: start,
    latest: end,
  }).toString();
  return url.toString();
}
export function flowRequest(edge: GraphEdge, index: GraphIndex): string {
  if (edge.relationship !== "communicates_with")
    throw new Error("A request needs a network conversation.");
  const client = index.node.get(edge.source),
    server = index.node.get(edge.target);
  return (
    [
      csvRow([
        "client_name",
        "client_ips",
        "server_name",
        "server_ips",
        "port",
        "transport",
        "direction_basis",
        "policy",
        "acl_action",
        "evidence",
        "confidence",
      ]),
      csvRow([
        client?.label ?? edge.source,
        client?.addresses?.join(" "),
        server?.label ?? edge.target,
        server?.addresses?.join(" "),
        edge.server_port,
        edge.transport,
        edge.direction_basis,
        contractSummary(edge),
        edge.acl_action,
        edge.evidence.join("; "),
        edge.confidence,
      ]),
    ].join("\r\n") + "\r\n"
  );
}
export function evidenceSearch(edge: GraphEdge, index: GraphIndex): string {
  if (edge.relationship === "calls") {
    // Span references are emitted by adm_graph. The action opens one collected trace.
    for (const ref of edge.evidence) {
      const match = /^span:([0-9a-f]{16,32})\/([0-9a-f]{16,32})$/.exec(ref);
      if (match && match[0] === ref)
        return buildTraceSearch(match[1], match[2]);
    }
    throw new Error("No valid trace reference is available for this call.");
  }
  if (edge.relationship === "traffic_observation") {
    const observations = edge.traffic_observations ?? [];
    if (!observations.length)
      throw new Error("No traffic observation tuple is available for Search.");
    const idFromEdge = /^traffic-observation:([0-9a-f]{64})$/.exec(
      edge.id,
    )?.[1];
    const observationId = edge.traffic_observation_id;
    if (!observationId || observationId !== idFromEdge)
      throw new Error(
        "No exact traffic observation identifier is available for Search.",
      );
    const context = observations[0];
    const tuple = {
      ...context,
      source_ip: edge.source_ip ?? context.source_ip,
      destination_ip: edge.destination_ip ?? context.destination_ip,
      server_port: edge.server_port ?? context.server_port,
      transport: edge.transport ?? context.transport,
    };
    const searches = [buildTrafficObservationSearch(tuple, observationId)];
    if (new Set(searches).size !== 1)
      throw new Error(
        "Multiple observation tuples prevent a single exact Search.",
      );
    return searches[0];
  }
  if (
    edge.relationship !== "communicates_with" ||
    edge.direction_basis === "unknown"
  )
    throw new Error(
      "A flow evidence search needs a conversation with known direction.",
    );
  const address = (id: string) => {
    const addresses = index.node.get(id)?.addresses;
    if (addresses?.length !== 1)
      throw new Error(
        "Multiple or missing endpoint addresses prevent an exact tuple search.",
      );
    return addresses[0];
  };
  return buildFlowSearch({
    client: address(edge.source),
    server: address(edge.target),
    port: edge.server_port!,
    transport: edge.transport!,
  });
}
