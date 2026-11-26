import type { Graph, GraphEdge } from "../graph";

export interface CiliumPolicyDraft {
  name: string;
  endpointSelector: { "k8s:io.kubernetes.pod.namespace": string };
  egress: {
    toCIDR: string[];
    toPorts: { ports: { port: string; protocol: string }[] }[];
  }[];
  yaml: string;
  coverage: string;
}

const ipv4 = (value: string) =>
  /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) ? `${value}/32` : undefined;

/**
 * L3/L4 CiliumNetworkPolicy from observed conversations. Never enables
 * daemon-wide audit mode; operators apply per-endpoint PolicyAuditMode.
 */
export function ciliumPolicyDraft(
  graph: Pick<Graph, "nodes" | "edges">,
  namespace: string,
  service: string,
): CiliumPolicyDraft {
  const edges = graph.edges.filter(
    (edge) =>
      edge.relationship === "communicates_with" &&
      edge.confidence === "observed" &&
      !edge.acl_action?.includes("drop"),
  );
  const cidrs = new Set<string>();
  const ports = new Map<string, string>();
  for (const edge of edges) {
    const dest = destinationOf(graph, edge);
    if (dest) cidrs.add(dest);
    if (edge.server_port && edge.transport)
      ports.set(
        `${edge.server_port}/${edge.transport}`,
        edge.transport.toUpperCase(),
      );
  }
  const toCIDR = [...cidrs].sort();
  const toPorts = [...ports.entries()].sort().map(([key, protocol]) => ({
    ports: [{ port: key.split("/")[0]!, protocol }],
  }));
  const name = `${service.replace(/[^A-Za-z0-9-]/g, "-")}-observed-l4`;
  const yaml = [
    "apiVersion: cilium.io/v2",
    "kind: CiliumNetworkPolicy",
    "metadata:",
    `  name: ${name}`,
    `  namespace: ${namespace}`,
    "spec:",
    "  endpointSelector:",
    `    matchLabels:`,
    `      k8s:io.kubernetes.pod.namespace: ${namespace}`,
    "  egress:",
    "  - toCIDR:",
    ...toCIDR.map((cidr) => `    - ${cidr}`),
    "    toPorts:",
    ...toPorts.flatMap((entry) => [
      "    - ports:",
      `      - port: "${entry.ports[0]!.port}"`,
      `        protocol: ${entry.ports[0]!.protocol}`,
    ]),
    "# Apply with per-endpoint PolicyAuditMode. Do not set daemon-wide audit mode.",
  ].join("\n");
  return {
    name,
    endpointSelector: { "k8s:io.kubernetes.pod.namespace": namespace },
    egress: [{ toCIDR, toPorts }],
    yaml,
    coverage:
      "L3/L4 observed conversations only. Hubble L7 and DNS identities are omitted.",
  };
}

function destinationOf(
  graph: Pick<Graph, "nodes">,
  edge: GraphEdge,
): string | undefined {
  const node = graph.nodes.find((candidate) => candidate.id === edge.target);
  const address = node?.addresses?.[0];
  return address ? ipv4(address) : undefined;
}
