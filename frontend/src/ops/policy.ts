import type { Graph, GraphEdge } from "../graph";

export interface CiliumPolicyDraft {
  name: string;
  endpointSelector: { "k8s:io.kubernetes.pod.namespace": string };
  egress: {
    toCIDR: string[];
    toPorts?: { ports: { port: string; protocol: string }[] }[];
  }[];
  yaml: string;
  coverage: string;
}

const K8S_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function ipv4(value: string): string | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const n = Number(part);
    if (n < 0 || n > 255) return undefined;
  }
  return `${value}/32`;
}

function dnsName(service: string): string {
  const base = service
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 240);
  return `${base || "workload"}-observed-l4`;
}

/**
 * L3/L4 CiliumNetworkPolicy from observed conversations. Never enables
 * daemon-wide audit mode; operators apply per-endpoint PolicyAuditMode.
 */
export function ciliumPolicyDraft(
  graph: Pick<Graph, "nodes" | "edges">,
  namespace: string,
  service: string,
): CiliumPolicyDraft {
  const ns = namespace.trim();
  if (!K8S_LABEL.test(ns)) {
    throw new Error(
      "CiliumNetworkPolicy export requires a valid Kubernetes namespace.",
    );
  }
  const sourceIds = new Set(
    graph.nodes
      .filter(
        (node) =>
          node.id === service ||
          node.label === service ||
          node.attributes?.service === service,
      )
      .map((node) => node.id),
  );
  sourceIds.add(service);
  const edges = graph.edges.filter(
    (edge) =>
      edge.relationship === "communicates_with" &&
      edge.confidence === "observed" &&
      !edge.acl_action?.includes("drop") &&
      sourceIds.has(edge.source),
  );
  const byCidr = new Map<string, Map<string, string>>();
  for (const edge of edges) {
    const dest = destinationOf(graph, edge);
    if (!dest) continue;
    const ports = byCidr.get(dest) ?? new Map<string, string>();
    if (edge.server_port && edge.transport) {
      ports.set(
        `${edge.server_port}/${edge.transport}`,
        edge.transport.toUpperCase(),
      );
    }
    byCidr.set(dest, ports);
  }
  if (byCidr.size === 0) {
    throw new Error(
      "No observed IPv4 egress destinations for this service in the current window.",
    );
  }
  const egress = [...byCidr.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([cidr, ports]) => {
      const toPorts = [...ports.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, protocol]) => ({
          ports: [{ port: key.split("/")[0]!, protocol }],
        }));
      return toPorts.length > 0
        ? { toCIDR: [cidr], toPorts }
        : { toCIDR: [cidr] };
    });
  const name = dnsName(service);
  const lines = [
    "apiVersion: cilium.io/v2",
    "kind: CiliumNetworkPolicy",
    "metadata:",
    `  name: "${name}"`,
    `  namespace: "${ns}"`,
    "spec:",
    "  endpointSelector:",
    "    matchLabels:",
    `      k8s:io.kubernetes.pod.namespace: "${ns}"`,
    "  egress:",
  ];
  for (const rule of egress) {
    lines.push("  - toCIDR:");
    for (const cidr of rule.toCIDR) lines.push(`    - ${cidr}`);
    if (rule.toPorts && rule.toPorts.length > 0) {
      lines.push("    toPorts:");
      for (const entry of rule.toPorts) {
        lines.push("    - ports:");
        lines.push(`      - port: "${entry.ports[0]!.port}"`);
        lines.push(`        protocol: ${entry.ports[0]!.protocol}`);
      }
    }
  }
  lines.push(
    "# Apply with per-endpoint PolicyAuditMode. Do not set daemon-wide audit mode.",
  );
  return {
    name,
    endpointSelector: { "k8s:io.kubernetes.pod.namespace": ns },
    egress,
    yaml: lines.join("\n"),
    coverage:
      "L3/L4 observed IPv4 egress conversations only. Hubble L7 and DNS identities are omitted.",
  };
}

function destinationOf(
  graph: Pick<Graph, "nodes">,
  edge: GraphEdge,
): string | undefined {
  const node = graph.nodes.find((candidate) => candidate.id === edge.target);
  for (const address of node?.addresses ?? []) {
    const cidr = ipv4(address);
    if (cidr) return cidr;
  }
  return undefined;
}
