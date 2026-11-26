import type { Graph, GraphEdge } from "../graph";

export interface CiliumEgressRule {
  toCIDR?: string[];
  toEndpoints?: { matchLabels: Record<string, string> }[];
  toPorts: { ports: { port: string; protocol: string }[] }[];
}

export interface CiliumPolicyDraft {
  name: string;
  endpointSelector: {
    "k8s:io.kubernetes.pod.namespace": string;
    "k8s:app.kubernetes.io/name": string;
  };
  egress: CiliumEgressRule[];
  yaml: string;
  coverage: string;
}

const K8S_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const L4_PROTOCOLS = new Set(["TCP", "UDP", "SCTP"]);

function validPort(port: number | undefined): number | undefined {
  if (typeof port !== "number" || !Number.isInteger(port)) return undefined;
  return port >= 1 && port <= 65535 ? port : undefined;
}

function validProtocol(transport: string | undefined): string | undefined {
  if (!transport) return undefined;
  const upper = transport.trim().toUpperCase();
  return L4_PROTOCOLS.has(upper) ? upper : undefined;
}

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

function dnsLabel(service: string): string {
  const base = service
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/, "");
  return base || "workload";
}

function dnsName(service: string): string {
  return `${dnsLabel(service).slice(0, 50)}-observed-l4`;
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
  const serviceLabel = dnsLabel(service);
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
  const byEndpoint = new Map<
    string,
    { namespace: string; app: string; ports: Map<string, string> }
  >();
  const byCidr = new Map<string, Map<string, string>>();
  for (const edge of edges) {
    const port = validPort(edge.server_port);
    const protocol = validProtocol(edge.transport);
    // Never widen a port-less or non-L4 edge to an all-ports allow rule.
    if (port === undefined || protocol === undefined) continue;
    const node = graph.nodes.find((candidate) => candidate.id === edge.target);
    const targetNs = node?.attributes?.namespace?.trim();
    if (
      targetNs &&
      K8S_LABEL.test(targetNs) &&
      (node?.kind === "workload" || node?.kind === "service")
    ) {
      const targetApp = dnsLabel(
        node.attributes?.service ?? node.label ?? node.id,
      );
      const key = `${targetNs}/${targetApp}`;
      const existing = byEndpoint.get(key) ?? {
        namespace: targetNs,
        app: targetApp,
        ports: new Map<string, string>(),
      };
      existing.ports.set(`${port}/${protocol}`, protocol);
      byEndpoint.set(key, existing);
      continue;
    }
    const dests = destinationsOf(graph, edge);
    for (const dest of dests) {
      const ports = byCidr.get(dest) ?? new Map<string, string>();
      ports.set(`${port}/${protocol}`, protocol);
      byCidr.set(dest, ports);
    }
  }
  if (byEndpoint.size === 0 && byCidr.size === 0) {
    throw new Error(
      "No observed L4 egress destinations with valid port and protocol for this service in the current window.",
    );
  }
  const formatPorts = (ports: Map<string, string>) =>
    [...ports.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, protocol]) => ({
        ports: [{ port: key.split("/")[0]!, protocol }],
      }));
  const egress: CiliumEgressRule[] = [
    ...[...byEndpoint.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([, entry]) => ({
        toEndpoints: [
          {
            matchLabels: {
              "k8s:io.kubernetes.pod.namespace": entry.namespace,
              "k8s:app.kubernetes.io/name": entry.app,
            },
          },
        ],
        toPorts: formatPorts(entry.ports),
      })),
    ...[...byCidr.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([cidr, ports]) => ({
        toCIDR: [cidr],
        toPorts: formatPorts(ports),
      })),
  ];
  const name = dnsName(service);
  const lines = [
    "# Draft CiliumNetworkPolicy from observed L4 conversations.",
    "# WARNING: Enforcing this policy enables default-deny egress for matching pods.",
    "# Add an explicit kube-dns egress rule (UDP/TCP 53) and verify pod labels before applying.",
    "apiVersion: cilium.io/v2",
    "kind: CiliumNetworkPolicy",
    "metadata:",
    `  name: "${name}"`,
    `  namespace: "${ns}"`,
    "spec:",
    "  endpointSelector:",
    "    matchLabels:",
    `      k8s:io.kubernetes.pod.namespace: "${ns}"`,
    `      k8s:app.kubernetes.io/name: "${serviceLabel}" # Verify label matches target workload pods`,
    "  egress:",
  ];
  for (const rule of egress) {
    if (rule.toEndpoints && rule.toEndpoints.length > 0) {
      const labels = rule.toEndpoints[0]!.matchLabels;
      lines.push("  - toEndpoints:");
      lines.push("    - matchLabels:");
      for (const [k, v] of Object.entries(labels)) {
        lines.push(`        ${k}: "${v}"`);
      }
    } else if (rule.toCIDR && rule.toCIDR.length > 0) {
      lines.push("  - toCIDR:");
      for (const cidr of rule.toCIDR) lines.push(`    - ${cidr}`);
    }
    lines.push("    toPorts:");
    for (const entry of rule.toPorts) {
      lines.push("    - ports:");
      lines.push(`      - port: "${entry.ports[0]!.port}"`);
      lines.push(`        protocol: ${entry.ports[0]!.protocol}`);
    }
  }
  lines.push(
    "# Apply with per-endpoint PolicyAuditMode. Do not set daemon-wide audit mode.",
  );
  return {
    name,
    endpointSelector: {
      "k8s:io.kubernetes.pod.namespace": ns,
      "k8s:app.kubernetes.io/name": serviceLabel,
    },
    egress,
    yaml: lines.join("\n"),
    coverage:
      "Observed L4 egress only (toEndpoints for namespaced Kubernetes workloads, toCIDR for external IPv4). Port-less flows, Hubble L7, and kube-dns egress are not included; add DNS egress before enforcing.",
  };
}

function destinationsOf(
  graph: Pick<Graph, "nodes">,
  edge: GraphEdge,
): string[] {
  const node = graph.nodes.find((candidate) => candidate.id === edge.target);
  const cidrs: string[] = [];
  for (const address of node?.addresses ?? []) {
    const cidr = ipv4(address);
    if (cidr) cidrs.push(cidr);
  }
  return cidrs;
}
