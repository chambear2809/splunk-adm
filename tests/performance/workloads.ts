import aci from "@fixtures/demo-rows-aci.json";
import nxos from "@fixtures/demo-rows.json";
import catalyst from "@fixtures/demo-networking-aci.json";
import meraki from "@fixtures/demo-networking-nxos.json";
import aciTopo from "@fixtures/demo-topology-aci.json";
import nxosTopo from "@fixtures/demo-topology.json";
import networkTopo from "@fixtures/demo-networking-topology.json";
import type { GraphArgs, Row } from "@atlas/rows";
import { addCiscoEvidence } from "./ciscoWorkloads";

export const scenarios = [
  "aci",
  "nxos",
  "catalyst-aci",
  "meraki-nxos",
] as const;
export type Scenario = (typeof scenarios)[number];
export type Size = "captured" | "realistic" | "near-limit";
const captures = { aci, nxos, "catalyst-aci": catalyst, "meraki-nxos": meraki };
const topology = {
  aci: aciTopo,
  nxos: nxosTopo,
  "catalyst-aci": networkTopo,
  "meraki-nxos": networkTopo,
};

/** Deterministic additions retain every original row and its source evidence. */
export async function workload(
  scenario: Scenario,
  size: Size,
  partial = false,
) {
  const capture = captures[scenario];
  const rows = structuredClone(capture.rows) as Row[];
  const topoCapture = topology[scenario];
  const topoRows = structuredClone(
    Array.isArray(topoCapture) ? topoCapture : topoCapture.rows,
  ) as Row[];
  const args: GraphArgs = capture.args;
  const nodes = rows.filter((row) => row.row_type === "node");
  const edges = rows.filter((row) => row.row_type === "edge");
  if (partial && size === "captured")
    throw new Error("Captured workloads must stay unchanged");
  if (size !== "captured") {
    const targetNodes = size === "near-limit" ? 500 : 100;
    const targetEdges = size === "near-limit" ? 2000 : 400;
    if (scenario.includes("-")) {
      await addCiscoEvidence({
        scenario,
        args,
        rows,
        nodes,
        edges,
        topoRows,
        targetNodes,
        targetEdges,
        partial,
      });
    } else {
      const root = nodes.find(
        (row) =>
          row.id ===
          `service:${args.cluster}/${args.namespace}/${args.service}/${args.environment}`,
      );
      if (!root) throw new Error("Captured root missing");
      const additions: Row[] = [];
      for (let i = nodes.length; i < targetNodes; i++) {
        const pod = i % 5 !== 0;
        const row: Row = {
          row_type: "node",
          id: `perf:${scenario}:${i}`,
          label: pod ? `perf-worker-${i}` : `perf-external-${i}`,
          kind: pod ? "workload" : "endpoint",
          namespace: args.namespace,
          cluster: args.cluster,
          addresses: [`198.18.${Math.floor(i / 250)}.${(i % 250) + 1}`],
          ...(pod
            ? { attr_owner: `perf-owner-${i % 16}`, attr_node: `node-${i % 6}` }
            : { endpoint_kind: i % 10 ? "external" : "unresolved" }),
        };
        nodes.push(row);
        rows.push(row);
        additions.push(row);
        if (pod) {
          const edge = {
            row_type: "edge",
            id: `perf:owns:${i}`,
            source: root.id,
            target: row.id,
            relationship: "runs_on",
            confidence: "correlated",
            evidence: ["performance-controlled"],
            count: "1",
          };
          edges.push(edge);
          rows.push(edge);
        }
      }
      // A seeded, mixed fanout; distinct IDs/ports represent distinct conversations.
      for (let i = 0; edges.length < targetEdges; i++) {
        const source = additions[i % additions.length];
        const target = additions[(i * 17 + 3) % additions.length];
        if (source === target) continue;
        const edge = {
          row_type: "edge",
          id: `perf:flow:${i}`,
          source: source.id,
          target: target.id,
          relationship: "communicates_with",
          confidence: i % 7 ? "correlated" : "unresolved",
          evidence: ["performance-controlled"],
          sources: [i % 3 ? "hubble" : "nd"],
          count: String((i % 11) + 1),
          bytes: String(((i % 31) + 1) * 1024),
          server_port: String([443, 8080, 5432, 6379][i % 4]),
          transport: "tcp",
          direction_basis: i % 7 ? "initiator" : "unknown",
        };
        edges.push(edge);
        rows.push(edge);
      }
    }
    const meta = rows.find((row) => row.row_type === "meta")!;
    meta.nodes = String(nodes.length);
    meta.edges = String(edges.length);
  }
  const records = (field: string) =>
    edges.flatMap((row) =>
      row[field]
        ? (JSON.parse(String(row[field])) as Record<string, unknown>[])
        : [],
    );
  const capturedEvidencePreserved = capture.rows
    .filter((row) => row.row_type !== "meta")
    .every((original) =>
      rows.some(
        (row) =>
          row.id === original.id &&
          row.row_type === original.row_type &&
          JSON.stringify(row) === JSON.stringify(original),
      ),
    );
  if (!capturedEvidencePreserved)
    throw new Error("Controlled workload changed captured evidence");
  const clients = nodes.filter((row) => row.endpoint_kind === "network_client");
  const nativeGroups = new Map<string, Set<string>>();
  for (const client of clients) {
    const key = JSON.stringify([client.attr_native_id, client.addresses]);
    if (!nativeGroups.has(key)) nativeGroups.set(key, new Set());
    nativeGroups.get(key)!.add(String(client.attr_source_authority));
  }
  const attachments = records("attachment_evidence"),
    traffic = records("traffic_observations");
  return {
    scenario,
    size,
    partial,
    args,
    rows,
    topoRows,
    expected: {
      nodes: nodes.length,
      edges: edges.length,
      graphRows: rows.length,
      topologyRows: topoRows.length,
      capturedRows: capture.rows.length,
      capturedEvidencePreserved,
      networkClients: clients.length,
      clientAuthorities: new Set(
        clients.map((row) => row.attr_source_authority),
      ).size,
      sharedNativeClientGroups: [...nativeGroups.values()].filter(
        (authorities) => authorities.size > 1,
      ).length,
      attachmentRecords: attachments.length,
      trafficObservationEdges: edges.filter(
        (row) => row.relationship === "traffic_observation",
      ).length,
      trafficRecords: traffic.length,
      uniqueTrafficFingerprints: new Set(
        traffic.map((row) => row.record_fingerprint).filter(Boolean),
      ).size,
      handoffRecords: records("client_handoffs").length,
      handoffCoverage: Object.fromEntries(
        ["complete", "partial", "unresolved"].map((coverage) => [
          coverage,
          edges.filter((row) => row.client_handoff_coverage === coverage)
            .length,
        ]),
      ),
      topologyDevices: topoRows.filter((row) => row.row_type === "device")
        .length,
      topologyLinks: topoRows.filter((row) => row.row_type === "link").length,
    },
  };
}
