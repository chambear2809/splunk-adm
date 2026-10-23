import { describe, expect, it } from "vitest";
import type { Graph } from "../graph";
import type { EvidenceConfiguration } from "./evidenceConfig";
import { serviceHealthSelection } from "./serviceHealthSelection";

const graph = {
  snapshot_id: "snapshot",
  window: { start: "2026-10-23T12:00:00Z", end: "2026-10-23T12:15:00Z" },
  boundary: {
    root_node_id: "service:cluster-a/ns-a/api/prod",
    service: "api",
    environment: "prod",
    cluster: "cluster-a",
    namespace: "ns-a",
  },
  nodes: [{ id: "service:cluster-a/ns-a/api/prod", kind: "service" }],
} as Graph;
const config = {
  fingerprint: "a".repeat(64),
  mappings: [
    {
      observer_kind: "o11y_export",
      observer: "exporter-a",
      scope: "prod-net",
      cluster: "cluster-a",
      mapping_status: "verified",
      organization_id: "org-a",
      realm: "us1",
    },
  ],
} as EvidenceConfiguration;

describe("service health selection", () => {
  it("retains all qualified graph-boundary dimensions", () => {
    const selection = serviceHealthSelection(
      graph,
      graph.boundary.root_node_id,
      "prod-net",
      config,
    );
    expect(selection.service).toEqual({
      name: "api",
      environment: "prod",
      cluster: "cluster-a",
      namespace: "ns-a",
    });
    expect(selection.workloads).toBeUndefined();
  });
  it("rejects other nodes and unverified or conflicting scopes", () => {
    expect(() =>
      serviceHealthSelection(graph, "service:other", "prod-net", config),
    ).toThrow();
    expect(() =>
      serviceHealthSelection(
        graph,
        graph.boundary.root_node_id,
        "other-net",
        config,
      ),
    ).toThrow();
    expect(() =>
      serviceHealthSelection(graph, graph.boundary.root_node_id, "prod-net", {
        ...config,
        mappings: [{ ...config.mappings[0], mapping_status: "mapped" }],
      }),
    ).toThrow();
  });
});
