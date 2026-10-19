import { describe, expect, it } from "vitest";
import type { Graph, GraphEdge, GraphNode } from "./graph";
import { diffGraphs } from "./diff";

const node = (
  id: string,
  kind: GraphNode["kind"],
  extra: Partial<GraphNode> = {},
): GraphNode => ({
  id,
  label: id,
  kind,
  ...extra,
});
const edge = (id: string, count = 1): GraphEdge => ({
  id,
  source: "svc",
  target: "other",
  relationship: "calls",
  evidence: [],
  confidence: "observed",
  count,
});
const graph = (nodes: GraphNode[], edges: GraphEdge[]): Graph => ({
  schema_version: 1,
  snapshot_id: "snapshot",
  generated_at: "2026-01-01T00:00:00.000Z",
  demo: false,
  window: {
    start: "2026-01-01T00:00:00.000Z",
    end: "2026-01-01T01:00:00.000Z",
  },
  boundary: {
    id: "svc",
    service: "svc",
    environment: "prod",
    cluster: "cluster",
    namespace: "ns",
    root_node_id: "svc",
  },
  nodes,
  edges,
  coverage: {
    spans: 0,
    conversations: 0,
    matched_conversations: 0,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
});

describe("diffGraphs", () => {
  it("classifies added, removed, and changed edges by their IDs", () => {
    const previous = graph(
      [node("svc", "service"), node("other", "service")],
      [edge("same"), edge("gone")],
    );
    const current = graph(
      [node("svc", "service"), node("other", "service")],
      [edge("same", 2), edge("new")],
    );
    const diff = diffGraphs(previous, current);
    expect(diff.changedEdges.map(({ id }) => id)).toEqual(["same"]);
    expect(diff.addedEdges.map(({ id }) => id)).toEqual(["new"]);
    expect(diff.removedEdges.map(({ id }) => id)).toEqual(["gone"]);
  });

  it("treats evidence ordering and refreshed span IDs as non-semantic", () => {
    const previousEdge = {
      ...edge("same"),
      evidence: ["flow-b", "flow-a", "span:old-trace/old-span"],
      sources: ["hubble", "netflow"],
      observers: ["node-b", "node-a"],
      span_ids: ["old-span"],
    };
    const currentEdge = {
      ...edge("same"),
      evidence: ["flow-a", "flow-b", "span:new-trace/new-span"],
      sources: ["netflow", "hubble"],
      observers: ["node-a", "node-b"],
      span_ids: ["new-span"],
    };
    expect(
      diffGraphs(graph([], [previousEdge]), graph([], [currentEdge])),
    ).toMatchObject({
      addedEdges: [],
      removedEdges: [],
      changedEdges: [],
    });
  });

  it("ignores pod UID, generated label, and replacement address churn", () => {
    const oldPod = node("pod/old-uid", "workload", {
      label: "api-abc12",
      namespace: "ns",
      cluster: "cluster",
      addresses: ["10.0.0.1"],
      attributes: { owner: "api", node: "node-a" },
    });
    const newPod = {
      ...oldPod,
      id: "pod/new-uid",
      label: "api-def34",
      addresses: ["10.0.0.2"],
    };
    const previous = graph([oldPod], []);
    const current = graph([newPod], []);
    expect(diffGraphs(previous, current)).toEqual({
      addedEdges: [],
      removedEdges: [],
      changedEdges: [],
      addedNodes: [],
      removedNodes: [],
      changedNodes: [],
    });
  });

  it("does not conflate ownerless pods that share a generated label", () => {
    const previousPod = node("pod/old-uid", "workload", {
      label: "api-7c8d9f",
      namespace: "ns",
      cluster: "cluster",
    });
    const currentPod = { ...previousPod, id: "pod/new-uid" };
    const result = diffGraphs(
      graph([previousPod], []),
      graph([currentPod], []),
    );
    expect(result.addedNodes).toEqual([currentPod]);
    expect(result.removedNodes).toEqual([previousPod]);
    expect(result.changedNodes).toEqual([]);
  });

  it("treats blank owner and service metadata as missing", () => {
    const previousPod = node("pod/old-uid", "workload", {
      label: "api-7c8d9f",
      namespace: "ns",
      cluster: "cluster",
      attributes: { owner: "  ", service: "" },
    });
    const currentPod = { ...previousPod, id: "pod/new-uid" };
    const result = diffGraphs(
      graph([previousPod], []),
      graph([currentPod], []),
    );
    expect(result.addedNodes).toEqual([currentPod]);
    expect(result.removedNodes).toEqual([previousPod]);
    expect(result.changedNodes).toEqual([]);
  });

  it("keeps service identities from different environments distinct", () => {
    const previous = node("service:c/ns/api/demo", "service", {
      label: "api",
      cluster: "c",
      namespace: "ns",
    });
    const current = { ...previous, id: "service:c/ns/api/prod" };
    const result = diffGraphs(graph([previous], []), graph([current], []));
    expect(result.addedNodes).toEqual([current]);
    expect(result.removedNodes).toEqual([previous]);
    expect(result.changedNodes).toEqual([]);
  });

  it("reports owner changes and keeps different services separate", () => {
    const oldPod = node("pod/uid", "workload", {
      namespace: "ns",
      cluster: "cluster",
      attributes: { owner: "api" },
    });
    const newPod = { ...oldPod, attributes: { owner: "worker" } };
    const diff = diffGraphs(graph([oldPod], []), graph([newPod], []));
    expect(diff.removedNodes).toHaveLength(1);
    expect(diff.addedNodes).toHaveLength(1);
    expect(diff.changedNodes).toHaveLength(0);
  });
});

it("compares the captured ACI windows and finds the new blocked conversation", async () => {
  const { demoGraph, previousDemoGraph } = await import("./data/demoClient");
  const previous = await previousDemoGraph("aci");
  expect(previous).toBeDefined();
  const result = diffGraphs(previous!, demoGraph("aci"));
  expect(
    result.addedEdges.some(
      (edge) =>
        edge.relationship === "communicates_with" && edge.acl_action === "drop",
    ),
  ).toBe(true);
  expect(result.addedNodes.filter((node) => node.kind === "workload")).toEqual(
    [],
  );
  expect(
    result.removedNodes.filter((node) => node.kind === "workload"),
  ).toEqual([]);
});

it("ignores evidence set ordering but preserves changed observation values", () => {
  const previousEdge: GraphEdge = {
    ...edge("context"),
    attachment_evidence: [
      {
        client_source: "meraki",
        client_authority: "org-a/network-a",
        client_native_id: "aa",
        event_time: 10,
      },
      {
        client_source: "catalyst",
        client_authority: "center-a",
        client_native_id: "aa",
        event_time: 11,
      },
    ],
    traffic_observations: [
      { source: "stream_ipfix", observation_point: "exporter-a", records: 1 },
      { source: "hubble", observation_point: "node-a", records: 2 },
    ],
    via_node: ["node-a", "node-b"],
    client_handoffs: [
      {
        target: "pod-a",
        basis: "time_inferred",
        connections: 1,
        receiving_nodes: ["node-a", "node-b"],
        observers: ["observer-a", "observer-b"],
      },
      {
        target: "pod-b",
        basis: "hubble_client_tuple",
        connections: 2,
        receiving_nodes: [],
        observers: [],
      },
    ],
  };
  const reordered: GraphEdge = {
    ...previousEdge,
    attachment_evidence: [...previousEdge.attachment_evidence!].reverse(),
    traffic_observations: [...previousEdge.traffic_observations!].reverse(),
    via_node: [...previousEdge.via_node!].reverse(),
    client_handoffs: previousEdge
      .client_handoffs!.map((record) => ({
        ...record,
        receiving_nodes: [...record.receiving_nodes].reverse(),
        observers: [...record.observers].reverse(),
      }))
      .reverse(),
  };
  const previous = graph([], [previousEdge]);
  expect(diffGraphs(previous, graph([], [reordered])).changedEdges).toEqual([]);
  for (const changed of [
    {
      ...reordered,
      attachment_evidence: [
        {
          ...reordered.attachment_evidence![0],
          client_authority: "other-center",
        },
        reordered.attachment_evidence![1],
      ],
    },
    {
      ...reordered,
      traffic_observations: [
        { ...reordered.traffic_observations![0], records: 3 },
        reordered.traffic_observations![1],
      ],
    },
    {
      ...reordered,
      client_handoffs: [
        { ...reordered.client_handoffs![0], basis: "time_inferred" as const },
        reordered.client_handoffs![1],
      ],
    },
  ])
    expect(
      diffGraphs(previous, graph([], [changed])).changedEdges,
    ).toHaveLength(1);
  // Sorting must never rewrite the source evidence supplied by the provider.
  expect(previousEdge.attachment_evidence![0].client_source).toBe("meraki");
  expect(previousEdge.client_handoffs![0].receiving_nodes).toEqual([
    "node-a",
    "node-b",
  ]);
});

it("compares late receipt changes without replacing their original source time", () => {
  const observation = {
    client_source: "catalyst_client_snapshot",
    client_authority: "center-a",
    client_native_id: "client-a",
    scope: "site-a",
    cluster: "cluster-a",
    event_time: 100,
    received_time: 259300,
  };
  const before = { ...edge("late-client"), attachment_evidence: [observation] };
  const after = {
    ...before,
    attachment_evidence: [{ ...observation, received_time: 259600 }],
  };
  const changed = diffGraphs(
    graph([], [before]),
    graph([], [after]),
  ).changedEdges;
  expect(changed).toHaveLength(1);
  expect(changed[0].previous.attachment_evidence).toEqual([observation]);
  expect(changed[0].current.attachment_evidence?.[0]).toEqual({
    ...observation,
    received_time: 259600,
  });
  expect(
    changed[0].current.attachment_evidence?.[0].collected_time,
  ).toBeUndefined();
});
