import { describe, expect, it } from "vitest";
import { indexGraph, type Graph, type GraphEdge } from "../graph";
import { buildHubbleJourney } from "./hubble";

const service = {
  id: "service:cluster/ns/web",
  label: "web",
  kind: "service" as const,
  endpoint_kind: "k8s_service" as const,
  cluster: "cluster",
  attributes: { handoff_coverage: "complete" },
};
const pod = { id: "pod:cluster/ns/a", label: "a", kind: "workload" as const };
const client = { id: "client:a", label: "client", kind: "client" as const };
const record = {
  target: pod.id,
  basis: "hubble_client_tuple" as const,
  connections: 2,
  receiving_nodes: ["receiver-a"],
  observers: ["hubble:proof-a"],
};
const edge = (extra: Partial<GraphEdge> = {}): GraphEdge => ({
  id: "client-edge",
  source: client.id,
  target: service.id,
  relationship: "communicates_with",
  confidence: "observed",
  evidence: [],
  count: 100,
  ...extra,
});
const qualified = {
  client_handoff_coverage: "complete" as const,
  client_handoff_connections: 2,
  client_handoff_determined: 2,
  client_handoff_unresolved: 0,
  client_handoffs: [record],
};
const graph = (edges: GraphEdge[], nodes = [client, service, pod]) =>
  ({ nodes, edges }) as Graph;

describe("selected-client Hubble journey", () => {
  it("uses qualified records and preserves distinct candidates without aggregate observers", () => {
    const second = {
      ...record,
      basis: "time_inferred" as const,
      connections: 1,
      receiving_nodes: [],
      observers: [],
    };
    const selected = edge({
      ...qualified,
      client_handoff_connections: 3,
      client_handoff_determined: 3,
      client_handoffs: [record, second],
      via_node: ["aggregate"],
      observers: ["aggregate"],
    });
    const g = graph([selected]);
    const before = structuredClone(g);
    expect(buildHubbleJourney(selected.id, indexGraph(g))).toMatchObject({
      status: "complete",
      candidates: [
        {
          backendId: pod.id,
          connections: 2,
          receivingNodes: ["receiver-a"],
          observers: ["hubble:proof-a"],
        },
        {
          backendId: pod.id,
          basis: "time_inferred",
          relation: "inferred",
          basisLabel: "Inferred from timing",
          connections: 1,
          receivingNodes: [],
          observers: [],
        },
      ],
    });
    expect(g).toEqual(before);
  });

  it("does not infer a client handoff from complete aggregate coverage or partial metadata", () => {
    for (const selected of [
      edge(),
      edge({ client_handoff_coverage: "complete" }),
      edge({
        ...qualified,
        client_handoff_coverage: "partial",
        client_handoff_connections: 3,
        client_handoff_unresolved: 1,
      }),
    ]) {
      expect(
        buildHubbleJourney(selected.id, indexGraph(graph([selected]))),
      ).toMatchObject({ status: "unavailable", candidates: [] });
    }
  });

  it("keeps concurrent clients separate", () => {
    const otherClient = { ...client, id: "client:b" };
    const otherPod = { ...pod, id: "pod:cluster/ns/b", label: "b" };
    const a = edge(qualified);
    const b = edge({
      ...qualified,
      id: "b-edge",
      source: otherClient.id,
      client_handoffs: [
        { ...record, target: otherPod.id, receiving_nodes: ["receiver-b"] },
      ],
    });
    const index = indexGraph(
      graph([a, b], [client, otherClient, service, pod, otherPod]),
    );
    expect(
      buildHubbleJourney(a.id, index)?.candidates.map((c) => c.backendId),
    ).toEqual([pod.id]);
    expect(
      buildHubbleJourney(b.id, index)?.candidates.map((c) => c.backendId),
    ).toEqual([otherPod.id]);
  });

  it("rejects missing and wrong-cluster backends", () => {
    for (const target of ["pod:cluster/ns/missing", "pod:other/ns/a"]) {
      const selected = edge({
        ...qualified,
        client_handoffs: [{ ...record, target }],
      });
      const other = { ...pod, id: "pod:other/ns/a" };
      expect(
        buildHubbleJourney(
          selected.id,
          indexGraph(graph([selected], [client, service, pod, other])),
        ),
      ).toMatchObject({ status: "unavailable", candidates: [] });
    }
  });

  it("rejects explicit scope and cluster conflicts without requiring missing metadata", () => {
    const scopedPod = { ...pod, attributes: { scope: "other" } };
    const scopedEdge = edge({ ...qualified, scope: "production" });
    expect(
      buildHubbleJourney(
        scopedEdge.id,
        indexGraph(graph([scopedEdge], [client, service, scopedPod])),
      ),
    ).toMatchObject({ status: "unavailable", candidates: [] });
    const mismatchedPod = { ...pod, cluster: "other" };
    expect(
      buildHubbleJourney(
        scopedEdge.id,
        indexGraph(graph([scopedEdge], [client, service, mismatchedPod])),
      ),
    ).toMatchObject({ status: "unavailable", candidates: [] });
    expect(
      buildHubbleJourney(scopedEdge.id, indexGraph(graph([scopedEdge]))),
    ).toMatchObject({ status: "complete" });
  });

  it("allows a client in another cluster when the service and backend agree", () => {
    const remoteClient = { ...client, cluster: "remote" };
    const selected = edge(qualified);
    expect(
      buildHubbleJourney(
        selected.id,
        indexGraph(graph([selected], [remoteClient, service, pod])),
      ),
    ).toMatchObject({
      status: "complete",
      candidates: [{ backendId: pod.id }],
    });
  });

  it("does not turn a Service-only forwarding edge into a client claim", () => {
    const forwarding = edge({
      id: "service-forward",
      source: service.id,
      target: pod.id,
      relationship: "forwards_to",
      ...qualified,
    });
    expect(
      buildHubbleJourney(forwarding.id, indexGraph(graph([forwarding]))),
    ).toBeUndefined();
  });
});
