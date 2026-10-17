import { expect, it } from "vitest";
import { indexGraph } from "../graph";
import {
  demoArgsFor,
  demoGraph,
  demoScenarioForArgs,
  demoTopology,
  demoWindowFor,
} from "./demoClient";
import { deviceSummaries, indexTopology } from "../topology";

it("exposes the captured Catalyst and Meraki demos with their exact scopes", () => {
  expect(demoArgsFor("catalyst-aci")).toEqual({
    service: "checkout",
    environment: "demo",
    cluster: "cilium-aci-east",
    namespace: "shop",
  });
  expect(demoArgsFor("meraki-nxos")).toEqual({
    service: "checkout",
    environment: "demo",
    cluster: "cilium-nxos-west",
    namespace: "shop",
  });
  expect(demoWindowFor("catalyst-aci")).toEqual(demoWindowFor("meraki-nxos"));
  const findArgs = {
    ...demoArgsFor("meraki-nxos"),
    pods: "1",
    last_seen: "1792176501",
  };
  expect(demoScenarioForArgs(findArgs)).toBe("meraki-nxos");
});

it.each(["catalyst-aci", "meraki-nxos"] as const)(
  "builds a map and topology from the captured %s rows",
  (scenario) => {
    const graph = demoGraph(scenario);
    const topology = demoTopology(scenario);
    const refs = deviceSummaries(
      graph.edges,
      indexTopology(topology),
      indexGraph(graph),
    ).attachmentReferences;
    expect(graph.demo).toBe(true);
    expect({
      service: graph.boundary.service,
      environment: graph.boundary.environment,
      cluster: graph.boundary.cluster,
      namespace: graph.boundary.namespace,
    }).toEqual(demoArgsFor(scenario));
    expect(
      graph.nodes.some(
        (node) =>
          node.kind === "client" && node.endpoint_kind === "network_client",
      ),
    ).toBe(true);
    expect(topology.devices.length).toBeGreaterThan(0);
    if (scenario === "meraki-nxos") {
      expect(
        topology.devices.some((device) => device.name === "MR-NXOS-01"),
      ).toBe(true);
      expect(
        graph.nodes.some(
          (node) =>
            node.attributes?.attachment_basis === "meraki_association_flow",
        ),
      ).toBe(true);
      expect(refs.map((reference) => reference.device?.name)).toContain(
        "MR-NXOS-01",
      );
    } else {
      expect(refs.map((reference) => reference.device?.name)).toContain(
        "CAMPUS-SW-01",
      );
    }
  },
);

it("does not resolve an attachment through a device-name alias", () => {
  const graph = structuredClone(demoGraph("meraki-nxos"));
  const topology = demoTopology("meraki-nxos");
  const edge = graph.edges.find(
    (candidate) =>
      candidate.relationship === "traffic_observation" &&
      candidate.attachment_evidence?.length,
  )!;
  const evidence = edge.attachment_evidence![0];
  const inventory = topology.devices.find(
    (device) => device.id === evidence.device_id,
  )!;

  evidence.device_id = inventory.name;
  const reference = deviceSummaries(
    graph.edges,
    indexTopology(topology),
    indexGraph(graph),
  ).attachmentReferences.find((candidate) => candidate.evidence === evidence);

  expect(reference?.device).toBeUndefined();
  expect(reference?.unresolvedReason).toMatch(/source-qualified device ID/);
});

it.each(["scope", "cluster", "device_authority"] as const)(
  "keeps an attachment unresolved when inventory %s does not match",
  (field) => {
    const graph = structuredClone(demoGraph("meraki-nxos"));
    const topology = demoTopology("meraki-nxos");
    const edge = graph.edges.find(
      (candidate) =>
        candidate.relationship === "traffic_observation" &&
        candidate.attachment_evidence?.length,
    )!;
    const evidence = edge.attachment_evidence![0];
    const inventory = topology.devices.find(
      (device) => device.id === evidence.device_id,
    )!;
    inventory[field] = `mismatch-${field}`;

    const reference = deviceSummaries(
      graph.edges,
      indexTopology(topology),
      indexGraph(graph),
    ).attachmentReferences.find(
      (candidate) => candidate.evidence.device_id === evidence.device_id,
    );

    expect(reference?.device).toBeUndefined();
    expect(reference?.unresolvedReason).toBeTruthy();
  },
);
