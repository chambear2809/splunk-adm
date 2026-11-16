import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  DevicesView,
  MAX_ATTACHMENT_REFERENCES,
  trafficObserverGroups,
} from "./DevicesView";
import { indexGraph, type Graph, type TrafficObservation } from "./graph";
import { demoGraph, demoTopology } from "./provider";
import { indexTopology } from "./topology";

const render = (extraClients: number, lateReceipt = false) => {
  const graph = structuredClone(demoGraph("catalyst-aci"));
  const edge = graph.edges.find(
    (candidate) => candidate.attachment_evidence?.length,
  )!;
  for (const other of graph.edges)
    if (other !== edge) delete other.attachment_evidence;
  const client = graph.nodes.find((node) => node.id === edge.source)!;
  const topology = structuredClone(demoTopology("catalyst-aci"));
  if (lateReceipt) {
    const device = topology.devices[0];
    device.source_time = "100";
    device.received_time = "259300";
    device.source_time_status = "stale";
    device.history_coverage = "unconfirmed";
  }
  for (let i = 0; i < extraClients; i++) {
    const node = structuredClone(client);
    node.id = `${client.id}-${i}`;
    node.label = `CLIENT-${i}`;
    const copy = structuredClone(edge);
    copy.id = `${edge.id}-${i}`;
    copy.source = node.id;
    graph.nodes.push(node);
    graph.edges.push(copy);
  }
  return renderToStaticMarkup(
    <DevicesView
      graph={graph}
      index={indexGraph(graph)}
      topo={indexTopology(topology)}
      onSelect={() => {}}
    />,
  );
};

describe("DevicesView attachment references", () => {
  it("caps the list and states how many references were omitted", () => {
    const total = MAX_ATTACHMENT_REFERENCES + 2;
    const html = render(total - 1);
    const start = html.indexOf("attachment-references");
    const end = html.indexOf("devices-idle", start);
    const section = html.slice(start, end < 0 ? undefined : end);
    expect(section.split("<li").length - 1).toBe(MAX_ATTACHMENT_REFERENCES);
    expect(html).toContain(`Showing ${MAX_ATTACHMENT_REFERENCES} of ${total}`);
  });

  it("counts the shown references against the total", () => {
    expect(render(MAX_ATTACHMENT_REFERENCES)).toContain(
      `Showing ${MAX_ATTACHMENT_REFERENCES} of ${MAX_ATTACHMENT_REFERENCES + 1}`,
    );
  });

  it("shows no count note within the cap", () => {
    expect(render(MAX_ATTACHMENT_REFERENCES - 1)).not.toContain("Showing ");
  });

  it("shows source age and retained-history uncertainty alongside receipt time", () => {
    const html = render(0, true);
    expect(html).toContain("Source time/freshness 100");
    expect(html).toContain("Received 259300");
    expect(html).toContain("Source time status stale");
    expect(html).toContain("Retained history coverage unconfirmed");
  });
});

describe("DevicesView compact device rows", () => {
  const withObservations = (observations: TrafficObservation[]) => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    graph.edges.push({
      ...edge,
      id: "native-observations",
      relationship: "traffic_observation",
      traffic_observations: observations,
      sources: ["hubble"],
    });
    return graph;
  };
  const html = (graph: Graph) =>
    renderToStaticMarkup(
      <DevicesView
        graph={graph}
        index={indexGraph(graph)}
        topo={indexTopology(demoTopology("catalyst-aci"))}
        onSelect={() => {}}
      />,
    );

  it("renders one humanized row per observer and no raw tuples", () => {
    const observations = Array.from({ length: 400 }, (_, i) => ({
      source: "hubble",
      source_authority: "cilium-lab",
      observation_point: "appd-k8-2/TO_ENDPOINT",
      profile: "k8-fabrix-ai-pod-network",
      scope: "K8-Fabrix-AI",
      cluster: "cilium-lab",
      source_ip: i % 2 ? "10.245.4.189" : "10.245.4.148",
      destination_ip: i % 2 ? "10.245.4.148" : "10.245.4.189",
      source_port: i % 2 ? 8080 : 40000 + i,
      destination_port: i % 2 ? 40000 + i : 8080,
      transport: "tcp",
      is_reply: i % 2 === 1,
      records: 1,
    }));
    const out = html(withObservations(observations));
    expect(out).toContain("appd-k8-2 · Cilium (to endpoint)");
    expect(out).toContain("1 conversation<");
    expect(out).not.toContain("Reply true");
    expect(out).not.toContain("10.245.4.189:8080");
    expect(out).not.toMatch(/Source [\d.]+:\d+ → Destination/);
    // Raw metadata is a tooltip, not visible copy.
    expect(out).toMatch(/title="[^"]*Authority cilium-lab[^"]*"/);
    expect(out).not.toContain(">Domain present");
    // Blocked is an exception chip: hidden when nothing is blocked.
    expect(out).toContain(">1 blocked<");
    expect(out).not.toContain(">0 blocked<");
  });

  it("links devices to their page and to impact", () => {
    const out = html(structuredClone(demoGraph("catalyst-aci")));
    expect(out).toMatch(/href="[^"]*device\?id=[^"]+"/);
    expect(out).toMatch(/href="[^"]*impact\?element=[^"]+"/);
    expect(out).toContain("Filter devices");
    // Conversation tables open on demand.
    expect(out).not.toContain("Last seen");
  });

  it("keeps observer contexts separate as rows", () => {
    const graph = withObservations([
      {
        source: "hubble",
        source_authority: "hubble",
        observation_point: "node-a/TO_STACK",
        cluster: "cluster-a",
        records: 1,
      },
      {
        source: "hubble",
        source_authority: "hubble",
        observation_point: "node-a/TO_ENDPOINT",
        cluster: "cluster-a",
        records: 1,
      },
    ]);
    const out = html(graph);
    expect(out).toContain("node-a · Cilium (to stack)");
    expect(out).toContain("node-a · Cilium (to endpoint)");
    expect(
      trafficObserverGroups(graph).filter((g) => g.source === "hubble"),
    ).toHaveLength(2);
  });

  it("windows the list when there are many devices", () => {
    const observers = 300;
    const graph = withObservations(
      Array.from({ length: observers }, (_, i) => ({
        source: "hubble",
        source_authority: "hubble",
        observation_point: `node-${i}/TO_ENDPOINT`,
        cluster: "cluster-a",
        source_ip: "10.0.0.1",
        destination_ip: "10.0.0.2",
        source_port: 50000,
        destination_port: 443,
        records: 1,
      })),
    );
    const out = html(graph);
    expect(out).toContain("devices-list virtual");
    const rendered = out.split("data-device-row=").length - 1;
    expect(rendered).toBeGreaterThan(0);
    expect(rendered).toBeLessThan(observers / 4);
  });
});
