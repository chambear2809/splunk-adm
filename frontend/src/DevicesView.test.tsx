import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  DevicesView,
  MAX_ATTACHMENT_REFERENCES,
  MAX_OBSERVER_ENTRIES,
  trafficObserverGroups,
} from "./DevicesView";
import { indexGraph } from "./graph";
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
    const section = html.slice(html.indexOf("attachment-references"));
    expect(section.split("<li").length - 1).toBe(MAX_ATTACHMENT_REFERENCES);
    expect(html).toContain(
      `2 additional attachment references were omitted because the list is capped at ${MAX_ATTACHMENT_REFERENCES}.`,
    );
  });

  it("uses the singular form for one omitted reference", () => {
    expect(render(MAX_ATTACHMENT_REFERENCES)).toContain(
      `1 additional attachment reference was omitted because the list is capped at ${MAX_ATTACHMENT_REFERENCES}.`,
    );
  });

  it("shows no omission note within the cap", () => {
    expect(render(MAX_ATTACHMENT_REFERENCES - 1)).not.toContain("omitted");
  });

  it("shows source age and retained-history uncertainty alongside receipt time", () => {
    const html = render(0, true);
    expect(html).toContain("Source time/freshness 100");
    expect(html).toContain("Received 259300");
    expect(html).toContain("Source time status stale");
    expect(html).toContain("Retained history coverage unconfirmed");
  });
});

describe("DevicesView traffic observers", () => {
  it("caps rendered records while retaining the source total", () => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    graph.edges.push({
      ...edge,
      id: "large-observer",
      relationship: "traffic_observation",
      traffic_observations: Array.from(
        { length: MAX_OBSERVER_ENTRIES + 7 },
        (_, index) => ({
          source: "hubble",
          source_authority: "hubble",
          observation_point: "node-a",
          scope: "scope-a",
          cluster: "cluster-a",
          records: index + 1,
        }),
      ),
    });
    const html = renderToStaticMarkup(
      <DevicesView
        graph={graph}
        index={indexGraph(graph)}
        topo={indexTopology(demoTopology("catalyst-aci"))}
        onSelect={() => {}}
      />,
    );
    expect(html).toContain("7 additional source records omitted from display");
    expect(html).toContain("total flow records remains 1,653");
  });

  it("does not merge records with different source or domain attestation", () => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    graph.edges.push({
      ...edge,
      id: "observer-contexts",
      relationship: "traffic_observation",
      traffic_observations: [
        {
          source: "hubble",
          profile: "flow-v1",
          exporter_ip: "192.0.2.10",
          scope: "scope-a",
          cluster: "cluster-a",
          observation_domain_present: 0,
          records: 1,
        },
        {
          source: "hubble",
          profile: "flow-v1",
          exporter_ip: "192.0.2.10",
          scope: "scope-a",
          cluster: "cluster-a",
          observation_domain_present: 0,
          observation_domain_id: "domain-b",
          records: 2,
        },
        {
          source: "netflow",
          profile: "flow-v1",
          exporter_ip: "192.0.2.10",
          scope: "scope-a",
          cluster: "cluster-a",
          records: 3,
        },
        {
          source: "hubble",
          profile: "flow-v1",
          scope: "scope-a",
          cluster: "cluster-a",
          records: 4,
        },
      ],
    });
    const groups = trafficObserverGroups(graph).filter((group) =>
      ["hubble", "netflow"].includes(group.source),
    );
    expect(groups).toHaveLength(4);
    expect(groups.map((group) => group.records).sort()).toEqual([1, 2, 3, 4]);
  });

  it("keeps NetFlow sensors and Hubble observer contexts separate", () => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    const observations = [
      {
        source: "netflow",
        source_authority: "netflow-a",
        profile: "13",
        scope: "blue",
        cluster: "cluster-a",
        exporter_ip: "192.0.2.13",
        source_ip: "192.0.2.10",
        destination_ip: "192.0.2.20",
        source_port: 1234,
        destination_port: 443,
        transport: "tcp",
        records: 13,
      },
      {
        source: "netflow",
        source_authority: "netflow-a",
        profile: "14",
        scope: "blue",
        cluster: "cluster-a",
        exporter_ip: "192.0.2.14",
        source_ip: "192.0.2.10",
        destination_ip: "192.0.2.20",
        source_port: 443,
        destination_port: 1234,
        transport: "tcp",
        is_reply: true,
        records: 14,
      },
      {
        source: "hubble",
        source_authority: "hubble",
        observation_point: "node-a",
        scope: "red",
        cluster: "cluster-b",
        source_ip: "192.0.2.30",
        destination_ip: "192.0.2.40",
        source_port: 8080,
        destination_port: 8443,
        transport: "tcp",
        is_reply: false,
        records: 1,
      },
    ];
    graph.edges.push({
      ...edge,
      id: "native-observations",
      relationship: "traffic_observation",
      traffic_observations: observations,
      sources: ["netflow", "hubble"],
    });
    const html = renderToStaticMarkup(
      <DevicesView
        graph={graph}
        index={indexGraph(graph)}
        topo={indexTopology(demoTopology("catalyst-aci"))}
        onSelect={() => {}}
      />,
    );
    expect(html).toContain("Flow exporters and observers");
    expect(html).toContain("192.0.2.13");
    expect(html).toContain("192.0.2.14");
    expect(html).toContain("node-a");
    expect(html).toContain("Flow records");
    expect(html).toContain("13");
    expect(html).toContain("14");
    expect(html).toContain("Reply true");
    expect(html).toContain("Reply false");
    expect(html).not.toContain("Forwarded to backend");
  });
});
