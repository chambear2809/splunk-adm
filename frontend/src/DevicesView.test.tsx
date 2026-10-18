import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { DevicesView, MAX_ATTACHMENT_REFERENCES } from "./DevicesView";
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
