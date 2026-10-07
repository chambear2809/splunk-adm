import { describe, expect, it } from "vitest";
import { indexGraph } from "./graph";
import { edgeIdentity, summarize } from "./glossary";
import { demoGraph } from "./provider";

const graph = demoGraph();
const index = indexGraph(graph);
const node = (id: string) => index.node.get(id);
const byLabel = (l: string) => graph.nodes.find((n) => n.label === l)!.id;

describe("identity and counts", () => {
  it("separates External from Unknown IP", () => {
    const ext = graph.edges.find((e) => e.target === byLabel("203.0.113.40"))!;
    const unk = graph.edges.find((e) => e.source === byLabel("10.99.0.7"))!;
    expect(edgeIdentity(ext, node)).toBe("external");
    expect(edgeIdentity(unk, node)).toBe("unknown");
  });
  it("counts the map once for the header and inspector", () => {
    const s = summarize(graph.nodes, graph.edges, node);
    expect(s).toMatchObject({
      services: 5,
      conversations: 15,
      identified: 13,
      external: 1,
      unknown: 1,
      multiple: 0,
      unknownSources: 1,
      unknownOther: 0,
      externalNodes: 1,
    });
    expect(s.identified + s.external + s.unknown + s.multiple).toBe(
      s.conversations,
    );
  });
});
