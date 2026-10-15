import { describe, expect, it } from "vitest";
import { previousWindow, changeEdgeLabel } from "./ChangePanel";
import { demoGraph } from "./provider";
describe("previous comparison window", () => {
  it("uses the same duration ending at the loaded start", () => {
    const graph = demoGraph();
    const bounds = previousWindow(graph);
    const start = Date.parse(graph.window.start) / 1000;
    const end = Date.parse(graph.window.end) / 1000;
    expect(Number(bounds.latest)).toBe(start);
    expect(Number(bounds.latest) - Number(bounds.earliest)).toBe(end - start);
  });
  it("rejects unknown and reversed windows", () => {
    const graph = demoGraph();
    for (const window of [
      { start: "invalid", end: graph.window.end },
      { start: graph.window.end, end: graph.window.start },
    ])
      expect(() => previousWindow({ ...graph, window })).toThrow();
  });
});

it("does not assign direction to an unoriented conversation", () => {
  const graph = demoGraph();
  const edge = {
    ...graph.edges[0],
    relationship: "communicates_with" as const,
    direction_basis: "unknown" as const,
  };
  expect(changeEdgeLabel(edge, graph)).toContain("↔");
  expect(changeEdgeLabel(edge, graph)).not.toContain("→");
});
