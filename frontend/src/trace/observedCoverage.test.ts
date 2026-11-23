import { describe, expect, it } from "vitest";
import { coverageLabel, observedCoverage } from "./traceModel";

const hop = (evidence: string, sources: string[], kind = "switch") => ({
  evidence,
  kind,
  sources,
});

describe("observedCoverage", () => {
  it("counts observed hops and distinct sources without summing records", () => {
    const c = observedCoverage([
      hop("observed", ["Stream NetFlow"]),
      hop("observed", ["Stream NetFlow", "Cisco FTD"]),
      hop("observed", ["Cisco Isovalent Hubble"], "host"),
      hop("gap", []),
      hop("inferred", ["Topology"]),
    ]);
    expect(c).toEqual({ hops: 3, sources: 3 });
    expect(coverageLabel(c)).toBe("3 observed hops from 3 sources");
  });

  it("keeps the incomplete label when nothing was observed", () => {
    const c = observedCoverage([hop("gap", []), hop("observed", [], "gap")]);
    expect(c).toEqual({ hops: 0, sources: 0 });
    expect(coverageLabel(c)).toBe("Source coverage incomplete");
  });

  it("uses singular wording", () => {
    expect(coverageLabel({ hops: 1, sources: 1 })).toBe(
      "1 observed hop from 1 source",
    );
  });
});
