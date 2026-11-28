import { describe, expect, it } from "vitest";
import {
  buildFlowEndpointPredicates,
  collectFilterSuggestions,
  matchesFlowEndpoints,
} from "./filterSpl";

describe("shared protocol flow filter SPL helpers", () => {
  it("builds directional predicates when bidirectional is false/omitted", () => {
    const preds = buildFlowEndpointPredicates({
      filter: { src: "10.0.0.1", dst: "10.0.0.2", port: "443" },
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
      portFields: ["dest_port", "src_port"],
    });
    expect(preds).toEqual([
      'src_ip="10.0.0.1"',
      'dest_ip="10.0.0.2"',
      '(dest_port="443" OR src_port="443")',
    ]);
  });

  it("builds bidirectional A <-> B predicates for pair and single endpoint", () => {
    const pair = buildFlowEndpointPredicates({
      filter: { src: "10.0.0.1", dst: "10.0.0.2", bidirectional: true },
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
    });
    expect(pair).toEqual([
      '((src_ip="10.0.0.1" AND dest_ip="10.0.0.2") OR (src_ip="10.0.0.2" AND dest_ip="10.0.0.1"))',
    ]);

    const single = buildFlowEndpointPredicates({
      filter: { src: "10.0.0.1", bidirectional: true },
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
    });
    expect(single).toEqual(['(src_ip="10.0.0.1" OR dest_ip="10.0.0.1")']);
  });

  it("matches endpoints client-side in directional and bidirectional modes", () => {
    expect(
      matchesFlowEndpoints(
        { src: "10.0.0.1", dst: "10.0.0.2", bidirectional: true, port: "443" },
        "10.0.0.2",
        "10.0.0.1",
        [443, 52100],
      ),
    ).toBe(true);
    expect(
      matchesFlowEndpoints(
        { src: "10.0.0.1", dst: "10.0.0.2", port: "443" },
        "10.0.0.2",
        "10.0.0.1",
        [443],
      ),
    ).toBe(false);
  });

  it("deduplicates and caps autocomplete suggestions", () => {
    expect(
      collectFilterSuggestions(
        ["10.0.0.1", "", "—", "10.0.0.1", "10.0.0.2"],
        2,
      ),
    ).toEqual(["10.0.0.1", "10.0.0.2"]);
  });
});
