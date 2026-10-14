import { describe, expect, it } from "vitest";
import { MAX_ROWS } from "../rows";
import { spikePage, spikeRows, spikeSearch } from "./settings";

describe("Toolkit spike boundary", () => {
  it("allows only the map view, including a Splunk root prefix", () => {
    expect(spikePage("/proxy/en-US/app/splunk_adm/map")).toBe("map");
    for (const page of ["setup", "map/elsewhere", "../map", "map%2fsetup"])
      expect(() => spikePage(`/en-US/app/splunk_adm/${page}`)).toThrow();
  });
  it("builds one read-only macro search with the explicit fixture window", () => {
    expect(
      spikeSearch(new URLSearchParams("earliest=1791373500&latest=1791374400")),
    ).toEqual({
      search: '`adm_graph("frontend","demo","demo-cluster","shop")`',
      earliest_time: "1791373500",
      latest_time: "1791374400",
    });
  });
  it("rejects SPL injection in every scope and time parameter", () => {
    for (const key of [
      "service",
      "environment",
      "cluster",
      "namespace",
      "earliest",
      "latest",
    ])
      for (const value of [
        'x")|collect index=other',
        "`adm_graph`",
        "$token$",
        "1\n|delete",
      ])
        expect(() =>
          spikeSearch(new URLSearchParams({ [key]: value })),
        ).toThrow();
    expect(() =>
      spikeSearch(new URLSearchParams("earliest=20&latest=10")),
    ).toThrow();
  });
  it("rejects empty, malformed and truncated oversized result sets", () => {
    for (const value of [
      null,
      {},
      { results: [] },
      { results: [null] },
      { results: [[]] },
      { results: Array(MAX_ROWS + 1).fill({}) },
    ])
      expect(() => spikeRows(value)).toThrow();
    expect(spikeRows({ results: [{ row_type: "meta" }] })).toEqual([
      { row_type: "meta" },
    ]);
  });
});
