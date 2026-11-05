import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { activeFacetCount } from "../map/FilterBar";
import {
  DeviceLookup,
  deviceURL,
  TracePathForm,
  traceURL,
} from "./ExploreTools";

describe("Explore placeholders", () => {
  it("builds a map trace link that keeps scope and drops device state", () => {
    const href = traceURL(
      "10.42.0.15",
      "orders-db-01",
      new URLSearchParams("service=frontend&mode=demo&id=leaf-1"),
    );
    const url = new URL(href, "http://local");
    expect(url.pathname.endsWith("/map")).toBe(true);
    expect(url.searchParams.get("service")).toBe("frontend");
    expect(url.searchParams.get("trace_src")).toBe("10.42.0.15");
    expect(url.searchParams.get("trace_dst")).toBe("orders-db-01");
    expect(url.searchParams.has("id")).toBe(false);
  });

  it("builds a device link with only the mode and id", () => {
    const href = deviceURL(
      "pod-1/node-103",
      new URLSearchParams("service=frontend&mode=live"),
    );
    const url = new URL(href, "http://local");
    expect(url.pathname.endsWith("/device")).toBe(true);
    expect([...url.searchParams.keys()]).toEqual(["mode", "id"]);
  });

  it("renders labelled, initially disabled forms", () => {
    const trace = renderToStaticMarkup(<TracePathForm />);
    expect(trace).toContain('aria-label="Trace source"');
    expect(trace).toContain('aria-label="Trace destination"');
    expect(trace).toMatch(/<button[^>]*disabled[^>]*>Trace<\/button>/);
    const device = renderToStaticMarkup(<DeviceLookup />);
    expect(device).toContain('aria-label="Device name or ID"');
  });

  it("counts active map facets for the Filters button", () => {
    expect(activeFacetCount({})).toBe(0);
    expect(
      activeFacetCount({ identity: "external", blocked: true, port: 443 }),
    ).toBe(3);
    expect(activeFacetCount({ blocked: false })).toBe(0);
  });
});
