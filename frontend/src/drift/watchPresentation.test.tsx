import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import fixture from "../../../fixtures/contracts/dependency-signatures.json";
import {
  WatchDependency,
  WatchStatusSummary,
  watchIdentity,
} from "./watchPresentation";

const tuple = (port: unknown = 443) => [
  1,
  "producer",
  "scope",
  "svc/a",
  "db|b",
  "tcp",
  port,
  "calls",
  "forward",
];

describe("watch occurrence presentation", () => {
  it("decodes shared Unicode signatures without normalizing identity", () => {
    for (const vector of fixture.vectors) {
      const parsed = watchIdentity(vector.signature);
      expect(parsed).toBeDefined();
      expect(vector.dependency).toMatchObject(parsed!);
    }
    expect(watchIdentity(fixture.vectors[0].signature)?.source).not.toEqual(
      watchIdentity(fixture.vectors[1].signature)?.source,
    );
  });

  it("accepts port boundaries and keeps delimiters as data", () => {
    expect(watchIdentity(JSON.stringify(tuple(1)))).toMatchObject({
      source: "svc/a",
      destination: "db|b",
      port: 1,
    });
    expect(watchIdentity(JSON.stringify(tuple(65535)))?.port).toBe(65535);
    for (const port of [0, 65536, 1.5, true, "443", null]) {
      expect(watchIdentity(JSON.stringify(tuple(port)))).toBeUndefined();
    }
  });

  it("fails closed for malformed, unknown and oversized identities", () => {
    const invalid = [
      "not json",
      JSON.stringify([2, ...tuple().slice(1)]),
      JSON.stringify(tuple().slice(0, 8)),
      JSON.stringify([1, "", ...tuple().slice(2)]),
      JSON.stringify([1, "producer\u0000", ...tuple().slice(2)]),
      JSON.stringify([1, "\ud800", ...tuple().slice(2)]),
      "x".repeat(4097),
    ];
    for (const signature of invalid) {
      expect(watchIdentity(signature)).toBeUndefined();
      const html = renderToStaticMarkup(
        <WatchDependency signature={signature} />,
      );
      expect(html).toContain("identity details unavailable");
      expect(html).not.toContain(signature);
    }
  });

  it("renders details as escaped text without raw serialized signatures", () => {
    const value = tuple();
    value[3] = "<script>alert(1)</script>";
    const signature = JSON.stringify(value);
    const html = renderToStaticMarkup(
      <WatchDependency signature={signature} />,
    );
    expect(html).toContain("Dependency change recorded:");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain(signature);
    for (const detail of [
      "Authority: producer",
      "Scope: scope",
      "Relationship:",
      "Direction: forward",
      "<details>",
    ])
      expect(html).toContain(detail);
  });

  it("reports only returned status facts at the checked time", () => {
    const html = renderToStaticMarkup(
      <WatchStatusSummary
        signature={JSON.stringify(tuple())}
        at={0}
        value={{
          count: 2,
          thresholdMet: false,
          expected: true,
          coolingDown: false,
        }}
      />,
    );
    expect(html).toContain("1970-01-01T00:00:00.000Z");
    expect(html).toContain("2 distinct observation windows; threshold");
    expect(html).toContain("not yet met");
    expect(html).toContain("expected window");
    expect(html).toContain("active");
    expect(html).toContain("cooldown");
    expect(html).toContain("inactive");
    const singular = renderToStaticMarkup(
      <WatchStatusSummary
        signature={JSON.stringify(tuple())}
        at={0}
        value={{
          count: 1,
          thresholdMet: true,
          expected: false,
          coolingDown: true,
        }}
      />,
    );
    expect(singular).toContain("1 distinct observation window; threshold");
    expect(singular).toContain("met");
  });
});
