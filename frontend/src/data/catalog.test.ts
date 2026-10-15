import { describe, expect, it } from "vitest";
import {
  createScopeCatalogRows,
  parseCatalogRows,
  parseFindRows,
  validatedBuildFindSearch,
} from "./catalog";

const key = "a".repeat(64);
const row = {
  _key: key,
  service: "frontend",
  environment: "prod",
  cluster: "c1",
  namespace: "shop",
  pods: "2",
  peers: 3,
  conversations_1h: "4",
  blocked_1h: 0,
  unknown_peers_1h: 1,
  first_seen: "10",
  last_seen: 20,
  updated: 30,
  window_start: 0,
  window_end: 60,
};

describe("catalog parsing", () => {
  it("parses typed scope metrics and preserves unavailable metrics", () => {
    expect(parseCatalogRows([row])[0]).toEqual({
      ...row,
      pods: 2,
      peers: 3,
      conversations_1h: 4,
      blocked_1h: 0,
      unknown_peers_1h: 1,
      first_seen: 10,
      last_seen: 20,
      updated: 30,
      window_start: 0,
      window_end: 60,
    });
    expect(
      parseCatalogRows([
        { ...row, _key: key, pods: undefined, peers: undefined },
      ])[0].pods,
    ).toBeUndefined();
    expect(createScopeCatalogRows([row])[0]).toMatchObject({
      service: "frontend",
      environment: "prod",
      cluster: "c1",
      namespace: "shop",
    });
    expect(createScopeCatalogRows([row])[0].pods).toBeUndefined();
  });

  it("rejects invalid dimensions, key, types, ranges, order, and counts", () => {
    expect(
      parseCatalogRows([{ ...row, namespace: "Bad" }])[0].scopeError,
    ).toBeDefined();
    expect(() => parseCatalogRows([{ ...row, _key: "svc" }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, _key: key + "\n" }])).toThrow();
    expect(() => parseFindRows([{ ...row, _key: key + "\n" }])).toThrow();
    expect(
      parseCatalogRows([{ ...row, namespace: "" }])[0].scopeError,
    ).toBeDefined();
    expect(() => parseCatalogRows([{ ...row, pods: -1 }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, pods: true }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, pods: [] }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, pods: " " }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, pods: "1\n" }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, blocked_1h: 5 }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, unknown_peers_1h: 5 }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, first_seen: 21 }])).toThrow();
    expect(() => parseCatalogRows([{ ...row, window_start: 61 }])).toThrow();
    expect(() =>
      parseCatalogRows([{ ...row, updated: 253402300800 }]),
    ).toThrow();
  });

  it("parses find rows and validates safe find macros", () => {
    expect(parseFindRows([row])).toEqual([
      {
        _key: key,
        service: "frontend",
        environment: "prod",
        cluster: "c1",
        namespace: "shop",
      },
    ]);
    expect(validatedBuildFindSearch("::1")).toBe('| `adm_find("::1")`');
    expect(validatedBuildFindSearch("epg/Prod_1:app@2")).toBe(
      '| `adm_find("epg/Prod_1:app@2")`',
    );
    for (const value of [
      "",
      "x\n",
      "x|search",
      "x`",
      'x"',
      "x$",
      "x'",
      "x ",
      "x".repeat(256),
    ])
      expect(() => validatedBuildFindSearch(value)).toThrow();
  });

  it("keeps valid scopes visible beside unsupported binding dimensions", () => {
    const rows = parseCatalogRows([
      row,
      { ...row, _key: "b".repeat(64), service: "x".repeat(260) },
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0].scopeError).toBeUndefined();
    expect(rows[1].scopeError).toBeDefined();
    const fallback = createScopeCatalogRows([
      row,
      { ...row, service: "x".repeat(260) },
    ]);
    expect(fallback).toHaveLength(2);
    expect(fallback[1].scopeError).toBeDefined();
  });

  it("surfaces bounded Find warnings before parsing rows", () => {
    expect(() =>
      parseFindRows([{ warnings: "incomplete identity evidence" }]),
    ).toThrow("incomplete identity evidence");
  });
});
