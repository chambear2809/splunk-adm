import { describe, expect, it } from "vitest";
import {
  createScopeCatalogRows,
  parseCatalogRows,
  parseFindRows,
  parseNetworkClientFindRows,
  catalogLimitMessage,
  validatedBuildCatalogSearch,
  validatedBuildFindSearch,
  validatedBuildNetworkClientFindSearch,
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

  it("ignores the reserved empty-catalog bookkeeping row", () => {
    expect(
      parseCatalogRows([{ _key: "adm-catalog-empty", updated: 10 }]),
    ).toEqual([]);
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
  it("collapses repeated Find identities and rejects conflicting duplicate keys", () => {
    expect(parseFindRows([row, row])).toHaveLength(1);
    expect(() =>
      parseFindRows([row, { ...row, service: "another-service" }]),
    ).toThrow("Find returned conflicting scope dimensions for one key.");
  });
  it("keeps source-qualified client Find evidence and rejects unsupported identities", () => {
    const parsed = parseNetworkClientFindRows([
      {
        row_type: "network_client",
        _key: "meraki:org-a/network-a:00:11:22:33:44:55",
        client_mac: "00:11:22:33:44:55",
        source: "meraki",
        source_authority: "org-a/network-a",
        routing_domain: "vrf-a",
        scope: "prod",
        cluster: "c1",
        source_time: 100,
        received_time: 101,
        attachment_status: "unmapped",
        quality_reason: "No exact scope mapping",
      },
    ]);
    expect(parsed[0]).toMatchObject({
      attachment_status: "unmapped",
      source_time: 100,
      received_time: 101,
      routing_domain: "vrf-a",
    });
    expect(
      validatedBuildNetworkClientFindSearch("00:11:22:33:44:55"),
    ).toContain("adm_find_network_client");
    expect(() => validatedBuildNetworkClientFindSearch("ap-name")).toThrow();
    expect(() =>
      parseNetworkClientFindRows([
        {
          row_type: "network_client",
          _key: "x",
          source: "meraki",
          attachment_status: "associated",
          received_time: "NaN",
        },
      ]),
    ).toThrow();
    expect(() =>
      parseNetworkClientFindRows([
        {
          row_type: "network_client",
          _key: "x",
          source: "meraki",
          attachment_status: "associated",
          source_time: 1e15,
        },
      ]),
    ).toThrow("outside the epoch range");
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

  it("pushes an exact service filter into the catalog lookup", () => {
    expect(validatedBuildCatalogSearch()).toBe("| inputlookup adm_app_catalog");
    expect(validatedBuildCatalogSearch("frontend")).toBe(
      '| inputlookup adm_app_catalog WHERE service="frontend"',
    );
    for (const value of ['frontend"', "frontend\n", "frontend|search", " "])
      expect(() => validatedBuildCatalogSearch(value)).toThrow();
  });

  it("gives over-limit catalog results an actionable message", () => {
    expect(catalogLimitMessage()).toMatch(/more than 5,000 rows/i);
    expect(catalogLimitMessage(12)).toMatch(/more than 12 rows/i);
    expect(catalogLimitMessage()).toMatch(/narrow the service scope/i);
  });
});
