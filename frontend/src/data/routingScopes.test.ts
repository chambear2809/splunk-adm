import { describe, expect, it, vi } from "vitest";
import {
  clearRoutingScopeCache,
  filterScopeOptions,
  isUnlistedScope,
  loadObserverMappings,
  routingScopeOptions,
  singleScope,
  type RoutingScopeOption,
  type RoutingScopeState,
} from "./routingScopes";
import type { ObserverMapping } from "./observerMappingClient";

const mappings: ObserverMapping[] = [
  {
    observer_kind: "apic",
    observer: "apic-1",
    scope: "fabric-a",
    mapping_status: "mapped",
  },
  {
    observer_kind: "cluster",
    observer: "k3s-lab",
    scope: "fabric-a",
    mapping_status: "verified",
  },
  {
    observer_kind: "firewall",
    observer: "192.0.2.10",
    scope: "dmz",
    mapping_status: "verified",
  },
  {
    observer_kind: "exporter",
    observer: "192.0.2.20",
    scope: "unmapped:192.0.2.20",
    mapping_status: "mapped",
  },
  {
    observer_kind: "exporter",
    observer: "192.0.2.21",
    scope: "branch",
    mapping_status: "unmapped",
  },
  { observer_kind: "exporter", observer: "192.0.2.22", scope: "legacy" },
  {
    observer_kind: "exporter",
    observer: "192.0.2.23",
    scope: "reserved:lab",
    mapping_status: "mapped",
  },
  {
    observer_kind: "exporter",
    observer: "192.0.2.24",
    scope: "bad scope",
    mapping_status: "mapped",
  },
];

const optionsFor = (...scopes: string[]): RoutingScopeOption[] =>
  scopes.map((scope) => ({ scope, observers: 1, verified: false }));
const ready = (...scopes: string[]): RoutingScopeState => ({
  status: "ready",
  options: optionsFor(...scopes),
});

describe("routing scope options", () => {
  it("offers distinct mapped and verified scopes only, sorted", () => {
    expect(routingScopeOptions(mappings)).toEqual([
      { scope: "dmz", observers: 1, verified: true },
      { scope: "fabric-a", observers: 2, verified: true },
    ]);
  });

  it("restricts endpoint investigation to verified attestations", () => {
    expect(
      routingScopeOptions(
        mappings.filter((row) => row.observer !== "k3s-lab"),
        "verified",
      ).map((option) => option.scope),
    ).toEqual(["dmz"]);
  });

  it("filters case-insensitively and keeps the current value", () => {
    const options = optionsFor("dc1-prod", "dc2-prod", "lab");
    expect(
      filterScopeOptions(options, "DC2", "lab").map((o) => o.scope),
    ).toEqual(["dc2-prod", "lab"]);
    expect(filterScopeOptions(options, "  ")).toHaveLength(3);
  });

  it("preselects only a single scope and only when nothing is chosen", () => {
    expect(singleScope(ready("fabric-a"), "")).toBe("fabric-a");
    expect(singleScope(ready("fabric-a"), "linked")).toBeUndefined();
    expect(singleScope(ready("a", "b"), "")).toBeUndefined();
    expect(singleScope({ status: "loading" }, "")).toBeUndefined();
  });

  it("marks a linked scope that is not in the loaded list", () => {
    expect(isUnlistedScope(ready("fabric-a"), "old-scope")).toBe(true);
    expect(isUnlistedScope(ready("fabric-a"), "fabric-a")).toBe(false);
    expect(isUnlistedScope({ status: "loading" }, "old-scope")).toBe(false);
  });
});

describe("observer mapping session cache", () => {
  it("issues one request for concurrent and later readers", async () => {
    const client = { list: vi.fn(async () => mappings) };
    const [first, second] = await Promise.all([
      loadObserverMappings(client),
      loadObserverMappings(client),
    ]);
    await loadObserverMappings(client);
    expect(first).toBe(second);
    expect(client.list).toHaveBeenCalledTimes(1);
    clearRoutingScopeCache(client);
    await loadObserverMappings(client);
    expect(client.list).toHaveBeenCalledTimes(2);
  });

  it("does not cache a failure, so retry reaches the server again", async () => {
    const client = {
      list: vi
        .fn<() => Promise<ObserverMapping[]>>()
        .mockRejectedValueOnce(new Error("HTTP 503"))
        .mockResolvedValueOnce(mappings),
    };
    await expect(loadObserverMappings(client)).rejects.toThrow("HTTP 503");
    await expect(loadObserverMappings(client)).resolves.toBe(mappings);
    expect(client.list).toHaveBeenCalledTimes(2);
  });
});
