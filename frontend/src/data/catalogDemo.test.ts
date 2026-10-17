import { afterEach, expect, it, vi } from "vitest";
import catalog from "../../../fixtures/demo-catalog.json";
import find from "../../../fixtures/demo-find.json";
import networkingCatalog from "../../../fixtures/demo-networking-catalog.json";
import networkingFind from "../../../fixtures/demo-networking-find.json";
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  vi.resetModules();
});
const response = (payload: unknown) => ({
  ok: true,
  json: async () => payload,
});
it("loads only on demand, keeps actual capture rows, and memoizes success", async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response(catalog))
    .mockResolvedValueOnce(response(find));
  vi.stubGlobal("fetch", fetcher);
  const loader = await import("./catalogDemo");
  expect(fetcher).not.toHaveBeenCalled();
  const data = await loader.loadCatalogDemo();
  expect(data.catalog.rows).toEqual(catalog.rows);
  expect(data.find.queries).toEqual(find.queries);
  expect(await loader.loadCatalogDemo()).toBe(data);
  expect(fetcher).toHaveBeenCalledTimes(2);
});
it("loads both captured networking flows and their separate client Find evidence", async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response(networkingCatalog))
    .mockResolvedValueOnce(response(networkingFind));
  vi.stubGlobal("fetch", fetcher);
  const loader = await import("./catalogDemo");
  const data = await loader.loadCatalogDemo("meraki-nxos");
  expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
    "/fixtures/demo-networking-catalog.json",
    "/fixtures/demo-networking-find.json",
  ]);
  expect(data.catalog.rows).toEqual(networkingCatalog.rows);
  expect(data.find.queries).toEqual(
    networkingFind.queries.map(({ query, search, rows }) => ({
      query,
      search,
      rows,
    })),
  );
  expect(data.find.network_client_queries).toEqual(
    networkingFind.network_client_queries.map(({ query, search, rows }) => ({
      query,
      search,
      rows,
    })),
  );
});
it("rejects malformed capture shape and retries after rejection", async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response({ rows: [] }))
    .mockResolvedValueOnce(response(find))
    .mockResolvedValueOnce(response(catalog))
    .mockResolvedValueOnce(response(find));
  vi.stubGlobal("fetch", fetcher);
  const loader = await import("./catalogDemo");
  await expect(loader.loadCatalogDemo()).rejects.toThrow(/shape/);
  await expect(loader.loadCatalogDemo()).resolves.toMatchObject({
    catalog: { rows: catalog.rows },
  });
});
it("reports failed fixture HTTP responses", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 404 }));
  const loader = await import("./catalogDemo");
  await expect(loader.loadCatalogDemo()).rejects.toThrow(/404/);
});
it("aborts stalled fixture requests within the bounded load timeout", async () => {
  vi.useFakeTimers();
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url: unknown, init: RequestInit) =>
        new Promise((_resolve, reject) =>
          init.signal?.addEventListener(
            "abort",
            () => reject(new Error("aborted")),
            { once: true },
          ),
        ),
    ),
  );
  const loader = await import("./catalogDemo");
  const rejected = expect(loader.loadCatalogDemo()).rejects.toThrow(/aborted/);
  await vi.advanceTimersByTimeAsync(10000);
  await rejected;
});
it("aborts the other fixture when one request fails before timeout", async () => {
  let secondSignal: AbortSignal | null | undefined;
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 404 })
      .mockImplementationOnce((_url: unknown, init: RequestInit) => {
        secondSignal = init.signal;
        return new Promise((_resolve, reject) =>
          init.signal?.addEventListener(
            "abort",
            () => reject(new Error("aborted")),
            { once: true },
          ),
        );
      }),
  );
  const loader = await import("./catalogDemo");
  await expect(loader.loadCatalogDemo()).rejects.toThrow(/404/);
  expect(secondSignal?.aborted).toBe(true);
});

it("rejects invalid or reversed captured windows before using them", async () => {
  for (const bounds of [
    { earliest: "abc", latest: "1791374400" },
    { earliest: "1791374400", latest: "1791370800" },
  ]) {
    vi.resetModules();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(response({ ...catalog, ...bounds }))
        .mockResolvedValueOnce(response(find)),
    );
    const loader = await import("./catalogDemo");
    await expect(loader.loadCatalogDemo()).rejects.toThrow(/shape/);
  }
});
