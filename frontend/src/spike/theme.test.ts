import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/splunk-utils/themes", () => ({ getUserTheme: vi.fn() }));
vi.mock("@splunk/splunk-utils/url", () => ({ createStaticURL: vi.fn() }));

const { resolveUserTheme } = await import("./theme");

const api = (theme: string) => ({ getTheme: () => Promise.resolve(theme) });

function host(
  load: (ok: (m: unknown) => void, fail: (e: unknown) => void) => void,
  global?: unknown,
) {
  const requested: string[][] = [];
  return {
    requested,
    host: {
      amdRequire: (
        deps: string[],
        ok: (m: unknown) => void,
        fail: (e: unknown) => void,
      ) => {
        requested.push(deps);
        load(ok, fail);
      },
      globalApi: () => global,
      staticURL: (path: string) => `/en-US/static/@1/${path}`,
      fallback: vi.fn(() => Promise.resolve("enterprise")),
    },
  };
}

describe("resolveUserTheme", () => {
  it("uses the theme API registered as an AMD module on Simple XML pages", async () => {
    const h = host((ok) => ok(api("dark")));
    await expect(resolveUserTheme(h.host)).resolves.toBe("dark");
    expect(h.requested).toEqual([["/en-US/static/@1/build/api/get_theme.js"]]);
    expect(h.host.fallback).not.toHaveBeenCalled();
  });

  it("uses the global theme API when the bundle sets it instead", async () => {
    const h = host((ok) => ok(undefined), api("light"));
    await expect(resolveUserTheme(h.host)).resolves.toBe("light");
  });

  it("falls back to splunk-utils when the API is missing, fails or is empty", async () => {
    for (const load of [
      (ok: (m: unknown) => void) => ok({}),
      (_ok: unknown, fail: (e: unknown) => void) => fail(new Error("404")),
      (ok: (m: unknown) => void) => ok(api("")),
    ]) {
      const h = host(load as never);
      await expect(resolveUserTheme(h.host)).resolves.toBe("enterprise");
      expect(h.host.fallback).toHaveBeenCalled();
    }
  });

  it("skips RequireJS entirely without an AMD loader", async () => {
    const fallback = vi.fn(() => Promise.resolve("prismaDark"));
    await expect(
      resolveUserTheme({
        globalApi: () => undefined,
        staticURL: String,
        fallback,
      }),
    ).resolves.toBe("prismaDark");
  });
});
