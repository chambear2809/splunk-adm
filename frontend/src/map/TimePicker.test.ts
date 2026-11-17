import { afterEach, describe, expect, it, vi } from "vitest";
import { parseTimePreview } from "./TimePicker";

afterEach(() => vi.unstubAllGlobals());

describe("time picker previews", () => {
  it("marks valid live previews as successful for the toolkit", async () => {
    const fetch = vi.fn<
      (
        url: string,
        init: RequestInit,
      ) => Promise<{
        ok: boolean;
        json: () => Promise<Record<string, string>>;
      }>
    >(async () => ({
      ok: true,
      json: async () => ({ "1794881820": "2026-11-17T02:17:00.000+00:00" }),
    }));
    vi.stubGlobal("fetch", fetch);
    const signal = new AbortController().signal;
    expect(await parseTimePreview("1794881820", "UTC", true, signal)).toEqual({
      time: "1794881820",
      iso: "2026-11-17T02:17:00.000+00:00",
      error: null,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].signal).toBe(signal);
  });

  it("rejects malformed successful responses and unrelated strings", async () => {
    const signal = new AbortController().signal;
    for (const body of [
      null,
      [],
      { message: "2026-11-17T02:17:00.000Z" },
      { "1794881820": null },
      { "1794881820": "not-a-date" },
      { "1794881820": "2026-11-17T02:17:00" },
      { "1794881820": "2026-02-30T02:17:00Z" },
      { "1794881820": "2026-11-17T02:17:00+25:00" },
      Object.create({ "1794881820": "2026-11-17T02:17:00Z" }),
    ]) {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => ({ ok: true, json: async () => body })),
      );
      expect(
        (await parseTimePreview("1794881820", "UTC", true, signal)).error,
      ).toBeTruthy();
    }
  });

  it("rejects invalid values without dispatch and reports failed previews", async () => {
    const fetch = vi.fn(async () => ({ ok: false }));
    vi.stubGlobal("fetch", fetch);
    const signal = new AbortController().signal;
    expect(
      (await parseTimePreview("bad time", "UTC", true, signal)).error,
    ).toBeTruthy();
    expect(fetch).not.toHaveBeenCalled();
    expect(
      (await parseTimePreview("1794881820", "UTC", true, signal)).error,
    ).toBeTruthy();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
