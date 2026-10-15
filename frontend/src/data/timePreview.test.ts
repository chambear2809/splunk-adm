import { describe, expect, it, vi } from "vitest";
import { createTimePreview } from "./timePreview";

describe("time preview coordination", () => {
  it("does not apply an older response after a newer request", async () => {
    const pending: Array<{
      raw: string;
      resolve: (value: string) => void;
    }> = [];
    const parse = vi.fn(
      (raw: string) =>
        new Promise<string>((resolve) => pending.push({ raw, resolve })),
    );
    const preview = createTimePreview(parse);
    const applied: string[] = [];
    void preview.request(
      "earliest",
      "A",
      (value) => applied.push(value),
      vi.fn(),
    );
    void preview.request(
      "earliest",
      "B",
      (value) => applied.push(value),
      vi.fn(),
    );
    pending.find((item) => item.raw === "B")?.resolve("B parsed");
    await Promise.resolve();
    pending.find((item) => item.raw === "A")?.resolve("A parsed");
    await Promise.resolve();
    expect(parse).toHaveBeenCalledTimes(2);
    expect(applied).toEqual(["B parsed"]);
  });

  it("cancels both fields on cleanup while allowing independent requests", async () => {
    const signals: AbortSignal[] = [];
    const parse = vi.fn((raw: string, signal: AbortSignal) => {
      signals.push(signal);
      return Promise.resolve(raw);
    });
    const preview = createTimePreview(parse);
    const applied: string[] = [];
    await preview.request(
      "earliest",
      "A",
      (value) => applied.push(value),
      vi.fn(),
    );
    await preview.request(
      "latest",
      "B",
      (value) => applied.push(value),
      vi.fn(),
    );
    preview.cancel();
    expect(signals).toHaveLength(2);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    expect(applied).toEqual(["A", "B"]);
  });

  it("reports an active timeout while stale cancellation stays silent", async () => {
    vi.useFakeTimers();
    try {
      const parse = vi.fn(
        (_raw: string, signal: AbortSignal) =>
          new Promise<string>((_resolve, reject) => {
            signal.addEventListener("abort", () =>
              reject(new Error("aborted")),
            );
          }),
      );
      const preview = createTimePreview(parse);
      const failures: unknown[] = [];
      const pending = preview.request("earliest", "A", vi.fn(), (error) =>
        failures.push(error),
      );
      await vi.advanceTimersByTimeAsync(10000);
      await pending;
      expect(failures).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
