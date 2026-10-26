import { describe, expect, it } from "vitest";
import { isCurrentRequest } from "./MapDnsInspection";

describe("Map DNS request invalidation", () => {
  it("rejects aborted and stale generations before state writes", () => {
    const controller = new AbortController();
    expect(isCurrentRequest(4, 4, controller.signal)).toBe(true);
    controller.abort();
    expect(isCurrentRequest(4, 4, controller.signal)).toBe(false);
    const fresh = new AbortController();
    expect(isCurrentRequest(4, 5, fresh.signal)).toBe(false);
  });
});
