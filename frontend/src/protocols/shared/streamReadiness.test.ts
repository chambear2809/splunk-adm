import { describe, expect, it, vi } from "vitest";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../data/searchClient";
import { checkStreamEstimateMode } from "./streamReadiness";

describe("Stream Estimate-mode readiness check", () => {
  it("expands stream:stats nested JSON and detects enabled, estimate_only, mixed, and unknown", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        { host: "fwd-1", stream_id: "tcp", stats_only: "true" },
        { host: "fwd-1", stream_id: "dns", stats_only: "false" },
        { host: "fwd-2", stream_id: "dns", stats_only: "false" },
        { host: "fwd-1", stream_id: "http", stats_only: "false" },
        { host: "fwd-2", stream_id: "http", stats_only: "true" },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const entries = await checkStreamEstimateMode(
      client,
      ["tcp", "dns", "http", "dhcp"],
      new AbortController().signal,
    );
    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({
        allowEmpty: true,
        overflow: "truncate",
        search: expect.stringContaining("senders{}.streams{}.stats_only"),
      }),
    );
    expect(entries.map((e) => [e.streamId, e.state])).toEqual([
      ["tcp", "estimate_only"],
      ["dns", "enabled"],
      ["http", "estimate_only"],
      ["dhcp", "unknown"],
    ]);
    expect(entries[2].detail).toContain("Mixed");
  });

  it("returns unknown when caller lacks _internal access", async () => {
    const client: SearchClient = {
      search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
    };
    const entries = await checkStreamEstimateMode(
      client,
      ["tcp", "dns"],
      new AbortController().signal,
    );
    expect(entries.every((e) => e.state === "unknown")).toBe(true);
  });
});
