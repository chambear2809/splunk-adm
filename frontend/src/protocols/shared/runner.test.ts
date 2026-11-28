import { describe, expect, it, vi } from "vitest";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../data/searchClient";
import type { BaseProtocolProfile } from "./contract";
import { runBoundedProtocolSearch } from "./runner";

const NOW = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "tcp-dc1",
  source: "protocol_tcp_tls",
  lens: "tcp_tls",
  scope: "lab:dc1",
  index: "netflow",
  observer: "streamfwd-01",
  validFrom: NOW - 3600,
  validUntil: NOW + 3600,
};

describe("runBoundedProtocolSearch", () => {
  it("passes allowEmpty and truncate overflow and handles zero rows as complete", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
      truncated: false,
    });
    const client: SearchClient = { search };
    const result = await runBoundedProtocolSearch(client, {
      lens: "tcp_tls",
      profile: PROFILE,
      spl: "search index=netflow sourcetype=stream:tcp | fields _time src_ip dest_ip",
      earliest: NOW - 900,
      latest: NOW - 60,
      signal: new AbortController().signal,
    });
    expect(result.outcome.state).toBe("complete");
    expect(result.rows).toEqual([]);
    expect(result.capped).toBe(false);
    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({
        allowEmpty: true,
        overflow: "truncate",
        maxRows: 256,
      }),
    );
  });

  it("reports truncated/capped results as partial and projects rows strictly to lens allowlist", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: "1800000000",
            src_ip: "10.0.0.1",
            dest_ip: "10.0.0.2",
            cookie: "secret-cookie",
            _raw: "raw payload",
          },
        ],
        warnings: [],
        errors: [],
        truncated: true,
      }),
    };
    const result = await runBoundedProtocolSearch(client, {
      lens: "tcp_tls",
      profile: PROFILE,
      spl: "search index=netflow sourcetype=stream:tcp | fields _time src_ip dest_ip",
      earliest: NOW - 900,
      latest: NOW - 60,
      maxRows: 10,
      signal: new AbortController().signal,
    });
    expect(result.outcome.state).toBe("partial");
    expect(result.capped).toBe(true);
    expect(result.rows).toEqual([
      { _time: "1800000000", src_ip: "10.0.0.1", dest_ip: "10.0.0.2" },
    ]);
  });

  it("maps SearchAccessDeniedError to blocked outcome", async () => {
    const client: SearchClient = {
      search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
    };
    const result = await runBoundedProtocolSearch(client, {
      lens: "tcp_tls",
      profile: PROFILE,
      spl: "search index=netflow sourcetype=stream:tcp | fields _time src_ip",
      earliest: NOW - 900,
      latest: NOW - 60,
      signal: new AbortController().signal,
    });
    expect(result.outcome.state).toBe("blocked");
  });

  it("rejects forbidden SPL fields, wildcard projections, and invalid maxRows before dispatch", async () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    await expect(
      runBoundedProtocolSearch(client, {
        lens: "tcp_tls",
        profile: PROFILE,
        spl: "search index=netflow | fields *",
        earliest: NOW - 900,
        latest: NOW - 60,
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow(/wildcard/i);
    await expect(
      runBoundedProtocolSearch(client, {
        lens: "tcp_tls",
        profile: PROFILE,
        spl: "search index=netflow | fields _time",
        earliest: NOW - 900,
        latest: NOW - 60,
        maxRows: Number.NaN,
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow(/maxRows/i);
    expect(search).not.toHaveBeenCalled();
  });
});
