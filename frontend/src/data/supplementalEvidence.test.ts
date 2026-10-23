import { describe, expect, it, vi } from "vitest";
import type { Row } from "../rows";
import type { EvidenceSelection } from "./evidence";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
} from "./evidenceConfig";
import {
  loadSupplementalEvidence,
  parseSupplementalEnvelope,
} from "./supplementalEvidence";
import type { SearchClient } from "./searchClient";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "endpoint-test",
  trafficContract: 1,
  window: { start: 1000, end: 1100 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
};
const configuration: EvidenceConfiguration = {
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["summary"],
  mappings: [],
  identities: [],
  identityAvailable: true,
  dns: [],
  maxAgeSeconds: 3600,
  supplemental: [
    {
      source: "proxy_envoy",
      state: "active",
      indexes: ["proxy_evidence"],
      authorities: ["proxy1"],
      schemaQualified: true,
      staleAfterSeconds: 1200,
      mappings: [],
    },
  ],
};
const record: Row = {
  kind: "supplemental_record",
  index: "proxy_evidence",
  value: "ok",
};
function response(
  rows: Row[] = [record],
  overrides: Record<string, unknown> = {},
) {
  return {
    rows: [
      ...rows,
      {
        kind: "supplemental_completion",
        schema_version: "1",
        input_count: String(rows.length),
        returned_count: String(rows.length),
        input_capped: "0",
        oversized: "0",
        ...overrides,
      },
    ],
    errors: [],
    warnings: [],
  };
}
const configClient = (
  read: () => EvidenceConfiguration,
): EvidenceConfigClient => ({
  read: async () => read(),
});
const searchBuilder = () => "search index=proxy_evidence | head 10001";
const normalizer = (rows: readonly Row[]) => ({
  records: rows.map((r) => String(r.value)),
  rejected: 0,
});

describe("supplemental evidence completion and isolation", () => {
  it("rejects duplicate, missing and inconsistent completion envelopes", () => {
    expect(() => parseSupplementalEnvelope([record])).toThrow(/completion/);
    expect(() =>
      parseSupplementalEnvelope([...response().rows, response().rows[1]]),
    ).toThrow(/completion/);
    expect(() =>
      parseSupplementalEnvelope(response([record], { input_count: "2" }).rows),
    ).toThrow(/counts/);
    expect(() =>
      parseSupplementalEnvelope(response([record], { input_capped: "1" }).rows),
    ).toThrow(/counts/);
    expect(() =>
      parseSupplementalEnvelope(
        response([record], {
          source_scan_count: "0",
          source_scan_capped: "0",
        }).rows,
      ),
    ).toThrow(/counts/);
  });
  it("does not admit an eligible subset from a capped source-wide scan", async () => {
    const client: SearchClient = {
      search: vi.fn(async () =>
        response([], {
          source_scan_count: "10001",
          source_scan_capped: "1",
        }),
      ),
    };
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => configuration),
    );
    expect(result.state).toBe("unavailable");
    expect(result.records).toEqual([]);
    expect(result.sourceScanCount).toBe(10001);
    expect(result.sourceScanCapped).toBe(true);
  });
  it("does not claim absence when scanned history has an unorderable revision", async () => {
    const client: SearchClient = {
      search: vi.fn(async () =>
        response([], {
          source_scan_count: "1",
          source_scan_capped: "0",
          source_scan_invalid_count: "1",
        }),
      ),
    };
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => configuration),
    );
    expect(result.state).toBe("unavailable");
    expect(result.records).toEqual([]);
    expect(result.sourceScanInvalidCount).toBe(1);
    expect(result.errorCode).toBe("completion");
  });
  it("dispatches nothing for an unselected source", async () => {
    const client: SearchClient = { search: vi.fn() };
    const config = structuredClone(configuration);
    config.supplemental![0].state = "not_selected";
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => config),
    );
    expect(result.state).toBe("not_selected");
    expect(client.search).not.toHaveBeenCalled();
  });
  it("requires caller-visible completion and an exact configured index", async () => {
    const client: SearchClient = {
      search: vi.fn(async () => response([{ ...record, index: "other" }])),
    };
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => configuration),
    );
    expect(result.state).toBe("unavailable");
    expect(result.records).toEqual([]);
    expect(result.errorCode).toBe("completion");
  });
  it("uses a bounded optional job and invalidates a capture after config changes", async () => {
    let reads = 0;
    const client: SearchClient = { search: vi.fn(async () => response()) };
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => ({
        ...configuration,
        fingerprint: ++reads === 1 ? configuration.fingerprint : "b".repeat(64),
      })),
    );
    expect(result.state).toBe("unavailable");
    expect(result.configurationChanged).toBe(true);
    expect(result.schemaQualified).toBe(false);
    expect(result.records).toEqual([]);
    expect(result.errorCode).toBe("configuration");
    expect(client.search).toHaveBeenCalledWith(
      expect.objectContaining({
        maxRows: 65,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      }),
    );
  });
  it("treats search warnings as incomplete evidence", async () => {
    const client: SearchClient = {
      search: async () => ({ ...response(), warnings: ["peer truncated"] }),
    };
    const result = await loadSupplementalEvidence(
      client,
      selection,
      new AbortController().signal,
      "proxy_envoy",
      searchBuilder,
      normalizer,
      configClient(() => configuration),
    );
    expect(result.state).toBe("unavailable");
    expect(result.errorCode).toBe("completion");
  });
});
