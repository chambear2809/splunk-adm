import { afterEach, describe, expect, it, vi } from "vitest";
import type { Row } from "../rows";
import type { EvidenceSelection } from "./evidence";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
  SupplementalSourceConfiguration,
} from "./evidenceConfig";
import type { SearchClient } from "./searchClient";
import {
  buildAssetHistorySearch,
  loadAssetHistoryEvidence,
  normalizeAssetHistoryEvidence,
} from "./inventoryEvidence";

const start = 1_792_483_200;
const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "asset-history-test",
  trafficContract: 1,
  window: { start, end: start + 300 },
  scope: "prod-east",
  addresses: ["10.20.0.10"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
};

const source: SupplementalSourceConfiguration = {
  source: "asset_history",
  state: "active",
  indexes: ["asset_history_idx"],
  authorities: ["cmdb-prod"],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "asset_authority",
      observer: "cmdb-prod",
      scope: "prod-east",
      cluster: "",
      mapping_status: "verified",
    },
  ],
};

function row(overrides: Partial<Row> = {}): Row {
  const validFrom = start - 60;
  return {
    kind: "supplemental_record",
    index: "asset_history_idx",
    _time: String(validFrom),
    indexed_at: String(start + 10),
    schema_version: "1",
    asset_authority: "cmdb-prod",
    scope: "prod-east",
    ip: "10.20.0.10",
    record_id: "assignment-1",
    revision: "1",
    asset_id: "asset-web-1",
    asset_name: "web-1",
    service_id: "service-checkout",
    service_name: "Checkout",
    environment: "production",
    owner_id: "team-commerce",
    owner_name: "Commerce Platform",
    network_id: "vpc-prod-east",
    validity_basis: "source_interval",
    valid_from: String(validFrom),
    valid_to: String(start + 600),
    snapshot_id: "export-1",
    snapshot_at: String(start + 600),
    snapshot_complete: "1",
    revision_conflict: "0",
    record_fingerprint: "a".repeat(64),
    ...overrides,
  };
}

const sharedConfiguration: EvidenceConfiguration = {
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["summary"],
  mappings: source.mappings,
  identities: [],
  identityAvailable: true,
  dns: [],
  maxAgeSeconds: 3600,
  supplemental: [source],
};

afterEach(() => {
  vi.useRealTimers();
});

describe("asset-history evidence contract", () => {
  it("builds a literal, scoped, bounded query over historical intervals", () => {
    const search = buildAssetHistorySearch(source, selection);
    expect(search).toContain("index=asset_history_idx");
    expect(search).toContain('sourcetype="adm:asset_history"');
    expect(search).toContain('asset_authority="cmdb-prod"');
    expect(search).toContain('scope="prod-east"');
    expect(search).toContain('ip="10.20.0.10"');
    expect(search).toContain(`tonumber(valid_from)<${selection.window.end}`);
    expect(search).toContain(`tonumber(valid_to)>${selection.window.start}`);
    expect(search).toContain("source_scan_count");
    expect(search).toContain(
      "sum(source_row_invalid) AS source_scan_invalid_count",
    );
    expect(search).toContain("source_scan_capped");
    expect(search).toContain("max(revision_number) AS latest_revision");
    expect(search).toContain("values(revision_semantic) AS revision_semantics");
    expect(search).toContain("mvcount(revision_semantics)>1");
    expect(search).toContain("revision_conflict");
    expect(search).toContain("isnull(validity_basis)");
    expect(search).toContain("sum(__eligible) AS input_count");
    expect(search).not.toContain("where revision_number=latest_revision");
    expect(search.indexOf("sum(__eligible) AS input_count")).toBeLessThan(
      search.indexOf("appendpipe"),
    );
    expect(search.indexOf("appendpipe")).toBeLessThan(
      search.indexOf('| where kind="supplemental_completion"'),
    );
    expect(
      search.indexOf("max(revision_number) AS latest_revision"),
    ).toBeLessThan(search.indexOf("eval __eligible=if("));
    expect(search).toContain("head 10001");
    expect(search).toContain("kind_rank<=64");
    expect(search).toContain('kind="supplemental_completion"');
    expect(search).toContain(
      "| fields kind schema_version input_count returned_count input_capped source_scan_count source_scan_invalid_count source_scan_capped",
    );
    expect(search).not.toContain("index=*");
  });

  it("fails closed for unqualified sources and unverified or mismatched authority", () => {
    expect(() =>
      buildAssetHistorySearch({ ...source, schemaQualified: false }, selection),
    ).toThrow(/active and schema-qualified/);
    expect(() =>
      buildAssetHistorySearch(
        {
          ...source,
          mappings: [{ ...source.mappings[0], mapping_status: "pending" }],
        },
        selection,
      ),
    ).toThrow(/authority mapping/);
    expect(() =>
      buildAssetHistorySearch(
        { ...source, indexes: ["asset_history_idx OR index=*"] },
        selection,
      ),
    ).toThrow(/index configuration/);
  });

  it("normalizes half-open history and does not confuse address reuse with overlap", () => {
    const previous = row({
      record_id: "assignment-old",
      asset_id: "asset-old",
      valid_from: String(start - 600),
      _time: String(start - 600),
      valid_to: String(start),
      snapshot_at: String(start + 100),
    });
    const current = row({
      record_id: "assignment-new",
      asset_id: "asset-new",
      valid_from: String(start),
      _time: String(start),
      valid_to: String(start + 600),
      snapshot_at: String(start + 600),
    });
    const result = normalizeAssetHistoryEvidence([current], selection, source);
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      assetId: "asset-new",
      environment: "production",
      ownerId: "team-commerce",
      ownerName: "Commerce Platform",
      networkId: "vpc-prod-east",
      validityBasis: "source_interval",
      windowCoverage: "full",
      conflict: false,
      attribution: "historical_interval",
    });
    expect(result.rejected).toBe(0);
    // The ended predecessor is outside the selected half-open interval.
    expect(
      normalizeAssetHistoryEvidence([previous], selection, source),
    ).toMatchObject({ records: [], rejected: 0 });
  });

  it("marks overlapping different owners ambiguous and keeps scope isolation", () => {
    const first = row({
      valid_from: String(start - 100),
      _time: String(start - 100),
      valid_to: String(start + 200),
    });
    const second = row({
      record_id: "assignment-2",
      asset_id: "asset-web-2",
      valid_from: String(start + 100),
      _time: String(start + 100),
      valid_to: String(start + 500),
    });
    const otherScope = row({
      record_id: "assignment-other-scope",
      asset_id: "asset-other-scope",
      scope: "prod-west",
      valid_from: String(start + 100),
      _time: String(start + 100),
    });
    const result = normalizeAssetHistoryEvidence(
      [first, second, otherScope],
      selection,
      source,
    );
    expect(result.rejected).toBe(0);
    expect(result.records).toHaveLength(2);
    expect(result.records.every((record) => record.conflict)).toBe(true);
    expect(
      result.records.every((record) => record.attribution === "ambiguous"),
    ).toBe(true);
  });

  it("marks overlapping contradictions for the same asset identity ambiguous", () => {
    const first = row({
      valid_from: String(start - 100),
      _time: String(start - 100),
      valid_to: String(start + 500),
      owner_id: "team-commerce",
      service_id: "service-checkout",
    });
    const second = row({
      record_id: "assignment-context-conflict",
      valid_from: String(start - 50),
      _time: String(start - 50),
      valid_to: String(start + 400),
      owner_id: "team-other",
      service_id: "service-other",
    });
    const result = normalizeAssetHistoryEvidence(
      [first, second],
      selection,
      source,
    );
    expect(result.records).toHaveLength(2);
    expect(
      result.records.every((record) => record.assetId === "asset-web-1"),
    ).toBe(true);
    expect(result.records.every((record) => record.conflict)).toBe(true);
    expect(
      result.records.every((record) => record.attribution === "ambiguous"),
    ).toBe(true);
  });

  it("treats current-only snapshots as point context and reports feed freshness", () => {
    const snapshotAt = start + 100;
    vi.useFakeTimers();
    vi.setSystemTime(new Date((snapshotAt + 30) * 1000));
    const snapshot = row({
      validity_basis: "snapshot_current",
      valid_from: String(snapshotAt),
      _time: String(snapshotAt),
      valid_to: undefined,
      retired_at: undefined,
      snapshot_at: String(snapshotAt),
    });
    const result = normalizeAssetHistoryEvidence([snapshot], selection, source);
    expect(result.records[0]).toMatchObject({
      validityBasis: "snapshot_current",
      attribution: "current_snapshot_context",
      windowCoverage: "point",
      freshness: "fresh",
    });
    vi.setSystemTime(new Date((snapshotAt + 7200) * 1000));
    expect(
      normalizeAssetHistoryEvidence([snapshot], selection, source).records[0]
        .freshness,
    ).toBe("stale");
  });

  it("keeps the highest source revision and exposes equal-revision disagreement", () => {
    const old = row({ revision: "1", asset_id: "asset-old" });
    const newer = row({ revision: "2", asset_id: "asset-new" });
    expect(
      normalizeAssetHistoryEvidence([old, newer], selection, source).records,
    ).toMatchObject([{ revision: 2, assetId: "asset-new" }]);
    const disagreement = row({ revision: "1", asset_id: "asset-other" });
    const result = normalizeAssetHistoryEvidence(
      [old, disagreement],
      selection,
      source,
    );
    expect(result.records).toHaveLength(2);
    expect(result.records.every((record) => record.conflict)).toBe(true);
    expect(
      result.records.every((record) => record.attribution === "ambiguous"),
    ).toBe(true);
  });

  it("resolves a later closure before testing a historical window", () => {
    const revisionOne = row({
      valid_from: String(start - 600),
      _time: String(start - 600),
      valid_to: String(start + 600),
      snapshot_at: String(start + 900),
    });
    const revisionTwo = row({
      revision: "2",
      valid_from: String(start - 600),
      _time: String(start - 600),
      valid_to: String(start - 100),
      retired_at: String(start - 100),
      snapshot_at: String(start + 900),
    });
    expect(
      normalizeAssetHistoryEvidence(
        [revisionOne, revisionTwo],
        selection,
        source,
      ),
    ).toMatchObject({ records: [], rejected: 0 });
  });

  it.each([
    ["IP", { ip: "10.20.0.11" }],
    ["scope", { scope: "prod-west" }],
  ])(
    "resolves a corrected %s before selected identity filtering",
    (_label, change) => {
      const revisionOne = row({
        valid_from: String(start - 600),
        _time: String(start - 600),
        valid_to: String(start + 600),
        snapshot_at: String(start + 900),
      });
      const revisionTwo = row({
        ...change,
        revision: "2",
        valid_from: String(start - 600),
        _time: String(start - 600),
        valid_to: String(start + 600),
        snapshot_at: String(start + 900),
      });
      expect(
        normalizeAssetHistoryEvidence(
          [revisionOne, revisionTwo],
          selection,
          source,
        ),
      ).toMatchObject({ records: [], rejected: 0 });
    },
  );

  it("does not admit an older revision when the latest starts after the window", () => {
    const revisionOne = row({
      valid_from: String(start - 600),
      _time: String(start - 600),
      valid_to: String(start + 600),
      snapshot_at: String(start + 900),
    });
    const correctedStart = selection.window.end + 10;
    const revisionTwo = row({
      revision: "2",
      valid_from: String(correctedStart),
      _time: String(correctedStart),
      valid_to: String(start + 1000),
      snapshot_at: String(start + 1100),
    });
    expect(
      normalizeAssetHistoryEvidence(
        [revisionOne, revisionTwo],
        selection,
        source,
      ),
    ).toMatchObject({ records: [], rejected: 0 });
  });

  it("preserves same-revision disagreements found outside the selected scope", () => {
    const candidate = row({ revision_conflict: "1" });
    const result = normalizeAssetHistoryEvidence(
      [candidate],
      selection,
      source,
    );
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      conflict: true,
      attribution: "ambiguous",
      conflictReason:
        "The same source record revision contains conflicting asset history.",
    });
  });

  it("rejects event-time, source, scope and identity mismatches", () => {
    for (const changes of [
      { _time: String(start - 59) },
      { index: "other_index" },
      { asset_authority: "unmapped" },
      { owner_name: "Commerce Platform", owner_id: undefined },
    ]) {
      expect(
        normalizeAssetHistoryEvidence([row(changes)], selection, source),
      ).toMatchObject({ records: [], rejected: 1 });
    }
    expect(
      normalizeAssetHistoryEvidence(
        [row({ ip: "10.20.0.11" }), row({ scope: "prod-west" })],
        selection,
        source,
      ),
    ).toMatchObject({ records: [], rejected: 0 });
  });

  it("dispatches from epoch zero and requires the exact completion envelope", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date((start + 800) * 1000));
    const client: SearchClient = {
      search: vi.fn(async () => ({
        rows: [
          row(),
          {
            kind: "supplemental_completion",
            index: "asset_history_idx",
            schema_version: "1",
            input_count: "1",
            returned_count: "1",
            input_capped: "0",
            source_scan_count: "1",
            source_scan_invalid_count: "0",
            source_scan_capped: "0",
            oversized: "0",
          },
        ],
        warnings: [],
        errors: [],
      })),
    };
    const configurationClient: EvidenceConfigClient = {
      read: vi.fn(async () => sharedConfiguration),
    };
    const result = await loadAssetHistoryEvidence(
      client,
      selection,
      new AbortController().signal,
      configurationClient,
    );
    expect(result.state).toBe("complete");
    expect(result.inspectedWindow).toEqual({
      start: 0,
      end: start + 800,
    });
    expect(client.search).toHaveBeenCalledWith(
      expect.objectContaining({
        earliest: "0",
        latest: String(start + 800),
        maxRows: 65,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      }),
    );
  });
});
