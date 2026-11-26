import { describe, expect, it, vi } from "vitest";
import {
  buildPlannerConversationSearch,
  buildPlannerCoverageSearch,
  expectedCoverage,
  loadPlannerDataset,
  parsePlannerConversations,
  parsePlannerCoverage,
  presetSelection,
  validatePlannerSelection,
} from "./data";
import { PLANNER_LIMITS } from "../ops/moveGroup";
import type { EvidenceConfigClient } from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";

const selection = { scope: "prod", start: 86400, end: 86400 * 2 };
const config = {
  fingerprint: "a".repeat(64),
  trafficContract: 2 as const,
  summaryIndexes: ["adm_summary_v2"],
  mappings: [
    {
      observer_kind: "exporter",
      observer: "leaf-101",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
  identities: [],
  identityAvailable: true,
  dns: [],
  maxAgeSeconds: 3600,
};
const row = (extra: Record<string, unknown> = {}) => ({
  row_type: "conversation",
  client_ip: "10.0.0.1",
  server_ip: "10.0.1.1",
  adm_port: "8080",
  adm_transport: "tcp",
  records: "12",
  bytes: "3400",
  first: "86500",
  last: "86900.5",
  sampled: "0",
  directed: "1",
  observers: "stream:leaf-101|stream:leaf-102",
  observers_capped: "0",
  sources: "stream",
  ...extra,
});
const completion = (input: number, output = input, extra = {}) => ({
  row_type: "completion",
  schema_version: "1",
  input_count: String(input),
  output_count: String(output),
  output_capped: input > PLANNER_LIMITS.conversations ? "1" : "0",
  unprotected_count: "0",
  ...extra,
});

describe("move-group planner searches", () => {
  it("bounds the window, scope and summary selector", () => {
    expect(validatePlannerSelection(selection)).toEqual(selection);
    expect(() =>
      validatePlannerSelection({ ...selection, end: selection.start + 60 }),
    ).toThrow("between 5 minutes and 30 days");
    expect(() =>
      validatePlannerSelection({ ...selection, end: 86400 * 40 }),
    ).toThrow("30 days");
    expect(() =>
      validatePlannerSelection({ ...selection, scope: "unmapped:x" }),
    ).toThrow("verified routing scope");
    expect(() =>
      validatePlannerSelection({ ...selection, scope: 'prod" OR 1=1' }),
    ).toThrow();
    expect(presetSelection("prod", 86400, 86400 * 3 + 299)).toEqual({
      scope: "prod",
      start: 86400 * 2,
      end: 86400 * 3,
    });
    expect(() =>
      buildPlannerConversationSearch(selection, "index=x | delete", 2),
    ).toThrow("Invalid planner search selection.");
  });

  it("aggregates per observer before taking the largest observer total", () => {
    const spl = buildPlannerConversationSearch(
      selection,
      "index=adm_summary_v2",
      2,
    );
    expect(spl).toContain(
      'source="adm:conversation" adm_record="conversation"',
    );
    expect(spl).toContain("_time>=86400 AND _time<173100");
    expect(spl).toContain("(tonumber(contract_version)=2)");
    expect(spl).toContain("dedup rollup_id keepempty=true");
    expect(spl).toContain('where scope="prod"');
    expect(spl).toContain("adm_last>=86400 AND adm_first<172800");
    expect(spl).toMatch(
      /by client_ip server_ip adm_port adm_transport adm_observer adm_source \| stats max\(adm_rec\) as records max\(adm_bytes\) as bytes/,
    );
    expect(spl).toContain(`head ${PLANNER_LIMITS.conversations + 1}`);
    expect(spl).toContain('row_type="completion"');
    expect(buildPlannerConversationSearch(selection, "index=a", 1)).toContain(
      "(isnull(contract_version) OR tonumber(contract_version)=1)",
    );
    const coverage = buildPlannerCoverageSearch(selection, "index=a", 2);
    expect(coverage).toContain("stats count by _time");
    expect(coverage).toContain("floor(_time/86400)*86400");
  });

  it("parses rows strictly and reports the row cap", () => {
    const parsed = parsePlannerConversations(
      [
        row(),
        row({ adm_port: "", adm_transport: "icmp", bytes: "" }),
        completion(2),
      ],
      selection,
    );
    expect(parsed.capped).toBe(false);
    expect(parsed.conversations[0]).toEqual({
      client: "10.0.0.1",
      server: "10.0.1.1",
      port: 8080,
      transport: "tcp",
      directed: true,
      records: 12,
      bytes: 3400,
      first: 86500,
      last: 86900.5,
      observers: ["stream:leaf-101", "stream:leaf-102"],
      observersCapped: false,
      sources: ["stream"],
      sampled: false,
    });
    expect(parsed.conversations[1]).not.toHaveProperty("port");
    expect(parsed.conversations[1]).not.toHaveProperty("bytes");
    const capRows = Array.from(
      { length: PLANNER_LIMITS.conversations + 1 },
      () => row(),
    );
    const capped = parsePlannerConversations(
      [...capRows, completion(9000, PLANNER_LIMITS.conversations + 1)],
      selection,
    );
    expect(capped.capped).toBe(true);
    expect(capped.inputCount).toBe(9000);
    expect(capped.conversations).toHaveLength(PLANNER_LIMITS.conversations);
  });

  it.each([
    ["a missing envelope", [row()]],
    ["a miscounted envelope", [row(), completion(2)]],
    ["an unexpected row type", [row(), { row_type: "other" }, completion(1)]],
    ["a malformed address", [row({ client_ip: "10.0.0.999" }), completion(1)]],
    ["a TCP row without a port", [row({ adm_port: "" }), completion(1)]],
    ["an out-of-window row", [row({ last: "100" }), completion(1)]],
    ["an invalid flag", [row({ directed: "maybe" }), completion(1)]],
    [
      "an oversized observer list",
      [row({ observers: "a|b|c|d|e|f|g|h|i" }), completion(1)],
    ],
  ])("fails closed on %s", (_name, rows) => {
    expect(() => parsePlannerConversations(rows, selection)).toThrow();
  });

  it("derives expected buckets per UTC day and validates coverage rows", () => {
    const expected = expectedCoverage({
      scope: "prod",
      start: 86400 - 600,
      end: 86400 + 900,
    });
    expect(expected).toEqual([
      { day: 0, buckets: 0, expected: 2 },
      { day: 86400, buckets: 0, expected: 3 },
    ]);
    const coverage = parsePlannerCoverage(
      [
        { row_type: "coverage_day", adm_day: "86400", buckets: "200" },
        {
          row_type: "completion",
          schema_version: "1",
          output_count: "1",
          covered_buckets: "200",
        },
      ],
      selection,
    );
    expect(coverage).toMatchObject({
      coveredBuckets: 200,
      expectedBuckets: 288,
    });
    expect(() =>
      parsePlannerCoverage(
        [
          { row_type: "coverage_day", adm_day: "86400", buckets: "289" },
          {
            row_type: "completion",
            schema_version: "1",
            output_count: "1",
            covered_buckets: "289",
          },
        ],
        selection,
      ),
    ).toThrow("coverage row");
  });

  it("requires a verified scope and a stable configuration", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [row(), completion(1)],
        warnings: [],
        errors: [],
      })
      .mockResolvedValueOnce({
        rows: [
          { row_type: "coverage_day", adm_day: "86400", buckets: "100" },
          {
            row_type: "completion",
            schema_version: "1",
            output_count: "1",
            covered_buckets: "100",
          },
        ],
        warnings: [],
        errors: [],
      });
    const client: SearchClient = { search };
    const read = vi.fn().mockResolvedValue(config);
    const configClient: EvidenceConfigClient = { read };
    const dataset = await loadPlannerDataset(
      client,
      configClient,
      selection,
      new AbortController().signal,
    );
    expect(dataset.selection).toMatchObject({
      scope: "prod",
      configurationFingerprint: "a".repeat(64),
      trafficContract: 2,
    });
    expect(dataset.coverage.coveredBuckets).toBe(100);
    expect(dataset.warnings.join(" ")).toContain(
      "collection gap or a quiet period",
    );
    expect(search.mock.calls[0][0]).toMatchObject({
      earliest: "86400",
      latest: "173100",
      maxRows: PLANNER_LIMITS.conversations + 2,
    });
    await expect(
      loadPlannerDataset(
        client,
        { read: vi.fn().mockResolvedValue({ ...config, mappings: [] }) },
        selection,
        new AbortController().signal,
      ),
    ).rejects.toThrow("verified routing scope");
    const changing = vi
      .fn()
      .mockResolvedValueOnce(config)
      .mockResolvedValueOnce({ ...config, fingerprint: "b".repeat(64) });
    const again: SearchClient = {
      search: vi
        .fn()
        .mockResolvedValueOnce({
          rows: [row(), completion(1)],
          warnings: [],
          errors: [],
        })
        .mockResolvedValueOnce({
          rows: [
            {
              row_type: "completion",
              schema_version: "1",
              output_count: "0",
              covered_buckets: "0",
            },
          ],
          warnings: [],
          errors: [],
        }),
    };
    await expect(
      loadPlannerDataset(
        again,
        { read: changing },
        selection,
        new AbortController().signal,
      ),
    ).rejects.toThrow("configuration changed");
  });

  it("rejects incomplete searches instead of planning on partial data", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [row(), completion(1)],
        warnings: ["Search auto-finalized"],
        errors: [],
      }),
    };
    await expect(
      loadPlannerDataset(
        client,
        { read: vi.fn().mockResolvedValue(config) },
        selection,
        new AbortController().signal,
      ),
    ).rejects.toThrow("incomplete");
  });
});
