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
    for (const badIndex of [
      "index=x | delete",
      "index=adm_summary_v2) OR (index=_internal",
      "",
      "adm_summary_v2",
      "index=ADM_UPPER",
    ]) {
      expect(() =>
        buildPlannerConversationSearch(selection, badIndex, 2),
      ).toThrow("Invalid planner search selection.");
      expect(() => buildPlannerCoverageSearch(selection, badIndex, 2)).toThrow(
        "Invalid planner search selection.",
      );
    }
    expect(() =>
      buildPlannerCoverageSearch(
        { ...selection, scope: " prod " },
        "index=adm_summary_v2",
        2,
      ),
    ).toThrow("Invalid planner search selection.");
    expect(
      buildPlannerCoverageSearch(
        selection,
        "index=adm_summary OR index=adm_summary_v2",
        2,
      ),
    ).toContain("(index=adm_summary OR index=adm_summary_v2)");
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
    expect(coverage).toContain("_time>=86400 AND _time<172800");
    expect(coverage).toContain("stats count by _time");
    expect(coverage).toContain("floor(_time/86400)*86400");
  });

  it("bounds coverage search strictly before selection.end to match expectedCoverage", () => {
    const cases = [
      {
        name: "UTC midnight aligned end",
        window: { scope: "prod", start: 86400, end: 172800 },
        expectedStart: 86400,
        expectedEnd: 172800,
      },
      {
        name: "mid-day 5-minute aligned end",
        window: { scope: "prod", start: 86400 - 600, end: 86400 + 900 },
        expectedStart: 85800,
        expectedEnd: 87300,
      },
      {
        name: "mid-bucket non-aligned end",
        window: { scope: "prod", start: 86400, end: 86400 + 901 },
        expectedStart: 86400,
        expectedEnd: 87301,
      },
      {
        name: "non-aligned start and end past UTC midnight",
        window: { scope: "prod", start: 86550, end: 172801 },
        expectedStart: 86400,
        expectedEnd: 172801,
      },
      {
        name: "preset selection",
        window: presetSelection("prod", 86400, 86400 * 3 + 299),
        expectedStart: 86400 * 2,
        expectedEnd: 86400 * 3,
      },
    ];

    for (const { window, expectedStart, expectedEnd } of cases) {
      const spl = buildPlannerCoverageSearch(window, "index=adm_summary_v2", 2);
      expect(spl).toContain(`_time>=${expectedStart} AND _time<${expectedEnd}`);
      const match = /_time>=(\d+) AND _time<(\d+)/.exec(spl);
      expect(match).not.toBeNull();
      const lower = Number(match![1]);
      const upper = Number(match![2]);

      // Simulate every 5-minute summary bucket from one bucket before start
      // through one bucket after end (including a bucket at t === window.end).
      const simulatedByDay = new Map<number, number>();
      for (let t = lower - 300; t <= upper + 300; t += 300) {
        if (t >= lower && t < upper) {
          const day = Math.floor(t / 86400) * 86400;
          simulatedByDay.set(day, (simulatedByDay.get(day) ?? 0) + 1);
        }
      }
      if (window.end % 300 === 0) {
        // An aligned end bucket at t === window.end must never be counted.
        expect(window.end < upper).toBe(false);
      }

      const expected = expectedCoverage(window);
      expect([...simulatedByDay]).toEqual(
        expected.map((d) => [d.day, d.expected]),
      );

      // Full-coverage rows produced by this search must parse cleanly.
      const totalBuckets = expected.reduce((n, d) => n + d.expected, 0);
      const rows = [
        ...[...simulatedByDay].map(([day, buckets]) => ({
          row_type: "coverage_day",
          adm_day: String(day),
          buckets: String(buckets),
        })),
        {
          row_type: "completion",
          schema_version: "1",
          output_count: String(simulatedByDay.size),
          covered_buckets: String(totalBuckets),
        },
      ];
      const parsed = parsePlannerCoverage(rows, window);
      expect(parsed.coveredBuckets).toBe(totalBuckets);
      expect(parsed.expectedBuckets).toBe(totalBuckets);
    }
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
    const midDayWindow = {
      scope: "prod",
      start: 86400 - 600,
      end: 86400 + 900,
    };
    const expected = expectedCoverage(midDayWindow);
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
    // Reject an out-of-window bucket at selection.end on a UTC midnight boundary
    // (day 172800 is outside [86400, 172800)).
    expect(() =>
      parsePlannerCoverage(
        [
          { row_type: "coverage_day", adm_day: "86400", buckets: "288" },
          { row_type: "coverage_day", adm_day: "172800", buckets: "1" },
          {
            row_type: "completion",
            schema_version: "1",
            output_count: "2",
            covered_buckets: "289",
          },
        ],
        selection,
      ),
    ).toThrow("coverage row");
    // Reject an out-of-window bucket at selection.end on a full-coverage final day
    // (4 buckets > 3 expected on day 86400).
    expect(() =>
      parsePlannerCoverage(
        [
          { row_type: "coverage_day", adm_day: "0", buckets: "2" },
          { row_type: "coverage_day", adm_day: "86400", buckets: "4" },
          {
            row_type: "completion",
            schema_version: "1",
            output_count: "2",
            covered_buckets: "6",
          },
        ],
        midDayWindow,
      ),
    ).toThrow("coverage row");
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
    expect(search.mock.calls[1][0]).toMatchObject({
      earliest: "86400",
      latest: "172800",
      maxRows: 40,
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
