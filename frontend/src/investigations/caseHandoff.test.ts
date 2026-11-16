import { expect, it } from "vitest";
import { caseHandoff } from "./caseHandoff";
import type { CaseRecord } from "./caseClient";

it("includes authorized context and redaction gaps without source rows", () => {
  const record: CaseRecord = {
    schema_version: 1,
    id: "case-1",
    revision: 2,
    title: "Test",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [
      {
        id: "e",
        revision: 1,
        author: "alice",
        created_at: "2026-01-01T01:00:00Z",
        type: "hypothesis",
        text: "Cause under investigation",
      },
    ],
    captures: [
      {
        id: "c",
        revision: 2,
        author: "alice",
        created_at: "2026-01-01T01:00:00Z",
        captured_at: "2026-01-01T01:00:00Z",
        label: "Capture",
        data: {
          source_contract: "admqualified-comparison-v1",
          scope: { service: "checkout" },
          windows: [
            {
              start: 100,
              end: 200,
              rows: [
                {
                  row_type: "meta",
                  warnings: ["Partial <coverage>"],
                  read_coverage: 75,
                  raw_pending_seconds: 60,
                  truncated: true,
                },
                { value: "SECRET_ROW" },
              ],
            },
          ],
        },
      },
    ],
    attachments: [],
    redactions: { captures: 1, attachments: 0 },
  };
  (record.captures[0].data.windows as unknown[]).push({
    start: 200,
    end: 300,
    rows: [{ row_type: "meta", warnings: "Delayed raw data", capped: false }],
  });
  const text = caseHandoff(record);
  expect(text).toContain("hypothesis · alice");
  expect(text).toContain("Source contract: admqualified-comparison-v1");
  expect(text).toContain(
    "Observations were indexed by each window end; later arrivals are excluded. Exact indexed times are not retained for all aggregates.",
  );
  expect(text).toContain("1970-01-01T00:01:40.000Z");
  expect(text).toContain("1 captures and 0 attachments withheld");
  expect(text).toContain("Coverage warning: Partial \\<coverage\\>");
  expect(text).toContain("Reported read_coverage: 75");
  expect(text).toContain("Reported raw_pending_seconds: 60");
  expect(text).toContain("Reported truncated: true");
  expect(text).toContain("Coverage warning: Delayed raw data");
  expect(text).toContain("Reported capped: false");
  expect(text).toContain("Unreported coverage details are unknown");
  expect(text).not.toContain("SECRET_ROW");
});
