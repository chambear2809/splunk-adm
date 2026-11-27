import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  changeRequestSearch,
  parseChangeRows,
  parseServiceNowUtc,
} from "./serviceNow";

const fixture = readFileSync(
  fileURLToPath(
    new URL(
      "../../../fixtures/raw-snow/change_request.ndjson",
      import.meta.url,
    ),
  ),
  "utf8",
)
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line) as Record<string, unknown>);

const row = (overrides: Record<string, unknown> = {}) => ({
  row_type: "change_request",
  number: "CHG0030001",
  sys_id: "a9e30c7dc61122760116894de7bcc7bd",
  state: "3",
  dv_state: "Closed",
  start_date: "2026-11-20 22:00:00",
  end_date: "2026-11-21 00:00:00",
  work_start: "2026-11-20 22:05:00",
  work_end: "2026-11-20 23:10:00",
  sys_updated_on: "2026-11-21 08:00:00",
  records_capped: "0",
  ...overrides,
});

describe("ServiceNow change windows", () => {
  it("parses only the UTC value form", () => {
    expect(parseServiceNowUtc("2026-11-20 22:05:00")).toBe(
      Date.UTC(2026, 10, 20, 22, 5) / 1000,
    );
    expect(parseServiceNowUtc("2026-02-30 00:00:00")).toBeUndefined();
    expect(parseServiceNowUtc("11/20/2026 10:05:00 PM")).toBeUndefined();
    expect(parseServiceNowUtc("2026-11-20T22:05:00Z")).toBeUndefined();
    expect(parseServiceNowUtc("")).toBeUndefined();
  });
  it("prefers actual work times, labelled, then planned times", () => {
    expect(parseChangeRows("CHG0030001", [row()])).toMatchObject({
      basis: "servicenow_actual",
      start: Date.UTC(2026, 10, 20, 22, 5) / 1000,
      state: "Closed",
    });
    expect(
      parseChangeRows("CHG0030001", [row({ work_start: "", work_end: "" })])
        .basis,
    ).toBe("servicenow_planned");
  });
  it("fails closed on ambiguity, caps, open work and missing records", () => {
    expect(() => parseChangeRows("CHG0030001", [])).toThrow(/No usable/);
    expect(() =>
      parseChangeRows("CHG0030001", [row(), row({ sys_id: "b" })]),
    ).toThrow(/2 ServiceNow records/);
    expect(() =>
      parseChangeRows("CHG0030001", [row({ records_capped: "1" })]),
    ).toThrow(/500/);
    expect(() =>
      parseChangeRows("CHG0030001", [row({ work_end: "" })]),
    ).toThrow(/work started/);
    expect(() =>
      parseChangeRows("CHG0030001", [row({ number: "CHG0030002" })]),
    ).toThrow(/incomplete/);
    expect(() =>
      parseChangeRows("CHG0030001", [row({ work_start: "", start_date: "" })]),
    ).toThrow();
  });
  it("fails closed on invalid sys_updated_on rows and stale records with invalid_updates", () => {
    expect(() =>
      parseChangeRows("CHG0030001", [row({ invalid_updates: "1" })]),
    ).toThrow(/unsupported sys_updated_on/);
    expect(() =>
      parseChangeRows("CHG0030001", [row({ invalid_updates: 2 })]),
    ).toThrow(/unsupported sys_updated_on/);
    expect(() =>
      parseChangeRows("CHG0030001", [
        {
          row_type: "change_request_invalid",
          number: "CHG0030001",
          records_capped: "0",
          invalid_updates: "3",
        },
      ]),
    ).toThrow(/unsupported sys_updated_on/);
    expect(() =>
      parseChangeRows("CHG0030001", [
        {
          row_type: "change_request_invalid",
          number: "CHG0030001",
          records_capped: "1",
          invalid_updates: "501",
        },
      ]),
    ).toThrow(/500/);
    expect(
      parseChangeRows("CHG0030001", [row({ invalid_updates: "0" })]).basis,
    ).toBe("servicenow_actual");
    for (const malformed of ["-1", -1, "   ", false, []]) {
      expect(() =>
        parseChangeRows("CHG0030001", [row({ invalid_updates: malformed })]),
      ).toThrow(/unsupported sys_updated_on/);
    }
  });
  it("validates the change number before building SPL", () => {
    expect(changeRequestSearch("CHG0030001")).toBe(
      "| `adm_change_request_window(CHG0030001)`",
    );
    expect(() => changeRequestSearch('CHG1" OR 1=1')).toThrow();
  });
  it("reads the grounded fixture's latest update", () => {
    const latest = fixture
      .filter((e) => e.number === "CHG0030001")
      .sort((a, b) =>
        String(b.sys_updated_on).localeCompare(String(a.sys_updated_on)),
      )[0];
    const record = parseChangeRows("CHG0030001", [
      { ...latest, row_type: "change_request" },
    ]);
    expect(record.basis).toBe("servicenow_actual");
    expect(record.end).toBeGreaterThan(record.start);
  });
});
