import { describe, expect, it } from "vitest";
import { evaluate, parseObservations, type Assertion } from "./model";
import type { VerificationRun } from "./searches";
import {
  CSV_COLUMNS,
  verificationCsv,
  verificationJson,
  verificationMarkdown,
  type LinkFor,
} from "./exports";

const assertion: Assertion = {
  id: "a1",
  name: "=Web | DB",
  kind: "reaches",
  scope: "prod",
  src: "10.1.1.10",
  dst: "10.2.2.20",
  transport: "tcp",
  port: 5432,
};
const after = parseObservations([
  {
    row_type: "observation",
    flow_source: "hubble",
    observer_device: "node-a",
    direction: "forward",
    records: "2",
    drops: "0",
    services: "tcp/5432",
    references: ["hubble/1/2"],
  },
]);
const before = parseObservations([]);
const window = (start: number) => ({ start, end: start + 3600 });
const run: VerificationRun = {
  windows: {
    before: window(1_790_000_000),
    after: window(1_790_010_000),
    basis: "servicenow_actual",
    change: { number: "CHG0030001", sysId: "abc", state: "Closed" },
  },
  generated: "2026-11-26T00:00:00.000Z",
  results: [
    {
      assertion,
      verdict: evaluate(assertion, before, after),
      before: {
        ...before,
        window: window(1_790_000_000),
        spl: "| `adm_path_trace(a,b,c)`",
      },
      after: {
        ...after,
        window: window(1_790_010_000),
        spl: "| `adm_path_trace(a,b,c)`",
      },
      liveness: [],
    },
  ],
};
const link: LinkFor = (_r, w) => `/app/splunk_adm/map?earliest=${w.start}`;

describe("verification exports", () => {
  it("JSON carries windows, SPL, evidence and the draft marker", () => {
    const doc = JSON.parse(verificationJson(run, link));
    expect(doc).toMatchObject({
      kind: "atlas-change-verification",
      draft: true,
      change: { number: "CHG0030001" },
      summary: { pass: 1, fail: 0, unknown: 0 },
    });
    expect(doc.results[0].after).toMatchObject({
      spl: "| `adm_path_trace(a,b,c)`",
      forwarded: ["hubble:node-a"],
      references: ["hubble/1/2"],
      traceLink: "/app/splunk_adm/map?earliest=1790010000",
    });
    expect(doc.basis).toMatch(/actual work/);
  });
  it("CSV neutralises formulas and keeps the column contract", () => {
    const [head, row] = verificationCsv(run, link).split("\r\n");
    expect(head).toBe(CSV_COLUMNS.join(","));
    expect(row.startsWith("'=Web | DB,Reaches,prod")).toBe(true);
  });
  it("Markdown escapes table cells and states unknown semantics", () => {
    const text = verificationMarkdown(run, link);
    expect(text).toContain("CHG0030001");
    expect(text).toContain("=Web \\| DB");
    expect(text).toContain("Unknown means the evidence was incomplete");
    expect(text).toContain("| PASS |");
  });
});
