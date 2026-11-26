import { csvRow } from "../csv";
import {
  BASIS_LABEL,
  describeAssertion,
  KIND_LABEL,
  serviceOf,
  tally,
  type TimeWindow,
  type WindowSummary,
} from "./model";
import type { VerificationRun, WindowRun } from "./searches";

export type LinkFor = (
  r: VerificationRun["results"][number],
  w: TimeWindow,
) => string;

export const iso = (seconds: number) =>
  new Date(seconds * 1000).toISOString().replace(/\.000Z$/, "Z");
export const span = (w: TimeWindow) => `${iso(w.start)} to ${iso(w.end)}`;

export function windowText(s: WindowSummary): string {
  const parts = [
    s.complete ? "complete" : `incomplete (${s.issues[0]})`,
    `${s.records} records`,
  ];
  if (s.forwarded.length) parts.push(`forwarded at ${s.forwarded.join(" ")}`);
  if (s.blocked.length) parts.push(`dropped at ${s.blocked.join(" ")}`);
  if (s.unresolved.length)
    parts.push(`outcome unknown at ${s.unresolved.join(" ")}`);
  if (s.dropKeys.length) parts.push(`drops ${s.dropKeys.join(" ")}`);
  return parts.join("; ");
}

const windowJson = (run: WindowRun, summary: WindowSummary, link: string) => ({
  earliest: iso(run.window.start),
  latest: iso(run.window.end),
  spl: run.spl,
  complete: summary.complete,
  issues: summary.issues,
  forwarded: summary.forwarded,
  blocked: summary.blocked,
  unresolved: summary.unresolved,
  records: summary.records,
  dropKeys: summary.dropKeys,
  references: [...new Set(run.observations.flatMap((o) => o.references))].slice(
    0,
    32,
  ),
  traceLink: link,
});

function header(run: VerificationRun) {
  const w = run.windows;
  return {
    generated: run.generated,
    basis: BASIS_LABEL[w.basis],
    ...(w.change ? { change: w.change } : {}),
    before: span(w.before),
    after: span(w.after),
  };
}

export function verificationJson(
  run: VerificationRun,
  linkFor: LinkFor,
): string {
  return JSON.stringify(
    {
      kind: "atlas-change-verification",
      draft: true,
      ...header(run),
      summary: tally(run.results.map((r) => r.verdict.status)),
      results: run.results.map((r) => ({
        assertion: r.assertion,
        statement: describeAssertion(r.assertion),
        status: r.verdict.status,
        basis: r.verdict.basis,
        reason: r.verdict.reason,
        before: windowJson(
          r.before,
          r.verdict.before,
          linkFor(r, r.before.window),
        ),
        after: windowJson(r.after, r.verdict.after, linkFor(r, r.after.window)),
        liveness: r.liveness,
      })),
    },
    null,
    2,
  );
}

export const CSV_COLUMNS = [
  "assertion",
  "kind",
  "scope",
  "source",
  "destination",
  "service",
  "result",
  "basis",
  "reason",
  "before_window",
  "before_evidence",
  "after_window",
  "after_evidence",
  "before_trace",
  "after_trace",
] as const;

export function verificationCsv(
  run: VerificationRun,
  linkFor: LinkFor,
): string {
  return [
    csvRow([...CSV_COLUMNS]),
    ...run.results.map((r) =>
      csvRow([
        r.assertion.name,
        KIND_LABEL[r.assertion.kind],
        r.assertion.scope,
        r.assertion.src,
        r.assertion.dst,
        serviceOf(r.assertion) ?? "any",
        r.verdict.status,
        r.verdict.basis,
        r.verdict.reason,
        span(r.before.window),
        windowText(r.verdict.before),
        span(r.after.window),
        windowText(r.verdict.after),
        linkFor(r, r.before.window),
        linkFor(r, r.after.window),
      ]),
    ),
  ].join("\r\n");
}

const md = (value: string) =>
  value.replace(/([\\`*_[\]|<>])/g, "\\$1").replace(/\s+/g, " ");

export function verificationMarkdown(
  run: VerificationRun,
  linkFor: LinkFor,
): string {
  const h = header(run);
  const t = tally(run.results.map((r) => r.verdict.status));
  const lines = [
    `## Change verification${run.windows.change ? ` · ${md(run.windows.change.number)}` : ""}`,
    "",
    `Draft generated ${h.generated} by Application Atlas. ${t.pass} pass · ${t.fail} fail · ${t.unknown} unknown.`,
    "",
    `- Windows: ${md(h.basis)}`,
    `- Before: ${h.before}`,
    `- After: ${h.after}`,
    "- Unknown means the evidence was incomplete or ambiguous, not that the dependency is healthy.",
    "",
    "| Result | Assertion | Why | Evidence |",
    "| --- | --- | --- | --- |",
    ...run.results.map(
      (r) =>
        `| ${r.verdict.status.toUpperCase()}${r.verdict.basis === "inferred" ? " (inferred)" : ""} | ${md(r.assertion.name)}: ${md(describeAssertion(r.assertion))} | ${md(r.verdict.reason)} | [before](${linkFor(r, r.before.window)}) · [after](${linkFor(r, r.after.window)}) |`,
    ),
    "",
  ];
  return lines.join("\n");
}
