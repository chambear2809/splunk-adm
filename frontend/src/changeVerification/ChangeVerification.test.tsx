import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({}),
}));
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => path,
}));

import {
  candidateDrafts,
  ChangeVerification,
  linkFor,
  MAX_CANDIDATE_DRAFTS,
} from "./ChangeVerification";
import type { AssertionResult } from "./searches";

const candidate = (port: number, src = "10.1.1.10") => ({
  name: `web → db tcp/${port}`,
  src,
  dst: "10.2.2.20",
  transport: "tcp" as const,
  port,
});

describe("candidateDrafts", () => {
  it("drafts reaches assertions from exact Impact rows, bounded and deduplicated", () => {
    const rows = [
      candidate(5432),
      candidate(5432),
      candidate(6379),
      candidate(1, "10.1.1.010"),
    ];
    const drafts = candidateDrafts(rows, "prod");
    expect(drafts.map((d) => d.port)).toEqual([5432, 6379]);
    expect(
      drafts.every((d) => d.kind === "reaches" && d.id.startsWith("draft-")),
    ).toBe(true);
    const many = Array.from({ length: 9 }, (_, i) => candidate(1000 + i));
    expect(candidateDrafts(many, "prod")).toHaveLength(MAX_CANDIDATE_DRAFTS);
    expect(candidateDrafts(rows, "unmapped:x")).toEqual([]);
  });
});

describe("ChangeVerification", () => {
  it("renders collapsed with only its heading", () => {
    const html = renderToStaticMarkup(
      <ChangeVerification
        live
        scope="prod"
        open={false}
        onToggle={() => undefined}
      />,
    );
    expect(html).toContain("Verify change");
    expect(html).not.toContain("Run verification");
  });
  it("states the semantics and the demo limitation when open", () => {
    const html = renderToStaticMarkup(
      <ChangeVerification
        live={false}
        scope=""
        editableScope
        open
        onToggle={() => undefined}
        candidates={[candidate(5432)]}
      />,
    );
    expect(html).toContain("nothing passes on missing evidence");
    expect(html).toContain("Verification runs against live Splunk data only");
    expect(html).toContain("Routing scope");
    expect(html).toContain("Enter the change start and end (UTC).");
    expect(html).not.toContain("ServiceNow change number");
  });
  it("offers ServiceNow lookup only for live searches", () => {
    const html = renderToStaticMarkup(
      <ChangeVerification live scope="prod" open onToggle={() => undefined} />,
    );
    expect(html).toContain("ServiceNow change number");
  });
  it("links each window to a scoped Trace", () => {
    const href = linkFor(
      {
        assertion: { src: "10.1.1.10", dst: "10.2.2.20", scope: "prod" },
      } as AssertionResult,
      { start: 100, end: 200 },
    );
    expect(href).toContain("trace_src=10.1.1.10");
    expect(href).toContain("trace_scope=prod");
    expect(href).toContain("earliest=100");
    expect(href).toContain("latest=200");
  });
});
