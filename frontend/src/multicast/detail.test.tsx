import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  IgmpEvidence,
  IgmpOperation,
  MulticastResult,
  Segment,
} from "./contract";
import { IgmpTimeline } from "./IgmpTimeline";
import { QuerierStrip } from "./QuerierStrip";

const FORBIDDEN = /deliver|member(ship)?|joined|elected/i;
const VLAN_110: Segment = { kind: "vlan", id: "110", domain: "dc1" };

let next = 0;
function igmp(
  operation: IgmpOperation,
  timestamp: number,
  overrides: Partial<IgmpEvidence> = {},
): IgmpEvidence {
  next += 1;
  return {
    id: `igmp-${next}`,
    kind: "igmp",
    source: "multicast_igmp",
    scope: "fabric-a",
    group: "239.1.1.1",
    observer: "leaf-a",
    timestamp,
    segment: VLAN_110,
    limits: [],
    operation,
    reporter: "192.0.2.10",
    reporterKind: "endpoint",
    sources: [],
    ...overrides,
  };
}
function result(evidence: IgmpEvidence[]): MulticastResult {
  return {
    version: 1,
    request: {
      version: 1,
      scope: "fabric-a",
      group: "239.1.1.1",
      earliest: 1000,
      latest: 2000,
    },
    capturedAt: 2000,
    configurationFingerprint: "verified",
    outcomes: [],
    evidence,
    senders: [],
    receivers: [],
    branches: [],
    capped: false,
  };
}
const timeline = (value: MulticastResult) =>
  renderToStaticMarkup(<IgmpTimeline result={value} timezone="UTC" />);
const strip = (value: MulticastResult) =>
  renderToStaticMarkup(<QuerierStrip result={value} timezone="UTC" />);

describe("multicast group detail", () => {
  it("timeline places marks by time within the window", () => {
    const html = timeline(
      result([
        igmp("report-v2", 1800),
        igmp("leave", 1100),
        igmp("report-v1", 1500),
        igmp("include", 1000),
        igmp("block-old-sources", 2000),
      ]),
    );
    const xs = [...html.matchAll(/data-t="(\d+)" (?:cx|x1|points)="([\d.]+)/g)]
      .map(([, t, x]) => [Number(t), Number(x)] as const)
      .sort((a, b) => a[0] - b[0]);
    expect(xs.map(([t]) => t)).toEqual([1000, 1100, 1500, 1800, 2000]);
    for (let index = 1; index < xs.length; index += 1)
      expect(xs[index][1]).toBeGreaterThan(xs[index - 1][1]);
    expect(html).toContain("<title>leave from 192.0.2.10 at ");
    expect(html).toContain("1970-01-01T00:18:20Z");
    expect(html).toContain(
      'aria-label="IGMP evidence for vlan 110 · dc1: 3 reports, 1 leave, 1 source update, 0 queries"',
    );
    expect(html).toContain('role="img"');
    expect(html).not.toMatch(FORBIDDEN);
  });
  it("timeline distinguishes general and group queries", () => {
    const html = timeline(
      result([
        igmp("query", 1200, { queryScope: "group", reporter: "192.0.2.1" }),
        igmp("query", 1300, {
          queryScope: "general",
          reporter: undefined,
          segment: undefined,
        }),
      ]),
    );
    expect(html).toContain('class="mc-mark group-query"');
    expect(html).toContain('class="mc-mark general-query"');
    expect(html).toContain("<title>group query from 192.0.2.1 at ");
    expect(html).toContain("<title>general query from unknown sender at ");
    expect(html).toContain("Segment not reported");
    expect(html).not.toMatch(FORBIDDEN);
  });
  it("distinguishes source updates from group leaves", () => {
    const html = timeline(
      result([
        igmp("change-to-include", 1100, { sources: ["192.0.2.20"] }),
        igmp("change-to-include", 1200, { sources: [] }),
        igmp("block-old-sources", 1300, { sources: ["192.0.2.20"] }),
      ]),
    );
    expect(html).toMatch(/<circle data-t="1100"[^>]+class="mc-mark report"/);
    expect(html).toMatch(/<circle data-t="1200"[^>]+class="mc-mark leave"/);
    expect(html).toMatch(
      /<polygon data-t="1300"[^>]+class="mc-mark source-update"/,
    );
    expect(html).toContain(
      "Filled circle report · hollow circle leave · diamond source update · line",
    );
    expect(html).toContain(
      'aria-label="IGMP evidence for vlan 110 · dc1: 1 report, 1 leave, 1 source update, 0 queries"',
    );
  });
  it("timeline titles a query without a reported scope", () => {
    const html = timeline(
      result([igmp("query", 1200, { reporter: "192.0.2.1" })]),
    );
    expect(html).toContain('class="mc-mark group-query"');
    expect(html).toContain(
      "<title>query (scope not reported) from 192.0.2.1 at ",
    );
    expect(html).not.toContain("<title>group query");
  });
  it("timeline reports an empty window", () => {
    expect(timeline(result([]))).toContain("No IGMP evidence in this window");
  });
  it("querier strip reports a change of query sender", () => {
    const html = strip(
      result([
        igmp("query", 1100, { queryScope: "general", reporter: "192.0.2.1" }),
        igmp("query", 1400, { queryScope: "group", reporter: "192.0.2.1" }),
        igmp("query", 1600, { queryScope: "general", reporter: "192.0.2.2" }),
        igmp("query", 1700, { queryScope: "general", reporter: undefined }),
        igmp("report-v2", 1200),
      ]),
    );
    expect(html).toContain("Observed query senders");
    expect(html).toContain("Query senders changed");
    expect(html).toContain("192.0.2.1");
    expect(html).toContain("192.0.2.2");
    expect(html).not.toContain("192.0.2.10");
    expect(html.match(/class="mc-sender-bar"/g)).toHaveLength(2);
    expect(html).toContain(
      'aria-label="Query senders observed for vlan 110 · dc1: 2 query senders (192.0.2.1, 192.0.2.2)"',
    );
    const steady = strip(
      result([
        igmp("query", 1100, { queryScope: "general", reporter: "192.0.2.1" }),
        igmp("query", 1600, { queryScope: "general", reporter: "192.0.2.1" }),
      ]),
    );
    expect(steady).not.toContain("Query senders changed");
    expect(steady).toContain(
      'aria-label="Query senders observed for vlan 110 · dc1: 1 query sender (192.0.2.1)"',
    );
  });
  it("querier strip never says elected", () => {
    const html = strip(
      result([
        igmp("query", 1100, { queryScope: "general", reporter: "192.0.2.1" }),
        igmp("query", 1600, { queryScope: "general", reporter: "192.0.2.2" }),
      ]),
    );
    expect(html).not.toMatch(FORBIDDEN);
    expect(html).toContain('role="img"');
    expect(strip(result([]))).toContain("No IGMP evidence in this window");
  });
});
