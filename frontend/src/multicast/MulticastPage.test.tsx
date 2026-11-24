import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  MulticastPage,
  MulticastResults,
  utcInput,
  utcSeconds,
} from "./MulticastPage";
import type { MulticastResult } from "./contract";

const result: MulticastResult = {
  version: 1,
  request: {
    version: 1,
    scope: "fabric-a",
    group: "239.1.2.3",
    earliest: 1000,
    latest: 2000,
  },
  capturedAt: 2000,
  configurationFingerprint: "verified",
  outcomes: [
    {
      source: "multicast_igmp",
      state: "partial",
      detail: "Some captures unavailable",
    },
  ],
  senders: [],
  receivers: [],
  branches: [],
  capped: false,
  evidence: [
    {
      id: "report-1",
      kind: "igmp",
      source: "multicast_igmp",
      scope: "fabric-a",
      group: "239.1.2.3",
      observer: "leaf-a",
      timestamp: 1500,
      interface: "eth1",
      operation: "report-v2",
      reporter: "192.0.2.4",
      reporterKind: "endpoint",
      sources: [],
      limits: ["capture is sampled"],
    },
  ],
};

describe("Multicast page", () => {
  it("preserves absolute seconds across the daylight-saving fall-back", () => {
    for (const seconds of [1793511000, 1793514600]) {
      expect(utcSeconds(utcInput(seconds))).toBe(seconds);
    }
    expect(utcInput(1793511000)).not.toBe(utcInput(1793514600));
  });
  it("does not imply demo data is live", () => {
    const html = renderToStaticMarkup(<MulticastPage live={false} />);
    expect(html).toContain("live Splunk connection");
    expect(html).not.toContain("Investigate</button>");
  });
  it("shows coverage, provenance and limitations alongside evidence", () => {
    const html = renderToStaticMarkup(
      <MulticastResults result={result} timezone="UTC" />,
    );
    expect(html).toContain("Coverage is incomplete");
    expect(html).toContain("Some captures unavailable");
    expect(html).toContain("leaf-a");
    expect(html).toContain("eth1");
    expect(html).toContain("capture is sampled");
    expect(html).toContain("Delivery remains unverified");
  });
  it("nests supported branches, keeping stale targets and other senders separate", () => {
    const forwarding = (id: string, observer: string, sender: string) => ({
      id,
      observer,
      sender,
      source: "device_state" as const,
      kind: "forwarding" as const,
      group: result.request.group,
      scope: result.request.scope,
      timestamp: 1500,
      validUntil: 2000,
      outputs: [],
      limits: [],
    });
    const html = renderToStaticMarkup(
      <MulticastResults
        result={{
          ...result,
          evidence: [
            forwarding("a", "leaf-a", "192.0.2.20"),
            forwarding("b", "spine-b", "192.0.2.20"),
            forwarding("c", "spine-b", "192.0.2.21"),
          ],
          branches: [
            {
              from: "leaf-a",
              output: "eth1",
              to: "spine-b",
              evidenceId: "a",
              state: "supported",
            },
            {
              from: "spine-b",
              output: "eth2",
              to: "leaf-c",
              evidenceId: "b",
              state: "supported",
            },
            {
              from: "spine-b",
              output: "eth5",
              to: "stale-target",
              evidenceId: "c",
              state: "stale",
            },
          ],
        }}
      />,
    );
    expect(html).toMatch(
      /Supported link<\/small><\/button><ul class="multicast-tree"><li><button[^>]*><strong>spine-b/,
    );
    expect(html).toContain("(192.0.2.21, 239.1.2.3)");
    expect(html).toContain("Stale state");
    expect(html).not.toContain("stale-target");
  });
  it("qualifies an empty result with coverage", () => {
    const html = renderToStaticMarkup(
      <MulticastResults result={{ ...result, evidence: [], capped: true }} />,
    );
    expect(html).toContain("Evidence was capped");
    expect(html).toContain("No evidence was returned");
    expect(html).toContain("Coverage and source status");
  });
});
