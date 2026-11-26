import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  MulticastPage,
  MulticastResults,
  observedGroupSuggestions,
  utcInput,
  utcSeconds,
} from "./MulticastPage";
import type { MulticastResult } from "./contract";
import type { SearchClient } from "../data/searchClient";

const client = {} as SearchClient;
const tab = (html: string, name: string) =>
  new RegExp(`<button[^>]*role="tab"[^>]*>${name}`).exec(html)?.[0] ?? "";

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
  it("defaults to the overview tab", () => {
    const html = renderToStaticMarkup(
      <MulticastPage
        live
        client={client}
        initialParams={new URLSearchParams()}
      />,
    );
    expect(html).toContain('role="tablist"');
    expect(tab(html, "Overview")).toContain('aria-selected="true"');
    expect(tab(html, "Matrix")).toContain('aria-selected="false"');
  });
  it("restores the matrix tab from a scope link", () => {
    const html = renderToStaticMarkup(
      <MulticastPage
        live
        client={client}
        initialParams={
          new URLSearchParams(
            "mode=live&mc_v=1&mc_scope=fabric-a&mc_earliest=1000&mc_latest=2000&mc_view=matrix",
          )
        }
      />,
    );
    expect(tab(html, "Matrix")).toContain('aria-selected="true"');
    expect(tab(html, "Overview")).toContain('aria-selected="false"');
  });
  it("topology tab is disabled with a reason", () => {
    const html = renderToStaticMarkup(
      <MulticastPage
        live
        client={client}
        initialParams={new URLSearchParams()}
      />,
    );
    const topology = tab(html, "Topology");
    expect(topology).toContain('aria-disabled="true"');
    expect(topology).toContain('aria-selected="false"');
    expect(topology).toContain('title="Not yet available"');
    expect(html).toMatch(/Topology<small[^>]*>Not yet available<\/small>/);
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
  it("suggests observed groups and the selected group's flow senders", () => {
    const flow = (group: string, senders: string[]) => ({
      kind: "flow" as const,
      profile: "netflow",
      group,
      observer: "leaf-a",
      direction: "ingress" as const,
      senders,
      samplingInterval: 1,
      replication: "unknown" as const,
      counters: "delta" as const,
      firstSeen: 1000,
      lastSeen: 2000,
    });
    const rows = [
      {
        group: "239.1.2.3",
        summaries: [
          flow("239.1.2.3", ["192.0.2.9", "192.0.2.1"]),
          flow("239.1.2.3", ["192.0.2.1"]),
        ],
        flags: [],
      },
      {
        group: "239.9.9.9",
        summaries: [flow("239.9.9.9", ["192.0.2.50"])],
        flags: [],
      },
    ];
    expect(observedGroupSuggestions(rows, " 239.1.2.3 ")).toEqual({
      groups: ["239.1.2.3", "239.9.9.9"],
      senders: ["192.0.2.1", "192.0.2.9"],
    });
    expect(observedGroupSuggestions(rows, "239.0.0.1").senders).toEqual([]);
    expect(observedGroupSuggestions(rows, "", 1).groups).toEqual(["239.1.2.3"]);
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
