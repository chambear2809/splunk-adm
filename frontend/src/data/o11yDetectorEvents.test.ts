import { describe, expect, it, vi } from "vitest";
import fixture from "../../../fixtures/o11y/detector_events.json";
import type { Row } from "../rows";
import type { ServiceHealthSelection } from "./evidence";
import type {
  EvidenceConfiguration,
  SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  buildDetectorEventsSearch,
  loadDetectorEvents,
  normalizeDetectorEvents,
} from "./o11yDetectorEvents";

const first = fixture.events[0].event;
export const detectorSelection: ServiceHealthSelection = {
  schemaVersion: 1,
  workflow: "service",
  selectionId: "checkout",
  scope: first.routing_scope,
  window: { start: first.capture_window_start, end: first.capture_window_end },
  service: {
    name: "checkout-api",
    environment: "production",
    cluster: first.cluster,
    namespace: "commerce",
  },
  identityBasis: "exact graph boundary",
  configurationFingerprint: "a".repeat(64),
};
export const detectorSource: SupplementalSourceConfiguration = {
  source: "o11y_detector_events",
  state: "active",
  indexes: ["atlas_o11y"],
  authorities: [first.observer_id],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "o11y_detector",
      observer: first.observer_id,
      scope: first.routing_scope,
      cluster: first.cluster,
      mapping_status: "verified",
      organization_id: first.organization_id,
      realm: first.realm,
      detector_ids: JSON.stringify(first.configured_detector_ids),
      observability_origin: "https://app.us0.signalfx.com",
    },
  ],
};
const rows = (): Row[] =>
  fixture.events.map((item) => ({
    _raw: JSON.stringify(item.event),
    host: item.host,
    index: "atlas_o11y",
    event_time_epoch: String(item.time),
    indexed_time_epoch: String(item.time + 1),
    kind: "supplemental_record",
  }));
const config = (source = detectorSource): EvidenceConfiguration => ({
  fingerprint: detectorSelection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: source.mappings,
  identities: [],
  identityAvailable: true,
  maxAgeSeconds: 3600,
  dns: [],
  supplemental: [source],
});
const response = (input = rows()) => ({
  rows: [
    ...input,
    {
      kind: "supplemental_completion",
      schema_version: "1",
      input_count: String(input.length),
      returned_count: String(input.length),
      input_capped: "0",
      oversized: "0",
      source_scan_count: String(input.length),
      source_scan_capped: "0",
    },
  ],
  warnings: [] as string[],
  errors: [],
});
function change(input: Row[], index: number, patch: Record<string, unknown>) {
  input[index]._raw = JSON.stringify({
    ...JSON.parse(String(input[index]._raw)),
    ...patch,
  });
  return input;
}

describe("detector event history", () => {
  it("preserves native trigger and clear values without claiming interval incident state", () => {
    const result = normalizeDetectorEvents(
      rows(),
      detectorSelection,
      detectorSource,
    );
    expect(result.rejected).toBe(0);
    expect(
      result.capture?.events.map((event) => [event.type, event.anomalyState]),
    ).toEqual([
      ["ALERT", "ANOMALOUS"],
      ["CLEAR", "OK"],
    ]);
    expect(result.capture?.events[0].sourceEvent.inputs).toEqual({
      A: 250000000,
    });
    expect(result.capture).not.toHaveProperty("service");
  });
  it("deduplicates exact capture/completion replay and rejects conflicting duplicates", () => {
    const input = rows();
    expect(
      normalizeDetectorEvents(
        [...input, ...input],
        detectorSelection,
        detectorSource,
      ).capture?.events,
    ).toHaveLength(2);
    const conflict = change(rows(), 0, { severity: "Warning" });
    expect(
      normalizeDetectorEvents(
        [...input, conflict[0]],
        detectorSelection,
        detectorSource,
      ).rejected,
    ).toBeGreaterThan(0);
  });
  it.each([
    "missing completion",
    "missing event",
    "different capture",
    "different detector set",
    "wrong authority",
    "wrong index",
    "outside interval",
    "native projection conflict",
  ])("suppresses %s", (reason) => {
    const input = rows();
    if (reason === "missing completion") input.pop();
    if (reason === "missing event") input.splice(0, 1);
    if (reason === "different capture")
      change(input, 0, { capture_id: "another" });
    if (reason === "different detector set")
      change(input, 0, { configured_detector_ids: ["other"] });
    if (reason === "wrong authority")
      change(input, 0, { organization_id: "other" });
    if (reason === "wrong index") input[0].index = "forbidden";
    if (reason === "outside interval")
      change(input, 0, {
        event_timestamp_ms: detectorSelection.window.start * 1000 - 1,
      });
    if (reason === "native projection conflict")
      change(input, 0, { source_event_type: "CLEAR" });
    expect(
      normalizeDetectorEvents(input, detectorSelection, detectorSource),
    ).toMatchObject({ rejected: expect.any(Number) });
    expect(
      normalizeDetectorEvents(input, detectorSelection, detectorSource).capture,
    ).toBeUndefined();
  });
  it("admits a completed empty interval, preserving the selected detector set", () => {
    const input = change(rows().slice(2), 0, { expected_record_count: 0 });
    expect(
      normalizeDetectorEvents(input, detectorSelection, detectorSource).capture,
    ).toMatchObject({ events: [], detectorIds: first.configured_detector_ids });
  });
  it("keeps event time and source identity literal, independent of service/MMS dimensions", () => {
    const search = buildDetectorEventsSearch(detectorSource, detectorSelection);
    expect(search).toContain('sourcetype="atlas:o11y_detector_event"');
    expect(search).toContain('"organization_id")="org-demo-01"');
    expect(search).toContain("| head 10001");
    expect(search).toContain("| dedup _raw");
    expect(search).not.toMatch(
      /apm_mms|service_name|\|\s*(join|map|lookup)\b|`/,
    );
    expect(() =>
      buildDetectorEventsSearch(
        {
          ...detectorSource,
          mappings: [...detectorSource.mappings, ...detectorSource.mappings],
        },
        detectorSelection,
      ),
    ).toThrow(/ambiguous/);
  });
  it("does not search unselected or staged sources", async () => {
    const search = vi.fn();
    for (const state of ["not_selected", "staged"] as const) {
      const result = await loadDetectorEvents(
        { search },
        detectorSelection,
        new AbortController().signal,
        { read: async () => config({ ...detectorSource, state }) },
      );
      expect(result.state).toBe(state);
    }
    expect(search).not.toHaveBeenCalled();
  });
  it("uses the optional budget and clears associations on configuration drift", async () => {
    const search = vi.fn(async () => response()),
      read = vi
        .fn()
        .mockResolvedValueOnce(config())
        .mockResolvedValueOnce({ ...config(), fingerprint: "b".repeat(64) });
    const result = await loadDetectorEvents(
      { search },
      detectorSelection,
      new AbortController().signal,
      { read },
    );
    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({
        optionalSource: "o11y_detector_events",
        maxRows: 65,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      }),
    );
    expect(result).toMatchObject({
      state: "unavailable",
      configurationChanged: true,
      capture: undefined,
    });
  });
  it.each(["cap", "warning", "missing transport completion"])(
    "fails closed on %s",
    async (reason) => {
      const output = response();
      if (reason === "cap")
        Object.assign(output.rows.at(-1)!, {
          input_count: "65",
          returned_count: "3",
        });
      if (reason === "warning") output.warnings.push("truncated");
      if (reason === "missing transport completion") output.rows.pop();
      const result = await loadDetectorEvents(
        { search: async () => output },
        detectorSelection,
        new AbortController().signal,
        { read: async () => config() },
      );
      expect(result.state).toBe("unavailable");
      expect(result.capture).toBeUndefined();
    },
  );
});
