import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { demoGraph } from "../provider";
import { AUDIT_TIMEOUT_MS, loadAudit, type AuditBatch } from "./audit";
import { AuditEvidence, auditExport, type AuditState } from "./AuditEvidence";
import { buildTimeline } from "./model";

const incident = {
  ...demoGraph(),
  window: { start: "2026-01-01T01:00:00Z", end: "2026-01-01T02:00:00Z" },
};
const baseline = {
  ...incident,
  window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
};
const batch = (): AuditBatch => ({
  coverage: {
    start: "2026-01-01T01:00:00Z",
    end: "2026-01-01T01:45:00Z",
    gaps: ["Page was unavailable"],
  },
  events: [
    {
      eventId: "event-1",
      authority: "apic",
      scope: "fabric",
      objectId: "uni/object",
      action: "modified",
      actionTime: "2026-01-01T02:15:00+01:00",
      receivedTime: "2026-01-01T01:20:00Z",
    },
    {
      eventId: "event-2",
      authority: "apic",
      scope: "fabric",
      objectId: "uni/other",
      action: "modified",
      actionTime: "2026-01-01T01:16:00Z",
      receivedTime: "2026-01-01T01:21:00Z",
    },
  ],
  bindings: [
    {
      authority: "apic",
      scope: "fabric",
      objectId: "uni/object",
      applicationId: "app-id",
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-01-01T02:00:00Z",
      bindingAuthority: "inventory",
      bindingEvidenceId: "proof-1",
    },
  ],
});

describe("injected audit producer workflow", () => {
  it("passes the exact selection and renders and exports admitted evidence, coverage and withheld reasons", async () => {
    const load = vi.fn(async () => ({
      producerId: "test producer",
      applicationId: "app-id",
      batch: batch(),
    }));
    const signal = new AbortController().signal;
    const result = await loadAudit(
      { load },
      { boundary: incident.boundary, window: incident.window },
      signal,
    );
    expect(load).toHaveBeenCalledWith(
      { boundary: incident.boundary, window: incident.window },
      expect.any(AbortSignal),
    );
    const timeline = buildTimeline(
      baseline,
      incident,
      undefined,
      result.projection,
    );
    const state: AuditState = { status: "available", result };
    const html = renderToStaticMarkup(
      <AuditEvidence
        state={state}
        window={incident.window}
        timeline={timeline}
      />,
    );
    expect(html).toContain("Page was unavailable");
    expect(html).toContain("does not span the requested incident window");
    expect(html).toContain("1 associated events");
    expect(html).toContain("no active binding: 1");
    const exported = auditExport(state, incident.window, timeline);
    expect(exported.events).toHaveLength(1);
    expect(exported.events[0].event.actionTime).toBe(
      "2026-01-01T02:15:00+01:00",
    );
    expect(exported.events[0].event.receivedTime).toBe("2026-01-01T01:20:00Z");
    expect(exported.events[0].binding.bindingEvidenceId).toBe("proof-1");
    expect(exported.timeline).toHaveLength(1);
    expect(exported.coverage.gaps).toEqual(["Page was unavailable"]);
    expect(exported.withheldReasons).toEqual({ "no active binding": 1 });
  });
  it("renders unavailable and failed states without claiming an empty source", () => {
    for (const status of ["unavailable", "failed"] as const) {
      const html = renderToStaticMarkup(
        <AuditEvidence
          state={{ status }}
          window={incident.window}
          timeline={[]}
        />,
      );
      expect(html).toContain("unavailable");
      expect(html).not.toContain("Download audit evidence");
    }
  });
  it("discards a late producer response after cancellation and rejects invalid producer output", async () => {
    const controller = new AbortController();
    let resolve!: (value: {
      producerId: string;
      applicationId: string;
      batch: AuditBatch;
    }) => void;
    const load = () =>
      new Promise<{
        producerId: string;
        applicationId: string;
        batch: AuditBatch;
      }>((done) => {
        resolve = done;
      });
    const pending = loadAudit(
      { load },
      { boundary: incident.boundary, window: incident.window },
      controller.signal,
    );
    await Promise.resolve();
    controller.abort();
    resolve({ producerId: "test", applicationId: "app-id", batch: batch() });
    await expect(pending).rejects.toThrow(/cancelled/);
    await expect(
      loadAudit(
        {
          load: async () => ({
            producerId: "",
            applicationId: "app-id",
            batch: batch(),
          }),
        },
        { boundary: incident.boundary, window: incident.window },
        new AbortController().signal,
      ),
    ).rejects.toThrow(/producer identity/);
  });
  it("bounds a producer that never settles and aborts its signal", async () => {
    vi.useFakeTimers();
    let producerSignal: AbortSignal | undefined;
    try {
      const pending = loadAudit(
        {
          load: (_request, signal) => {
            producerSignal = signal;
            return new Promise(() => {});
          },
        },
        { boundary: incident.boundary, window: incident.window },
        new AbortController().signal,
      );
      const rejected = expect(pending).rejects.toThrow(/timed out/);
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(AUDIT_TIMEOUT_MS);
      await rejected;
      expect(producerSignal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
  it("copies only admitted fields and resists later producer mutation", async () => {
    const input = batch();
    Object.assign(input.events[0], { secretExtra: "not retained" });
    Object.assign(input.bindings[0], { secretExtra: "not retained" });
    Object.assign(input.coverage, { secretExtra: "not retained" });
    const result = await loadAudit(
      {
        load: async () => ({
          producerId: "test",
          applicationId: "app-id",
          batch: input,
        }),
      },
      { boundary: incident.boundary, window: incident.window },
      new AbortController().signal,
    );
    input.events[0].actionTime = "2020-01-01T00:00:00Z";
    input.bindings[0].bindingEvidenceId = "changed";
    input.coverage.gaps[0] = "changed";
    const timeline = buildTimeline(
      baseline,
      incident,
      undefined,
      result.projection,
    );
    const output = JSON.stringify(
      auditExport({ status: "available", result }, incident.window, timeline),
    );
    expect(output).toContain("2026-01-01T02:15:00+01:00");
    expect(output).toContain("proof-1");
    expect(output).toContain("Page was unavailable");
    expect(output).not.toContain("secretExtra");
    expect(output).not.toContain("changed");
  });
});
