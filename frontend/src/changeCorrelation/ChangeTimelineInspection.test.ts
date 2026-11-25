import { describe, expect, it, vi } from "vitest";
import type { ChangeTimelineResult } from "./types";

const mocked = vi.hoisted(() => ({
  activation: vi.fn(),
  timeline: vi.fn(),
}));

vi.mock("./history", async () => {
  const actual = await vi.importActual<typeof import("./history")>("./history");
  return {
    ...actual,
    loadChangeActivation: mocked.activation,
    loadChangeTimeline: mocked.timeline,
  };
});

import { runChangeTimelineInspection } from "./ChangeTimelineInspection";

const view = { scope: "prod-east", window: { start: 100, end: 200 } };
const client = {} as Parameters<
  typeof runChangeTimelineInspection
>[0]["client"];
const result = {} as ChangeTimelineResult;

describe("runChangeTimelineInspection", () => {
  it("gates activation and generation reads behind selected configuration", async () => {
    const phases: string[] = [];
    const configurationClient = {
      read: vi.fn(async () => ({
        state: "selected" as const,
        index: "atlas_changes",
        activation_id: "a".repeat(64),
      })),
    };
    mocked.activation.mockResolvedValueOnce({ activation_id: "a".repeat(64) });
    mocked.timeline.mockResolvedValueOnce(result);

    await expect(
      runChangeTimelineInspection({
        client,
        view,
        configurationClient,
        signal: new AbortController().signal,
        onPhase: (phase) => phases.push(phase),
      }),
    ).resolves.toEqual({ status: "loaded", result });
    expect(phases).toEqual(["configuration", "activation", "history"]);
    expect(mocked.activation).toHaveBeenCalledWith(
      client,
      "atlas_changes",
      "a".repeat(64),
      expect.any(AbortSignal),
    );
    expect(mocked.timeline).toHaveBeenCalledWith(
      client,
      expect.objectContaining({
        activation: { activation_id: "a".repeat(64) },
        ...view,
      }),
      expect.any(AbortSignal),
    );
  });

  it("does not query activation or generation when history is unselected", async () => {
    const configurationClient = {
      read: vi.fn(async () => ({ state: "not_selected" as const })),
    };
    await expect(
      runChangeTimelineInspection({
        client,
        view,
        configurationClient,
        signal: new AbortController().signal,
      }),
    ).resolves.toEqual({ status: "not_selected" });
    expect(mocked.activation).not.toHaveBeenCalled();
    expect(mocked.timeline).not.toHaveBeenCalled();
  });

  it("propagates cancellation to the configuration boundary", async () => {
    const controller = new AbortController();
    const configurationClient = {
      read: vi.fn((signal: AbortSignal) => {
        expect(signal).toBe(controller.signal);
        return Promise.reject(new DOMException("Aborted", "AbortError"));
      }),
    };
    await expect(
      runChangeTimelineInspection({
        client,
        view,
        configurationClient,
        signal: controller.signal,
      }),
    ).rejects.toThrow("Aborted");
    expect(mocked.activation).not.toHaveBeenCalled();
    expect(mocked.timeline).not.toHaveBeenCalled();
  });

  it("stops before activation when cancellation races configuration", async () => {
    const controller = new AbortController();
    const configurationClient = {
      read: vi.fn(async () => ({
        state: "selected" as const,
        index: "atlas_changes",
        activation_id: "a".repeat(64),
      })),
    };
    await expect(
      runChangeTimelineInspection({
        client,
        view,
        configurationClient,
        signal: controller.signal,
        onPhase: (phase) => {
          if (phase === "configuration") controller.abort();
        },
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(mocked.activation).not.toHaveBeenCalled();
    expect(mocked.timeline).not.toHaveBeenCalled();
  });
});
