import { describe, expect, it } from "vitest";
import {
  DEFAULT_DEMO_PHASE,
  DEMO_PHASES,
  DEMO_TRACKS,
  demoTrack,
  isDemoPhase,
  isDemoScenario,
  requireDemoPhase,
  requireDemoScenario,
} from "./demoRegistry";

describe("demo registry", () => {
  it("exposes only the two blocked presenter tracks", () => {
    expect(DEMO_TRACKS.map(({ id }) => id)).toEqual([
      "track-a-firewall",
      "track-b-fabric",
    ]);
    expect(
      DEMO_TRACKS.every((track) => track.args.service === "checkout"),
    ).toBe(true);
  });

  it("validates scenarios and phases without enabling capture", () => {
    expect(isDemoScenario("track-a-firewall")).toBe(true);
    expect(isDemoScenario("unknown")).toBe(false);
    expect(isDemoPhase(DEFAULT_DEMO_PHASE)).toBe(true);
    expect(DEMO_PHASES).toHaveLength(4);
    expect(requireDemoScenario("track-b-fabric")).toBe("track-b-fabric");
    expect(requireDemoPhase("impact")).toBe("impact");
    expect(() => requireDemoScenario("unknown")).toThrow("retired");
    expect(() => requireDemoPhase("unknown")).toThrow("Unsupported");
    expect(demoTrack("track-a-firewall").scope).toBe("change-a");
  });
});
