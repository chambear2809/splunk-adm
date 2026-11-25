import { describe, expect, it } from "vitest";
import { validateDemoCapture } from "./demoCapture";
import type { DemoScenario } from "./demoRegistry";
import { demoCaptureBundle, rehashDemoCapture } from "./demoCapture.testUtils";

describe("offline demo capture contract", () => {
  it("round-trips the synthetic blocked bundle without enabling runtime capture", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const validated = await validateDemoCapture(bundle, scenario, template);

    expect(validated.manifest.scenario_id).toBe(scenario);
    expect(validated.manifest.capture_status).toBe("complete");
    expect(Object.keys(validated.results)).toHaveLength(19);
  });

  it("refuses a bundle with altered result content", async () => {
    const scenario: DemoScenario = "track-b-fabric";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    const impact = altered.results["graph.impact"] as { rows: unknown[] };
    impact.rows.push({ tampered: true });

    await expect(
      validateDemoCapture(altered, scenario, template),
    ).rejects.toThrow(/result hash|bundle hash/);
  });

  it("refuses timeline selections that are not bound to retained rows", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    const timeline = altered.results["timeline.selected"] as {
      selection?: { change_ids?: string[] };
    };
    timeline.selection = { ...timeline.selection, change_ids: ["foreign"] };
    const resigned = await rehashDemoCapture(altered);
    await expect(
      validateDemoCapture(resigned, scenario, template),
    ).rejects.toThrow(/selection is not bound/);
  });

  it("refuses shallow or foreign captured dependency identities", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    altered.manifest.captured_dependencies = [
      {
        authority: "atlas:observed_dependency",
        type: "captured_dependency",
        id: "captured_dependency:fake",
        binding: { scenario_id: "other-track" },
      },
    ];
    const resigned = await rehashDemoCapture(altered);
    await expect(
      validateDemoCapture(resigned, scenario, template),
    ).rejects.toThrow(/dependency/);
  });
});
