import type { DemoScenario } from "../data/demoClient";
import type { GraphArgs } from "../rows";

export function applicationMapTarget(
  mode: "demo" | "live",
  scenario: DemoScenario,
  earliest: string,
  latest: string,
  resolveDemoTarget: () => {
    scenario: DemoScenario;
    earliest: string;
    latest: string;
  },
  liveWindow?: { earliest?: number; latest?: number },
): { scenario: DemoScenario; earliest: string; latest: string } {
  if (mode === "demo") return resolveDemoTarget();
  return {
    scenario,
    earliest:
      liveWindow?.earliest !== undefined
        ? String(liveWindow.earliest)
        : earliest,
    latest:
      liveWindow?.latest !== undefined ? String(liveWindow.latest) : latest,
  };
}

export function applicationDemoEntryTarget(
  mode: "demo" | "live",
  args: GraphArgs,
  earliest: string,
  latest: string,
  defaults: { args: GraphArgs; earliest: string; latest: string },
): { args: GraphArgs; earliest: string; latest: string } {
  return mode === "live" ? defaults : { args, earliest, latest };
}
