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
): { scenario: DemoScenario; earliest: string; latest: string } {
  return mode === "demo" ? resolveDemoTarget() : { scenario, earliest, latest };
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
