import { describe, expect, it, vi } from "vitest";
import { DEMO_WINDOW, demoArgs } from "../data/demoClient";
import { parseUrlState, stateParams } from "../app/urlState";
import {
  applicationDemoEntryTarget,
  applicationMapTarget,
} from "./applicationMapTarget";

describe("applicationMapTarget", () => {
  it("uses the live scope and time range without resolving demo data", () => {
    const resolveDemoTarget = vi.fn(() => {
      throw new Error("Demo data is not prepared.");
    });

    expect(
      applicationMapTarget("live", "aci", "-60m@m", "now", resolveDemoTarget),
    ).toEqual({ scenario: "aci", earliest: "-60m@m", latest: "now" });
    expect(resolveDemoTarget).not.toHaveBeenCalled();
  });

  it("uses the matching captured scope and time range in demo mode", () => {
    const resolveDemoTarget = vi.fn(() => ({
      scenario: "catalyst-aci" as const,
      earliest: "1781542800",
      latest: "1781546400",
    }));

    expect(
      applicationMapTarget("demo", "aci", "-60m@m", "now", resolveDemoTarget),
    ).toEqual({
      scenario: "catalyst-aci",
      earliest: "1781542800",
      latest: "1781546400",
    });
    expect(resolveDemoTarget).toHaveBeenCalledOnce();
  });
});

it("creates a valid demo entry from a live render with empty scope", () => {
  const live = parseUrlState(new URLSearchParams("mode=live"), true);
  const target = applicationDemoEntryTarget(
    live.mode,
    live.args,
    live.earliest,
    live.latest,
    {
      args: demoArgs,
      earliest: DEMO_WINDOW.earliest,
      latest: DEMO_WINDOW.latest,
    },
  );
  const demoLink = {
    ...live,
    mode: "demo" as const,
    ...target,
  };

  expect(target.args).toEqual(demoArgs);
  expect(parseUrlState(stateParams(demoLink)).mode).toBe("demo");
  expect(parseUrlState(stateParams(demoLink)).args).toEqual(demoArgs);
});
