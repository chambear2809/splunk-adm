import type { GraphArgs } from "../rows";

export type DemoScenario = "track-a-firewall" | "track-b-fabric";
export type DemoPhase = "baseline" | "change" | "impact" | "recovery";

export interface DemoTrackDefinition {
  id: DemoScenario;
  label: string;
  ticket: string;
  scope: string;
  clientIp: string;
  args: GraphArgs;
}

export const DEFAULT_DEMO_PHASE: DemoPhase = "impact";
export const DEMO_PHASES: readonly { id: DemoPhase; label: string }[] = [
  { id: "baseline", label: "Before the change" },
  { id: "change", label: "Change window" },
  { id: "impact", label: "Impact" },
  { id: "recovery", label: "After the change" },
];

/** Presenter metadata only; no capture or live-query path is enabled here. */
export const DEMO_TRACKS: readonly DemoTrackDefinition[] = [
  {
    id: "track-a-firewall",
    label: "Wireless checkout",
    ticket:
      "A wireless user at the demo site cannot reach checkout after a network change window.",
    scope: "change-a",
    clientIp: "10.71.0.20",
    args: {
      service: "checkout",
      environment: "demo",
      cluster: "cc-a-cilium",
      namespace: "shop",
    },
  },
  {
    id: "track-b-fabric",
    label: "Branch checkout",
    ticket:
      "Checkout fails for a wired branch user after a WAN and data-center change window.",
    scope: "change-b",
    clientIp: "10.61.0.20",
    args: {
      service: "checkout",
      environment: "demo",
      cluster: "cc-b-cilium",
      namespace: "shop",
    },
  },
];

export const DEMO_SCENARIOS: readonly { id: DemoScenario; label: string }[] =
  DEMO_TRACKS.map(({ id, label }) => ({ id, label }));

export function isDemoScenario(value: unknown): value is DemoScenario {
  return DEMO_TRACKS.some((track) => track.id === value);
}

export function requireDemoScenario(value: unknown): DemoScenario {
  if (!isDemoScenario(value))
    throw new Error("This demo track is retired or unsupported.");
  return value;
}

export function demoTrack(scenario: DemoScenario): DemoTrackDefinition {
  return DEMO_TRACKS.find((track) => track.id === scenario)!;
}

export function isDemoPhase(value: unknown): value is DemoPhase {
  return DEMO_PHASES.some((phase) => phase.id === value);
}

export function requireDemoPhase(value: unknown): DemoPhase {
  if (!isDemoPhase(value)) throw new Error("Unsupported demo phase.");
  return value;
}
