import type { ResiliencePosture } from "./spof";

export interface CabPack {
  changeId: string;
  window: { start: string; end: string };
  singlePoints: string[];
  verification: string[];
}

/** CAB pack from observed SPOF posture. It does not dispatch a collector. */
export function cabPack(
  changeId: string,
  window: { start: string; end: string },
  posture: ResiliencePosture,
): CabPack {
  const id = changeId.trim();
  if (!id || id.length > 80) throw new Error("Invalid change identity.");
  return {
    changeId: id,
    window,
    singlePoints: posture.singlePoints.map((row) => row.label),
    verification: [
      "Run Verify change on the saved dependency assertions with before and after windows around the change.",
      "Confirm Stream NetFlow, SC4SNMP and OTel traces still populate health.",
      "Newly blocked conversations stay disabled until a webhook URL is configured.",
    ],
  };
}
