import { useEffect, useState } from "react";
import type { ImpactData } from "../impact/data";
import type { FailsResult } from "../impact/model";
import { assessmentInputFromImpact } from "./adapter";
import { MaintenancePlanner } from "./MaintenancePlanner";
import type { AssessmentInput } from "./model";

export type ImpactPlanningProps = {
  data?: ImpactData;
  result?: FailsResult;
  selection: {
    elements: string[];
    earliest: string;
    latest?: string;
    scope: string;
    demo: boolean;
  };
  loading?: boolean;
  denied?: boolean;
};
/** Retain earlier planning captures across refresh; never admit an unreturned window. */
export function ImpactMaintenancePlanner({
  data,
  result,
  selection,
  loading,
  denied,
}: ImpactPlanningProps) {
  const key = JSON.stringify(selection);
  const [snapshot, setSnapshot] = useState<{
    key: string;
    input: AssessmentInput;
    demo: boolean;
  }>();
  useEffect(() => {
    if (denied) {
      setSnapshot(undefined);
      return;
    }
    if (!data?.graph || !result) return;
    const start = Date.parse(data.graph.window.start) / 1000,
      end = Date.parse(data.graph.window.end) / 1000;
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start)
      return;
    setSnapshot({
      key,
      demo: selection.demo,
      input: assessmentInputFromImpact(data, result, {
        id: `impact:${key}`,
        capturedAt: Date.now() / 1000,
        window: { start, end },
        scope: selection.scope || (selection.demo ? "synthetic-demo" : ""),
      }),
    });
  }, [data, result, key, denied, selection.demo, selection.scope]);
  if (denied || !snapshot)
    return (
      <section aria-label="Maintenance planning">
        <h2>Maintenance planning</h2>
        <p role="status">
          A permitted impact capture with an absolute returned window is
          unavailable. Readiness and capacity cannot be assessed.
        </p>
      </section>
    );
  return (
    <MaintenancePlanner
      input={snapshot.input}
      description={
        snapshot.demo
          ? "Demo data with synthetic topology context. Operational readiness and measured capacity are not established."
          : "Potential exposure from the loaded impact capture. Operational readiness and measured capacity require separate qualified evidence."
      }
      unavailableReason={
        loading || !result || snapshot.key !== key
          ? "Previous planning evidence is retained. Capture controls are unavailable until the selected impact scope and window return successfully in If this fails mode."
          : undefined
      }
    />
  );
}
