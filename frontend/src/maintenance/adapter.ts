import type { ImpactData } from "../impact/data";
import { appsOf, type FailsResult } from "../impact/model";
import type { AssessmentInput, ServiceEvidence } from "./model";

/**
 * Impact analysis supplies candidate exposure, not qualified operational evidence.
 * Its current reader cannot establish the scope and time guarantees required by
 * the assessment model, so all converted evidence remains unqualified.
 */
export function assessmentInputFromImpact(
  data: ImpactData,
  result: FailsResult,
  options: {
    id: string;
    capturedAt: number;
    window: AssessmentInput["window"];
    scope: string;
  },
): AssessmentInput {
  const services = new Map<string, ServiceEvidence>();
  for (const row of result.rows) {
    for (const app of appsOf(row.conv)) {
      const id = app.name;
      let service = services.get(id);
      if (!service) {
        service = {
          id,
          name: app.name,
          scope: options.scope,
          topology: {
            value: "exposed",
            scope: options.scope,
            source: `${data.source}: ${row.traversal} traversal; ${app.basis} attribution`,
            qualified: false,
            state: data.capped || data.truncated ? "capped" : "unknown",
            observedAt: row.conv.lastSeen ?? options.window.end,
            validUntil: options.capturedAt,
          },
          alternatives: [],
        };
        services.set(id, service);
      }
      for (const name of row.alternate) {
        if (!service.alternatives.some((candidate) => candidate.name === name))
          service.alternatives.push({ name });
      }
    }
  }
  return {
    id: options.id,
    capturedAt: options.capturedAt,
    window: { ...options.window },
    selectedElements: data.elements.map((element) => element.token),
    services: [...services.values()],
  };
}
