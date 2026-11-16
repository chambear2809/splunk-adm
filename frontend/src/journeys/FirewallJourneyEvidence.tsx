import type { NatObservation } from "../graph";
import type { EvidenceWindow } from "../data/evidence";
import { natJourneys } from "./model";
import { JourneyEvidence } from "./JourneyEvidence";

export function FirewallJourneyEvidence({
  observations,
  truncated,
  window,
}: {
  observations: NatObservation[];
  truncated?: boolean;
  window?: EvidenceWindow;
}) {
  if (!observations.length && !truncated) return null;
  const results = window
    ? [...new Set(observations.map((record) => record.scope))].map((scope) =>
        natJourneys(
          observations.filter((record) => record.scope === scope),
          scope,
          window,
          truncated,
        ),
      )
    : [];
  return (
    <JourneyEvidence
      title="Firewall translation evidence"
      window={window}
      result={{
        journeys: results.flatMap((result) => result.journeys),
        gaps: window
          ? [
              ...results.flatMap((result) => result.gaps),
              ...(truncated && !results.length
                ? ["Additional NAT observations may have been omitted."]
                : []),
            ]
          : [
              "The loaded graph window is unavailable; translation evidence cannot be admitted.",
            ],
      }}
    />
  );
}
