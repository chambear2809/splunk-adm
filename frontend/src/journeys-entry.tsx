import { FirewallJourneyEvidence } from "./journeys/FirewallJourneyEvidence";
import { HubbleJourneyEvidence } from "./journeys/HubbleJourneyEvidence";
import { JourneyEvidence } from "./journeys/JourneyEvidence";
import { proxyJourneys } from "./journeys/model";
import type { JourneyEvidenceProps } from "./JourneyLazyEvidence";

export const assetVersion =
  typeof __ADM_JOURNEYS_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_JOURNEYS_ASSET_VERSION__;
export function JourneyEvidenceInspection(props: JourneyEvidenceProps) {
  if (props.kind === "nat") return <FirewallJourneyEvidence {...props} />;
  if (props.kind === "hubble") return <HubbleJourneyEvidence {...props} />;
  return (
    <JourneyEvidence
      title="Proxy request legs"
      result={proxyJourneys(props.result, props.result.selection)}
      window={props.result.selection.window}
    />
  );
}
