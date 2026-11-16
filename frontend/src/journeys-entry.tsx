import { FirewallJourneyEvidence } from "./journeys/FirewallJourneyEvidence";
import { HubbleJourneyEvidence } from "./journeys/HubbleJourneyEvidence";
import { JourneyEvidence } from "./journeys/JourneyEvidence";
import { proxyJourneys } from "./journeys/model";
import type { JourneyEvidenceProps } from "./JourneyLazyEvidence";
import { ImpactMaintenancePlanner } from "./maintenance/ImpactMaintenancePlanner";
import { LiveDependencyMonitor } from "./drift/LiveDependencyMonitor";
import { OwnershipEvidence } from "./businessServices/OwnershipEvidence";
import { DependencyMonitor } from "./drift/DependencyMonitor";
import { BusinessServiceImport } from "./businessServices/BusinessServiceImport";
import { CaseRecords } from "./investigations/CaseRecords";

export const assetVersion =
  typeof __ADM_JOURNEYS_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_JOURNEYS_ASSET_VERSION__;
export function JourneyEvidenceInspection(props: JourneyEvidenceProps) {
  if (props.kind === "cases") return <CaseRecords {...props} />;
  if (props.kind === "ownership") return <OwnershipEvidence {...props} />;
  if (props.kind === "ownershipImport") return <BusinessServiceImport />;
  if (props.kind === "baseline")
    return props.selection ? (
      <LiveDependencyMonitor {...props} selection={props.selection} />
    ) : (
      <DependencyMonitor {...props} />
    );
  if (props.kind === "maintenance")
    return <ImpactMaintenancePlanner {...props} />;
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
