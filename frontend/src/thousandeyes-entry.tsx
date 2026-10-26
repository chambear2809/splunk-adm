import { ThousandEyesEvidenceInspection as Inspection } from "./ThousandEyesEvidencePanel";
import { loadThousandEyesEvidence } from "./data/thousandEyesEvidence";
import { compareThousandEyesMeasurements } from "./data/thousandEyesAttribution";
import type { ThousandEyesInspectionProps } from "./ThousandEyesLazyInspection";

export const assetVersion =
  typeof __ADM_TE_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_TE_ASSET_VERSION__;

export function ThousandEyesEvidenceInspection(
  props: ThousandEyesInspectionProps,
) {
  return (
    <Inspection
      {...props}
      loadEvidence={loadThousandEyesEvidence}
      compareMeasurements={compareThousandEyesMeasurements}
    />
  );
}
