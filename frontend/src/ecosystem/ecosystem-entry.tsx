import "./ecosystem.css";

export const assetVersion =
  typeof __ADM_ECOSYSTEM_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_ECOSYSTEM_ASSET_VERSION__;
export { EcosystemEvidencePanel } from "./EcosystemEvidencePanel";
export { EcosystemReceiptPanel } from "./EcosystemReceiptPanel";
