import "./o11y.css";

export const assetVersion =
  typeof __ADM_O11Y_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_O11Y_ASSET_VERSION__;
export { MapServiceHealthInspection } from "../MapServiceHealthInspection";
