import { ChangeTimelineInspection } from "./changeCorrelation/ChangeTimelineInspection";

export const assetVersion =
  typeof __ADM_HISTORY_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_HISTORY_ASSET_VERSION__;

export { ChangeTimelineInspection };
export { CmdbWorkspace } from "./cmdb/CmdbWorkspace";
