import * as contract from "./shared/contract";
import * as fields from "./shared/fields";
import * as filterSpl from "./shared/filterSpl";
import * as format from "./shared/format";
import * as runner from "./shared/runner";
import * as streamReadiness from "./shared/streamReadiness";
import * as nxosSyslog from "./shared/adapters/nxosSyslog";
import * as ui from "./shared/ui";

export { ProtocolsPage } from "./ProtocolsPage";
export const assetVersion = __ADM_PROTOCOLS_CORE_ASSET_VERSION__;

/**
 * Expose the shared Protocols SDK on a frozen global bridge so individual
 * per-lens IIFE bundles do not duplicate React or UI primitives.
 */
const runtime = globalThis as typeof globalThis & {
  __AtlasProtocolsCore?: unknown;
};
if (!runtime.__AtlasProtocolsCore) {
  Object.defineProperty(runtime, "__AtlasProtocolsCore", {
    value: Object.freeze({
      assetVersion,
      contract,
      fields,
      filterSpl,
      format,
      runner,
      streamReadiness,
      nxosSyslog,
      ui,
    }),
  });
}
