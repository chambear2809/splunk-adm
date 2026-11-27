import "./endpoints.css";
import { EndpointsPage } from "../pages/EndpointsPage";
import { EndpointEvidencePanels } from "../EndpointEvidencePanels";
import { MapDnsInspection } from "../MapDnsInspection";
import type { SearchClient } from "../data/searchClient";

export const assetVersion =
  typeof __ADM_ENDPOINTS_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_ENDPOINTS_ASSET_VERSION__;

export interface EndpointsViewProps {
  client?: SearchClient;
  live: boolean;
}

export function EndpointsView({ client, live }: EndpointsViewProps) {
  return (
    <EndpointsPage
      client={client}
      live={live}
      renderEvidence={(selection) =>
        client && live ? (
          <EndpointEvidencePanels
            key={JSON.stringify(selection)}
            selection={selection}
            client={client}
          />
        ) : null
      }
    />
  );
}

export { MapDnsInspection };
