import "./admin.css";
import { AdminPage } from "../pages/AdminPage";
import { HealthPage } from "../pages/HealthPage";
import { SetupPage } from "../pages/SetupPage";
import {
  setupClient as nativeSetupClient,
  type SetupClient,
} from "../data/setupClient";
import type { DeploymentClient } from "../data/deploymentHealth";
import type { SearchClient } from "../data/searchClient";

export const assetVersion =
  typeof __ADM_ADMIN_ASSET_VERSION__ === "undefined"
    ? "development"
    : __ADM_ADMIN_ASSET_VERSION__;

export interface AdminViewProps {
  tab: "setup" | "data_health";
  client?: SearchClient;
  live: boolean;
  setupLive: boolean;
  timezone?: string;
  inSplunk: boolean;
  setupClient?: SetupClient;
  deploymentClient?: DeploymentClient;
}

export function AdminView({
  tab,
  client,
  live,
  setupLive,
  timezone,
  inSplunk,
  setupClient,
  deploymentClient,
}: AdminViewProps) {
  return (
    <AdminPage tab={tab}>
      {tab === "data_health" ? (
        <HealthPage client={client} live={live} timezone={timezone} />
      ) : (
        <SetupPage
          client={setupClient ?? (inSplunk ? nativeSetupClient : undefined)}
          live={setupLive}
          deploymentClient={deploymentClient}
        />
      )}
    </AdminPage>
  );
}
