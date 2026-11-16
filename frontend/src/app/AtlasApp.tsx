import { useState } from "react";
import { deploymentClient as nativeDeploymentClient } from "../data/deploymentClient";
import type { DeploymentClient } from "../data/deploymentHealth";
import { HealthProvider } from "../data/healthStatus";
import {
  setupClient as nativeSetupClient,
  type SetupClient,
} from "../data/setupClient";
import { Shell } from "./Shell";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { MapPage } from "../pages/MapPage";
import { EndpointsPage } from "../pages/EndpointsPage";
import { EndpointEvidencePanels } from "../EndpointEvidencePanels";
import { HealthPage } from "../pages/HealthPage";
import { SetupPage } from "../pages/SetupPage";
import { HelpPage } from "../pages/HelpPage";
import { AdminPage } from "../pages/AdminPage";
import { DevicePage } from "../pages/DevicePage";
import { ExploreTabs } from "../pages/ExploreTools";
import { ImpactPage } from "../impact/ImpactPage";
import type { SearchClient } from "../data/searchClient";
import type { Page, UrlState } from "./urlState";
import type { Theme } from "../theme";
export function AtlasApp({
  page,
  state,
  client,
  theme,
  timezone,
  inSplunk = false,
  setupClient,
  deploymentClient,
  user,
  usePersonaDefault,
}: {
  user?: string;
  usePersonaDefault?: boolean;
  page: Page;
  state: UrlState;
  client?: SearchClient;
  theme: Theme;
  timezone?: string;
  inSplunk?: boolean;
  setupClient?: SetupClient;
  deploymentClient?: DeploymentClient;
}) {
  const [mode, setMode] = useState(state.mode);
  const live = !!client && mode === "live";
  const healthLive = live && page !== "help";
  const deployment =
    deploymentClient ?? (inSplunk ? nativeDeploymentClient : undefined);
  return (
    <HealthProvider
      client={client}
      live={healthLive}
      scope={page === "setup" ? "jobs" : "full"}
      deploymentClient={deployment}
    >
      <Shell page={page} client={client} live={live}>
        {page === "map" ? (
          <MapPage
            user={user}
            usePersonaDefault={usePersonaDefault}
            client={client}
            initialState={state}
            onModeChange={setMode}
            theme={theme}
            timezone={timezone}
            inSplunk={inSplunk}
          />
        ) : page === "endpoints" ? (
          <main className="atlas-page atlas-page-wide atlas-explore">
            <h1 className="atlas-visually-hidden">Explore</h1>
            <ExploreTabs active="endpoints" />
            <EndpointsPage
              key={`${user ?? "anonymous"}:${mode}`}
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
          </main>
        ) : page === "applications" ? (
          <ApplicationsPage
            state={state}
            client={client}
            timezone={timezone}
            inSplunk={inSplunk}
          />
        ) : page === "data_health" ? (
          <AdminPage tab="data_health">
            <HealthPage client={client} live={live} timezone={timezone} />
          </AdminPage>
        ) : page === "setup" ? (
          <AdminPage tab="setup">
            <SetupPage
              client={setupClient ?? (inSplunk ? nativeSetupClient : undefined)}
              live={mode === "live"}
              deploymentClient={deployment}
            />
          </AdminPage>
        ) : page === "impact" ? (
          <ImpactPage
            client={client}
            live={live}
            timezone={timezone}
            inSplunk={inSplunk}
            theme={theme}
          />
        ) : page === "device" ? (
          <DevicePage
            state={state}
            client={client}
            live={live}
            timezone={timezone}
            inSplunk={inSplunk}
            theme={theme}
          />
        ) : (
          <HelpPage />
        )}
      </Shell>
    </HealthProvider>
  );
}
