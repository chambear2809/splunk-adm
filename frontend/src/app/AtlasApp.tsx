import { useState } from "react";
import { deploymentClient as nativeDeploymentClient } from "../data/deploymentClient";
import type { DeploymentClient } from "../data/deploymentHealth";
import { HealthProvider } from "../data/healthStatus";
import type { SetupClient } from "../data/setupClient";
import { Shell } from "./Shell";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { MapPage } from "../pages/MapPage";
import { EndpointsLazyPage } from "../endpoints/EndpointsLazyPage";
import { AdminLazyPage } from "../admin/AdminLazyPage";
import { HelpPage } from "../pages/HelpPage";
import { DevicePage } from "../pages/DevicePage";
import { ExploreTabs } from "../pages/ExploreTools";
import { ImpactLazyPage } from "../impact/ImpactLazyPage";
import { CasesPage } from "../pages/CasesPage";
import { MulticastLazyPage } from "../multicast/MulticastLazyPage";
import { ProtocolsLazyPage } from "../protocols/ProtocolsLazyPage";
import { MigrationLazyPage } from "../migration/MigrationLazyPage";
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
  const healthLive =
    live &&
    page !== "help" &&
    page !== "cases" &&
    page !== "multicast" &&
    page !== "protocols";
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
            <EndpointsLazyPage
              key={`${user ?? "anonymous"}:${mode}`}
              client={client}
              live={live}
            />
          </main>
        ) : page === "migration" ? (
          <main className="atlas-page atlas-page-wide atlas-explore">
            <h1 className="atlas-visually-hidden">Explore</h1>
            <ExploreTabs active="migration" />
            <MigrationLazyPage
              key={`${user ?? "anonymous"}:${mode}`}
              client={client}
              live={live}
            />
          </main>
        ) : page === "multicast" ? (
          <MulticastLazyPage
            key={`${user ?? "anonymous"}:${mode}`}
            client={client}
            live={live}
            timezone={timezone}
          />
        ) : page === "protocols" ? (
          <ProtocolsLazyPage
            key={`${user ?? "anonymous"}:${mode}`}
            client={client}
            live={live}
            timezone={timezone}
            theme={theme}
          />
        ) : page === "applications" ? (
          <ApplicationsPage
            state={state}
            client={client}
            timezone={timezone}
            inSplunk={inSplunk}
          />
        ) : page === "cases" ? (
          <CasesPage />
        ) : page === "data_health" || page === "setup" ? (
          <AdminLazyPage
            tab={page}
            client={client}
            live={live}
            setupLive={mode === "live"}
            timezone={timezone}
            inSplunk={inSplunk}
            setupClient={setupClient}
            deploymentClient={deployment}
          />
        ) : page === "impact" ? (
          <ImpactLazyPage
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
