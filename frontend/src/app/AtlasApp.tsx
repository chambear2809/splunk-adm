import { useState } from "react";
import { HealthProvider } from "../data/healthStatus";
import {
  setupClient as nativeSetupClient,
  type SetupClient,
} from "../data/setupClient";
import { Shell } from "./Shell";
import { ApplicationsPage } from "../pages/ApplicationsPage";
import { MapPage } from "../pages/MapPage";
import { HealthPage } from "../pages/HealthPage";
import { SetupPage } from "../pages/SetupPage";
import { HelpPage } from "../pages/HelpPage";
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
}) {
  const [mode, setMode] = useState(state.mode);
  const live = !!client && mode === "live";
  const healthLive = live && page !== "help" && page !== "setup";
  return (
    <HealthProvider client={client} live={healthLive}>
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
        ) : page === "applications" ? (
          <ApplicationsPage
            state={state}
            client={client}
            timezone={timezone}
            inSplunk={inSplunk}
          />
        ) : page === "data_health" ? (
          <HealthPage client={client} live={live} />
        ) : page === "setup" ? (
          <SetupPage
            client={setupClient ?? (inSplunk ? nativeSetupClient : undefined)}
            live={mode === "live"}
          />
        ) : (
          <HelpPage />
        )}
      </Shell>
    </HealthProvider>
  );
}
