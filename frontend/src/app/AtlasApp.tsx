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
}: {
  page: Page;
  state: UrlState;
  client?: SearchClient;
  theme: Theme;
  timezone?: string;
  inSplunk?: boolean;
}) {
  return (
    <Shell page={page}>
      {page === "map" ? (
        <MapPage
          client={client}
          initialState={state}
          theme={theme}
          timezone={timezone}
          inSplunk={inSplunk}
        />
      ) : page === "applications" ? (
        <ApplicationsPage state={state} />
      ) : page === "data_health" ? (
        <HealthPage client={client} live={inSplunk && state.mode === "live"} />
      ) : page === "setup" ? (
        <SetupPage />
      ) : (
        <HelpPage />
      )}
    </Shell>
  );
}
