import { createRoot } from "react-dom/client";
import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { getThemeOptions } from "@splunk/splunk-utils/themes";
import { username } from "@splunk/splunk-utils/config";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { toolkitDefault } from "./app/interop";
import { resolveUserTheme } from "./app/theme";
import {
  pageFromPath,
  pageURL,
  parseUrlState,
  type Page,
} from "./app/urlState";
import { AtlasApp } from "./app/AtlasApp";
import { jobClient } from "./data/searchClient";
import { prepareDemo } from "./data/demoClient";
import "./styles.css";

const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
async function userTimezone(): Promise<string | undefined> {
  if (!username) return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(
      createRESTURL(`authentication/users/${encodeURIComponent(username)}`, {
        sharing: "system",
      }) + "?output_mode=json",
      { ...getDefaultFetchInit(), signal: controller.signal },
    );
    if (!response.ok) return;
    const data = await response.json();
    const tz: unknown = data.entry?.[0]?.content?.tz;
    if (typeof tz === "string" && tz) {
      new Intl.DateTimeFormat(undefined, { timeZone: tz });
      return tz;
    }
  } catch {
    /* Browser timezone remains available if REST access is unavailable. */
  } finally {
    clearTimeout(timer);
  }
}
async function mount(node: HTMLElement) {
  if (node.dataset.mounted) return;
  node.dataset.mounted = "true";
  try {
    const params = new URLSearchParams(location.search);
    const page: Page | "dependency_map" = __ADM_SPLUNK_BUILD__
      ? pageFromPath(location.pathname)
      : (() => {
          const name =
            location.pathname.split("/").filter(Boolean).at(-1) ??
            "applications";
          return pageFromPath(
            `/app/splunk_adm/${name === "index.html" ? "applications" : name}`,
          );
        })();
    if (page === "dependency_map") {
      location.replace(pageURL("map", params));
      return;
    }
    const state = parseUrlState(params, __ADM_SPLUNK_BUILD__);
    if (page === "map" && state.mode === "demo") await prepareDemo();
    const [preference, timezone] = await Promise.all([
      __ADM_SPLUNK_BUILD__
        ? resolveUserTheme()
        : Promise.resolve(params.get("theme") === "dark" ? "dark" : "light"),
      __ADM_SPLUNK_BUILD__ ? userTimezone() : Promise.resolve(undefined),
    ]);
    const options = getThemeOptions(preference);
    createRoot(node).render(
      <ThemeProvider {...options}>
        <AtlasApp
          page={page}
          state={state}
          client={__ADM_SPLUNK_BUILD__ ? jobClient : undefined}
          theme={options.colorScheme === "dark" ? "dark" : "light"}
          timezone={timezone}
          inSplunk={__ADM_SPLUNK_BUILD__}
        />
      </ThemeProvider>,
    );
  } catch (error) {
    node.textContent = `Application Atlas could not load. ${error instanceof Error ? error.message : "Reload the page."}`;
  }
}
// Simple XML loads custom JS before its HTML panel is necessarily ready.
const existing = document.getElementById("atlas-root");
if (existing) void mount(existing);
else {
  const observer = new MutationObserver(() => {
    const node = document.getElementById("atlas-root");
    if (node) {
      observer.disconnect();
      clearTimeout(timer);
      void mount(node);
    }
  });
  const timer = setTimeout(() => {
    observer.disconnect();
    console.error("Application Atlas mount node did not appear.");
  }, 30000);
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
}
