import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { AtlasApp } from "../../frontend/src/app/AtlasApp";
import { parseUrlState, type Page } from "../../frontend/src/app/urlState";
import type {
  SearchClient,
  SearchRequest,
} from "../../frontend/src/data/searchClient";
import { FINALIZED_SEARCH_WARNING } from "../../frontend/src/provider";
import scopes from "../../fixtures/demo-scopes.json";
import aciRows from "../../fixtures/demo-rows-aci.json";
import "../../frontend/src/styles.css";
const ThemeProvider = toolkitDefault(ThemeProviderExport);
const faultScenario = new URLSearchParams(location.search).get("scenario");
class FakeSearchClient implements SearchClient {
  async search(request: SearchRequest) {
    window.__ADM_REQUESTS__ ??= [];
    window.__ADM_REQUESTS__.push({
      spl: request.search,
      earliest: request.earliest,
      latest: request.latest ?? "now",
    });
    if (request.search === "| `adm_scope_options`")
      return { rows: scopes.rows, warnings: [] };
    if (request.search === "`adm_topology`") return { rows: [], warnings: [] };
    window.__ADM_LAST_EARLIEST__ = request.earliest;
    window.__ADM_LAST_GRAPH_SEARCH__ = request.search;
    const scenario = faultScenario;
    if (scenario === "permission")
      throw new Error(
        "The Splunk search failed. Splunk reported: index=otel permission denied",
      );
    return {
      rows: aciRows.rows,
      warnings: scenario === "incomplete" ? [FINALIZED_SEARCH_WARNING] : [],
    };
  }
}
const params = new URLSearchParams(location.search);
const page = params.get("page") ?? "map";
const stateParams = new URLSearchParams(params);
// Fault scenarios are harness configuration, not demo scenario state.
if (
  params.get("scenario") === "permission" ||
  params.get("scenario") === "incomplete"
)
  stateParams.delete("scenario");
const root = document.getElementById("adm-root");
if (!root) throw new Error("Missing browser test root");
try {
  const state = parseUrlState(stateParams);
  const dark = params.get("theme") === "dark";
  createRoot(root).render(
    <ThemeProvider family="enterprise" colorScheme={dark ? "dark" : "light"}>
      <AtlasApp
        page={page as Page}
        state={state}
        client={new FakeSearchClient()}
        theme={dark ? "dark" : "light"}
      />
    </ThemeProvider>,
  );
} catch (error) {
  root.textContent = error instanceof Error ? error.message : "Invalid state";
}
