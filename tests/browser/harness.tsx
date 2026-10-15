import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { AtlasApp } from "../../frontend/src/app/AtlasApp";
import { parseUrlState, type Page } from "../../frontend/src/app/urlState";
import type {
  SearchClient,
  SearchRequest,
} from "../../frontend/src/data/searchClient";
import type {
  SetupClient,
  SetupSnapshot,
  SetupMacro,
  BuilderSearch,
  IndexMacro,
} from "../../frontend/src/data/setupClient";
import { FINALIZED_SEARCH_WARNING } from "../../frontend/src/provider";
import scopes from "../../fixtures/demo-scopes.json";
import aciRows from "../../fixtures/demo-rows-aci.json";
import catalogCapture from "../../fixtures/demo-catalog.json";
import findCapture from "../../fixtures/demo-find.json";
import "../../frontend/src/styles.css";
const ThemeProvider = toolkitDefault(ThemeProviderExport);
const queryParams = new URLSearchParams(location.search);
const faultScenario = queryParams.get("fault") ?? queryParams.get("scenario");
const setupRequest = (value: string) => {
  const target = window as Window & { __ADM_SETUP_REQUESTS__?: string[] };
  target.__ADM_SETUP_REQUESTS__ ??= [];
  target.__ADM_SETUP_REQUESTS__.push(value);
};

class FakeSetupClient implements SetupClient {
  private snapshot: SetupSnapshot;
  private writes = 0;
  constructor() {
    const uppercase = faultScenario === "setup-uppercase";
    const names = [
      "adm_index_netflow",
      "adm_index_dcn",
      "adm_index_ftd",
      "adm_index_isovalent",
      "adm_index_k8s",
      "adm_index_traces",
      "adm_index_hubble",
      "adm_index_summary",
      "adm_summary_index_name",
    ] as const;
    const macros: SetupMacro[] = names.map((name) => ({
      name,
      definition:
        name === "adm_summary_index_name"
          ? "adm_summary"
          : name === "adm_index_summary"
            ? "index=adm_summary"
            : "index=adm_" + name.slice(10),
      canWrite: true,
    }));
    const builders = [
      "ADM - Identity builder",
      "ADM - Service binding",
      "ADM - Service backends",
      "ADM - ACI policy",
      "ADM - Interface inventory",
      "ADM - Conversation rollup",
      "ADM - Application catalog",
    ] as const;
    this.snapshot = {
      authorized: faultScenario !== "setup-unknown",
      macros,
      summaryIndex: { name: "adm_summary", exists: true },
      observerScopes: {
        rows:
          faultScenario === "setup-blank"
            ? []
            : [
                {
                  _key: "aci:prod",
                  observer_kind: uppercase ? "ACI" : "aci",
                  observer: uppercase ? "ACI-01" : "aci-01",
                  scope: "prod",
                  cluster: "cluster-a",
                },
              ],
        complete: true,
      },
      savedSearches: builders.map((name) => ({
        name,
        disabled: true,
        scheduled: true,
        canWrite: true,
      })),
      warnings: [],
    };
  }
  async read(signal?: AbortSignal) {
    setupRequest("read");
    if (faultScenario === "setup-stale")
      await new Promise((resolve) => setTimeout(resolve, 250));
    if (faultScenario === "setup-partial" && this.writes > 0)
      throw new Error("verification failed");
    if (signal?.aborted) throw new Error("cancelled");
    return this.snapshot;
  }
  async setIndexMacro(name: IndexMacro, index: string) {
    setupRequest(`macro:${name}:${index}`);
    this.writes += 1;
    if (faultScenario === "setup-fail")
      throw new Error("setup mutation failed");
    const macro = this.snapshot.macros.find((row) => row.name === name);
    if (macro)
      macro.definition =
        name === "adm_summary_index_name" ? index : `index=${index}`;
  }
  async setBuilderEnabled(name: BuilderSearch) {
    setupRequest(`builder:${name}`);
    this.writes += 1;
    if (faultScenario === "setup-fail")
      throw new Error("setup mutation failed");
    const job = this.snapshot.savedSearches.find((row) => row.name === name);
    if (job) job.disabled = false;
  }
}
class FakeSearchClient implements SearchClient {
  async search(request: SearchRequest) {
    window.__ADM_REQUESTS__ ??= [];
    window.__ADM_REQUESTS__.push({
      spl: request.search,
      earliest: request.earliest,
      latest: request.latest ?? "now",
    });
    if (request.search === "| inputlookup adm_app_catalog") {
      if (faultScenario === "empty-catalog") return { rows: [], warnings: [] };
      if (faultScenario === "stale") {
        await new Promise((resolve) => setTimeout(resolve, 250));
        return { rows: catalogCapture.rows, warnings: [] };
      }
      return { rows: catalogCapture.rows, warnings: [] };
    }
    if (request.search === "| `adm_scope_options`")
      return { rows: scopes.rows, warnings: [] };
    if (request.search.startsWith('| `adm_find("')) {
      const query = request.search.match(/adm_find\("(.*)"\)/)?.[1] ?? "";
      const capture = findCapture.queries.find((item) => item.query === query);
      if (faultScenario === "find-stale" && query === "10.42.0.15")
        await new Promise((resolve) => setTimeout(resolve, 250));
      if (faultScenario === "find-stale" && query === "db")
        return {
          rows: findCapture.queries
            .flatMap((item) => item.rows)
            .filter((row) => row.service === "checkout"),
          warnings: [],
        };
      return { rows: capture?.rows ?? [], warnings: [] };
    }
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
        user="browser-viewer"
        usePersonaDefault={!queryParams.has("tab")}
        page={page as Page}
        state={state}
        client={new FakeSearchClient()}
        setupClient={new FakeSetupClient()}
        theme={dark ? "dark" : "light"}
      />
    </ThemeProvider>,
  );
} catch (error) {
  root.textContent = error instanceof Error ? error.message : "Invalid state";
}
