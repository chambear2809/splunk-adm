import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { DeepLinkNotice } from "../../frontend/src/app/DeepLinkNotice";
import { AtlasApp } from "../../frontend/src/app/AtlasApp";
import {
  recoverUrlState,
  writeUrlState,
  type Page,
} from "../../frontend/src/app/urlState";
import type {
  SearchClient,
  SearchRequest,
} from "../../frontend/src/data/searchClient";
import { SearchResultLimitError } from "../../frontend/src/data/searchClient";
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
    if (request.search.startsWith("| inputlookup adm_app_catalog")) {
      if (
        faultScenario === "catalog-overlimit-narrowed" &&
        request.search.includes(' WHERE service="')
      )
        return { rows: catalogCapture.rows, warnings: ["narrowed warning"] };
      if (
        ["catalog-overlimit", "catalog-overlimit-narrowed"].includes(
          faultScenario ?? "",
        )
      )
        throw new SearchResultLimitError(5000);
      if (
        ["empty-catalog", "empty-catalog-fallback-fails"].includes(
          faultScenario ?? "",
        )
      )
        return { rows: [], warnings: [] };
      if (faultScenario === "marker-only-catalog")
        return {
          rows: [{ _key: "adm-catalog-empty", updated: 10 }],
          warnings: [],
        };
      if (faultScenario === "catalog-and-fallback-fail")
        throw new Error("Catalog unavailable.");
      if (faultScenario === "stale") {
        await new Promise((resolve) => setTimeout(resolve, 250));
        return { rows: catalogCapture.rows, warnings: [] };
      }
      const service = request.search.match(/WHERE service="([^"]+)"/)?.[1];
      return {
        rows: service
          ? catalogCapture.rows.filter((row) => row.service === service)
          : catalogCapture.rows,
        warnings: [],
      };
    }
    if (request.search === "| `adm_scope_options`") {
      if (
        ["empty-catalog-fallback-fails", "catalog-and-fallback-fail"].includes(
          faultScenario ?? "",
        )
      )
        throw new Error("Configured scopes unavailable.");
      return {
        rows:
          faultScenario === "single-scope"
            ? scopes.rows
                .filter((row) => row.service === "frontend")
                .slice(0, 1)
            : scopes.rows,
        warnings: [],
      };
    }
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
    const rows = structuredClone(aciRows.rows) as Record<string, unknown>[];
    if (scenario === "vlan-ui") {
      const node = rows.find(
        (row) =>
          row.row_type === "node" && row.endpoint_kind === "k8s_node_proxy",
      );
      if (node) {
        node.attr_epg = "EPG-ui";
        node.attr_vlan = "1030";
        node.attr_bridge_domain = "bd-clients";
        node.attr_network_history_capped = "1";
      }
      const edge = rows.find(
        (row) =>
          row.row_type === "edge" && row.relationship === "communicates_with",
      );
      if (edge)
        edge.vlan_observations = JSON.stringify([
          {
            vlan: 1030,
            position: "ingress",
            exporter: "198.51.100.10",
            interface_index: "49",
            src_ip: "10.0.0.1",
            dest_ip: "10.0.0.2",
            first_seen: 1791373500,
            last_seen: 1791373520,
          },
        ]);
      const incomplete = rows.find(
        (row) =>
          row.row_type === "node" &&
          row.endpoint_kind === "k8s_node_proxy" &&
          row !== node,
      );
      if (incomplete) {
        incomplete.attr_tenant = "shop";
        incomplete.attr_epg = "EPG-incomplete";
        incomplete.attr_mac = "02:00:00:00:00:02";
        incomplete.attr_vlan_status = "incomplete";
        incomplete.attr_bridge_domain_status = "incomplete";
      }
    }
    return {
      rows,
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
  const { state, notice } = recoverUrlState(stateParams);
  if (notice) writeUrlState(state);
  const dark = params.get("theme") === "dark";
  createRoot(root).render(
    <ThemeProvider family="enterprise" colorScheme={dark ? "dark" : "light"}>
      <DeepLinkNotice message={notice} />
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
