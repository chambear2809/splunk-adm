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
import {
  incompleteSearchError,
  SearchResultLimitError,
} from "../../frontend/src/data/searchClient";
import type {
  SetupClient,
  SetupSnapshot,
  SetupMacro,
  BuilderSearch,
  IndexMacro,
  CiscoIntegrationStatus,
} from "../../frontend/src/data/setupClient";
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
      ciscoIntegration: {
        macros: [
          {
            name: "adm_data_contract_version",
            definition: "1",
            canWrite: false,
          },
          {
            name: "adm_graph",
            definition: "search index=adm_summary",
            canWrite: false,
          },
          {
            name: "adm_graph_v2",
            definition: "search index=adm_summary_v2",
            canWrite: false,
          },
          {
            name: "adm_index_summary_v2",
            definition: "index=adm_summary_v2",
            canWrite: false,
          },
          {
            name: "adm_summary_index_v2_name",
            definition: "adm_summary_v2",
            canWrite: false,
          },
          {
            name: "adm_network_client_history_observations",
            definition: "search index=adm_network_client_history",
            canWrite: false,
          },
          {
            name: "adm_network_client_history_build",
            definition: "search index=cisco_catalyst OR index=cisco_meraki",
            canWrite: false,
          },
        ],
        searches: [
          "ADM - Network client history builder",
          "ADM - Conversation rollup v2",
          "ADM - Traffic observation rollup v2",
        ].map((name) => ({
          name,
          disabled: true,
          scheduled: true,
          canWrite: false,
        })),
        summaryIndex: { name: "adm_summary_v2", exists: true },
        sourceProfiles: {
          rows: [
            {
              _key: "a".repeat(64),
              mapping_key: "c".repeat(64),
              duplicate_count: 1,
              source: "stream_ipfix",
              source_authority: "192.0.2.20",
              domain_kind: "exporter",
              observation_domain_present: "1",
              observation_domain_id: "0",
              vpn_id: "42",
              routing_domain: "42",
              scope: "prod",
              cluster: "cluster-a",
              mapping_status: "mapped",
              profile: "catalyst_sdwan_ipfix",
            },
          ],
          complete: true,
        },
        clusterSettings: {
          rows: [
            {
              _key: "b".repeat(64),
              cluster: "cluster-a",
              lb_mode: "snat",
              ingress_mode: "dedicated",
              l2announcements_enabled: "0",
              mapping_status: "mapped",
            },
          ],
          complete: true,
        },
        state: "staged",
        reasons: [],
      } satisfies CiscoIntegrationStatus,
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
        return {
          rows: catalogCapture.rows,
          warnings: ["narrowed warning"],
          errors: [],
        };
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
        return { rows: [], warnings: [], errors: [] };
      if (faultScenario === "marker-only-catalog")
        return {
          rows: [{ _key: "adm-catalog-empty", updated: 10 }],
          warnings: [],
          errors: [],
        };
      if (faultScenario === "catalog-and-fallback-fail")
        throw new Error("Catalog unavailable.");
      if (faultScenario === "stale") {
        await new Promise((resolve) => setTimeout(resolve, 250));
        return { rows: catalogCapture.rows, warnings: [], errors: [] };
      }
      const service = request.search.match(/WHERE service="([^"]+)"/)?.[1];
      return {
        rows: service
          ? catalogCapture.rows.filter((row) => row.service === service)
          : catalogCapture.rows,
        warnings: [],
        errors: [],
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
        errors: [],
      };
    }
    if (request.search.startsWith('| `adm_find("')) {
      const query = request.search.match(/adm_find\("(.*)"\)/)?.[1] ?? "";
      if (faultScenario === "find-app-fails")
        throw new Error("application search permission denied");
      const capture = findCapture.queries.find((item) => item.query === query);
      if (faultScenario === "find-stale" && query === "10.42.0.15")
        await new Promise((resolve) => setTimeout(resolve, 250));
      if (faultScenario === "find-stale" && query === "db")
        return {
          rows: findCapture.queries
            .flatMap((item) => item.rows)
            .filter((row) => row.service === "checkout"),
          warnings: [],
          errors: [],
        };
      return { rows: capture?.rows ?? [], warnings: [], errors: [] };
    }
    if (request.search.startsWith('| `adm_find_network_client("')) {
      if (faultScenario === "find-client-fails")
        throw new Error("network-client search was truncated");
      return {
        rows: [
          {
            row_type: "network_client",
            _key: "meraki:org-a/network-a:00:11:22:33:44:55",
            client_mac: "00:11:22:33:44:55",
            client_ip: "10.71.0.20",
            source: "meraki",
            access_platform: "Meraki",
            source_authority: "org-a/network-a",
            routing_domain: "vrf-a",
            attachment_status: "unmapped",
            mapping_status: "unmapped",
            attachment_basis: "meraki_association_event",
            source_time: 1791700000,
            received_time: 1791700001,
            attachment_event_time: 1791700000,
            attachment_received_time: 1791700001,
            quality_reason: "No exact routing scope mapping",
          },
        ],
        warnings:
          faultScenario === "find-client-warning"
            ? ["Network-client evidence may be incomplete."]
            : [],
        errors: [],
      };
    }
    if (request.search === "`adm_topology`")
      return { rows: [], warnings: [], errors: [] };
    window.__ADM_LAST_EARLIEST__ = request.earliest;
    window.__ADM_LAST_GRAPH_SEARCH__ = request.search;
    const scenario = faultScenario;
    if (scenario === "permission")
      throw new Error(
        "The Splunk search failed. Splunk reported: index=otel permission denied",
      );
    if (scenario === "incomplete") {
      throw new Error(incompleteSearchError({ content: { isFinalized: "1" } }));
    }
    const rows = structuredClone(aciRows.rows) as Record<string, unknown>[];
    if (
      scenario === "partial-shared-handoff" ||
      scenario === "missing-client-handoff"
    ) {
      const frontend = rows.find(
        (row) =>
          row.row_type === "node" &&
          row.id ===
            "k8s_service:demo-cluster/shop/checkout-api/10.50.0.20:8080",
      );
      if (!frontend)
        throw new Error("Captured checkout frontend is unavailable.");
      const aggregate = rows.find(
        (row) =>
          row.row_type === "edge" &&
          row.relationship === "forwards_to" &&
          row.source === frontend.id,
      );
      const selectedClientEdge = rows.find(
        (row) =>
          row.row_type === "edge" &&
          row.relationship === "communicates_with" &&
          row.source === "vm:prod/10.30.40.25" &&
          row.target === frontend.id,
      );
      if (!aggregate || !selectedClientEdge)
        throw new Error("Captured checkout handoff edges are unavailable.");
      if (scenario === "partial-shared-handoff") {
        const determinedTarget = aggregate.target;
        Object.assign(frontend, {
          attr_handoff_coverage: "partial",
          attr_handoff_connections: "2",
          attr_handoff_determined: "1",
          attr_handoff_unresolved: "1",
        });
        Object.assign(selectedClientEdge, {
          client_handoff_coverage: "partial",
          client_handoff_connections: "2",
          client_handoff_determined: "1",
          client_handoff_unresolved: "1",
          client_handoffs: JSON.stringify([
            {
              target: determinedTarget,
              basis: "hubble_client_tuple",
              connections: 1,
              receiving_nodes: ["node-b"],
              observers: ["hubble:node-b"],
            },
          ]),
        });
      } else {
        Object.assign(frontend, {
          attr_handoff_coverage: "complete",
          attr_handoff_connections: "1",
          attr_handoff_determined: "1",
          attr_handoff_unresolved: "0",
        });
        delete selectedClientEdge.client_handoff_coverage;
        delete selectedClientEdge.client_handoff_connections;
        delete selectedClientEdge.client_handoff_determined;
        delete selectedClientEdge.client_handoff_unresolved;
        delete selectedClientEdge.client_handoffs;
      }
    }
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
      warnings:
        scenario === "graph-warning" ? ["Peer indexer-3 was unreachable."] : [],
      errors: [],
    };
  }
}
const params = new URLSearchParams(location.search);
const page = params.get("page") ?? "map";
const stateParams = new URLSearchParams(params);
// Fault scenarios are harness configuration, not demo scenario state.
if (
  params.get("scenario") === "permission" ||
  params.get("scenario") === "incomplete" ||
  params.get("scenario") === "graph-warning"
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
