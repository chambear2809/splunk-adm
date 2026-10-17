import { useEffect, useState } from "react";
import { createStaticURL } from "@splunk/splunk-utils/url";
import { parseScopes, type ScopeOption } from "./scopes";
import type { SearchClient } from "./searchClient";
import demoScopes from "../../../fixtures/demo-scopes.json";
import networkingScopes from "../../../fixtures/demo-networking-scopes.json";
import type { DemoScenario } from "./demoClient";
export function useScopeOptions(
  live: boolean,
  client?: SearchClient,
  scenario: DemoScenario = "aci",
) {
  const [state, setState] = useState<{
    rows: ScopeOption[];
    loading: boolean;
    error?: string;
    warnings?: string[];
  }>({ rows: [], loading: true });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setState({ rows: [], loading: true });
    const timer = setTimeout(() => controller.abort(), 120000);
    const load = async () => {
      if (live) {
        if (!client)
          throw new Error("Scope options are available inside Splunk.");
        const result = await client.search({
          search: "| `adm_scope_options`",
          earliest: "0",
          latest: "now",
          maxRows: 20000,
          signal: controller.signal,
        });
        return { rows: parseScopes(result.rows), warnings: result.warnings };
      }
      if (!__ADM_SPLUNK_BUILD__)
        return {
          rows: parseScopes(
            scenario === "catalyst-aci" || scenario === "meraki-nxos"
              ? networkingScopes.rows
              : demoScopes.rows,
          ),
        };
      const response = await fetch(
        createStaticURL(
          `app/splunk_adm/demo/${scenario === "catalyst-aci" || scenario === "meraki-nxos" ? "demo-networking-scopes.json" : "demo-scopes.json"}`,
        ),
        { signal: controller.signal },
      );
      if (!response.ok)
        throw new Error(`Scope fixture request failed (${response.status}).`);
      const payload = await response.json();
      return { rows: parseScopes(payload.rows) };
    };
    void load()
      .then((result) => {
        if (active) setState({ ...result, loading: false });
      })
      .catch((error) => {
        if (active)
          setState({
            rows: [],
            loading: false,
            error:
              error instanceof Error
                ? error.message
                : "Unable to load scope options.",
          });
      })
      .finally(() => clearTimeout(timer));
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [live, client, scenario, revision]);
  return { ...state, retry: () => setRevision((value) => value + 1) };
}
