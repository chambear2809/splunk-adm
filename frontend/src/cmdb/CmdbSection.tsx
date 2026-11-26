import { useEffect, useState } from "react";
import type { CatalogRow } from "../data/catalog";
import { evidenceConfigClient } from "../data/evidenceConfig";
import { routingScope } from "../data/evidence";
import type { SearchClient } from "../data/searchClient";
import { loadHistoryUi } from "../HistoryLazyInspection";

type Ui = Awaited<ReturnType<typeof loadHistoryUi>>;

const readAssetConfig = (signal: AbortSignal, scope: string) =>
  evidenceConfigClient
    .read(signal, undefined, scope)
    .then((config) =>
      config.supplemental?.find((source) => source.source === "asset_history"),
    );

/** Loads the optional workspace only after the operator opens it. */
export function CmdbSection({
  client,
  catalog,
  catalogWarning,
}: {
  client: SearchClient;
  catalog: readonly CatalogRow[];
  catalogWarning?: string;
}) {
  const [open, setOpen] = useState(false);
  const [ui, setUi] = useState<Ui>();
  const [error, setError] = useState<string>();
  const [scopes, setScopes] = useState<string[]>([]);
  const started = open || !!ui;
  useEffect(() => {
    if (!started) return;
    let active = true;
    const controller = new AbortController();
    void loadHistoryUi()
      .then((next) => active && setUi(next))
      .catch(() => active && setError("ITSI export is unavailable."));
    void evidenceConfigClient
      .read(controller.signal)
      .then((config) => {
        if (!active) return;
        const valid = config.mappings
          .map((mapping) => mapping.scope)
          .filter((scope) => {
            try {
              return routingScope(scope) === scope;
            } catch {
              return false;
            }
          });
        setScopes([...new Set(valid)].sort());
      })
      .catch(() => undefined);
    return () => {
      active = false;
      controller.abort();
    };
  }, [started]);
  return (
    <details
      className="atlas-disclosure"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>ITSI export and CMDB reconciliation</summary>
      {open &&
        (ui ? (
          <ui.CmdbWorkspace
            client={client}
            catalog={catalog}
            catalogWarning={catalogWarning}
            readAssetConfig={readAssetConfig}
            scopeSuggestions={scopes}
          />
        ) : (
          <p role={error ? "alert" : "status"}>{error ?? "Loading…"}</p>
        ))}
    </details>
  );
}
