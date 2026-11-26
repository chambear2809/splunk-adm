import { useEffect, useMemo, useRef, useState } from "react";
import type { CatalogRow } from "../data/catalog";
import type { SupplementalSourceConfiguration } from "../data/evidenceConfig";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import { routingScope } from "../data/evidence";
import { downloadBlob } from "../download";
import {
  browserLocalStorage,
  readLocalImport,
} from "../businessServices/localImport";
import {
  buildItsiExport,
  ITSI_BATCH_DEFAULT,
  ITSI_BATCH_MAX,
  ITSI_BATCH_MIN,
  itsiBrokenEdgesCsv,
  itsiEntitiesCsv,
  itsiServicesCsv,
  type ExcludedItem,
  type ItsiExportInput,
} from "./itsiExport";
import {
  businessServiceParents,
  catalogServiceKeys,
  observedEntities,
  observedServiceDependencies,
} from "./itsiInputs";
import {
  assetAuthorities,
  buildCmdbAssetSearch,
  buildCmdbRelationshipSearch,
  buildObservedRelationshipSearch,
  CMDB_LIMITS,
  ENDPOINT_STATUS_LABEL,
  endpointFindingsCsv,
  parseCmdbAssets,
  parseCmdbRelationships,
  parseObservedRelationships,
  reconcileCmdb,
  RELATIONSHIP_STATUS_LABEL,
  relationshipFindingsCsv,
  type EndpointStatus,
  type Parsed,
  type Reconciliation,
  type RelationshipStatus,
  type SourceCompleteness,
} from "./reconciliation";
import "./cmdb.css";

export interface CmdbWorkspaceProps {
  client: SearchClient;
  catalog: readonly CatalogRow[];
  catalogWarning?: string;
  readAssetConfig: (
    signal: AbortSignal,
    scope: string,
  ) => Promise<SupplementalSourceConfiguration | undefined>;
  scopeSuggestions?: readonly string[];
  now?: () => number;
}

interface Result {
  reconciliation: Reconciliation;
  itsiInput: Omit<ItsiExportInput, "batchSize">;
  itsiExcluded: ExcludedItem[];
  identityIncomplete: boolean;
  businessStatus: string;
  observed: Parsed<unknown>;
}

const DISPLAY_ROWS = 200;
const utc = (epoch?: number) =>
  epoch === undefined
    ? "—"
    : new Date(epoch * 1000).toISOString().slice(0, 16).replace("T", " ");
const message = (reason: unknown, fallback: string) =>
  reason instanceof SearchAccessDeniedError
    ? "Splunk denied access to this search with your current permissions."
    : reason instanceof Error
      ? reason.message
      : fallback;
const unavailable = (reason: string): SourceCompleteness => ({
  state: "unavailable",
  reasons: [reason],
  inputCount: 0,
  returnedCount: 0,
  rejected: 0,
});
const notConfigured = (reason: string): SourceCompleteness => ({
  ...unavailable(reason),
  state: "not_configured",
});
const SOURCE_LABEL = {
  complete: "Complete",
  incomplete: "Incomplete",
  unavailable: "Unavailable",
  not_configured: "Not configured",
} as const;

export function CmdbWorkspace({
  client,
  catalog,
  catalogWarning,
  readAssetConfig,
  scopeSuggestions = [],
  now = () => Date.now() / 1000,
}: CmdbWorkspaceProps) {
  const [scope, setScope] = useState("");
  const [days, setDays] = useState<number>(7);
  const [batchSize, setBatchSize] = useState(ITSI_BATCH_DEFAULT);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<Result>();
  const [endpointFilter, setEndpointFilter] = useState<EndpointStatus | "all">(
    "all",
  );
  const [relationshipFilter, setRelationshipFilter] = useState<
    RelationshipStatus | "all"
  >("all");
  const [text, setText] = useState("");
  const [partialAck, setPartialAck] = useState(false);
  const controller = useRef<AbortController>();
  useEffect(() => () => controller.current?.abort(), []);

  let scopeError: string | undefined;
  try {
    routingScope(scope);
  } catch (reason) {
    scopeError = scope ? message(reason, "Invalid scope.") : undefined;
  }

  const run = async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    const signal = current.signal;
    const end = Math.floor(now() / 60) * 60;
    const window = { start: end - days * 86400, end };
    setLoading(true);
    setError(undefined);
    setResult(undefined);
    setPartialAck(false);
    try {
      const observedSearch = client
        .search({
          search: buildObservedRelationshipSearch(scope),
          earliest: String(window.start),
          latest: String(window.end),
          maxRows: CMDB_LIMITS.relationships + 1,
          allowEmpty: true,
          signal,
        })
        .then((r) => requireNoSearchErrors(r, "Observed relationship search"));
      const assetsSearch = (async (): Promise<Parsed<never>> => {
        const config = await readAssetConfig(signal, scope).catch(
          () => undefined,
        );
        if (!config || config.state === "not_selected")
          return {
            records: [],
            completeness: notConfigured(
              "Asset history is not selected for this deployment.",
            ),
          };
        let search: string;
        let authorities: string[];
        try {
          search = buildCmdbAssetSearch(config, scope, window);
          authorities = assetAuthorities(config, scope);
        } catch (reason) {
          return {
            records: [],
            completeness: unavailable(message(reason, "Not configured.")),
          };
        }
        const rows = await client.search({
          search,
          earliest: "0",
          latest: String(Math.max(window.end, Math.floor(now()))),
          maxRows: CMDB_LIMITS.assets + 1,
          allowEmpty: true,
          signal,
          optionalSource: "asset_history",
        });
        requireNoSearchErrors(rows, "Asset-history search");
        return parseCmdbAssets(rows.rows, scope, authorities) as Parsed<never>;
      })().catch((reason: unknown): Parsed<never> => ({
        records: [],
        completeness: unavailable(
          message(reason, "Asset-history search failed."),
        ),
      }));
      const relationshipsSearch = client
        .search({
          search: buildCmdbRelationshipSearch(scope),
          earliest: "0",
          latest: "now",
          maxRows: CMDB_LIMITS.cmdbRelationships + 2,
          allowEmpty: true,
          signal,
        })
        .then((r) =>
          parseCmdbRelationships(
            requireNoSearchErrors(r, "CMDB relationship lookup").rows,
            scope,
          ),
        )
        .catch((reason: unknown) => ({
          records: [],
          completeness: unavailable(
            message(reason, "CMDB relationship lookup failed."),
          ),
        }));
      const [observedRows, assets, relationships] = await Promise.all([
        observedSearch,
        assetsSearch,
        relationshipsSearch,
      ]);
      if (signal.aborted) return;
      const observed = parseObservedRelationships(observedRows.rows, scope);
      if (observedRows.warnings.length)
        observed.completeness.reasons.push(...observedRows.warnings);
      const reconciliation = reconcileCmdb({
        scope,
        window,
        observed,
        assets,
        relationships,
      });
      const local = readLocalImport(browserLocalStorage());
      const business = businessServiceParents(
        catalog,
        local.status === "ready" ? local.preview : undefined,
        window,
      );
      setResult({
        reconciliation,
        itsiInput: {
          services: catalogServiceKeys(catalog),
          dependencies: observedServiceDependencies(observed.records),
          businessServices: business.parents,
          entities: observedEntities(observed.records),
          window,
        },
        itsiExcluded: business.excluded,
        identityIncomplete: observed.identityIncomplete,
        observed,
        businessStatus:
          local.status === "ready"
            ? `${business.parents.length} business services from this browser's local import resolved to qualified Atlas services.`
            : local.status === "empty"
              ? "No business-service import is saved in this browser."
              : "The browser-local business-service import is unavailable or uncertain; no business services were exported.",
      });
    } catch (reason) {
      if (!signal.aborted)
        setError(message(reason, "Reconciliation search failed."));
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  };

  const rec = result?.reconciliation;
  const itsi = useMemo(
    () => result && buildItsiExport({ ...result.itsiInput, batchSize }),
    [result, batchSize],
  );
  const needle = text.trim().toLowerCase();
  const endpoints = useMemo(
    () =>
      (rec?.endpoints ?? []).filter(
        (row) =>
          (endpointFilter === "all" || row.status === endpointFilter) &&
          (!needle ||
            [row.ip, row.identity, row.assetIds.join(" ")].some((v) =>
              (v ?? "").toLowerCase().includes(needle),
            )),
      ),
    [rec, endpointFilter, needle],
  );
  const relationships = useMemo(
    () =>
      (rec?.relationships ?? []).filter(
        (row) =>
          (relationshipFilter === "all" || row.status === relationshipFilter) &&
          (!needle ||
            [row.clientIp, row.serverIp, row.relationshipIds.join(" ")].some(
              (v) => v.toLowerCase().includes(needle),
            )),
      ),
    [rec, relationshipFilter, needle],
  );
  const stamp = rec
    ? `${rec.scope.replace(/[^A-Za-z0-9._-]/g, "_")}-${rec.window.end}`
    : "";
  const itsiPartial =
    !!result &&
    (result.observed.completeness.state !== "complete" ||
      result.identityIncomplete ||
      !!catalogWarning);
  const itsiBlocked = itsiPartial && !partialAck;

  return (
    <section
      className="cmdb-workspace"
      aria-label="ITSI export and CMDB reconciliation"
    >
      <p className="cmdb-workspace__muted">
        Compares observed conversations with CMDB records and prepares ITSI
        import files. Searches run with your Splunk permissions. Atlas never
        writes to ITSI or to a CMDB; exports are files for review.
      </p>
      <div className="cmdb-workspace__controls">
        <label>
          Routing scope
          <input
            value={scope}
            list="cmdb-scope-suggestions"
            spellCheck={false}
            onChange={(event) => setScope(event.target.value.trim())}
            aria-invalid={!!scopeError}
          />
        </label>
        <datalist id="cmdb-scope-suggestions">
          {scopeSuggestions.map((value) => (
            <option key={value} value={value} />
          ))}
        </datalist>
        <label>
          Window
          <select
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
          >
            {CMDB_LIMITS.windowDays.map((value) => (
              <option key={value} value={value}>
                Last {value} {value === 1 ? "day" : "days"}
              </option>
            ))}
          </select>
        </label>
        <label>
          ITSI batch size
          <select
            value={batchSize}
            onChange={(event) => setBatchSize(Number(event.target.value))}
          >
            {[ITSI_BATCH_MIN, ITSI_BATCH_DEFAULT, ITSI_BATCH_MAX].map((n) => (
              <option key={n} value={n}>
                {n} services
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          disabled={loading || !scope || !!scopeError}
          onClick={() => void run()}
        >
          {loading ? "Running…" : "Run reconciliation"}
        </button>
        {loading && (
          <button
            type="button"
            onClick={() => {
              controller.current?.abort();
              setLoading(false);
            }}
          >
            Cancel
          </button>
        )}
      </div>
      {scopeError && <p role="alert">{scopeError}</p>}
      {error && <p role="alert">{error}</p>}
      {loading && (
        <p role="status">Searching observed traffic and CMDB sources…</p>
      )}
      {rec && result && itsi && (
        <>
          <p className="cmdb-workspace__muted">
            Scope {rec.scope} · window {utc(rec.window.start)} to{" "}
            {utc(rec.window.end)} UTC (half-open)
          </p>
          <h3>Source completeness</h3>
          <ul>
            {(
              [
                ["Observed traffic", rec.sources.observed],
                ["Asset history", rec.sources.assets],
                ["CMDB relationship lookup", rec.sources.relationships],
              ] as const
            ).map(([label, source]) => (
              <li key={label}>
                <strong>{label}:</strong> {SOURCE_LABEL[source.state]}
                {source.state === "complete" || source.state === "incomplete"
                  ? ` · ${source.returnedCount.toLocaleString()} of ${source.inputCount.toLocaleString()} rows`
                  : ""}
                {source.reasons.length ? ` · ${source.reasons.join(" ")}` : ""}
              </li>
            ))}
          </ul>
          <div className="cmdb-workspace__notice">
            <ul>
              {rec.caveats.map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
            </ul>
          </div>
          <div className="cmdb-workspace__controls">
            <label>
              Filter by IP, asset or relationship
              <input
                value={text}
                spellCheck={false}
                onChange={(event) => setText(event.target.value)}
              />
            </label>
          </div>

          <h3>Endpoints</h3>
          <div className="cmdb-workspace__chips" aria-label="Endpoint counts">
            {(Object.keys(ENDPOINT_STATUS_LABEL) as EndpointStatus[]).map(
              (status) => (
                <span
                  key={status}
                  className={
                    status === "not_in_cmdb" ||
                    status === "ambiguous" ||
                    status === "coverage_unknown"
                      ? "cmdb-workspace__chip cmdb-workspace__chip--warning"
                      : "cmdb-workspace__chip"
                  }
                >
                  {ENDPOINT_STATUS_LABEL[status]}:{" "}
                  {rec.endpointCounts[status].toLocaleString()}
                </span>
              ),
            )}
          </div>
          <div className="cmdb-workspace__controls">
            <label>
              Endpoint status
              <select
                value={endpointFilter}
                onChange={(event) =>
                  setEndpointFilter(
                    event.target.value as EndpointStatus | "all",
                  )
                }
              >
                <option value="all">All</option>
                {(Object.keys(ENDPOINT_STATUS_LABEL) as EndpointStatus[]).map(
                  (status) => (
                    <option key={status} value={status}>
                      {ENDPOINT_STATUS_LABEL[status]}
                    </option>
                  ),
                )}
              </select>
            </label>
            <button
              type="button"
              disabled={!endpoints.length}
              onClick={() =>
                downloadBlob(
                  `atlas-cmdb-endpoints-${stamp}.csv`,
                  "text/csv",
                  endpointFindingsCsv(endpoints),
                )
              }
            >
              Export endpoints CSV
            </button>
          </div>
          <FindingTable
            label="Endpoint reconciliation"
            headers={[
              "Status",
              "IP",
              "Atlas identity",
              "CMDB basis",
              "Last seen (UTC)",
              "Note",
            ]}
            rows={endpoints.map((row) => [
              ENDPOINT_STATUS_LABEL[row.status],
              row.ip,
              row.identity ?? "—",
              row.basis.length
                ? `${row.basis.join(", ")}${row.assetIds.length ? ` · ${row.assetIds.join(", ")}` : ""}`
                : "—",
              utc(row.lastSeen),
              row.note,
            ])}
          />

          <h3>CMDB relationships</h3>
          {rec.sources.relationships.state === "not_configured" ? (
            <p className="cmdb-workspace__muted">
              Configure and qualify the CMDB relationship lookup to compare
              recorded relationships with observed traffic.
            </p>
          ) : (
            <>
              <div
                className="cmdb-workspace__chips"
                aria-label="Relationship counts"
              >
                {(
                  Object.keys(RELATIONSHIP_STATUS_LABEL) as RelationshipStatus[]
                ).map((status) => (
                  <span
                    key={status}
                    className={
                      status === "matched"
                        ? "cmdb-workspace__chip"
                        : "cmdb-workspace__chip cmdb-workspace__chip--warning"
                    }
                  >
                    {RELATIONSHIP_STATUS_LABEL[status]}:{" "}
                    {rec.relationshipCounts[status].toLocaleString()}
                  </span>
                ))}
              </div>
              <div className="cmdb-workspace__controls">
                <label>
                  Relationship status
                  <select
                    value={relationshipFilter}
                    onChange={(event) =>
                      setRelationshipFilter(
                        event.target.value as RelationshipStatus | "all",
                      )
                    }
                  >
                    <option value="all">All</option>
                    {(
                      Object.keys(
                        RELATIONSHIP_STATUS_LABEL,
                      ) as RelationshipStatus[]
                    ).map((status) => (
                      <option key={status} value={status}>
                        {RELATIONSHIP_STATUS_LABEL[status]}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  type="button"
                  disabled={!relationships.length}
                  onClick={() =>
                    downloadBlob(
                      `atlas-cmdb-relationships-${stamp}.csv`,
                      "text/csv",
                      relationshipFindingsCsv(relationships),
                    )
                  }
                >
                  Export relationships CSV
                </button>
              </div>
              <FindingTable
                label="Relationship reconciliation"
                headers={[
                  "Status",
                  "Client",
                  "Server",
                  "CMDB IDs",
                  "Last seen (UTC)",
                  "Note",
                ]}
                rows={relationships.map((row) => [
                  RELATIONSHIP_STATUS_LABEL[row.status],
                  row.clientIp,
                  `${row.serverIp}${row.serverPort === undefined ? "" : `:${row.serverPort}`}${row.transport ? `/${row.transport}` : ""}`,
                  row.relationshipIds.join(", ") || "—",
                  utc(row.lastSeen),
                  row.note,
                ])}
              />
            </>
          )}

          <h3>ITSI export</h3>
          <p className="cmdb-workspace__muted">
            {itsi.serviceCount.toLocaleString()} services ·{" "}
            {itsi.dependencyCount.toLocaleString()} dependencies ·{" "}
            {itsi.entities.length.toLocaleString()} entities ·{" "}
            {itsi.batches.length} batches of up to {itsi.batchSize} ·{" "}
            {itsi.brokenEdges.length} cycle edges removed.{" "}
            {result.businessStatus}
          </p>
          <p className="cmdb-workspace__muted">
            Import batches in order with ITSI Import from CSV. Map service_title
            as Service Title, service_description as Description and
            services_depends_on as Services (dependent services). Each batch
            depends only on services in the same or an earlier batch.
          </p>
          {itsiPartial && (
            <div className="cmdb-workspace__notice cmdb-workspace__notice--warning">
              <p>
                This export is partial: observed traffic, service bindings or
                the application catalog are incomplete, so some services or
                dependencies may be missing.
              </p>
              <label>
                <input
                  type="checkbox"
                  checked={partialAck}
                  onChange={(event) => setPartialAck(event.target.checked)}
                />{" "}
                I understand this export is partial
              </label>
            </div>
          )}
          <div className="cmdb-workspace__controls">
            {itsi.batches.map((batch) => (
              <button
                key={batch.index}
                type="button"
                disabled={itsiBlocked}
                onClick={() =>
                  downloadBlob(
                    `atlas-itsi-services-batch-${batch.index}-${stamp}.csv`,
                    "text/csv",
                    itsiServicesCsv(batch),
                  )
                }
              >
                Services batch {batch.index} ({batch.rows.length})
              </button>
            ))}
            <button
              type="button"
              disabled={itsiBlocked || !itsi.entities.length}
              onClick={() =>
                downloadBlob(
                  `atlas-itsi-entities-${stamp}.csv`,
                  "text/csv",
                  itsiEntitiesCsv(itsi.entities),
                )
              }
            >
              Entities ({itsi.entities.length})
            </button>
            <button
              type="button"
              disabled={!itsi.brokenEdges.length}
              onClick={() =>
                downloadBlob(
                  `atlas-itsi-removed-cycle-edges-${stamp}.csv`,
                  "text/csv",
                  itsiBrokenEdgesCsv(itsi.brokenEdges),
                )
              }
            >
              Removed cycle edges ({itsi.brokenEdges.length})
            </button>
          </div>
          {itsi.batches[0] && (
            <FindingTable
              label="ITSI services preview"
              headers={["Service title", "Depends on"]}
              rows={itsi.batches.flatMap((batch) =>
                batch.rows.map((row) => [
                  `${batch.index} · ${row.service_title}`,
                  row.services_depends_on || "—",
                ]),
              )}
            />
          )}
          {itsi.brokenEdges.length > 0 && (
            <>
              <h4>Removed dependency edges</h4>
              <ul>
                {itsi.brokenEdges.slice(0, DISPLAY_ROWS).map((edge) => (
                  <li key={`${edge.from}>${edge.to}`}>
                    {edge.from} → {edge.to} left out of the export (cycle:{" "}
                    {edge.cycle.join(" → ")})
                  </li>
                ))}
              </ul>
              {itsi.brokenEdges.length > DISPLAY_ROWS && (
                <p className="cmdb-workspace__muted">
                  Showing {DISPLAY_ROWS} of {itsi.brokenEdges.length}; download
                  the removed cycle edges for the full list.
                </p>
              )}
            </>
          )}
          {[...itsi.excluded, ...result.itsiExcluded].length > 0 && (
            <details>
              <summary>
                Excluded from export (
                {itsi.excluded.length + result.itsiExcluded.length})
              </summary>
              <ul>
                {[...itsi.excluded, ...result.itsiExcluded]
                  .slice(0, DISPLAY_ROWS)
                  .map((item, index) => (
                    <li key={index}>
                      {item.item}: {item.reason}
                    </li>
                  ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  );
}

function FindingTable({
  label,
  headers,
  rows,
}: {
  label: string;
  headers: string[];
  rows: string[][];
}) {
  if (!rows.length) return <p className="cmdb-workspace__muted">No rows.</p>;
  return (
    <>
      <div className="atlas-table-scroll">
        <table className="atlas-table" aria-label={label}>
          <thead>
            <tr>
              {headers.map((header) => (
                <th key={header}>{header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, DISPLAY_ROWS).map((row, index) => (
              <tr key={index}>
                {row.map((cell, column) => (
                  <td key={column}>{cell}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > DISPLAY_ROWS && (
        <p className="cmdb-workspace__muted">
          Showing {DISPLAY_ROWS} of {rows.length.toLocaleString()} rows; export
          CSV for all.
        </p>
      )}
    </>
  );
}
