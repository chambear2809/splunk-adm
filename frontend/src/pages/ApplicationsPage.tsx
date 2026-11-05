import { ControllerCatalogSection } from "../AppDynamicsCatalog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import Table from "../SimpleTable";
import TextExport from "@splunk/react-ui/Text";
import { ScopeBar } from "../map/ScopeBar";
import { TimePicker } from "../map/TimePicker";
import {
  SearchResultLimitError,
  type SearchClient,
  requireNoSearchErrors,
} from "../data/searchClient";
import { settledFindResults } from "../data/findResults";
import {
  createScopeCatalogRows,
  parseCatalogRows,
  parseFindRows,
  catalogLimitMessage,
  validatedBuildCatalogSearch,
  validatedBuildFindSearch,
  validatedBuildNetworkClientFindSearch,
  parseNetworkClientFindRows,
  type CatalogRow,
  type FindRow,
  type NetworkClientFindRow,
} from "../data/catalog";
import {
  DEMO_SCENARIOS,
  demoArgsFor,
  demoScenarioForArgs,
  demoWindowFor,
  type DemoScenario,
} from "../data/demoClient";
import { loadCatalogDemo, type FindQueryCapture } from "../data/catalogDemo";
import { toolkitDefault } from "../app/interop";
import { pageURL, stateParams, type UrlState } from "../app/urlState";
import { argError } from "../provider";
import { timeError } from "../data/timeBounds";
import type { GraphArgs } from "../rows";
import { applicationMapTarget } from "./applicationMapTarget";
import { DeviceLookup, ExploreTabs, TracePathForm } from "./ExploreTools";
import { TraceView } from "../trace/TraceView";
import { usePathTrace } from "../trace/usePathTrace";

const Button = toolkitDefault(ButtonExport);
const Text = toolkitDefault(TextExport);
type SortKey = keyof CatalogRow;
const utc = (epoch: string | number) => {
  const value = Number(epoch);
  if (!Number.isFinite(value) || value < 0 || value > 253402300799)
    return "Unknown time";
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : date.toISOString().replace("T", " ").replace(":00.000Z", " UTC");
};
const scopeLabel = (value: string) =>
  value.length > 255 ? value.slice(0, 255) + "…" : value;
const isSearchResultLimitError = (
  value: unknown,
): value is SearchResultLimitError =>
  value instanceof SearchResultLimitError ||
  (value instanceof Error && value.name === "SearchResultLimitError");
const columns: { key: SortKey; label: string }[] = [
  { key: "service", label: "Service" },
  { key: "environment", label: "Scope" },
  { key: "pods", label: "Pods" },
  { key: "peers", label: "Peers" },
  { key: "conversations_1h", label: "Conversations (1h)" },
  { key: "blocked_1h", label: "Blocked (1h)" },
  { key: "unknown_peers_1h", label: "Unknown (1h)" },
  { key: "window_end", label: "Window end (UTC)" },
];

export function ApplicationsPage({
  state,
  client,
  timezone,
  inSplunk = false,
}: {
  state: UrlState;
  client?: SearchClient;
  timezone?: string;
  inSplunk?: boolean;
}) {
  // The demo bundle is loaded on demand in Splunk builds. Do not resolve demo
  // fixtures while rendering a live catalog route, where they are not prepared.
  // Demo captures ship only with the development build; the packaged app is
  // live-only, so every demo reference below is compiled out there.
  const demoMode = !__ADM_SPLUNK_BUILD__ && state.mode === "demo";
  const demoArgs =
    !__ADM_SPLUNK_BUILD__ && state.mode === "demo"
      ? demoArgsFor(state.scenario)
      : state.args;
  const demoWindow =
    !__ADM_SPLUNK_BUILD__ && state.mode === "demo"
      ? demoWindowFor(state.scenario)
      : { earliest: state.earliest, latest: state.latest };
  const [args, setArgs] = useState(demoArgs);
  const [earliest, setEarliest] = useState(
    demoMode ? demoWindow.earliest : state.earliest,
  );
  const [latest, setLatest] = useState(
    demoMode ? demoWindow.latest : state.latest,
  );
  const [traceRequest, setTraceRequest] = useState(state.trace);
  const traceResult = usePathTrace({
    request: traceRequest,
    demo: demoMode,
    client,
    earliest,
    latest,
    timezone,
  });
  const changeTrace = (next?: { src: string; dst: string }) => {
    setTraceRequest(next);
    const params = new URLSearchParams(location.search);
    params.delete("trace_src");
    params.delete("trace_dst");
    if (next) {
      params.set("trace_src", next.src);
      params.set("trace_dst", next.dst);
    }
    history.replaceState(null, "", `${location.pathname}?${params}`);
  };
  const scopeKnown =
    demoMode ||
    (Object.keys(args) as (keyof GraphArgs)[]).every(
      (key) => !argError(key, args[key]),
    );
  const [catalog, setCatalog] = useState<CatalogRow[]>([]);
  const [findRows, setFindRows] = useState<FindRow[]>([]);
  const [networkClientRows, setNetworkClientRows] = useState<
    NetworkClientFindRow[]
  >([]);
  const [findValue, setFindValue] = useState("");
  const [error, setError] = useState<string>();
  const [findError, setFindError] = useState<string>();
  const [networkClientError, setNetworkClientError] = useState<string>();
  const [warning, setWarning] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [findLoading, setFindLoading] = useState(false);
  const [findRan, setFindRan] = useState(false);
  const [demoQueries, setDemoQueries] = useState<FindQueryCapture[]>([]);
  const [demoNetworkClientQueries, setDemoNetworkClientQueries] = useState<
    FindQueryCapture[]
  >([]);
  const [demoRetry, setDemoRetry] = useState(0);
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean }>({
    key: "blocked_1h",
    descending: true,
  });
  const revision = useRef(0);
  const findRevision = useRef(0);
  const catalogController = useRef<AbortController>();
  const findController = useRef<AbortController>();
  // Only an over-limit catalog narrows by service, so scope edits must not
  // otherwise restart the catalog or reset Find.
  const service = useRef(args.service);
  const catalogService = useRef<string>();
  const catalogLimited = useRef(false);
  useEffect(() => {
    service.current = args.service;
  }, [args.service]);

  const loadCatalog = useCallback(() => {
    if (!client || state.mode !== "live") return;
    catalogController.current?.abort();
    const selectedService = service.current;
    catalogService.current = selectedService;
    const controller = new AbortController();
    catalogController.current = controller;
    const current = ++revision.current;
    setLoading(true);
    setError(undefined);
    setWarning(undefined);
    setCatalog([]);
    void client
      .search({
        search: validatedBuildCatalogSearch(),
        // Catalog metrics are precomputed per row; the Find/map picker does
        // not change which lookup window is returned.
        earliest: "0",
        latest: "now",
        maxRows: 5000,
        signal: controller.signal,
        allowEmpty: true,
      })
      .then((result) => {
        if (controller.signal.aborted || current !== revision.current) return;
        requireNoSearchErrors(result, "Application catalog search");
        catalogLimited.current = false;
        const parsed = parseCatalogRows(result.rows);
        if (parsed.length) {
          setCatalog(parsed);
          setWarning(result.warnings.join(" ") || undefined);
          return;
        }
        throw new Error("No application catalog rows were returned.");
      })
      .catch(async (reason: unknown) => {
        if (controller.signal.aborted || current !== revision.current) return;
        if (isSearchResultLimitError(reason)) {
          catalogLimited.current = true;
          if (!selectedService) {
            setError(catalogLimitMessage(reason.maxRows));
            return;
          }
          try {
            const serviceSearch = validatedBuildCatalogSearch(selectedService);
            const narrowed = await client.search({
              search: serviceSearch,
              earliest: "0",
              latest: "now",
              maxRows: 5000,
              signal: controller.signal,
              allowEmpty: true,
            });
            if (controller.signal.aborted || current !== revision.current)
              return;
            requireNoSearchErrors(narrowed, "Narrowed catalog search");
            if (narrowed.rows.length) {
              setCatalog(parseCatalogRows(narrowed.rows));
              setWarning(
                [
                  `Catalog narrowed to service “${selectedService}”; metrics use each row’s last completed hour.`,
                  ...narrowed.warnings,
                ].join(" "),
              );
            } else {
              setError(catalogLimitMessage(reason.maxRows));
            }
          } catch (narrowReason: unknown) {
            if (!controller.signal.aborted && current === revision.current)
              setError(
                isSearchResultLimitError(narrowReason)
                  ? catalogLimitMessage(narrowReason.maxRows)
                  : narrowReason instanceof Error
                    ? narrowReason.message
                    : catalogLimitMessage(reason.maxRows),
              );
          }
          return;
        }
        setWarning(
          `Application catalog unavailable (${reason instanceof Error ? reason.message : "search failed"}); showing configured scopes.`,
        );
        try {
          const fallback = await client.search({
            search: "| `adm_scope_options`",
            earliest: "0",
            latest: "now",
            maxRows: 5000,
            signal: controller.signal,
            allowEmpty: true,
          });
          if (controller.signal.aborted || current !== revision.current) return;
          requireNoSearchErrors(fallback, "Scope options search");
          setCatalog(createScopeCatalogRows(fallback.rows));
          setWarning(
            fallback.rows.length
              ? `Application catalog unavailable (${reason instanceof Error ? reason.message : "search failed"}); metrics are unavailable for fallback scopes.`
              : "No catalog or configured scopes were returned.",
          );
        } catch (fallbackReason: unknown) {
          if (!controller.signal.aborted && current === revision.current)
            setError(
              fallbackReason instanceof Error
                ? fallbackReason.message
                : reason instanceof Error
                  ? reason.message
                  : "Unable to load applications.",
            );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && current === revision.current)
          setLoading(false);
      });
  }, [client, state.mode]);

  useEffect(() => {
    findController.current?.abort();
    findRevision.current++;
    setFindRows([]);
    setNetworkClientRows([]);
    setFindLoading(false);
    setFindRan(false);
    setFindError(undefined);
    setNetworkClientError(undefined);
    if (state.mode === "live") loadCatalog();
    else if (!__ADM_SPLUNK_BUILD__) {
      catalogController.current?.abort();
      findController.current?.abort();
      setCatalog([]);
      setFindRows([]);
      setNetworkClientRows([]);
      setFindError(undefined);
      setNetworkClientError(undefined);
      setError(undefined);
      const current = ++revision.current;
      setLoading(true);
      void loadCatalogDemo(state.scenario)
        .then((capture) => {
          if (current !== revision.current) return;
          setCatalog(parseCatalogRows(capture.catalog.rows));
          setDemoQueries(capture.find.queries);
          setDemoNetworkClientQueries(
            capture.find.network_client_queries ?? [],
          );
          setEarliest(capture.find.earliest);
          setLatest(capture.find.latest);
          setWarning(undefined);
        })
        .catch((reason: unknown) => {
          if (current === revision.current)
            setError(
              reason instanceof Error
                ? reason.message
                : "Unable to load captured catalog.",
            );
        })
        .finally(() => {
          if (current === revision.current) setLoading(false);
        });
    }
    return () => {
      // These are request counters, not DOM refs; bumping them invalidates in-flight work.
      /* eslint-disable react-hooks/exhaustive-deps */
      revision.current++;
      findRevision.current++;
      /* eslint-enable react-hooks/exhaustive-deps */
      catalogController.current?.abort();
      findController.current?.abort();
    };
  }, [demoRetry, loadCatalog, state.mode, state.scenario]);

  useEffect(() => {
    if (catalogLimited.current && args.service !== catalogService.current)
      loadCatalog();
  }, [args.service, loadCatalog]);

  useEffect(
    () => () => {
      catalogController.current?.abort();
      findController.current?.abort();
    },
    [],
  );

  const sorted = useMemo(() => {
    const rows = [...catalog];
    const compare = (key: SortKey, left: CatalogRow, right: CatalogRow) => {
      const a = left[key];
      const b = right[key];
      return typeof a === "number" || typeof b === "number"
        ? (typeof a === "number" ? a : -1) - (typeof b === "number" ? b : -1)
        : String(a ?? "").localeCompare(String(b ?? ""));
    };
    rows.sort((left, right) => {
      const result = compare(sort.key, left, right);
      const ordered = sort.descending ? -result : result;
      if (ordered) return ordered;
      // Problems first, then a stable name order, whichever column is sorted.
      return (
        compare("blocked_1h", right, left) ||
        compare("unknown_peers_1h", right, left) ||
        compare("service", left, right) ||
        compare("cluster", left, right)
      );
    });
    return rows;
  }, [catalog, sort]);

  const keys = Object.keys(args) as (keyof GraphArgs)[];
  const errors = [
    ...keys.map((key) => argError(key, args[key])),
    timeError(earliest, latest, timezone),
  ].filter(Boolean);
  const mapReason = (row: FindRow) =>
    row.scopeError ??
    (!__ADM_SPLUNK_BUILD__ && state.mode === "demo" && !demoScenarioForArgs(row)
      ? "No captured map for this scope"
      : undefined);
  const open = (row: FindRow) => {
    if (mapReason(row)) return;
    const target = applicationMapTarget(
      state.mode,
      state.scenario,
      earliest,
      latest,
      () => {
        if (__ADM_SPLUNK_BUILD__)
          return { scenario: state.scenario, earliest, latest };
        const rowScenario = demoScenarioForArgs(row) ?? state.scenario;
        const rowWindow = demoWindowFor(rowScenario);
        return {
          scenario: rowScenario,
          earliest: rowWindow.earliest,
          latest: rowWindow.latest,
        };
      },
      { earliest: row.window_start, latest: row.window_end },
    );
    location.assign(
      pageURL(
        "map",
        stateParams({
          ...state,
          scenario: target.scenario,
          args: {
            service: row.service,
            environment: row.environment,
            cluster: row.cluster,
            namespace: row.namespace,
          },
          earliest: target.earliest,
          latest: target.latest,
          tab: "network",
          query: "",
        }),
      ),
    );
  };
  const mapAction = (row: FindRow) => (
    <div className="atlas-application-cell">
      <div>
        <strong>{scopeLabel(row.service) || "(incomplete scope)"}</strong>
        <Button
          label="Open map"
          aria-label={`Open map for ${scopeLabel(row.service)}`}
          disabled={!!mapReason(row)}
          title={mapReason(row)}
          onClick={() => open(row)}
        />
      </div>
      {row.scopeError && <small>{row.scopeError}</small>}
    </div>
  );
  let findValidation: string | undefined;
  try {
    validatedBuildFindSearch(findValue);
  } catch {
    findValidation = "Enter an exact IP, EPG or attached-device value.";
  }
  const uncaptured =
    demoMode &&
    !demoQueries.some((query) => query.query === findValue) &&
    !demoNetworkClientQueries.some((query) => query.query === findValue);
  const changeFind = (value: string) => {
    findController.current?.abort();
    setFindValue(value);
    setFindRows([]);
    setNetworkClientRows([]);
    setFindRan(false);
    setFindLoading(false);
    setFindError(undefined);
    setNetworkClientError(undefined);
  };
  const findDisabled =
    findLoading ||
    !!findValidation ||
    uncaptured ||
    (state.mode === "live" && !client) ||
    !!timeError(earliest, latest, timezone);
  const runFind = () => {
    if (demoMode) {
      const match = demoQueries.find((query) => query.query === findValue);
      const clientMatch = demoNetworkClientQueries.find(
        (query) => query.query === findValue,
      );
      if (!match && !clientMatch) return;
      setFindRows(
        parseFindRows(
          (match?.rows ?? []).filter(
            (row) =>
              row.row_type !== "network_client" && row.row_type !== "warning",
          ),
        ),
      );
      setNetworkClientRows(
        parseNetworkClientFindRows([
          ...(match?.rows ?? []).filter(
            (row) => row.row_type === "network_client",
          ),
          ...(clientMatch?.rows ?? []).filter(
            (row) => row.row_type === "network_client",
          ),
        ]),
      );
      setFindError(undefined);
      setNetworkClientError(undefined);
      setFindRan(true);
      setWarning(undefined);
      return;
    }
    if (!client) return;
    let search: string;
    try {
      search = validatedBuildFindSearch(findValue);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Invalid find value.",
      );
      return;
    }
    findController.current?.abort();
    const controller = new AbortController();
    findController.current = controller;
    const current = ++findRevision.current;
    setFindRows([]);
    setNetworkClientRows([]);
    setFindError(undefined);
    setNetworkClientError(undefined);
    setFindRan(true);
    setFindLoading(true);
    setError(undefined);
    setWarning(undefined);
    let networkSearch: string | undefined;
    try {
      networkSearch = validatedBuildNetworkClientFindSearch(findValue);
    } catch {
      /* Network-client Find is restricted to exact IP or MAC; app Find still runs. */
    }
    void Promise.allSettled([
      client
        .search({
          search,
          earliest,
          latest,
          timezone,
          maxRows: 5000,
          signal: controller.signal,
          allowEmpty: true,
        })
        .then((result) =>
          requireNoSearchErrors(result, "Application Find search"),
        ),
      ...(networkSearch
        ? [
            client
              .search({
                search: networkSearch,
                earliest,
                latest,
                timezone,
                maxRows: 5000,
                signal: controller.signal,
                allowEmpty: true,
              })
              .then((result) =>
                requireNoSearchErrors(result, "Network-client Find search"),
              ),
          ]
        : []),
    ])
      .then((results) => {
        if (controller.signal.aborted || current !== findRevision.current)
          return;
        const settled = settledFindResults(results[0], results[1]);
        const warnings = [
          ...(settled.applications?.warnings ?? []),
          ...(settled.networkClients?.warnings ?? []),
        ];
        setFindRows([]);
        setNetworkClientRows([]);
        setFindError(settled.applicationError);
        setNetworkClientError(settled.networkClientError);
        if (settled.applications) {
          try {
            setFindRows(parseFindRows(settled.applications.rows));
          } catch (reason) {
            setFindError(
              `Application Find unavailable: ${reason instanceof Error ? reason.message : "Invalid search results."}`,
            );
          }
        }
        if (settled.networkClients) {
          const rows = settled.networkClients.rows;
          const warningRows = rows.filter((row) => row.row_type === "warning");
          try {
            setNetworkClientRows(
              parseNetworkClientFindRows(
                rows.filter((row) => row.row_type === "network_client"),
              ),
            );
          } catch (reason) {
            setNetworkClientError(
              `Network-client Find unavailable: ${reason instanceof Error ? reason.message : "Invalid search results."}`,
            );
          }
          warnings.push(
            ...warningRows.map((row) =>
              String(row.warning ?? "Network client evidence is incomplete."),
            ),
          );
        }
        setWarning(
          [...new Set(warnings.filter(Boolean))].join(" ") || undefined,
        );
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted && current === findRevision.current)
          setFindError(
            `Application Find unavailable: ${reason instanceof Error ? reason.message : "Find failed."}`,
          );
      })
      .finally(() => {
        if (!controller.signal.aborted && current === findRevision.current)
          setFindLoading(false);
      });
  };
  const capturedQueries = [...demoQueries, ...demoNetworkClientQueries]
    .map((query) => query.query)
    .filter((query, index, values) => values.indexOf(query) === index);
  const text = findValue.trim().toLowerCase();
  const textMatches = text
    ? sorted.filter((row) =>
        [row.service, row.namespace, row.cluster, row.environment].some(
          (value) =>
            String(value ?? "")
              .toLowerCase()
              .includes(text),
        ),
      )
    : sorted;
  // The omnibox narrows the catalog by name; addresses fall through to Find.
  const shown = textMatches.length ? textMatches : sorted;
  return (
    <main className="atlas-page atlas-page-wide atlas-explore">
      <h1 className="atlas-visually-hidden">Explore</h1>
      <ExploreTabs active="applications" />
      <div className="atlas-omnibox" role="search">
        <label htmlFor="atlas-find-value" className="atlas-visually-hidden">
          Find an address, EPG, or device
        </label>
        <Text
          inputId="atlas-find-value"
          autoComplete="off"
          spellCheck={false}
          placeholder="Application, IP, MAC, EPG or device"
          value={findValue}
          onChange={(_event, { value }) => changeFind(value)}
          onKeyDown={(event: React.KeyboardEvent) => {
            if (event.key === "Enter") {
              event.preventDefault();
              if (!findDisabled) runFind();
            }
          }}
        />
        <Button
          label={findLoading ? "Finding…" : "Find"}
          aria-label="Find"
          onClick={runFind}
          disabled={findDisabled}
        />
        <TimePicker
          earliest={earliest}
          latest={latest}
          timezone={timezone}
          live={inSplunk}
          disabled={demoMode}
          onChange={(start, end) => {
            findController.current?.abort();
            setEarliest(start);
            setLatest(end);
            setFindRows([]);
            setNetworkClientRows([]);
            setFindRan(false);
            setFindLoading(false);
            setFindError(undefined);
            setNetworkClientError(undefined);
          }}
        />
        {!__ADM_SPLUNK_BUILD__ && state.mode === "demo" && (
          <>
            <span
              className="chip demo"
              title={`Captured Find window ${utc(earliest)}–${utc(latest)}; map window ${utc(demoWindow.earliest)}–${utc(demoWindow.latest)}`}
            >
              Demo data
            </span>
            <select
              className="atlas-compact-select"
              aria-label="Demo scenario"
              value={state.scenario}
              onChange={(event) => {
                const scenario = event.target.value as DemoScenario;
                const nextWindow = demoWindowFor(scenario);
                location.assign(
                  pageURL(
                    "applications",
                    stateParams({
                      ...state,
                      scenario,
                      args: demoArgsFor(scenario),
                      earliest: nextWindow.earliest,
                      latest: nextWindow.latest,
                    }),
                  ),
                );
              }}
            >
              {DEMO_SCENARIOS.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </>
        )}
      </div>
      <div className="atlas-explore-tools" aria-label="Investigate">
        <TracePathForm
          key={traceRequest ? `${traceRequest.src}>${traceRequest.dst}` : ""}
          initial={traceRequest}
          onSubmit={(src, dst) => changeTrace({ src, dst })}
        />
        <DeviceLookup />
      </div>
      {traceRequest && (
        <TraceView
          key={`${traceRequest.src}>${traceRequest.dst}`}
          request={traceRequest}
          result={traceResult}
          onCancel={traceResult.cancel}
          onRetry={traceResult.retry}
          onClose={() => changeTrace(undefined)}
          actions={
            scopeKnown ? (
              <a
                className="atlas-trace-btn"
                href={pageURL(
                  "map",
                  stateParams({
                    ...state,
                    args,
                    earliest,
                    latest,
                    trace: traceRequest,
                  }),
                )}
              >
                Open on map
              </a>
            ) : undefined
          }
        />
      )}
      {demoMode && uncaptured && capturedQueries.length > 0 && (
        <p className="atlas-suggestions muted small">
          {text && !textMatches.length ? "No captured evidence · try" : "Try"}
          {capturedQueries.map((query) => (
            <button
              key={query}
              type="button"
              className="link"
              onClick={() => changeFind(query)}
            >
              {query}
            </button>
          ))}
        </p>
      )}
      {state.mode === "live" && findValue && findValidation && (
        <p className="muted small">{findValidation}</p>
      )}
      {findLoading && <p role="status">Searching…</p>}
      {findError && (
        <p role="alert">
          {findError} <Button label="Retry Find" onClick={runFind} />
        </p>
      )}
      {networkClientError && (
        <p role="alert">
          {networkClientError} <Button label="Retry Find" onClick={runFind} />
        </p>
      )}
      {findRan &&
        !findLoading &&
        !findError &&
        !networkClientError &&
        !findRows.length &&
        !networkClientRows.length && (
          <p>
            {demoMode
              ? "Not in captured evidence"
              : "No matching applications found."}
          </p>
        )}
      <div className="atlas-explore-results">
        {findRows.length > 0 && (
          <Table aria-label="Find results" horizontalOverflow="scroll">
            <Table.Head>
              <Table.HeadCell width={280}>Service</Table.HeadCell>
              <Table.HeadCell width={140}>Environment</Table.HeadCell>
              <Table.HeadCell width={180}>Cluster</Table.HeadCell>
              <Table.HeadCell width={140}>Namespace</Table.HeadCell>
            </Table.Head>
            <Table.Body>
              {findRows.map((row) => (
                <Table.Row key={row._key}>
                  <Table.Cell title={row.scopeError}>
                    {mapAction(row)}
                  </Table.Cell>
                  <Table.Cell>{scopeLabel(row.environment)}</Table.Cell>
                  <Table.Cell>{scopeLabel(row.cluster)}</Table.Cell>
                  <Table.Cell>{scopeLabel(row.namespace)}</Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        )}
        {networkClientRows.length > 0 && (
          <NetworkClientTable rows={networkClientRows} />
        )}
      </div>
      {loading && <p role="status">Loading applications…</p>}
      {error && (
        <p role="alert">
          {error}{" "}
          <Button
            label="Retry"
            onClick={() =>
              demoMode ? setDemoRetry((value) => value + 1) : loadCatalog()
            }
          />
        </p>
      )}
      {warning && (
        <p role="status" className="muted small">
          {warning}
        </p>
      )}
      {!loading && !error && !sorted.length && (
        <p>
          No applications in this window.
          {state.mode === "live" && (
            <>
              {" "}
              Qualified identity unavailable ·{" "}
              <a href={pageURL("data_health", stateParams(state))}>
                Data health
              </a>
            </>
          )}
        </p>
      )}
      {!!sorted.length && (
        <Table aria-label="Application catalog" horizontalOverflow="scroll">
          <Table.Head>
            {columns.map((column) => (
              <Table.HeadCell
                key={column.label}
                width={
                  column.key === "service"
                    ? 220
                    : column.key === "environment"
                      ? 220
                      : column.key === "window_end"
                        ? 160
                        : column.key === "conversations_1h"
                          ? 150
                          : 100
                }
                sortKey={column.key}
                sortDir={
                  sort.key === column.key
                    ? sort.descending
                      ? "desc"
                      : "asc"
                    : "none"
                }
                onSort={(_event, data) =>
                  setSort({
                    key: column.key,
                    descending: data.sortDir === "desc",
                  })
                }
              >
                {column.label}
              </Table.HeadCell>
            ))}
          </Table.Head>
          <Table.Body>
            {shown.map((row) => (
              <Table.Row key={row._key}>
                {columns.map((column) => (
                  <Table.Cell
                    key={column.label}
                    title={row.scopeError}
                    className={
                      (column.key === "blocked_1h" ||
                        column.key === "unknown_peers_1h") &&
                      (row[column.key] ?? 0) > 0
                        ? "atlas-exception"
                        : undefined
                    }
                  >
                    {column.key === "service" ? (
                      mapAction(row)
                    ) : column.key === "environment" ? (
                      [row.environment, row.cluster, row.namespace]
                        .map((value) => scopeLabel(String(value ?? "")))
                        .join(" · ")
                    ) : column.key === "window_end" ? (
                      typeof row.window_end === "number" ? (
                        <span
                          title={
                            typeof row.window_start === "number"
                              ? `${utc(row.window_start)} – ${utc(row.window_end)}`
                              : undefined
                          }
                        >
                          {utc(row.window_end).replace(" UTC", "")}
                        </span>
                      ) : (
                        "—"
                      )
                    ) : typeof row[column.key] === "string" ? (
                      scopeLabel(row[column.key] as string)
                    ) : (
                      (row[column.key] ?? "—")
                    )}
                  </Table.Cell>
                ))}
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      )}
      <details className="atlas-disclosure">
        <summary>Open by scope</summary>
        <form
          className="atlas-scope-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!errors.length)
              location.assign(
                pageURL(
                  "map",
                  stateParams({
                    ...state,
                    args,
                    scenario: state.scenario,
                    earliest: demoMode ? demoWindow.earliest : earliest,
                    latest: demoMode ? demoWindow.latest : latest,
                  }),
                ),
              );
          }}
        >
          <ScopeBar
            args={args}
            onChange={setArgs}
            live={state.mode === "live"}
            client={client}
            demoArgs={demoMode ? demoArgs : undefined}
            scenario={state.scenario}
          />
          <Button
            type="submit"
            appearance="primary"
            disabled={!!errors.length}
            label="Open map"
          />
        </form>
      </details>
      {state.mode === "live" && client && (
        <details className="atlas-disclosure">
          <summary>AppDynamics applications</summary>
          <ControllerCatalogSection state={state} client={client} />
        </details>
      )}
    </main>
  );
}

function NetworkClientTable({ rows }: { rows: NetworkClientFindRow[] }) {
  return (
    <Table aria-label="Network client evidence" horizontalOverflow="scroll">
      <Table.Head>
        <Table.HeadCell>Client</Table.HeadCell>
        <Table.HeadCell>Source and authority</Table.HeadCell>
        <Table.HeadCell>Routing scope</Table.HeadCell>
        <Table.HeadCell>Attachment evidence</Table.HeadCell>
        <Table.HeadCell>SSID</Table.HeadCell>
        <Table.HeadCell>Source and collection times</Table.HeadCell>
      </Table.Head>
      <Table.Body>
        {rows.map((row) => (
          <Table.Row key={row._key}>
            <Table.Cell>
              {row.client_mac ?? row.client_ip ?? row.native_id ?? row._key}
              {row.attachment_device_name && (
                <small>
                  <br />
                  Observed device: {row.attachment_device_name}
                  {row.attachment_device_id
                    ? ` · ${row.attachment_device_id}`
                    : ""}
                </small>
              )}
            </Table.Cell>
            <Table.Cell>
              {row.access_platform ?? row.source}
              {row.source_authority ? ` · ${row.source_authority}` : ""}
            </Table.Cell>
            <Table.Cell>
              {row.scope ?? "Unmapped"}
              {row.routing_domain ? ` · ${row.routing_domain}` : ""}
              {row.cluster ? ` · ${row.cluster}` : ""}
            </Table.Cell>
            <Table.Cell>
              {row.attachment_status}
              {row.mapping_status &&
              row.mapping_status !== row.attachment_status
                ? ` · mapping ${row.mapping_status}`
                : ""}
              {row.attachment_basis ? ` · ${row.attachment_basis}` : ""}
              {row.diagnostic_status && ` · ${row.diagnostic_status}`}
              {row.diagnostic_reason || row.quality_reason || row.warning ? (
                <small>
                  <br />
                  {row.diagnostic_reason ?? row.quality_reason ?? row.warning}
                </small>
              ) : null}
            </Table.Cell>
            <Table.Cell>{row.ssid_number ?? "—"}</Table.Cell>
            <Table.Cell>
              {row.source_time !== undefined
                ? utc(row.source_time)
                : "Source time unavailable"}
              {row.attachment_event_time !== undefined && (
                <small>
                  <br />
                  Attachment event {utc(row.attachment_event_time)}
                </small>
              )}
              <small>
                <br />
                Received{" "}
                {row.attachment_received_time !== undefined ||
                row.received_time !== undefined
                  ? utc(row.attachment_received_time ?? row.received_time!)
                  : "time unavailable"}
                {row.attachment_collected_time !== undefined
                  ? ` · collected ${utc(row.attachment_collected_time)}`
                  : ""}
                {row.latest_received_time !== undefined &&
                row.latest_received_time !== row.received_time
                  ? ` · latest ${utc(row.latest_received_time)}`
                  : ""}
                {row.attachment_collected_time !== undefined
                  ? ` · source collection ${utc(row.attachment_collected_time)}`
                  : ""}
              </small>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
}
