import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import TableExport from "@splunk/react-ui/Table";
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
  DEMO_WINDOW,
  DEMO_SCENARIOS,
  demoArgs as defaultDemoArgs,
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
import {
  applicationDemoEntryTarget,
  applicationMapTarget,
} from "./applicationMapTarget";

const Button = toolkitDefault(ButtonExport);
const Table = toolkitDefault(TableExport);
const Text = toolkitDefault(TextExport);
type SortKey = keyof CatalogRow;
const utc = (epoch: string | number) =>
  new Date(Number(epoch) * 1000)
    .toISOString()
    .replace("T", " ")
    .replace(":00.000Z", " UTC");
const scopeLabel = (value: string) =>
  value.length > 255 ? value.slice(0, 255) + "…" : value;
const isSearchResultLimitError = (
  value: unknown,
): value is SearchResultLimitError =>
  value instanceof SearchResultLimitError ||
  (value instanceof Error && value.name === "SearchResultLimitError");
const columns: { key: SortKey; label: string }[] = [
  { key: "service", label: "Service" },
  { key: "environment", label: "Environment" },
  { key: "cluster", label: "Cluster" },
  { key: "namespace", label: "Namespace" },
  { key: "pods", label: "Bound pods" },
  { key: "peers", label: "Peers" },
  { key: "conversations_1h", label: "Conversations (1h)" },
  { key: "blocked_1h", label: "Blocked (1h)" },
  { key: "unknown_peers_1h", label: "Unknown peers (1h)" },
  { key: "window_start", label: "Last completed hour start (UTC)" },
  { key: "window_end", label: "Last completed hour end (UTC)" },
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
  const demoArgs =
    state.mode === "demo" ? demoArgsFor(state.scenario) : state.args;
  const demoWindow =
    state.mode === "demo"
      ? demoWindowFor(state.scenario)
      : { earliest: state.earliest, latest: state.latest };
  const demoEntryTarget = applicationDemoEntryTarget(
    state.mode,
    demoArgs,
    demoWindow.earliest,
    demoWindow.latest,
    {
      args: defaultDemoArgs,
      earliest: DEMO_WINDOW.earliest,
      latest: DEMO_WINDOW.latest,
    },
  );
  const [args, setArgs] = useState(
    state.mode === "demo" ? demoArgsFor(state.scenario) : state.args,
  );
  const [earliest, setEarliest] = useState(
    state.mode === "demo" ? demoWindow.earliest : state.earliest,
  );
  const [latest, setLatest] = useState(
    state.mode === "demo" ? demoWindow.latest : state.latest,
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
    key: "service",
    descending: false,
  });
  const revision = useRef(0);
  const findRevision = useRef(0);
  const catalogController = useRef<AbortController>();
  const findController = useRef<AbortController>();

  const loadCatalog = useCallback(() => {
    if (!client || state.mode !== "live") return;
    catalogController.current?.abort();
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
          if (!args.service) {
            setError(catalogLimitMessage(reason.maxRows));
            return;
          }
          try {
            const serviceSearch = validatedBuildCatalogSearch(args.service);
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
                  `Catalog narrowed to service “${args.service}”; metrics use each row’s last completed hour.`,
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
  }, [args.service, client, state.mode]);

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
    else {
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
          setWarning(
            "Captured catalog; metrics reflect the captured observation window.",
          );
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
      revision.current++;
      findRevision.current++;
      catalogController.current?.abort();
      findController.current?.abort();
    };
  }, [demoRetry, loadCatalog, state.mode, state.scenario]);

  useEffect(
    () => () => {
      catalogController.current?.abort();
      findController.current?.abort();
    },
    [],
  );

  const sorted = useMemo(() => {
    const rows = [...catalog];
    rows.sort((left, right) => {
      const a = left[sort.key];
      const b = right[sort.key];
      const result =
        typeof a === "number" && typeof b === "number"
          ? a - b
          : String(a ?? "").localeCompare(String(b ?? ""));
      return sort.descending ? -result : result;
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
    (state.mode === "demo" && !demoScenarioForArgs(row)
      ? "No captured map is available for this scope."
      : undefined);
  const open = (row: FindRow) => {
    if (mapReason(row)) return;
    const target = applicationMapTarget(
      state.mode,
      state.scenario,
      earliest,
      latest,
      () => {
        const rowScenario = demoScenarioForArgs(row) ?? state.scenario;
        const rowWindow = demoWindowFor(rowScenario);
        return {
          scenario: rowScenario,
          earliest: rowWindow.earliest,
          latest: rowWindow.latest,
        };
      },
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
          onClick={() => open(row)}
        />
      </div>
      {mapReason(row) && <small>{mapReason(row)}</small>}
    </div>
  );
  let findValidation: string | undefined;
  try {
    validatedBuildFindSearch(findValue);
  } catch {
    findValidation = "Enter an exact IP, EPG or attached-device value.";
  }
  const uncaptured =
    state.mode === "demo" &&
    !demoQueries.some((query) => query.query === findValue) &&
    !demoNetworkClientQueries.some((query) => query.query === findValue);
  const runFind = () => {
    if (state.mode === "demo") {
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
      setWarning("Captured Find result.");
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
  return (
    <main className="atlas-page">
      <h1>Applications</h1>
      {state.mode === "demo" && (
        <label className="scenario">
          <span>Demo scenario</span>
          <select
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
        </label>
      )}
      {state.mode === "demo" && state.scenario === "meraki-nxos" && (
        <p className="muted">
          Wireless attribution is correlated from Meraki association and MS390
          IPFIX flow evidence; it does not establish a packet route.
        </p>
      )}
      {state.mode === "demo" &&
        (demoQueries.length > 0 || demoNetworkClientQueries.length > 0) && (
          <p>
            Captured Find window: {utc(earliest)}–{utc(latest)}. Map links use
            the selected captured map window: {utc(demoWindow.earliest)}–
            {utc(demoWindow.latest)}.
          </p>
        )}
      <p>
        Find returns applications bound to a matching pod or observed
        communicating with the matching endpoint. Exact IPv4 or MAC searches
        also return source-qualified client attachment evidence when available.
        Bound pods reflect retained bindings; counts describe distinct direct
        conversations in the displayed window.
      </p>
      <p>
        Choose an application scope to explore its services and network
        dependencies.
      </p>
      <p>
        Catalog metrics use each row’s last completed hour; the selected
        Find/map time window does not change this catalog window.
      </p>
      {(state.mode === "live" || state.mode === "demo") && (
        <>
          <div className="atlas-find">
            <label htmlFor="atlas-find-value">
              Find an address, EPG, or device
            </label>
            <div className="atlas-find-controls">
              <Text
                inputId="atlas-find-value"
                autoComplete="off"
                spellCheck={false}
                value={findValue}
                onChange={(_event, { value }) => {
                  findController.current?.abort();
                  setFindValue(value);
                  setFindRows([]);
                  setNetworkClientRows([]);
                  setFindRan(false);
                  setFindLoading(false);
                  setFindError(undefined);
                  setNetworkClientError(undefined);
                }}
              />
              <Button
                label="Find"
                onClick={runFind}
                disabled={
                  findLoading ||
                  !!findValidation ||
                  uncaptured ||
                  (state.mode === "live" && !client) ||
                  !!timeError(earliest, latest, timezone)
                }
              />
            </div>
          </div>
          {uncaptured && (
            <p>
              Choose a captured query:{" "}
              {[...demoQueries, ...demoNetworkClientQueries]
                .map((query) => query.query)
                .filter(
                  (query, index, values) => values.indexOf(query) === index,
                )
                .join(", ")}
              . Other values have no captured Find evidence.
            </p>
          )}
          {state.mode === "live" && findValidation && <p>{findValidation}</p>}
          {findLoading && <p>Searching the selected time window…</p>}
          {findError && (
            <p role="alert">
              {findError} <Button label="Retry Find" onClick={runFind} />
            </p>
          )}
          {networkClientError && (
            <p role="alert">
              {networkClientError}{" "}
              <Button label="Retry Find" onClick={runFind} />
            </p>
          )}
          {findRan &&
            !findLoading &&
            !findError &&
            !networkClientError &&
            !findRows.length &&
            !networkClientRows.length && (
              <p>
                {state.mode === "demo"
                  ? "This Find query is not included in the captured evidence."
                  : "No matching applications found."}
              </p>
            )}
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
            <Table
              aria-label="Network client evidence"
              horizontalOverflow="scroll"
            >
              <Table.Head>
                <Table.HeadCell>Client</Table.HeadCell>
                <Table.HeadCell>Source and authority</Table.HeadCell>
                <Table.HeadCell>Routing scope</Table.HeadCell>
                <Table.HeadCell>Attachment evidence</Table.HeadCell>
                <Table.HeadCell>SSID</Table.HeadCell>
                <Table.HeadCell>Source and collection times</Table.HeadCell>
              </Table.Head>
              <Table.Body>
                {networkClientRows.map((row) => (
                  <Table.Row key={row._key}>
                    <Table.Cell>
                      {row.client_mac ??
                        row.client_ip ??
                        row.native_id ??
                        row._key}
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
                      {row.quality_reason || row.warning ? (
                        <small>
                          <br />
                          {row.quality_reason ?? row.warning}
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
                          ? utc(
                              row.attachment_received_time ??
                                row.received_time!,
                            )
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
          )}
          {loading && <p>Loading application catalog…</p>}
          {error && (
            <p role="alert">
              {error}{" "}
              <Button
                label="Retry"
                onClick={() =>
                  state.mode === "demo"
                    ? setDemoRetry((value) => value + 1)
                    : loadCatalog()
                }
              />
            </p>
          )}
          {warning && <p role="status">{warning}</p>}
          {!loading && !error && !sorted.length && (
            <p>No applications are available for this time window.</p>
          )}
          {!!sorted.length && (
            <Table aria-label="Application catalog" horizontalOverflow="scroll">
              <Table.Head>
                {columns.map((column) => (
                  <Table.HeadCell
                    key={column.key}
                    width={
                      column.key === "service"
                        ? 280
                        : column.key.startsWith("window_")
                          ? 190
                          : column.key === "conversations_1h" ||
                              column.key === "unknown_peers_1h"
                            ? 155
                            : 110
                    }
                    tooltip={column.label}
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
                {sorted.map((row) => (
                  <Table.Row key={row._key}>
                    {columns.map((column) => (
                      <Table.Cell key={column.key} title={row.scopeError}>
                        {column.key === "service"
                          ? mapAction(row)
                          : ["window_start", "window_end"].includes(
                                column.key,
                              ) && typeof row[column.key] === "number"
                            ? new Date(
                                (row[column.key] as number) * 1000,
                              ).toISOString()
                            : typeof row[column.key] === "string"
                              ? scopeLabel(row[column.key] as string)
                              : (row[column.key] ?? "—")}
                      </Table.Cell>
                    ))}
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          )}
        </>
      )}
      <p>
        <a href={pageURL("setup", stateParams(state))}>Check catalog setup</a>
      </p>
      <form
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
                  earliest:
                    state.mode === "demo" ? demoWindow.earliest : earliest,
                  latest: state.mode === "demo" ? demoWindow.latest : latest,
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
          demoArgs={state.mode === "demo" ? demoArgs : undefined}
          scenario={state.scenario}
        />
        <TimePicker
          earliest={earliest}
          latest={latest}
          timezone={timezone}
          live={inSplunk}
          disabled={state.mode === "demo"}
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
        <Button
          type="submit"
          appearance="primary"
          disabled={!!errors.length}
          label="Open map"
        />
      </form>
      <p>
        <a
          href={pageURL(
            "map",
            stateParams({
              ...state,
              mode: "demo",
              args: demoEntryTarget.args,
              earliest: demoEntryTarget.earliest,
              latest: demoEntryTarget.latest,
            }),
          )}
        >
          Explore captured synthetic demo data
        </a>
      </p>
    </main>
  );
}
