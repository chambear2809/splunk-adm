import { ControllerMap } from "../AppDynamicsCatalog";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  Ban,
  ChevronDown,
  CircleAlert,
  MoreHorizontal,
  RefreshCw,
  Search,
  Settings2,
  SlidersHorizontal,
  TriangleAlert,
  X,
} from "lucide-react";
import type { Graph, GraphEdge, GraphRead } from "../graph";
import { isBlocked, plural, portLabel, warningTitle } from "../glossary";
import type { View } from "../layout";
import { MapView } from "../MapView";
import { Inspector } from "../Inspector";
import { MapDnsInspection } from "../MapDnsInspection";
import { MapServiceHealthInspection } from "../MapServiceHealthInspection";
import { deriveFindings } from "../findings";
import { FindingsList, EvidenceActions } from "../FindingsList";
import { useHealthStatus } from "../data/healthStatus";
import { PathStrip } from "../PathStrip";
import { TraceView } from "../trace/TraceView";
import { usePathTrace } from "../trace/usePathTrace";
import { traceHighlight } from "../trace/traceModel";
import { deviceURL, TracePathForm } from "./ExploreTools";
import { DevicesView } from "../DevicesView";
import { formatUtc, formatInZone, graphWindowLabel } from "../time";
import { argError } from "../provider";
import { ScopeBar } from "../map/ScopeBar";
import { TimePicker, pickerBound } from "../map/TimePicker";
import { timeError, isIncompleteWindow } from "../data/timeBounds";
import {
  DEMO_SCENARIOS,
  demoArgsFor,
  type DemoScenario,
} from "../data/demoClient";
import type { SearchClient } from "../data/searchClient";
import { pageURL, parseUrlState, writeUrlState } from "../app/urlState";
import { useMapPresentation } from "../map/useMapPresentation";
import { useMapSnapshot } from "../map/useMapSnapshot";
import { ExportMenu } from "../map/ExportMenu";
import { ChangePanel } from "../ChangePanel";
import { SavedViews } from "../SavedViews";
import { useMapExports } from "../map/useMapExports";
import "../print.css";
import { activeFacetCount, FilterBar, FocusSelect } from "../map/FilterBar";
import {
  prefsFor,
  mapPreferences,
  PERSONAS,
  PERSONA_VIEWS,
  type Persona,
} from "../app/prefs";
import { Legend } from "../map/Legend";
import { TableView } from "../map/TableView";
import type { GraphArgs } from "../rows";
import { useTheme, type Theme } from "../theme";
import { resolveDevice, type Topology } from "../topology";
import { ImpactButton } from "../impact/ImpactButton";
import { useImpactOverlay } from "../impact/useImpactOverlay";

const ARG_FIELDS: [keyof GraphArgs, string, string][] = [
  ["service", "Entry service", "OTel service.name"],
  ["environment", "Environment", "deployment.environment.name"],
  ["cluster", "Cluster", "k8s.cluster.name"],
  ["namespace", "Namespace", "Kubernetes namespace"],
];
type Tab = View | "devices" | "table";
type Panel =
  | "settings"
  | "help"
  | "warnings"
  | "export"
  | "changes"
  | "saved"
  | "scope"
  | "filters"
  | "more"
  | "legend";
const FOCUS_PREFIX = {
  any: "Within",
  callers: "Observed callers within",
  dependencies: "Observed dependencies within",
} as const;
// Extra shell height while a candidate path is open, so the map keeps its size.
const PATH_STRIP_ROOM = 260;
const TRACE_ROOM = 150;
const TABS: [Tab, string][] = [
  ["network", "Network"],
  ["services", "Services"],
  ["devices", "Devices"],
  ["table", "Table"],
];

const themeOverride = (): Theme | undefined => {
  const t =
    typeof location !== "undefined"
      ? new URLSearchParams(location.search).get("theme")
      : null;
  return t === "dark" || t === "light" ? t : undefined;
};

export function MapPage(props: Parameters<typeof StandardMapPage>[0]) {
  const state =
    props.initialState ??
    parseUrlState(
      new URLSearchParams(
        typeof location === "undefined" ? "" : location.search,
      ),
    );
  return state.appd ? (
    <ControllerMap state={state} client={props.client} />
  ) : (
    <StandardMapPage {...props} />
  );
}

function StandardMapPage({
  client,
  initialState = parseUrlState(
    new URLSearchParams(typeof location === "undefined" ? "" : location.search),
  ),
  theme: toolkitTheme,
  timezone,
  inSplunk = false,
  demoData,
  onModeChange,
  user,
  usePersonaDefault = false,
}: {
  user?: string;
  usePersonaDefault?: boolean;
  client?: SearchClient;
  initialState?: import("../app/urlState").UrlState;
  theme?: Theme;
  timezone?: string;
  inSplunk?: boolean;
  onModeChange?: (mode: "demo" | "live") => void;
  /** Overrides the shipped demo (development harness only). */
  demoData?: { graph: () => Graph; topology: () => Topology };
}) {
  const detectedTheme = useTheme(inSplunk, themeOverride());
  const theme = toolkitTheme ?? detectedTheme;
  const {
    graph,
    topology,
    snapshot,
    mode,
    scenario,
    args,
    earliest,
    latest,
    busy,
    error,
    visible,
    setArgs,
    setEarliest,
    setLatest,
    cancelQuery,
    refresh: refreshSnapshot,
    showDemo: showDemoSnapshot,
    switchLive: switchSnapshotLive,
  } = useMapSnapshot({ client, initialState, timezone, demoData });
  const preferences = useMemo(
    () => (user ? prefsFor(user) : undefined),
    [user],
  );
  const [saved] = useState(() => mapPreferences(preferences?.read() ?? {}));
  const [persona, setPersona] = useState<Persona>(saved.persona);
  const [mergeFrontends, setMergeFrontends] = useState(saved.mergeFrontends);
  const [tab, setTab] = useState<Tab>(
    usePersonaDefault ? saved.view : initialState.tab,
  );
  const {
    facets,
    focus,
    followedEdges,
    setFocus,
    clearFilters,
    changeFacets,
    selection,
    pathHidden,
    setPathHidden,
    query,
    setQuery,
    matchIdx,
    focusTarget,
    focusRequest,
    select,
    clearSelection,
    resetView,
    index,
    topo,
    node,
    displayGraph,
    displayIndex,
    narrowed,
    layout,
    onFitScale,
    q,
    matchNodes,
    matchEdges,
    matchList,
    cycleMatch,
    nodeMatchCount,
    edgeMatchCount,
    totals,
    warnings,
    selectedFrontends,
    selectedEdge,
    pathTab,
    path,
    label,
    deviceLabel,
    describeEdge,
    setExpanded,
    setBackend,
  } = useMapPresentation({
    graph,
    topology,
    tab,
    setTab,
    mergeFrontends,
    initialQuery: initialState.query,
  });
  const empty = visible && graph.nodes.length === 0;
  const selectedBundle = useMemo(() => {
    if (selection?.kind !== "edge") return undefined;
    const routed = layout.edges.find(
      (r) => r.card && r.members.includes(selection.id),
    );
    return routed?.card
      ? { title: routed.card.title, edgeIds: routed.members }
      : undefined;
  }, [layout, selection]);
  const [traceRequest, setTraceRequest] = useState(initialState.trace);
  const traceResult = usePathTrace({
    request: traceRequest,
    demo: !__ADM_SPLUNK_BUILD__ && mode === "demo",
    client: snapshot.client ?? client,
    graph: mode === "live" && visible ? graph : undefined,
    topology: mode === "live" && visible ? topology : undefined,
    earliest,
    latest,
    timezone,
  });
  const tracedPath =
    traceResult.status === "done" ? traceResult.trace : undefined;
  const traceMatch = useMemo(
    () =>
      tracedPath && tracedPath.status !== "unresolved"
        ? traceHighlight(tracedPath)
        : undefined,
    [tracedPath],
  );
  const impact = useImpactOverlay(graph, topo);
  const openNode = (id: string) => {
    const n = index.node.get(id);
    const device = [n?.label, ...(n?.addresses ?? [])]
      .map((raw) => resolveDevice(raw, topo))
      .find(Boolean);
    if (device) location.assign(deviceURL(device.id));
  };
  const focusNotes: string[] = [];
  if (focus && focus.direction !== "any" && followedEdges) {
    const followed = displayGraph.edges.filter((edge) =>
      followedEdges.has(edge.id),
    );
    const kind = focus.direction === "callers" ? "callers" : "dependencies";
    focusNotes.push(
      "Limited to conversations and traced calls observed in this window and these sources.",
    );
    if (!followed.length)
      focusNotes.push(
        `No ${kind} were observed here; that does not show that none exist.`,
      );
    const unknown = followed.filter(
      (edge) => edge.direction_basis === "unknown",
    ).length;
    const inferred = followed.filter(
      (edge) => edge.direction_basis === "port_rule",
    ).length;
    const blocked = displayGraph.edges.filter(
      (edge) => edge.relationship === "communicates_with" && isBlocked(edge),
    ).length;
    if (unknown)
      focusNotes.push(
        `${plural(unknown, "followed connection")} with unknown direction, followed both ways.`,
      );
    if (inferred)
      focusNotes.push(
        `${plural(inferred, "followed connection")} with direction inferred from ports.`,
      );
    if (blocked)
      focusNotes.push(
        `${plural(blocked, "blocked conversation")} between shown cards, not followed.`,
      );
  }
  const savePreferences = (nextPersona: Persona, merge: boolean) => {
    preferences?.write({
      ...preferences.read(),
      persona: nextPersona,
      mergeFrontends: merge,
    });
  };
  const healthReport = useHealthStatus()?.report;
  useEffect(() => onModeChange?.(mode), [mode, onModeChange]);
  // A live map starts unscoped: open the scope fields so they are the first step.
  const [panel, setPanel] = useState<Panel | null>(() =>
    initialState.mode === "live" &&
    Object.values(initialState.args).some((value) => !value)
      ? "scope"
      : null,
  );
  useEffect(() => {
    if (visible) setPanel((current) => (current === "scope" ? null : current));
  }, [visible]);
  const [findingsOpen, setFindingsOpen] = useState(false);
  const filterCount = activeFacetCount(facets);
  const root = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  useLayoutEffect(() => {
    const el = root.current;
    if (el) setTop(el.getBoundingClientRect().top + window.scrollY);
  }, []);

  const pathOpen =
    visible && !!pathTab && !!path && !!selectedEdge && !pathHidden;
  const traceOpen = !!traceRequest;
  useEffect(() => {
    if (pathOpen)
      root.current
        ?.querySelector(".path-strip")
        ?.scrollIntoView?.({ block: "nearest" });
  }, [pathOpen, selectedEdge?.id]);

  const snapshotChanged = () => {
    resetView();
    clearFilters();
    select(null);
    setPanel(null);
  };
  const showDemo = async (sc: DemoScenario = scenario) => {
    if (await showDemoSnapshot(sc)) {
      resetView();
      clearFilters();
      select(null);
    }
  };
  const refresh = async () => {
    const result = await refreshSnapshot();
    if (result) snapshotChanged();
    else if (result === false) setPanel(null);
  };
  useEffect(() => {
    writeUrlState({
      args,
      earliest,
      latest,
      mode,
      scenario,
      tab,
      query,
      ...(traceRequest ? { trace: traceRequest } : {}),
    });
  }, [args, earliest, latest, mode, scenario, tab, query, traceRequest]);
  const switchLive = () => {
    switchSnapshotLive();
    clearSelection();
    setPanel("scope");
  };
  const argErrors = ARG_FIELDS.map(([key]) => argError(key, args[key])).filter(
    Boolean,
  );

  const {
    exportBusy,
    exportError,
    exportCsv,
    exportContextEvidenceCsv,
    exportJson,
    exportPng,
    exportPrint,
  } = useMapExports({
    graph,
    index,
    topo,
    root,
    close: () => setPanel(null),
    edges: layout.edges,
  });
  const togglePanel = (p: Panel) => setPanel((cur) => (cur === p ? null : p));
  const [errorHint, errorDetail] = error.split(" Splunk reported: ");

  const findings = useMemo(
    () =>
      deriveFindings(graph, index, mode === "live" ? healthReport : undefined),
    [graph, index, mode, healthReport],
  );
  const showFindingPath = (edge: GraphEdge) => {
    if (edge.relationship === "forwards_to") {
      const conversation = (index.incident.get(edge.source) ?? []).find(
        (e) =>
          e.relationship === "communicates_with" && e.target === edge.source,
      );
      if (conversation) {
        select({ kind: "edge", id: conversation.id });
        setBackend(edge.target);
      } else select({ kind: "edge", id: edge.id });
    } else select({ kind: "edge", id: edge.id });
    clearFilters();
    setTab("network");
    setPathHidden(false);
  };
  const summary = (
    <FindingsList
      findings={findings}
      graph={graph}
      index={index}
      live={mode === "live"}
      onShowPath={showFindingPath}
      onClose={() => setFindingsOpen(false)}
    />
  );

  const unknownChips = [
    totals.unknownSources > 0 &&
      plural(totals.unknownSources, "unknown source"),
    totals.unknownOther > 0 && plural(totals.unknownOther, "unknown endpoint"),
  ].filter(Boolean) as string[];
  const edgeCountLabel = (edges: GraphEdge[]) =>
    [
      edges.filter((e) => e.relationship === "calls").length &&
        `${edges.filter((e) => e.relationship === "calls").length} calls`,
      edges.filter((e) => e.relationship === "communicates_with").length &&
        `${edges.filter((e) => e.relationship === "communicates_with").length} conversations`,
      edges.filter((e) => e.relationship === "traffic_observation").length &&
        `${edges.filter((e) => e.relationship === "traffic_observation").length} observation links`,
    ]
      .filter(Boolean)
      .join(", ");

  return (
    <div
      className="adm"
      data-adm-theme={theme}
      data-timezone={
        timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone
      }
      data-loaded={visible ? "true" : "false"}
      data-node-count={visible ? graph.nodes.length : 0}
      data-edge-count={visible ? graph.edges.length : 0}
      data-line-count={visible ? layout.edges.length : 0}
      ref={root}
      style={{
        height: `calc(max(600px, 100vh - ${Math.round(top) + (inSplunk ? 16 : 0)}px) + ${(pathOpen ? PATH_STRIP_ROOM : 0) + (traceOpen ? TRACE_ROOM : 0)}px)`,
      }}
      onKeyDown={(e) => {
        if (e.key !== "Escape" || e.defaultPrevented) return;
        if (panel) setPanel(null);
        else if (selection) clearSelection();
      }}
    >
      <header className="bar atlas-map-header">
        <button
          className="scope-button"
          aria-label="Scope"
          aria-expanded={panel === "scope"}
          title={[args.environment, args.cluster, args.namespace, args.service]
            .filter(Boolean)
            .join(" · ")}
          onClick={() => togglePanel("scope")}
        >
          <strong className="scope-service">
            {(visible ? graph.boundary.service : args.service) ||
              "Choose scope"}
          </strong>
          <span className="scope-dims">
            {(visible
              ? [
                  graph.boundary.environment,
                  graph.boundary.cluster,
                  graph.boundary.namespace,
                ]
              : [args.environment, args.cluster, args.namespace]
            )
              .filter(Boolean)
              .join(" · ")}
          </span>
          <ChevronDown size={14} aria-hidden />
        </button>
        {argErrors.length > 0 && panel !== "scope" && (
          <button
            className="chip warn"
            onClick={() => setPanel("scope")}
            title={argErrors.join(" ")}
          >
            Invalid scope
          </button>
        )}
        <TimePicker
          earliest={earliest}
          latest={latest}
          timezone={timezone}
          live={inSplunk}
          disabled={mode === "demo"}
          onChange={(start, end) => {
            cancelQuery();
            setEarliest(start);
            setLatest(end);
          }}
        />
        {mode === "live" && (
          <button
            className="primary-button"
            onClick={refresh}
            disabled={
              busy ||
              argErrors.length > 0 ||
              !!timeError(earliest, latest, timezone)
            }
          >
            {busy ? "Building…" : "Build map"}
          </button>
        )}
        {!__ADM_SPLUNK_BUILD__ && mode === "demo" && (
          <span
            className="chip demo"
            title={
              visible
                ? `Captured window ${formatInZone(graph.window.start, timezone)} → ${formatInZone(graph.window.end, timezone)}`
                : undefined
            }
          >
            Demo data
          </span>
        )}
        {mode === "live" && !visible && !busy && (
          <span className="chip">Not loaded</span>
        )}
        {mode === "live" && visible && graphWindowLabel(graph, timezone) && (
          <span
            className="chip"
            data-testid="graph-window"
            title="The window this graph counts. Windows over five minutes start on a five-minute boundary."
          >
            {graphWindowLabel(graph, timezone)}
          </span>
        )}
        {mode === "live" && isIncompleteWindow(latest, timezone) && (
          <span
            className="chip warn"
            title="Conversations use 5-minute buckets; the latest 10 minutes may still be filling."
          >
            Incomplete window
          </span>
        )}
        {busy && visible && (
          <span className="chip" role="status">
            <RefreshCw size={13} className="spin" /> Updating…
          </span>
        )}
        {visible && !empty && (
          <div className="kpis" aria-label="Summary">
            <span className="kpi">
              <b>{totals.services}</b>{" "}
              {totals.services === 1 ? "service" : "services"}
            </span>
            {unknownChips.length > 0 && (
              <button
                className="kpi warn"
                aria-pressed={facets.identity === "unknown"}
                title={unknownChips.join(" · ")}
                onClick={() =>
                  changeFacets({
                    ...facets,
                    identity:
                      facets.identity === "unknown" ? undefined : "unknown",
                  })
                }
              >
                <CircleAlert size={14} aria-hidden />
                {totals.unknownSources + totals.unknownOther} unknown
              </button>
            )}
            {totals.externalNodes > 0 && (
              <button
                className="kpi"
                aria-pressed={facets.identity === "external"}
                onClick={() =>
                  changeFacets({
                    ...facets,
                    identity:
                      facets.identity === "external" ? undefined : "external",
                  })
                }
              >
                {totals.externalNodes} external
              </button>
            )}
            {totals.blocked > 0 && (
              <button
                className="kpi blocked"
                aria-pressed={!!facets.blocked}
                onClick={() =>
                  changeFacets({ ...facets, blocked: !facets.blocked })
                }
              >
                <Ban size={14} aria-hidden />
                {totals.blocked} blocked
              </button>
            )}
            {graph.read && <ReadChip read={graph.read} />}
            {warnings.length > 0 && (
              <button
                className="kpi warn"
                aria-expanded={panel === "warnings"}
                onClick={() => togglePanel("warnings")}
              >
                <TriangleAlert size={14} aria-hidden />
                {plural(warnings.length, "warning")}
              </button>
            )}
          </div>
        )}
        <div className="actions">
          <button
            className="icon-button"
            aria-label="More actions"
            aria-haspopup="true"
            aria-expanded={panel === "more"}
            onClick={() => togglePanel("more")}
          >
            <MoreHorizontal size={18} />
          </button>
        </div>
        {panel === "scope" && (
          <section
            className="popover scope-popover"
            aria-label="Application scope"
          >
            <ScopeBar
              args={args}
              live={mode === "live"}
              autoSelectSingle
              client={client}
              scenario={scenario}
              demoArgs={
                !__ADM_SPLUNK_BUILD__ && mode === "demo"
                  ? demoArgsFor(scenario)
                  : undefined
              }
              onChange={(next) => {
                cancelQuery();
                setArgs(next);
              }}
            />
            {!__ADM_SPLUNK_BUILD__ && mode === "demo" && (
              <p className="muted small">
                Demo scope is fixed ·{" "}
                <button className="link" onClick={() => setPanel("settings")}>
                  Map settings
                </button>
              </p>
            )}
          </section>
        )}
        {panel === "more" && (
          <section className="popover more-menu" aria-label="More actions">
            <button
              className="menu-item"
              disabled={!visible || busy}
              onClick={() => setPanel("changes")}
            >
              Changes
            </button>
            <button className="menu-item" onClick={() => setPanel("saved")}>
              Saved views
            </button>
            <button
              className="menu-item"
              disabled={
                !visible || empty || tab === "devices" || tab === "table"
              }
              onClick={() => setPanel("legend")}
            >
              Legend
            </button>
            <button
              className="menu-item"
              disabled={!visible || empty}
              onClick={() => setPanel("export")}
            >
              Export
            </button>
            <button className="menu-item" onClick={() => setPanel("settings")}>
              Map settings
            </button>
            <button className="menu-item" onClick={() => setPanel("help")}>
              How to read this map
            </button>
          </section>
        )}
        {panel === "legend" && visible && !empty && (
          <section className="popover" aria-label="Map legend">
            <div className="popover-head">
              <h2>Legend</h2>
              <button
                className="icon-button"
                aria-label="Close legend"
                onClick={() => setPanel(null)}
              >
                <X size={16} />
              </button>
            </div>
            <Legend
              alwaysOpen
              edges={layout.edges.flatMap((e) =>
                e.members.flatMap((id) => displayIndex.edge.get(id) ?? []),
              )}
              index={displayIndex}
              collapsed={layout.collapsed}
            />
          </section>
        )}
        {panel === "export" && (
          <ExportMenu
            close={() => setPanel(null)}
            onCsv={exportCsv}
            onContextEvidenceCsv={exportContextEvidenceCsv}
            hasContextEvidence={graph.edges.some(
              (edge) =>
                (edge.attachment_evidence?.length ?? 0) > 0 ||
                (edge.traffic_observations?.length ?? 0) > 0,
            )}
            onJson={exportJson}
            onPng={exportPng}
            onPrint={exportPrint}
            pngDisabled={
              !pathTab || exportBusy || displayGraph.nodes.length === 0
            }
            busy={exportBusy}
            error={exportError}
          />
        )}
        {panel === "changes" && visible && (
          <section className="popover atlas-phase8-panel">
            <button
              className="icon-button"
              aria-label="Close changes"
              onClick={() => setPanel(null)}
            >
              <X size={16} />
            </button>
            <ChangePanel
              key={`${mode}:${scenario}:${graph.snapshot_id}`}
              graph={graph}
              client={snapshot.client ?? client}
              timezone={timezone}
              scenario={scenario}
            />
          </section>
        )}
        {panel === "saved" && (
          <section className="popover atlas-phase8-panel">
            <button
              className="icon-button"
              aria-label="Close saved views"
              onClick={() => setPanel(null)}
            >
              <X size={16} />
            </button>
            <SavedViews
              key={user}
              user={user}
              state={
                visible
                  ? {
                      args: {
                        service: graph.boundary.service,
                        environment: graph.boundary.environment,
                        cluster: graph.boundary.cluster,
                        namespace: graph.boundary.namespace,
                      },
                      earliest: pickerBound(graph.window.start),
                      latest: pickerBound(graph.window.end),
                      mode,
                      scenario,
                      tab,
                      query,
                    }
                  : undefined
              }
            />
          </section>
        )}
        {panel === "settings" && (
          <section className="popover settings" aria-label="Map settings">
            <div className="popover-head">
              <h2>Application</h2>
              <button
                className="icon-button"
                aria-label="Close settings"
                onClick={() => setPanel(null)}
              >
                <X size={16} />
              </button>
            </div>
            <label className="scenario">
              <span>Default view for</span>
              <select
                aria-label="Default view for persona"
                value={persona}
                onChange={(e) => {
                  const next = e.target.value as Persona;
                  setPersona(next);
                  setTab(PERSONA_VIEWS[next]);
                  clearFilters();
                  savePreferences(next, mergeFrontends);
                }}
              >
                {Object.entries(PERSONAS).map(([id, label]) => (
                  <option key={id} value={id}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="atlas-filter-check">
              <input
                type="checkbox"
                checked={mergeFrontends}
                onChange={(e) => {
                  setMergeFrontends(e.target.checked);
                  savePreferences(persona, e.target.checked);
                }}
              />
              Group Service frontends
            </label>
            {!__ADM_SPLUNK_BUILD__ && (
              <div className="segmented" role="group" aria-label="Data source">
                <button
                  aria-pressed={mode === "demo"}
                  onClick={() => showDemo()}
                >
                  Demo
                </button>
                <button
                  aria-pressed={mode === "live"}
                  onClick={switchLive}
                  disabled={!client}
                  title={
                    client
                      ? undefined
                      : "Available when the app runs inside Splunk"
                  }
                >
                  Splunk
                </button>
              </div>
            )}
            {!__ADM_SPLUNK_BUILD__ && mode === "demo" && !demoData && (
              <label className="scenario">
                <span>Demo scenario</span>
                <select
                  value={scenario}
                  onChange={(e) => {
                    showDemo(e.target.value as DemoScenario);
                    setPanel("settings");
                  }}
                >
                  {DEMO_SCENARIOS.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <p className="muted small">
              <a href={pageURL("setup")}>Admin · Setup</a>
            </p>
          </section>
        )}
        {panel === "warnings" && (
          <section className="popover" aria-label="Search warnings">
            <div className="popover-head">
              <h2>Search warnings</h2>
              <button
                className="icon-button"
                aria-label="Close warnings"
                onClick={() => setPanel(null)}
              >
                <X size={16} />
              </button>
            </div>
            <ul className="warning-list">
              {warnings.map((w, i) => (
                <li key={i}>
                  <b>{warningTitle(w)}</b>
                  <span>{w}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {panel === "help" && (
          <section className="popover help" aria-label="How to read this map">
            <div className="popover-head">
              <h2>How to read this map</h2>
              <button
                className="icon-button"
                aria-label="Close help"
                onClick={() => setPanel(null)}
              >
                <X size={16} />
              </button>
            </div>
            <ul>
              <li>
                Lanes: <b>Sources</b> → <b>Entry points</b> → <b>Application</b>{" "}
                → <b>Dependencies</b>; <b>Infrastructure</b> below.
              </li>
              <li>
                Arrow = client → server; pill = server port; no arrow = unknown
                direction.
              </li>
              <li>
                Dashed grey = <b>inferred</b> backend. Red ⦸ = <b>Blocked</b>.
              </li>
              <li>
                Keyboard: ←/→ columns · ↑/↓ cards · Enter select · Esc clear.
              </li>
              <li>
                <a href={`${pageURL("help")}#about-evidence`}>About evidence</a>
              </li>
            </ul>
            <p className="muted small">
              {graph.coverage.spans.toLocaleString()} spans in this map.
              Generated {formatUtc(graph.generated_at)} UTC.
            </p>
          </section>
        )}
      </header>
      {error && (
        <div className="banner error" role="alert">
          <CircleAlert size={16} aria-hidden />
          <div className="banner-text">
            <strong>Couldn't build the map.</strong> {errorHint}
            {visible && mode === "live" && " The previous map is still shown."}
            {errorDetail && (
              <details>
                <summary>Details</summary>
                <code>{errorDetail}</code>
              </details>
            )}
          </div>
          <button
            className="secondary-button"
            onClick={refresh}
            disabled={busy || mode === "demo"}
          >
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      )}
      <div
        className={`body ${findingsOpen ? "has-findings" : ""} ${selection ? "has-selection" : ""}`}
      >
        <section className="map-panel">
          <div className="toolbar">
            <div className="segmented" role="group" aria-label="View">
              {TABS.map(([t, name]) => (
                <button
                  key={t}
                  aria-pressed={tab === t}
                  onClick={() => {
                    if (t === "services") clearFilters();
                    setTab(t);
                  }}
                >
                  {name}
                </button>
              ))}
            </div>
            <label className="search">
              <Search size={15} aria-hidden />
              <input
                aria-label="Highlight by name, IP, EPG, port or device"
                placeholder="Highlight name, IP, EPG, port…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    cycleMatch(e.shiftKey ? -1 : 1);
                  } else if (e.key === "Escape" && query) {
                    e.preventDefault();
                    setQuery("");
                  }
                }}
              />
              {q && (
                <span
                  className={`match-count ${nodeMatchCount + edgeMatchCount ? "" : "none"}`}
                  role="status"
                >
                  {nodeMatchCount + edgeMatchCount === 0
                    ? "No matches"
                    : matchIdx >= 0
                      ? `${matchIdx + 1} of ${matchList.length}`
                      : [
                          nodeMatchCount && plural(nodeMatchCount, "card"),
                          edgeMatchCount &&
                            plural(edgeMatchCount, "conversation"),
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                </span>
              )}
            </label>
            {visible && !empty && (
              <FocusSelect
                focus={{
                  hops: focus?.hops ?? 0,
                  direction: focus?.direction ?? "any",
                }}
                canFocus={selection?.kind === "node"}
                onFocus={(hops, direction) => {
                  if (!hops) setFocus(null);
                  else {
                    const id =
                      selection?.kind === "node" ? selection.id : focus?.id;
                    if (id) setFocus({ id, hops, direction });
                  }
                }}
              />
            )}
            {visible && !empty && (
              <ImpactButton
                compact
                token={selection?.kind === "node" ? selection.id : undefined}
                label={
                  selection?.kind === "node" ? label(selection.id) : undefined
                }
              />
            )}
            <TracePathForm
              compact
              key={
                traceRequest ? `${traceRequest.src}>${traceRequest.dst}` : ""
              }
              initial={traceRequest}
              onSubmit={(src, dst) => {
                setTraceRequest({ src, dst });
                if (tab === "table" || tab === "devices") setTab("network");
              }}
            />
            <span className="toolbar-spacer" />
            {visible && !empty && tab !== "services" && (
              <button
                className={`secondary-button ${filterCount ? "active" : ""}`}
                aria-expanded={panel === "filters"}
                onClick={() => togglePanel("filters")}
              >
                <SlidersHorizontal size={14} aria-hidden /> Filters
                {filterCount ? ` (${filterCount})` : ""}
              </button>
            )}
            {visible && (
              <button
                className="secondary-button"
                aria-expanded={findingsOpen}
                aria-controls="atlas-findings"
                onClick={() => setFindingsOpen((open) => !open)}
              >
                Findings
                <span className={`count-badge ${findings.length ? "has" : ""}`}>
                  {findings.length}
                </span>
              </button>
            )}
            {panel === "filters" && visible && !empty && (
              <section className="popover filters-popover" aria-label="Filters">
                <div className="popover-head">
                  <h2>Filters</h2>
                  <button
                    className="icon-button"
                    aria-label="Close filters"
                    onClick={() => setPanel(null)}
                  >
                    <X size={16} />
                  </button>
                </div>
                <FilterBar
                  network={tab !== "services"}
                  graph={graph}
                  facets={facets}
                  onChange={changeFacets}
                />
              </section>
            )}
          </div>
          {visible && !empty && narrowed && (
            <div className="atlas-filter-status">
              <span>
                {displayGraph.nodes.length} of {graph.nodes.length} nodes ·{" "}
                {edgeCountLabel(
                  displayGraph.edges.filter(
                    (e) => e.relationship !== "runs_on",
                  ),
                ) || "relationships"}{" "}
                of{" "}
                {edgeCountLabel(
                  graph.edges.filter((e) => e.relationship !== "runs_on"),
                ) || "relationships"}
                {focus
                  ? ` · ${FOCUS_PREFIX[focus.direction]} ${plural(focus.hops, "hop")} of ${label(focus.id)}`
                  : ""}
                . Findings and exports use the full map.
                {focusNotes.length ? ` ${focusNotes.join(" ")}` : ""}
              </span>
              <button className="link" onClick={clearFilters}>
                Clear filters and focus
              </button>
            </div>
          )}
          <div className="map-area">
            {!visible ? (
              busy ? (
                <Skeleton />
              ) : (
                <div className="state">
                  <h2>Choose an application to map</h2>
                  <button
                    className="primary-button"
                    onClick={() => {
                      setPanel("scope");
                      requestAnimationFrame(() =>
                        root.current
                          ?.querySelector<HTMLInputElement>(
                            '.scope-popover [role="combobox"]',
                          )
                          ?.focus(),
                      );
                    }}
                  >
                    Choose scope
                  </button>
                </div>
              )
            ) : empty ? (
              <div className="state">
                <h2>
                  No traces for {graph.boundary.service} in{" "}
                  {graph.boundary.namespace}
                </h2>
                {warnings.length > 0 && (
                  <ul className="state-warnings">
                    {warnings.map((w, i) => (
                      <li key={i}>
                        <TriangleAlert size={14} aria-hidden />{" "}
                        <b>{warningTitle(w)}.</b> {w}
                      </li>
                    ))}
                  </ul>
                )}
                <p>
                  The map starts from the entry service's spans. Next steps:
                </p>
                <ul>
                  <li>
                    Check that the service and environment match{" "}
                    <code>service.name</code> and{" "}
                    <code>deployment.environment.name</code>.
                  </li>
                  <li>Widen the time range.</li>
                  <li>
                    Confirm the collector sends traces to Splunk Platform and
                    the ADM saved searches are enabled.
                  </li>
                </ul>
                <button
                  className="primary-button"
                  onClick={() => setPanel("settings")}
                >
                  <Settings2 size={15} /> Change application
                </button>
              </div>
            ) : displayGraph.nodes.length === 0 ? (
              <div className="state">
                <h2>No matches for these filters</h2>
                <button className="secondary-button" onClick={clearFilters}>
                  Clear filters and focus
                </button>
              </div>
            ) : tab === "table" ? (
              <TableView
                graph={displayGraph}
                label={label}
                selected={selection?.kind === "edge" ? selection.id : undefined}
                onSelect={(id) => select({ kind: "edge", id })}
                topo={topo}
                index={displayIndex}
                node={node}
              />
            ) : tab === "devices" ? (
              <DevicesView
                onOpenDevice={(id) => location.assign(deviceURL(id))}
                graph={displayGraph}
                index={displayIndex}
                topo={topo}
                selected={selection?.kind === "edge" ? selection.id : undefined}
                onSelect={(id) => select({ kind: "edge", id })}
                client={snapshot.client ?? client}
                live={mode === "live"}
                earliest={earliest}
                latest={latest}
              />
            ) : (
              <MapView
                layout={layout}
                index={displayIndex}
                emphasisReason={
                  q
                    ? `Highlight matches “${q}”`
                    : impact && !traceMatch
                      ? impact.headline
                      : traceMatch && traceRequest
                        ? `Trace ${traceRequest.src} → ${traceRequest.dst}`
                        : selection?.kind === "node"
                          ? `Connections to ${label(selection.id)}`
                          : "Selected connection and its path"
                }
                onClearEmphasis={() => {
                  setQuery("");
                  clearSelection();
                  if (!q) setTraceRequest(undefined);
                }}
                matchNodes={matchNodes ?? traceMatch?.nodes ?? impact?.nodes}
                matchEdges={matchEdges ?? traceMatch?.edges ?? impact?.edges}
                impactClass={impact?.className}
                selection={selection}
                onSelect={(s) => (s ? select(s) : clearSelection())}
                onOpenNode={openNode}
                focusTarget={focusTarget}
                focusRequest={focusRequest}
                onFitScale={onFitScale}
                onExpand={(g) => setExpanded((cur) => new Set(cur).add(g))}
                deviceLabel={deviceLabel}
                describeEdge={describeEdge}
                label={`${graph.boundary.service} dependency map`}
              />
            )}
          </div>
          {traceRequest && (
            <div className="atlas-map-trace">
              <TraceView
                key={`${traceRequest.src}>${traceRequest.dst}`}
                request={traceRequest}
                result={traceResult}
                onCancel={traceResult.cancel}
                onRetry={traceResult.retry}
                onClose={() => setTraceRequest(undefined)}
              />
            </div>
          )}
          {pathOpen && path && selectedEdge && (
            <PathStrip
              path={path}
              title={`${label(selectedEdge.source)} → ${label(selectedEdge.target)} · ${portLabel(selectedEdge)}`}
              onClose={() => setPathHidden(true)}
              onBackend={setBackend}
            />
          )}
        </section>
        <aside className="inspector" aria-label="Details" id="atlas-findings">
          {visible ? (
            <>
              {selectedFrontends &&
                selectedFrontends.length > 1 &&
                selection && (
                  <label className="atlas-frontend-picker">
                    Frontend
                    <select
                      aria-label="Inspect Service frontend"
                      value={selection.id}
                      onChange={(e) =>
                        select({ kind: "node", id: e.target.value })
                      }
                    >
                      {selectedFrontends.map((id) => (
                        <option key={id} value={id}>
                          {index.node.get(id)?.label ?? id}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
              <Inspector
                selection={selection}
                index={index}
                topo={topo}
                onSelect={(s) => (s ? select(s) : clearSelection())}
                onClose={clearSelection}
                onShowPath={() => {
                  if (!pathTab) setTab("network");
                  setPathHidden(false);
                }}
                pathOpen={pathTab && !!path && !pathHidden}
                summary={findingsOpen ? summary : null}
                bundle={selectedBundle}
              />
              {selection && (
                <MapDnsInspection
                  key={`${user ?? "anonymous"}:${graph.snapshot_id}:${selection.kind}:${selection.id}:${mode}`}
                  graph={graph}
                  index={index}
                  selection={selection}
                  client={client}
                  live={mode === "live"}
                />
              )}
              {selection && (
                <MapServiceHealthInspection
                  key={`service-health:${graph.snapshot_id}:${selection.kind}:${selection.id}:${mode}`}
                  graph={graph}
                  index={index}
                  selection={selection}
                  client={client}
                  live={mode === "live"}
                />
              )}
              {selectedEdge && (
                <div className="inspector-body">
                  <EvidenceActions
                    key={`${graph.snapshot_id}-${selectedEdge.id}`}
                    edge={selectedEdge}
                    graph={graph}
                    index={index}
                    live={mode === "live"}
                    onShowPath={showFindingPath}
                  />
                </div>
              )}
            </>
          ) : (
            <p className="callout neutral">
              Load Splunk data to inspect the map.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}

function Skeleton() {
  return (
    <div className="skeleton" aria-label="Building map" role="status">
      {[0, 1, 2, 3].map((c) => (
        <div key={c} className="sk-col">
          {[0, 1, 2].slice(0, 3 - (c % 2)).map((r) => (
            <div key={r} className="sk-card" />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Long-window read state: summarized (exact) or a coverage percentage. */
export function ReadChip({ read }: { read: GraphRead }) {
  const tail = Math.round((read.rawTailSeconds ?? 0) / 60);
  if (read.pendingSeconds)
    return (
      <span
        className="kpi"
        role="status"
        title="Totals from five-minute summaries; the newest minutes are being read."
      >
        Summarized · newest {Math.max(1, Math.round(read.pendingSeconds / 60))}{" "}
        min loading…
      </span>
    );
  if (read.summarySeconds !== undefined && read.coverage === 100)
    return (
      <span
        className="kpi"
        title={`Exact totals from five-minute summaries${tail ? `; newest ${tail} min read raw` : ""}.`}
      >
        Summarized{tail ? ` · ${tail} min raw` : ""}
      </span>
    );
  if (read.coverage === 100) return null;
  return (
    <span
      className="kpi warn"
      title="Counts describe the slices read, not the whole window."
    >
      {read.summarySeconds !== undefined
        ? `Summary coverage ${read.coverage}%`
        : `Sampled ${read.coverage}%`}
    </span>
  );
}
