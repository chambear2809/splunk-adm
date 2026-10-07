import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ArrowRight,
  Ban,
  BookOpen,
  CircleAlert,
  Download,
  FileSpreadsheet,
  FileJson,
  RefreshCw,
  Search,
  Settings2,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  indexGraph,
  matchesQuery,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "./graph";
import {
  confidenceLabel,
  edgeIdentity,
  handoffShort,
  plural,
  portLabel,
  prettyBytes,
  relationshipLabel,
  summarize,
} from "./glossary";
import { computeLayout, type View } from "./layout";
import { FIT_MIN, MapView, type Selection } from "./MapView";
import { handoffText, IdentityBadge, Inspector } from "./Inspector";
import { PathStrip } from "./PathStrip";
import { DevicesView } from "./DevicesView";
import { requiredFlowsCsv } from "./csv";
import { formatUtc, formatUtcRange } from "./time";
import {
  argError,
  demoArgs,
  demoGraph,
  demoTopology,
  loadLive,
  loadTopology,
  TIME_RANGES,
  type SearchConstructor,
} from "./provider";
import type { GraphArgs } from "./rows";
import { useTheme, type Theme } from "./theme";
import {
  buildPath,
  deviceName,
  edgeMatches,
  emptyTopology,
  indexTopology,
  observationsByDevice,
  type Topology,
} from "./topology";

const ARG_FIELDS: [keyof GraphArgs, string, string][] = [
  ["service", "Entry service", "OTel service.name"],
  ["environment", "Environment", "deployment.environment.name"],
  ["cluster", "Cluster", "k8s.cluster.name"],
  ["namespace", "Namespace", "Kubernetes namespace"],
];
type Tab = View | "devices" | "table";
type Panel = "settings" | "help" | "warnings" | "export";
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
const download = (name: string, type: string, body: string) => {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export function App({
  SearchManager,
  releaseManager,
  inSplunk = false,
  demoData,
}: {
  SearchManager?: SearchConstructor;
  releaseManager?: (id: string) => void;
  inSplunk?: boolean;
  /** Overrides the shipped demo (development harness only). */
  demoData?: { graph: () => Graph; topology: () => Topology };
}) {
  const theme = useTheme(inSplunk, themeOverride());
  const loadDemo = demoData?.graph ?? demoGraph;
  const loadDemoTopology = demoData?.topology ?? demoTopology;
  const [graph, setGraph] = useState<Graph>(() => loadDemo());
  const [topology, setTopology] = useState<Topology>(() => loadDemoTopology());
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [tab, setTab] = useState<Tab>("network");
  const [selection, setSelection] = useState<Selection | null>(null);
  const [pathHidden, setPathHidden] = useState(false);
  const [query, setQuery] = useState("");
  const [matchIdx, setMatchIdx] = useState(-1);
  const [focusTarget, setFocusTarget] = useState<{
    kind: "node" | "edge";
    id: string;
    nonce: number;
  }>();
  const [focusRequest, setFocusRequest] = useState<{
    id: string;
    nonce: number;
  }>();
  const [panel, setPanel] = useState<Panel | null>(null);
  const [args, setArgs] = useState<GraphArgs>(demoArgs);
  const [earliest, setEarliest] = useState("-1h");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [hasLiveGraph, setHasLiveGraph] = useState(false);
  const [collapse, setCollapse] = useState(false);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const request = useRef<AbortController | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  useLayoutEffect(() => {
    const el = root.current;
    if (el) setTop(el.getBoundingClientRect().top + window.scrollY);
  }, []);
  useEffect(() => () => request.current?.abort(), []);

  const select = (s: Selection | null) => {
    setSelection(s);
    setPathHidden(false);
  };
  /** Clears the selection and returns keyboard focus to its card on the map. */
  const clearSelection = () => {
    const prev = selection;
    select(null);
    if (!prev) return;
    const id = prev.kind === "node" ? prev.id : index.edge.get(prev.id)?.source;
    if (id) setFocusRequest({ id, nonce: Date.now() });
  };
  const resetView = () => {
    setCollapse(false);
    setExpanded(new Set());
  };
  const showDemo = () => {
    request.current?.abort();
    request.current = null;
    setBusy(false);
    setGraph(loadDemo());
    setTopology(loadDemoTopology());
    setMode("demo");
    setArgs(demoArgs);
    setHasLiveGraph(false);
    setError("");
    resetView();
    select(null);
  };
  const refresh = async () => {
    if (mode === "demo") {
      setGraph(loadDemo());
      select(null);
      return;
    }
    if (!SearchManager) {
      setError("Live search is available inside the installed Splunk app.");
      return;
    }
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError("");
    try {
      const [result, topo] = await Promise.all([
        loadLive(
          SearchManager,
          { ...args, earliest },
          controller.signal,
          releaseManager,
        ),
        // A missing topology only degrades candidate paths and device names.
        loadTopology(
          SearchManager,
          earliest,
          controller.signal,
          releaseManager,
        ).catch(() => emptyTopology()),
      ]);
      if (!controller.signal.aborted) {
        setGraph(result);
        setTopology(topo);
        setHasLiveGraph(true);
        resetView();
        select(null);
        setPanel(null);
      }
    } catch (e) {
      if (!controller.signal.aborted) {
        setError(e instanceof Error ? e.message : "Unable to load the map.");
        setPanel(null);
      }
    } finally {
      if (request.current === controller) setBusy(false);
    }
  };
  const switchLive = () => {
    request.current?.abort();
    setBusy(false);
    setMode("live");
    setHasLiveGraph(false);
    setError("");
    setPanel("settings");
  };
  const changeArg = (key: keyof GraphArgs, value: string) => {
    request.current?.abort();
    setBusy(false);
    setArgs((a) => ({ ...a, [key]: value }));
  };
  const argErrors = ARG_FIELDS.map(([key]) => argError(key, args[key])).filter(
    Boolean,
  );
  const visible = mode === "demo" || hasLiveGraph;

  const index = useMemo(() => indexGraph(graph), [graph]);
  const topo = useMemo(() => indexTopology(topology), [topology]);
  const node = useCallback((id: string) => index.node.get(id), [index]);
  const view: View = tab === "services" ? "services" : "network";
  const layout = useMemo(
    () => computeLayout(graph, index, view, { collapse, expanded }),
    [graph, index, view, collapse, expanded],
  );
  useEffect(() => resetView(), [view]);
  const onFitScale = useCallback(
    (raw: number) => setCollapse(raw < FIT_MIN),
    [],
  );

  const q = query.trim();
  const matchNodes = useMemo(
    () =>
      q
        ? new Set(
            graph.nodes.filter((n) => matchesQuery(n, q)).map((n) => n.id),
          )
        : undefined,
    [q, graph],
  );
  const matchEdges = useMemo(
    () =>
      q
        ? new Set(
            graph.edges.filter((e) => edgeMatches(e, q, topo)).map((e) => e.id),
          )
        : undefined,
    [q, graph, topo],
  );
  const matchList = useMemo(() => {
    if (!matchNodes || !matchEdges) return [];
    const seen = new Set<string>();
    const nodes = layout.order.filter((id) => {
      const it = layout.items.get(id)!;
      return (
        (it.members ?? [id]).some((m) => matchNodes.has(m)) &&
        !seen.has(id) &&
        seen.add(id)
      );
    });
    const edges = layout.edges
      .filter((r) => matchEdges.has(r.id))
      .sort((a, b) => a.mid.x - b.mid.x || a.mid.y - b.mid.y)
      .map((r) => r.id);
    return [
      ...nodes.map((id) => ({ kind: "node" as const, id })),
      ...edges.map((id) => ({ kind: "edge" as const, id })),
    ];
  }, [matchNodes, matchEdges, layout]);
  useEffect(() => setMatchIdx(-1), [query, layout]);
  const cycleMatch = (step: number) => {
    if (!matchList.length) return;
    const next = (matchIdx + step + matchList.length) % matchList.length;
    setMatchIdx(next);
    setFocusTarget({ ...matchList[next], nonce: Date.now() });
  };
  const nodeMatchCount = matchNodes?.size ?? 0;
  const edgeMatchCount = matchEdges?.size ?? 0;

  const totals = useMemo(
    () => summarize(graph.nodes, graph.edges, node),
    [graph, node],
  );
  const warnings = graph.coverage.warnings;
  const selectedEdge =
    selection?.kind === "edge" ? index.edge.get(selection.id) : undefined;
  const path = useMemo(
    () =>
      selectedEdge?.relationship === "communicates_with"
        ? buildPath(selectedEdge, graph, index, topo)
        : undefined,
    [selectedEdge, graph, index, topo],
  );
  const label = (id: string) => index.node.get(id)?.label ?? id;
  const empty = visible && graph.nodes.length === 0;
  const deviceLabel = useCallback(
    (raw: string) => deviceName(raw, topo).name,
    [topo],
  );
  const describeEdge = useCallback(
    (e: GraphEdge) => {
      const name = (id: string) => node(id)?.label ?? id;
      const title = `${name(e.source)} ${e.direction_basis === "unknown" ? "↔" : "→"} ${name(e.target)}`;
      if (e.relationship === "calls")
        return {
          title,
          lines: [`Traced call · ${plural(e.count, "span")}`],
        };
      if (e.relationship === "forwards_to")
        return {
          title,
          lines: [
            `${confidenceLabel[e.confidence]} · ${handoffShort[e.handoff_basis!]}`,
            handoffText(e, index),
          ],
        };
      const seen = observationsByDevice(e, topo)
        .map((d) => d.label)
        .join(", ");
      return {
        title,
        lines: [
          [
            portLabel(e),
            e.bytes !== undefined ? prettyBytes(e.bytes) : "bytes not reported",
            edgeIdentity(e, node) === "identified"
              ? "Identified"
              : edgeIdentity(e, node) === "external"
                ? "External"
                : "Unknown IP",
          ].join(" · "),
          seen ? `Seen by ${seen}` : "No observer recorded",
          ...(e.acl_action === "drop"
            ? ["Blocked by the fabric (ACL log)"]
            : []),
          ...(e.contract_basis === "intent" && e.contract
            ? [`Contract ${e.contract} (intent)`]
            : []),
        ],
      };
    },
    [topo, node, index],
  );

  const fileStem = `adm-${graph.boundary.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const exportCsv = () => {
    download(
      `${fileStem}-required-flows.csv`,
      "text/csv;charset=utf-8",
      requiredFlowsCsv(graph, index, topo),
    );
    setPanel(null);
  };
  const exportJson = () => {
    download(
      `${fileStem}.json`,
      "application/json",
      JSON.stringify(graph, null, 2),
    );
    setPanel(null);
  };
  const togglePanel = (p: Panel) => setPanel((cur) => (cur === p ? null : p));
  const [errorHint, errorDetail] = error.split(" Splunk reported: ");

  const summary = (
    <>
      <h2 className="summary-title">Select something on the map</h2>
      <p className="muted">
        Choose a service, pod, endpoint or line to see who it talks to, on which
        port, and where the traffic was seen.
      </p>
      <dl className="facts">
        <dt>Conversations</dt>
        <dd>{totals.conversations}</dd>
        <dt>Identified</dt>
        <dd>{totals.identified}</dd>
        <dt>External</dt>
        <dd>{totals.external}</dd>
        <dt>Unknown IP</dt>
        <dd>{totals.unknown}</dd>
        {totals.blocked > 0 && (
          <>
            <dt>Blocked</dt>
            <dd>{totals.blocked}</dd>
          </>
        )}
        {totals.multiple > 0 && (
          <>
            <dt>Multiple owners</dt>
            <dd>{totals.multiple}</dd>
          </>
        )}
        <dt>Traced spans</dt>
        <dd>{graph.coverage.spans.toLocaleString()}</dd>
      </dl>
    </>
  );

  const unknownChips = [
    totals.unknownSources > 0 &&
      plural(totals.unknownSources, "unknown source"),
    totals.unknownOther > 0 && plural(totals.unknownOther, "unknown endpoint"),
  ].filter(Boolean) as string[];

  return (
    <div
      className="adm"
      data-adm-theme={theme}
      ref={root}
      style={{
        height: `max(600px, calc(100vh - ${Math.round(top) + (inSplunk ? 16 : 0)}px))`,
      }}
      onKeyDown={(e) => {
        if (e.key !== "Escape" || e.defaultPrevented) return;
        if (panel) setPanel(null);
        else if (selection) clearSelection();
      }}
    >
      <header className="bar">
        <div className="scope">
          {visible ? (
            <>
              <strong className="scope-service">
                {graph.boundary.service}
              </strong>
              <span className="scope-dims">
                {graph.boundary.environment} · {graph.boundary.cluster} ·{" "}
                {graph.boundary.namespace}
              </span>
              <span className="scope-time">
                {formatUtcRange(graph.window.start, graph.window.end)} UTC
              </span>
              {graph.demo && <span className="chip demo">Synthetic demo</span>}
            </>
          ) : (
            <>
              <strong className="scope-service">
                {args.service || "No application selected"}
              </strong>
              <span className="scope-dims">
                {[args.environment, args.cluster, args.namespace]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
              <span className="chip">Splunk · not loaded</span>
            </>
          )}
          {busy && visible && (
            <span className="chip" role="status">
              <RefreshCw size={13} className="spin" /> Updating…
            </span>
          )}
        </div>
        {visible && !empty && (
          <div className="kpis" aria-label="Summary">
            <span className="kpi">
              <b>{totals.services}</b>{" "}
              {totals.services === 1 ? "service" : "services"}
            </span>
            {totals.conversations > 0 && (
              <span className="kpi">
                <b>{totals.identified}</b> of {totals.conversations}{" "}
                conversations identified
              </span>
            )}
            {unknownChips.length > 0 && (
              <span className="kpi warn">
                <CircleAlert size={14} aria-hidden />
                {unknownChips.join(" · ")}
              </span>
            )}
            {totals.externalNodes > 0 && (
              <span className="kpi">{totals.externalNodes} external</span>
            )}
            {totals.blocked > 0 && (
              <span className="kpi blocked">
                <Ban size={14} aria-hidden />
                {totals.blocked} blocked
              </span>
            )}
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
          <div className="segmented" role="group" aria-label="Data source">
            <button aria-pressed={mode === "demo"} onClick={showDemo}>
              Demo
            </button>
            <button
              aria-pressed={mode === "live"}
              onClick={switchLive}
              disabled={!SearchManager}
              title={
                SearchManager
                  ? undefined
                  : "Available when the app runs inside Splunk"
              }
            >
              Splunk
            </button>
          </div>
          <button
            className="icon-button"
            aria-label="How to read this map"
            aria-expanded={panel === "help"}
            onClick={() => togglePanel("help")}
          >
            <BookOpen size={17} />
          </button>
          <button
            className="icon-button"
            aria-label="Export"
            aria-expanded={panel === "export"}
            onClick={() => togglePanel("export")}
            disabled={!visible || empty}
          >
            <Download size={17} />
          </button>
          <button
            className="icon-button"
            aria-label="Map settings"
            aria-expanded={panel === "settings"}
            onClick={() => togglePanel("settings")}
          >
            <Settings2 size={17} />
          </button>
        </div>
        {panel === "export" && (
          <section className="popover export" aria-label="Export">
            <div className="popover-head">
              <h2>Export</h2>
              <button
                className="icon-button"
                aria-label="Close export"
                onClick={() => setPanel(null)}
              >
                <X size={16} />
              </button>
            </div>
            <button className="menu-item" onClick={exportCsv}>
              <FileSpreadsheet size={17} aria-hidden />
              <span>
                <b>Required flows (CSV)</b>
                <small>
                  One row per conversation: client, server, EPG, namespace,
                  port, identity and seen-by. For firewall rule and ACI contract
                  requests.
                </small>
              </span>
            </button>
            <button className="menu-item" onClick={exportJson}>
              <FileJson size={17} aria-hidden />
              <span>
                <b>Map data (JSON)</b>
                <small>The complete graph shown on screen.</small>
              </span>
            </button>
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
            {mode === "demo" && (
              <p className="muted">
                Demo data is fixed. Switch to Splunk to choose an application.
              </p>
            )}
            <div className="fields">
              {ARG_FIELDS.map(([key, title, hint]) => {
                const err =
                  mode === "live" ? argError(key, args[key]) : undefined;
                return (
                  <label key={key}>
                    <span>
                      {title} <small>{hint}</small>
                    </span>
                    <input
                      value={args[key]}
                      onChange={(e) => changeArg(key, e.target.value)}
                      disabled={mode === "demo"}
                      aria-invalid={!!err}
                    />
                    {err && <small className="field-error">{err}</small>}
                  </label>
                );
              })}
              <label>
                <span>Time range</span>
                <select
                  value={earliest}
                  onChange={(e) => {
                    request.current?.abort();
                    setBusy(false);
                    setEarliest(e.target.value);
                  }}
                  disabled={mode === "demo"}
                >
                  {TIME_RANGES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <button
              className="primary-button"
              onClick={refresh}
              disabled={busy || mode === "demo" || argErrors.length > 0}
            >
              <RefreshCw size={15} /> {busy ? "Building…" : "Build map"}
            </button>
            <p className="muted small">
              Uses the Application Atlas saved searches; an administrator
              enables them after setting the index macros.
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
                <li key={i}>{w}</li>
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
                Lanes run left to right: <b>Sources</b> that call in,{" "}
                <b>Entry points</b> where they enter the cluster, the{" "}
                <b>Application</b> (services with their pods inside), and the{" "}
                <b>Dependencies</b> it calls. <b>Infrastructure</b> below them
                holds Kubernetes nodes seen only in node-to-node tunnel traffic.
              </li>
              <li>
                <b>Entry points</b> are Kubernetes Service frontends: a
                LoadBalancer VIP, a NodePort, or Cilium Gateway/Ingress (Envoy).
                The grey line from a frontend to a pod says how that backend was
                identified (Hubble, an SNAT translation, Envoy's
                X-Forwarded-For). A dashed grey line marked <b>inferred</b>{" "}
                rests on timing only. "Backend not determined" means no evidence
                picked a pod.
              </li>
              <li>
                <b>Contract</b> labels are intent: the ACI policy that should
                permit the conversation according to collected objects. An{" "}
                <b>ACL log</b> entry is an observation by the enforcing leaf.{" "}
                <b>Blocked</b> (red, ⦸) means the fabric logged drops.
              </li>
              <li>
                Between two ACI leaves the path shows <b>one of N spines</b>:
                traffic is spread over equal-cost spines (ECMP) and no source
                says which one carried it.
              </li>
              <li>
                Arrows point from client to server, and the pill at the server
                end shows the service port. A line without an arrowhead means
                the direction is unknown.
              </li>
              <li>
                <b>Traced call</b> comes from OpenTelemetry spans.{" "}
                <b>Network conversation</b> comes from flow records (Stream
                NetFlow, Nexus Dashboard, FTD, Isovalent).
              </li>
              <li>
                <b>Identified</b>: exactly one pod, node or VM owned each
                address. <b>External</b>: a public address outside the fabric.{" "}
                <b>Unknown IP</b> and <b>Multiple owners</b> stay on the map so
                gaps are visible.
              </li>
              <li>
                Candidate paths come from inventory (CDP, ACI fabric links, LLDP
                and attachments). Observations mark where traffic was seen; they
                don't prove the order packets took.
              </li>
              <li>
                Traces and flows are sampled: a missing line is not proof that
                no traffic exists.
              </li>
              <li>
                <b>Keyboard:</b> Tab into the map, then ←/→ move between columns
                (nearest card), ↑/↓ within a column, Enter selects or expands,
                Esc clears. In the search box, Enter and Shift+Enter jump
                between matches. Ctrl/⌘ + scroll zooms.
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
      <div className={`body ${selection ? "has-selection" : ""}`}>
        <section className="map-panel">
          <div className="toolbar">
            <div className="segmented" role="group" aria-label="View">
              {TABS.map(([t, name]) => (
                <button
                  key={t}
                  aria-pressed={tab === t}
                  onClick={() => setTab(t)}
                >
                  {name}
                </button>
              ))}
            </div>
            <label className="search">
              <Search size={15} aria-hidden />
              <input
                aria-label="Highlight by name, IP, EPG, port or device"
                placeholder="Highlight name, IP, EPG, port, leaf…"
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
            {!selection && visible && !empty && (
              <span className="toolbar-hint">
                Select a card or line for details
              </span>
            )}
          </div>
          <div className="map-area">
            {!visible ? (
              busy ? (
                <Skeleton />
              ) : (
                <div className="state">
                  <h2>Choose an application to map</h2>
                  <p>
                    Open <b>Settings</b>, enter the entry service and its
                    namespace, then build the map.
                  </p>
                  <button
                    className="primary-button"
                    onClick={() => setPanel("settings")}
                  >
                    <Settings2 size={15} /> Open settings
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
                        <TriangleAlert size={14} aria-hidden /> {w}
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
            ) : tab === "table" ? (
              <TableView
                graph={graph}
                label={label}
                selected={selection?.kind === "edge" ? selection.id : undefined}
                onSelect={(id) => select({ kind: "edge", id })}
                topo={topo}
                node={node}
              />
            ) : tab === "devices" ? (
              <DevicesView
                graph={graph}
                index={index}
                topo={topo}
                selected={selection?.kind === "edge" ? selection.id : undefined}
                onSelect={(id) => select({ kind: "edge", id })}
              />
            ) : (
              <MapView
                layout={layout}
                index={index}
                matchNodes={matchNodes}
                matchEdges={matchEdges}
                selection={selection}
                onSelect={(s) => (s ? select(s) : clearSelection())}
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
          {visible && !empty && (tab === "network" || tab === "services") && (
            <Legend
              view={view}
              collapsed={layout.collapsed}
              forwards={graph.edges.some(
                (e) => e.relationship === "forwards_to",
              )}
              blocked={totals.blocked > 0}
            />
          )}
          {path && selectedEdge && !pathHidden && (
            <PathStrip
              path={path}
              title={`${label(selectedEdge.source)} → ${label(selectedEdge.target)} · ${portLabel(selectedEdge)}`}
              onClose={() => setPathHidden(true)}
            />
          )}
        </section>
        <aside className="inspector" aria-label="Details">
          <Inspector
            selection={selection}
            index={index}
            topo={topo}
            onSelect={(s) => (s ? select(s) : clearSelection())}
            onClose={clearSelection}
            onShowPath={() => setPathHidden(false)}
            pathOpen={!!path && !pathHidden}
            summary={summary}
          />
        </aside>
      </div>
    </div>
  );
}

function Legend({
  view,
  collapsed,
  forwards,
  blocked,
}: {
  view: View;
  collapsed: boolean;
  forwards: boolean;
  blocked: boolean;
}) {
  const line = (cls: string) => (
    <svg width="28" height="10" aria-hidden>
      <line x1="2" y1="5" x2="26" y2="5" className={`lg ${cls}`} />
    </svg>
  );
  return (
    <div className="legend" aria-label="Legend">
      <span>{line("call")}Traced call</span>
      {view === "network" && (
        <>
          <span>{line("conv")}Network conversation</span>
          <span>{line("conv unknown")}Unknown IP</span>
          <span>{line("conv external")}External</span>
          <span>{line("tunnel")}Node tunnel</span>
          {forwards && (
            <>
              <span>{line("forward")}To backend</span>
              <span>{line("forward inferred")}Backend inferred</span>
            </>
          )}
          {blocked && (
            <span>
              {line("conv blocked")}
              <Ban size={13} aria-hidden /> Blocked
            </span>
          )}
          <span>
            <span className="lg-pill">8080/tcp</span>Server port
          </span>
          {collapsed && (
            <span className="legend-note">Pod lists collapsed to fit</span>
          )}
        </>
      )}
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

function TableView({
  graph,
  label,
  selected,
  onSelect,
  topo,
  node,
}: {
  graph: Graph;
  label: (id: string) => string;
  selected?: string;
  onSelect: (id: string) => void;
  topo: ReturnType<typeof indexTopology>;
  node: (id: string) => GraphNode | undefined;
}) {
  const conv = graph.edges.filter(
    (e) => e.relationship === "communicates_with",
  );
  const calls = graph.edges.filter((e) => e.relationship === "calls");
  return (
    <div className="table-view">
      <table>
        <caption>Network conversations</caption>
        <thead>
          <tr>
            <th scope="col">Client → Server</th>
            <th scope="col">Port</th>
            <th scope="col">Seen at</th>
            <th scope="col">Contract</th>
            <th scope="col" className="num">
              Bytes
            </th>
            <th scope="col">Identity</th>
          </tr>
        </thead>
        <tbody>
          {conv.map((e) => (
            <tr key={e.id} className={selected === e.id ? "selected" : ""}>
              <td>
                <button className="link" onClick={() => onSelect(e.id)}>
                  {label(e.source)}
                  {e.direction_basis === "unknown" ? (
                    " ↔ "
                  ) : (
                    <ArrowRight size={13} aria-label="to" />
                  )}
                  {label(e.target)}
                </button>
              </td>
              <td>{portLabel(e)}</td>
              <td>
                {observationsByDevice(e, topo)
                  .map((d) => d.label)
                  .join(", ") || "—"}
              </td>
              <td>
                {e.contract_basis === "intent"
                  ? e.contract
                  : e.contract_basis === "not_evaluated"
                    ? "Not fully evaluated"
                    : e.contract_basis === "none"
                      ? "None found"
                      : "—"}
              </td>
              <td className="num">
                {e.bytes !== undefined ? prettyBytes(e.bytes) : "—"}
              </td>
              <td>
                {e.acl_action === "drop" ? (
                  <span className="status blocked">Blocked</span>
                ) : (
                  <IdentityBadge state={edgeIdentity(e, node)} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <table>
        <caption>Traced calls</caption>
        <thead>
          <tr>
            <th scope="col">Caller → Callee</th>
            <th scope="col" className="num">
              Spans
            </th>
          </tr>
        </thead>
        <tbody>
          {calls.map((e) => (
            <tr key={e.id} className={selected === e.id ? "selected" : ""}>
              <td>
                <button className="link" onClick={() => onSelect(e.id)}>
                  {label(e.source)} <ArrowRight size={13} aria-label="to" />{" "}
                  {label(e.target)}
                </button>
              </td>
              <td className="num">{e.count.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        {relationshipLabel.communicates_with} rows include every conversation
        that touches the namespace in the selected time range.
      </p>
    </div>
  );
}
