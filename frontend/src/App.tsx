import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Box,
  ChevronRight,
  CircleHelp,
  Database,
  GitBranch,
  Layers3,
  Network,
  Radio,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  X,
} from "lucide-react";
import { DependencyGraph, type Selection } from "./DependencyGraph";
import { prettyBytes, relationshipLabel, type Graph } from "./graph";
import { demoGraph, loadLive, type SearchConstructor } from "./provider";
export function App({
  SearchManager,
  releaseManager,
}: {
  SearchManager?: SearchConstructor;
  releaseManager?: (id: string) => void;
}) {
  const [graph, setGraph] = useState<Graph>(() => demoGraph());
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [layer, setLayer] = useState<"application" | "network">("application");
  const [selection, setSelection] = useState<Selection | null>(null);
  const [query, setQuery] = useState("");
  const [settings, setSettings] = useState(false);
  const [index, setIndex] = useState("adm");
  const [boundary, setBoundary] = useState("shop-demo");
  const [earliest, setEarliest] = useState("-24h");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [hasLiveGraph, setHasLiveGraph] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  const showDemo = () => {
    request.current?.abort();
    request.current = null;
    setBusy(false);
    setGraph(demoGraph());
    setMode("demo");
    setHasLiveGraph(false);
    setError("");
    setSelection(null);
  };
  const refresh = async () => {
    if (mode === "demo") {
      setGraph(demoGraph());
      setSelection(null);
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
    setHasLiveGraph(false);
    try {
      const result = await loadLive(
        SearchManager,
        { index, boundary, earliest },
        controller.signal,
        releaseManager,
      );
      if (!controller.signal.aborted) {
        setGraph(result);
        setHasLiveGraph(true);
        setSelection(null);
      }
    } catch (e) {
      if (!controller.signal.aborted)
        setError(e instanceof Error ? e.message : "Unable to load snapshot.");
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
    setSettings(true);
  };
  const changeConfig = (setter: (s: string) => void, value: string) => {
    request.current?.abort();
    request.current = null;
    setBusy(false);
    setter(value);
    setHasLiveGraph(false);
  };
  const visible = mode === "demo" || hasLiveGraph;
  const services = graph.nodes.filter((n) => n.kind === "service").length;
  const calls = graph.edges.filter((e) => e.relationship === "calls");
  const flows = graph.edges.filter(
    (e) => e.relationship === "communicates_with",
  );
  const selectedNode =
    selection?.kind === "node"
      ? graph.nodes.find((n) => n.id === selection.id)
      : undefined;
  const selectedEdge =
    selection?.kind === "edge"
      ? graph.edges.find((e) => e.id === selection.id)
      : undefined;
  const exportGraph = () => {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `adm-${graph.boundary.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="atlas">
      <aside className="sidebar">
        <div className="brand-mark">
          <GitBranch size={24} />
        </div>
        <div className="sidebar-rule" />
        <button className="nav-icon active" aria-label="Dependency map">
          <Network size={21} />
        </button>
        <button
          className="nav-icon"
          aria-label="Open data configuration"
          onClick={() => setSettings(true)}
        >
          <Database size={20} />
        </button>
        <a
          className="nav-icon help"
          href="https://help.splunk.com/en/splunk-observability-cloud/monitor-application-performance/use-service-map-and-traces-to-explore-services"
          target="_blank"
          rel="noreferrer"
          aria-label="Splunk APM documentation"
        >
          <CircleHelp size={21} />
        </a>
        <span className="sidebar-bottom">ADM</span>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="wordmark">
            application<span>atlas</span>
            <span className="version">PILOT / 0.1</span>
          </div>
          <div className="topbar-right">
            <span className="splunk-label">Splunk application</span>
            <button
              className="icon-button"
              aria-label="Data configuration"
              onClick={() => setSettings((s) => !s)}
            >
              <Settings2 size={18} />
            </button>
          </div>
        </header>
        <section className="page-heading">
          <div>
            <div className="breadcrumb">
              OBSERVABILITY <ChevronRight size={12} /> APPLICATION INTELLIGENCE
            </div>
            <h1>
              Follow the application.
              <br />
              <span>Understand the network.</span>
            </h1>
            <p>
              Explore dependencies from a frontend boundary to the workloads and
              connections beneath it.
            </p>
          </div>
          <div className="mode-control" aria-label="Data source">
            <button
              className={mode === "demo" ? "selected" : ""}
              onClick={showDemo}
            >
              Demo data
            </button>
            <button
              className={mode === "live" ? "selected" : ""}
              onClick={switchLive}
              disabled={!SearchManager}
              title={
                !SearchManager
                  ? "Install the app in Splunk to enable live search"
                  : undefined
              }
            >
              Splunk data
            </button>
          </div>
        </section>
        <div className={`notice ${mode === "demo" ? "demo-notice" : ""}`}>
          <Radio size={16} />
          <span>
            {mode === "demo"
              ? "Synthetic pilot · No live Kubernetes or network data is connected."
              : "Splunk snapshots · Indexed evidence from your configured graph pipeline."}
          </span>
          <button onClick={() => setSettings((s) => !s)}>
            Data configuration <ArrowRight size={14} />
          </button>
        </div>
        {settings && (
          <section className="config-panel" aria-label="Data configuration">
            <div className="section-title">
              <div>
                <h2>Connect your graph snapshots</h2>
                <p>
                  Load a complete <code>adm:graph</code> event by boundary ID.
                  Your Splunk permissions apply.
                </p>
              </div>
              <button
                className="icon-button"
                aria-label="Close configuration"
                onClick={() => setSettings(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="config-fields">
              <label>
                Splunk index
                <input
                  value={index}
                  onChange={(e) => changeConfig(setIndex, e.target.value)}
                  disabled={mode === "demo"}
                />
              </label>
              <label>
                Application boundary ID
                <input
                  value={boundary}
                  onChange={(e) => changeConfig(setBoundary, e.target.value)}
                  disabled={mode === "demo"}
                />
              </label>
              <label>
                Snapshot search window
                <select
                  value={earliest}
                  onChange={(e) => changeConfig(setEarliest, e.target.value)}
                  disabled={mode === "demo"}
                >
                  <option value="-15m">Last 15 minutes</option>
                  <option value="-1h">Last hour</option>
                  <option value="-24h">Last 24 hours</option>
                  <option value="-7d">Last 7 days</option>
                  <option value="0">All time (demo import)</option>
                </select>
              </label>
              <button
                className="primary-button"
                onClick={refresh}
                disabled={busy || mode === "demo"}
              >
                <RefreshCw size={15} />
                {busy ? "Loading…" : "Load snapshot"}
              </button>
            </div>
            <p className="config-note">
              An OpenTelemetry Collector does not automatically populate this
              graph. Export selected spans and time scoped pod inventory, run
              the offline projector, then ingest its HEC events. Cisco
              attachment enrichment is planned.
            </p>
          </section>
        )}
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {!visible ? (
          <section className="panel empty">
            <Database size={32} />
            <h2>
              {busy
                ? "Loading graph snapshot…"
                : "Choose a boundary and load its snapshot"}
            </h2>
            <p>
              No live graph is displayed until the selected search succeeds.
              Configure your index above or return to demo data.
            </p>
          </section>
        ) : (
          <>
            <section className="boundary-bar">
              <div className="boundary-icon">
                <Box size={22} />
              </div>
              <div>
                <span className="eyebrow">ENTRY BOUNDARY</span>
                <h2>{graph.boundary.service}</h2>
              </div>
              <span className="scope-pill">{graph.boundary.environment}</span>
              <div className="scope-items">
                <span>
                  <b>Cluster</b>
                  {graph.boundary.cluster}
                </span>
                <span>
                  <b>Namespace</b>
                  {graph.boundary.namespace}
                </span>
                <span>
                  <b>Evidence window · UTC</b>
                  {new Date(graph.window.start)
                    .toISOString()
                    .slice(0, 16)
                    .replace("T", " ")}{" "}
                  → {new Date(graph.window.end).toISOString().slice(11, 16)}
                </span>
              </div>
            </section>
            {graph.demo && mode === "live" && (
              <div className="notice demo-notice">
                This indexed snapshot contains synthetic data. It is not live
                telemetry.
              </div>
            )}
            <section className="metrics" aria-label="Snapshot summary">
              <Metric
                icon={<Layers3 size={18} />}
                value={services}
                label="Application services"
                detail="Qualified OTel identities"
              />
              <Metric
                icon={<GitBranch size={18} />}
                value={calls.length}
                label="Call relationships"
                detail={`${graph.coverage.spans.toLocaleString()} spans in snapshot`}
              />
              <Metric
                icon={<Activity size={18} />}
                value={graph.coverage.flows}
                label="Network flow records"
                detail={`${graph.coverage.matched_flows} fully resolved to pods`}
              />
              <Metric
                icon={<ShieldCheck size={18} />}
                value={graph.coverage.unresolved_flows}
                label="Unresolved flow records"
                detail="Identity requires more evidence"
                caution={graph.coverage.unresolved_flows > 0}
              />
            </section>
            <div className="workspace">
              <section className="panel map-panel">
                <div className="map-header">
                  <div>
                    <span className="eyebrow">DEPENDENCY EXPLORER</span>
                    <h2>Frontend service dependencies</h2>
                  </div>
                  <button className="secondary-button" onClick={exportGraph}>
                    <ArrowDownToLine size={15} /> Export
                  </button>
                </div>
                <div className="map-controls">
                  <div className="tabs">
                    <button
                      className={layer === "application" ? "selected" : ""}
                      onClick={() => {
                        setLayer("application");
                        setSelection(null);
                      }}
                    >
                      Application
                    </button>
                    <button
                      className={layer === "network" ? "selected" : ""}
                      onClick={() => {
                        setLayer("network");
                        setSelection(null);
                      }}
                    >
                      Network & workloads
                    </button>
                  </div>
                  <label className="search-field">
                    <Search size={15} />
                    <input
                      aria-label="Highlight service or IP"
                      placeholder="Highlight service or IP…"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                    />
                  </label>
                  <button
                    className="icon-button"
                    onClick={refresh}
                    disabled={busy}
                    aria-label="Refresh snapshot"
                  >
                    <RefreshCw size={16} />
                  </button>
                </div>
                <DependencyGraph
                  graph={graph}
                  layer={layer}
                  query={query}
                  selection={selection}
                  onSelect={setSelection}
                />
                <div className="legend">
                  <span>
                    <i className="call" /> Observed call
                  </span>
                  <span>
                    <i className="flow" /> Network communication
                  </span>
                  <span>
                    <i className="binding" /> Workload binding
                  </span>
                  <span>
                    <i className="unknown" /> Unresolved identity
                  </span>
                </div>
              </section>
              <aside className="panel detail-panel">
                <div className="detail-heading">
                  <span className="eyebrow">EVIDENCE INSPECTOR</span>
                  {selection && (
                    <button
                      className="icon-button"
                      aria-label="Clear selection"
                      onClick={() => setSelection(null)}
                    >
                      <X size={16} />
                    </button>
                  )}
                </div>
                {selectedNode ? (
                  <>
                    <div className={`detail-symbol ${selectedNode.kind}`}>
                      <Box size={27} />
                    </div>
                    <h2>{selectedNode.label}</h2>
                    <span className="type-pill">{selectedNode.kind}</span>
                    <dl>
                      <dt>Cluster</dt>
                      <dd>{selectedNode.cluster ?? "Unknown"}</dd>
                      <dt>Namespace</dt>
                      <dd>{selectedNode.namespace ?? "Unresolved"}</dd>
                      <dt>Addresses</dt>
                      <dd>
                        {selectedNode.addresses?.join(", ") ||
                          "No address binding"}
                      </dd>
                      <dt>Identity</dt>
                      <dd className="mono">{selectedNode.id}</dd>
                    </dl>
                    {selectedNode.reason && (
                      <p className="explanation">{selectedNode.reason}</p>
                    )}
                    <h3>Related evidence</h3>
                    <div className="related-list">
                      {graph.edges
                        .filter(
                          (e) =>
                            e.source === selectedNode.id ||
                            e.target === selectedNode.id,
                        )
                        .map((e) => (
                          <button
                            key={e.id}
                            onClick={() =>
                              setSelection({ kind: "edge", id: e.id })
                            }
                          >
                            <span>
                              {relationshipLabel[e.relationship]}
                              <small>{e.evidence.join(" · ")}</small>
                            </span>
                            <ChevronRight size={15} />
                          </button>
                        ))}
                    </div>
                  </>
                ) : selectedEdge ? (
                  <>
                    <div className="detail-symbol">
                      <GitBranch size={27} />
                    </div>
                    <h2>{relationshipLabel[selectedEdge.relationship]}</h2>
                    <span
                      className={`type-pill ${selectedEdge.confidence === "unresolved" ? "amber" : ""}`}
                    >
                      {selectedEdge.confidence}
                    </span>
                    <dl>
                      <dt>Source</dt>
                      <dd>
                        {
                          graph.nodes.find((n) => n.id === selectedEdge.source)
                            ?.label
                        }
                      </dd>
                      <dt>Destination</dt>
                      <dd>
                        {
                          graph.nodes.find((n) => n.id === selectedEdge.target)
                            ?.label
                        }
                      </dd>
                      <dt>Observations</dt>
                      <dd>{selectedEdge.count.toLocaleString()}</dd>
                      {selectedEdge.bytes !== undefined && (
                        <>
                          <dt>Transferred bytes</dt>
                          <dd>{prettyBytes(selectedEdge.bytes)}</dd>
                        </>
                      )}
                      <dt>Evidence sources</dt>
                      <dd>{selectedEdge.evidence.join(" · ")}</dd>
                      {selectedEdge.observers?.length ? (
                        <>
                          <dt>Observation points</dt>
                          <dd>{selectedEdge.observers.join(", ")}</dd>
                        </>
                      ) : null}
                    </dl>
                    <p className="explanation">
                      {selectedEdge.reason ||
                        "Evidence applies only to this snapshot window."}
                    </p>
                    {selectedEdge.relationship === "communicates_with" && (
                      <p className="fine-print">
                        Flow direction and exporters do not establish a routed
                        path or a business application call.
                      </p>
                    )}
                  </>
                ) : (
                  <>
                    <div className="detail-symbol">
                      <Network size={28} />
                    </div>
                    <h2>Evidence, in context.</h2>
                    <p className="inspector-copy">
                      Select a service, workload, or connection to inspect its
                      identity and supporting evidence.
                    </p>
                    <div className="evidence-card">
                      <span className="source-dot purple" />
                      <div>
                        <b>OpenTelemetry</b>
                        <p>
                          Frontend descendants and cross-service span
                          relationships.
                        </p>
                      </div>
                    </div>
                    <div className="evidence-card">
                      <span className="source-dot teal" />
                      <div>
                        <b>Kubernetes inventory</b>
                        <p>
                          Pod UIDs and address ownership with validity
                          intervals.
                        </p>
                      </div>
                    </div>
                    <div className="evidence-card">
                      <span className="source-dot amber" />
                      <div>
                        <b>Splunk Stream / NetFlow</b>
                        <p>
                          Observed endpoints and traffic. Unresolved addresses
                          stay visible.
                        </p>
                      </div>
                    </div>
                    <div className="planned">
                      <span className="eyebrow">NEXT ENRICHMENT</span>
                      <p>
                        Cisco ACI / Nexus attachment, Isovalent context, and
                        security evidence.
                      </p>
                      <span>Planned · not yet connected</span>
                    </div>
                  </>
                )}
              </aside>
            </div>
            <section className="bottom-grid">
              <div className="panel evidence-table">
                <div className="section-title">
                  <div>
                    <span className="eyebrow">NETWORK EVIDENCE</span>
                    <h2>Connections below the application</h2>
                  </div>
                  <span className="count-pill">
                    {flows.length} relationships
                  </span>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Source → Destination</th>
                        <th>Flow records</th>
                        <th>Bytes</th>
                        <th>Identity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flows.map((e) => (
                        <tr key={e.id}>
                          <td>
                            <button
                              onClick={() => {
                                setLayer("network");
                                setSelection({ kind: "edge", id: e.id });
                              }}
                            >
                              {
                                graph.nodes.find((n) => n.id === e.source)
                                  ?.label
                              }
                              <ArrowRight size={13} />
                              {
                                graph.nodes.find((n) => n.id === e.target)
                                  ?.label
                              }
                            </button>
                          </td>
                          <td>{e.count}</td>
                          <td>{prettyBytes(e.bytes ?? 0)}</td>
                          <td>
                            <span
                              className={`status ${e.confidence === "unresolved" ? "amber" : ""}`}
                            >
                              {e.confidence}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!flows.length && (
                    <p className="fine-print">
                      No network relationships are present in this snapshot.
                    </p>
                  )}
                </div>
              </div>
              <div className="panel coverage-panel">
                <span className="eyebrow">COVERAGE & LIMITS</span>
                <h2>Keep uncertainty visible.</h2>
                {graph.coverage.warnings.length ? (
                  <ul>
                    {graph.coverage.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No projector warnings for this snapshot.</p>
                )}
                <p className="fine-print">
                  Sampled traces and flows describe observed dependencies;
                  absence of evidence is not proof of absence.
                </p>
              </div>
            </section>
            <footer>
              <span>
                Snapshot {graph.snapshot_id} · generated{" "}
                {new Date(graph.generated_at)
                  .toISOString()
                  .replace("T", " ")
                  .slice(0, 19)}{" "}
                UTC
              </span>
              <span>
                {graph.demo ? "SYNTHETIC DATA" : "INDEXED SNAPSHOT"} / SCHEMA v
                {graph.schema_version}
              </span>
            </footer>
          </>
        )}
      </main>
    </div>
  );
}
function Metric({
  icon,
  value,
  label,
  detail,
  caution = false,
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
  detail: string;
  caution?: boolean;
}) {
  return (
    <div className={`metric ${caution ? "caution" : ""}`}>
      <div className="metric-top">
        <span>{label}</span>
        {icon}
      </div>
      <strong>{value.toLocaleString()}</strong>
      <p>{detail}</p>
    </div>
  );
}
