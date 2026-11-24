import { useEffect, useId, useRef, useState } from "react";
import type { SearchClient } from "../data/searchClient";
import type {
  MulticastConfiguration,
  MulticastEvidence,
  MulticastResult,
} from "./contract";
import {
  multicastLink,
  parseMulticastLink,
  parseMulticastView,
  parseScopeLink,
  scopeLink,
  validateRequest,
  validateScopeWindow,
} from "./inputs";
import {
  investigateMulticast,
  MulticastConfigurationChangedError,
  readMulticastConfiguration,
} from "./investigation";
import { formatTime } from "./format";
import { ForwardingTree } from "./ForwardingTree";
import { IgmpTimeline } from "./IgmpTimeline";
import { MatrixView } from "./MatrixView";
import { OverviewView } from "./OverviewView";
import { QuerierStrip } from "./QuerierStrip";
import { investigateScope, type ScopeOverviewResult } from "./scopeOverview";
import { SourceCoverage, sourceLabel } from "./SourceCoverage";
import { URL_STATE_CHANGED } from "../app/urlState";
import "./multicast.css";

interface Props {
  client?: SearchClient;
  live: boolean;
  timezone?: string;
  initialParams?: URLSearchParams;
}

type ConfigurationState =
  | { status: "loading" }
  | { status: "ready"; value: MulticastConfiguration }
  | { status: "error"; message: string };
type InvestigationState =
  | { status: "idle" | "loading" | "cancelled" | "stale" }
  | { status: "error"; message: string }
  | { status: "done"; value: MulticastResult };
type ScopeState =
  | { status: "idle" | "loading" | "cancelled" | "stale" }
  | { status: "error"; message: string }
  | { status: "done"; value: ScopeOverviewResult; comparing: boolean };
type View = "overview" | "matrix";
const VIEW_LABEL: Record<View, string> = {
  overview: "Overview",
  matrix: "Matrix",
};

const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The investigation could not be completed.";
export const utcInput = (seconds: number) =>
  new Date(seconds * 1000).toISOString().slice(0, 19);
export const utcSeconds = (value: string) => Date.parse(`${value}Z`) / 1000;

function EvidenceDetails({
  evidence,
  timezone,
}: {
  evidence: MulticastEvidence;
  timezone?: string;
}) {
  return (
    <>
      <strong>
        {evidence.kind === "igmp"
          ? `IGMP ${evidence.operation}`
          : evidence.kind === "flow"
            ? "Multicast flow"
            : "Forwarding state"}
      </strong>
      {evidence.kind === "igmp" && (
        <div>
          Reporter: {evidence.reporter ?? "unknown"} ({evidence.reporterKind});
          sources: {evidence.sources.join(", ") || "none reported"}
        </div>
      )}
      {evidence.kind === "flow" && (
        <div>
          Sender: {evidence.sender}; {evidence.direction}; domain{" "}
          {evidence.observationDomain}, template {evidence.template}; sampling
          1:{evidence.samplingInterval}; replication {evidence.replication};
          counters {evidence.counters}
          {evidence.packets !== undefined
            ? `; ${evidence.packets} packets`
            : ""}
          {evidence.bytes !== undefined ? `; ${evidence.bytes} bytes` : ""}
        </div>
      )}
      {evidence.kind === "forwarding" && (
        <div>
          Input: {evidence.input ?? "unknown"}; outputs:{" "}
          {evidence.outputs.join(", ") || "none"}; valid until{" "}
          {formatTime(evidence.validUntil, timezone)}
        </div>
      )}
      <div>
        Source: {sourceLabel[evidence.source]}; observer: {evidence.observer};
        interface: {evidence.interface ?? "unknown"}; observed:{" "}
        {formatTime(evidence.timestamp, timezone)}
      </div>
      {evidence.segment && (
        <div>
          Segment: {evidence.segment.kind} {evidence.segment.id} (domain{" "}
          {evidence.segment.domain})
        </div>
      )}
      <div>
        Limits:{" "}
        {evidence.limits.length ? evidence.limits.join("; ") : "None recorded"}
      </div>
    </>
  );
}

export function MulticastResults({
  result,
  timezone,
}: {
  result: MulticastResult;
  timezone?: string;
}) {
  const [selected, setSelected] = useState<string | undefined>();
  const chosen = result.evidence.find((item) => item.id === selected);
  const receiverSegments = new Map<string, typeof result.receivers>();
  for (const receiver of result.receivers) {
    const { domain, kind, id } = receiver.segment;
    const key = JSON.stringify([domain, kind, id]);
    const segment = receiverSegments.get(key);
    if (segment) segment.push(receiver);
    else receiverSegments.set(key, [receiver]);
  }
  return (
    <section className="multicast-results" aria-label="Investigation results">
      <div className="multicast-summary">
        <div>
          <h2>Observed multicast evidence</h2>
          <p>
            {result.evidence.length === 0 &&
              `${result.request.group} · ${result.request.scope} · `}
            {formatTime(result.request.earliest, timezone)} –{" "}
            {formatTime(result.request.latest, timezone)}
          </p>
        </div>
        <p>Captured {formatTime(result.capturedAt, timezone)}</p>
      </div>
      {result.outcomes.some((item) => item.state !== "complete") && (
        <p className="multicast-notice" role="status">
          Coverage is incomplete. Missing evidence cannot establish that a
          sender, receiver, or path is absent.
        </p>
      )}
      {result.capped && (
        <p className="multicast-notice" role="status">
          Evidence was capped. Narrow the time window or scope to investigate
          further.
        </p>
      )}
      {result.evidence.length === 0 ? (
        <p>
          No evidence was returned for this selection. Check source coverage
          before drawing conclusions.
        </p>
      ) : (
        <>
          <div className="multicast-map-board">
            <header className="multicast-map-heading">
              <div>
                <h3>Multicast tree</h3>
                <p>
                  Group <strong>{result.request.group}</strong> ·{" "}
                  {result.request.scope}
                </p>
              </div>
              {result.branches.some(
                (branch) => branch.state === "supported",
              ) && (
                <span>Solid tree links show supported device branches.</span>
              )}
            </header>
            <div
              className="multicast-map"
              role="group"
              aria-label="Observed evidence map"
            >
              <section>
                <h4>Senders</h4>
                {result.senders.length ? (
                  result.senders.map((sender) => (
                    <button
                      key={sender.address}
                      type="button"
                      aria-label={sender.address}
                      onClick={() => setSelected(sender.evidenceIds[0])}
                    >
                      <strong>{sender.address}</strong>
                      <small>
                        {sender.evidenceIds.length} flow{" "}
                        {sender.evidenceIds.length === 1
                          ? "observation"
                          : "observations"}
                      </small>
                    </button>
                  ))
                ) : (
                  <p>None observed</p>
                )}
              </section>
              <section>
                <h4>Forwarding branches</h4>
                <ForwardingTree result={result} inspect={setSelected} />
              </section>
              <section>
                <h4>Receiver interest</h4>
                {receiverSegments.size ? (
                  [...receiverSegments].map(([key, receivers]) => {
                    const { kind, id, domain } = receivers[0].segment;
                    return (
                      <div className="multicast-segment" key={key}>
                        <h5>
                          {kind.toUpperCase()} {id} <span>· {domain}</span>
                        </h5>
                        {receivers.map((receiver) => (
                          <button
                            key={receiver.evidenceId}
                            type="button"
                            onClick={() => setSelected(receiver.evidenceId)}
                          >
                            <strong>{receiver.reporter}</strong>
                            <small>
                              {receiver.state === "observed"
                                ? "Interest observed"
                                : "Interest uncertain"}
                            </small>
                          </button>
                        ))}
                      </div>
                    );
                  })
                ) : (
                  <p>None observed</p>
                )}
              </section>
            </div>
            <p className="multicast-map-note">
              Sender traffic and receiver interest are separate observations.
              Delivery remains unverified.
            </p>
          </div>
          {chosen && (
            <aside className="multicast-selected" aria-live="polite">
              <button
                type="button"
                onClick={() => setSelected(undefined)}
                aria-label="Close selected evidence"
              >
                ×
              </button>
              <EvidenceDetails evidence={chosen} timezone={timezone} />
            </aside>
          )}
          <h3>Evidence records</h3>
          <div className="multicast-table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Evidence</th>
                  <th scope="col">Details and limitations</th>
                </tr>
              </thead>
              <tbody>
                {result.evidence.map((item, index) => (
                  <tr key={item.id}>
                    <td>
                      <button
                        type="button"
                        onClick={() => setSelected(item.id)}
                        aria-label={`Inspect evidence record ${index + 1}`}
                      >
                        Inspect
                      </button>
                    </td>
                    <td>
                      <EvidenceDetails evidence={item} timezone={timezone} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <SourceCoverage outcomes={result.outcomes} />
    </section>
  );
}

function readInitial(params: URLSearchParams) {
  try {
    const view: View =
      parseMulticastView(params) === "matrix" ? "matrix" : "overview";
    if (params.has("mc_group"))
      return { view, request: parseMulticastLink(params), detail: true };
    return { view, window: parseScopeLink(params), detail: false };
  } catch (error) {
    return { view: "overview" as View, detail: false, error: message(error) };
  }
}

function StatusNotices({
  state,
  refreshSources,
}: {
  state: { status: string; message?: string };
  refreshSources(): void;
}) {
  return (
    <>
      {state.status === "loading" && (
        <p role="status">Investigating multicast evidence…</p>
      )}
      {state.status === "cancelled" && (
        <p role="status">
          Investigation cancelled. Run it again for the current selection.
        </p>
      )}
      {state.status === "stale" && (
        <div className="multicast-notice" role="alert">
          Source verification changed during the investigation. Refresh sources
          and investigate again.
          <button type="button" onClick={refreshSources}>
            Refresh sources
          </button>
        </div>
      )}
      {state.status === "error" && (
        <p role="alert">Investigation unavailable: {state.message}</p>
      )}
    </>
  );
}

export function MulticastPage({
  client,
  live,
  timezone,
  initialParams,
}: Props) {
  const [initial] = useState(() =>
    readInitial(
      initialParams ??
        new URLSearchParams(
          typeof window === "undefined" ? "" : window.location.search,
        ),
    ),
  );
  const now = Math.floor(Date.now() / 1000);
  const start = initial.request ?? initial.window;
  const [scope, setScope] = useState(start?.scope ?? "");
  const [group, setGroup] = useState(initial.request?.group ?? "");
  const [sender, setSender] = useState(initial.request?.sender ?? "");
  const [earliest, setEarliest] = useState(
    utcInput(start?.earliest ?? now - 900),
  );
  const [latest, setLatest] = useState(utcInput(start?.latest ?? now));
  const [view, setView] = useState<View>(initial.view);
  const [detail, setDetail] = useState(initial.detail);
  const [configuration, setConfiguration] = useState<ConfigurationState>({
    status: "loading",
  });
  const [overview, setOverview] = useState<ScopeState>({ status: "idle" });
  const [investigation, setInvestigation] = useState<InvestigationState>({
    status: "idle",
  });
  const [error, setError] = useState(initial.error ?? "");
  const activeScope = useRef<AbortController>();
  const active = useRef<AbortController>();
  const [configurationRevision, setConfigurationRevision] = useState(0);
  const [revision, setRevision] = useState(0);
  const [resultRevision, setResultRevision] = useState(0);
  const tabsId = useId();
  useEffect(() => {
    if (!live) return;
    const controller = new AbortController();
    readMulticastConfiguration(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted)
          setConfiguration({ status: "ready", value });
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted)
          setConfiguration({ status: "error", message: message(err) });
      });
    return () => controller.abort();
  }, [live, configurationRevision]);
  useEffect(
    () => () => {
      activeScope.current?.abort();
      active.current?.abort();
    },
    [],
  );
  const scopes =
    configuration.status === "ready"
      ? [
          ...new Set(
            configuration.value.profiles.map((profile) => profile.scope),
          ),
        ].sort()
      : [];
  const writeLink = (params: URLSearchParams) => {
    const mode = (
      initialParams ?? new URLSearchParams(window.location.search)
    ).get("mode");
    if (mode) params.set("mode", mode);
    window.history.replaceState(
      window.history.state,
      "",
      `${window.location.pathname}?${params.toString()}${window.location.hash}`,
    );
    window.dispatchEvent(new Event(URL_STATE_CHANGED));
  };
  const abortGroup = () => {
    active.current?.abort();
    active.current = undefined;
  };
  const abortScope = () => {
    activeScope.current?.abort();
    activeScope.current = undefined;
  };
  /** Scope and window edits invalidate both searches and their results. */
  const editWindow = (setter: (value: string) => void, value: string) => {
    abortScope();
    abortGroup();
    setOverview((current) =>
      current.status === "loading" ||
      (current.status === "done" && current.comparing)
        ? { status: "cancelled" }
        : { status: "idle" },
    );
    setInvestigation((current) =>
      current.status === "loading"
        ? { status: "cancelled" }
        : { status: "idle" },
    );
    setter(value);
    setRevision((current) => current + 1);
  };
  const editGroup = (setter: (value: string) => void, value: string) => {
    abortGroup();
    setInvestigation((current) =>
      current.status === "loading" ? { status: "cancelled" } : current,
    );
    setter(value);
    setRevision((current) => current + 1);
  };
  const searchScope = async (
    target: ReturnType<typeof validateScopeWindow>,
    comparePrevious: boolean,
  ) => {
    if (!client || configuration.status !== "ready") return;
    abortScope();
    const controller = new AbortController();
    activeScope.current = controller;
    try {
      const value = await investigateScope(
        client,
        target,
        configuration.value,
        controller.signal,
        { comparePrevious },
      );
      if (!controller.signal.aborted)
        setOverview({ status: "done", value, comparing: false });
    } catch (err) {
      if (!controller.signal.aborted)
        setOverview(
          err instanceof MulticastConfigurationChangedError
            ? { status: "stale" }
            : { status: "error", message: message(err) },
        );
    }
  };
  const run = (event: React.FormEvent) => {
    event.preventDefault();
    if (!client || configuration.status !== "ready") return;
    try {
      const target = validateScopeWindow({
        version: 1,
        scope,
        earliest: utcSeconds(earliest),
        latest: utcSeconds(latest),
      });
      if (!scopes.includes(target.scope))
        throw new Error("Choose a scope with a verified multicast profile.");
      abortGroup();
      setError("");
      setDetail(false);
      setInvestigation({ status: "idle" });
      setOverview({ status: "loading" });
      writeLink(scopeLink(target, view));
      void searchScope(target, false);
    } catch (err) {
      setError(message(err));
    }
  };
  const compare = () => {
    if (overview.status !== "done") return;
    setOverview({ ...overview, comparing: true });
    void searchScope(overview.value.window, true);
  };
  const investigateGroup = async (input: unknown) => {
    if (!client || configuration.status !== "ready") return;
    try {
      const request = validateRequest(input);
      if (!scopes.includes(request.scope))
        throw new Error("Choose a scope with a verified multicast profile.");
      abortGroup();
      const controller = new AbortController();
      active.current = controller;
      setError("");
      setDetail(true);
      setInvestigation({ status: "loading" });
      setResultRevision(revision);
      const params = multicastLink(request);
      params.set("mc_view", view);
      writeLink(params);
      try {
        const value = await investigateMulticast(
          client,
          request,
          configuration.value,
          controller.signal,
        );
        if (!controller.signal.aborted)
          setInvestigation({ status: "done", value });
      } catch (err) {
        if (!controller.signal.aborted)
          setInvestigation(
            err instanceof MulticastConfigurationChangedError
              ? { status: "stale" }
              : { status: "error", message: message(err) },
          );
      }
    } catch (err) {
      setError(message(err));
    }
  };
  const runGroup = (event: React.FormEvent) => {
    event.preventDefault();
    void investigateGroup({
      version: 1,
      scope,
      group,
      ...(sender.trim() ? { sender: sender.trim() } : {}),
      earliest: utcSeconds(earliest),
      latest: utcSeconds(latest),
    });
  };
  const openGroup = (selected: string) => {
    if (overview.status !== "done") return;
    const { scope: chosen, earliest: from, latest: to } = overview.value.window;
    setGroup(selected);
    setSender("");
    void investigateGroup({
      version: 1,
      scope: chosen,
      group: selected,
      earliest: from,
      latest: to,
    });
  };
  /** Leaves the group detail for a view, keeping the last scope result. */
  const showView = (next: View) => {
    abortGroup();
    setInvestigation({ status: "idle" });
    setDetail(false);
    setView(next);
    const params = new URLSearchParams(window.location.search);
    if (params.has("mc_v")) {
      params.delete("mc_group");
      params.delete("mc_sender");
      params.delete("mode");
      params.set("mc_view", next);
      writeLink(params);
    }
  };
  const refreshSources = () => {
    abortScope();
    abortGroup();
    setConfiguration({ status: "loading" });
    setOverview({ status: "idle" });
    setInvestigation({ status: "idle" });
    setConfigurationRevision((current) => current + 1);
  };
  const cancelScope = () => {
    abortScope();
    setOverview({ status: "cancelled" });
  };
  const cancelGroup = () => {
    abortGroup();
    setInvestigation({ status: "cancelled" });
  };
  const staleConfiguration = (fingerprint: string) =>
    configuration.status === "ready" &&
    fingerprint !== configuration.value.fingerprint;
  const connected = live && client;
  return (
    <main className="multicast-page">
      <header>
        <h1>Multicast</h1>
        <p>
          Find multicast senders, receiver interest, and gaps in forwarding
          visibility.
        </p>
      </header>
      {connected && (
        <div className="mc-tabs" role="tablist" aria-label="Multicast views">
          {(["overview", "matrix"] as const).map((value) => (
            <button
              key={value}
              type="button"
              role="tab"
              id={`${tabsId}-${value}`}
              aria-selected={view === value}
              aria-controls={`${tabsId}-panel`}
              onClick={() => (view !== value || detail) && showView(value)}
            >
              {VIEW_LABEL[value]}
            </button>
          ))}
          <button
            type="button"
            role="tab"
            aria-selected={false}
            aria-disabled="true"
            title="Not yet available"
          >
            Topology<small className="mc-tab-note">Not yet available</small>
          </button>
        </div>
      )}
      {!connected ? (
        <p className="multicast-notice">
          Multicast investigation is available with a live Splunk connection.
        </p>
      ) : configuration.status === "loading" ? (
        <p role="status">Loading verified multicast profiles…</p>
      ) : configuration.status === "error" ? (
        <div role="alert">
          <p>Multicast configuration unavailable: {configuration.message}</p>
          <button type="button" onClick={refreshSources}>
            Refresh sources
          </button>
        </div>
      ) : configuration.value.profiles.length === 0 ? (
        <div className="multicast-notice">
          <p>
            Setup required: ask an administrator to configure verified Stream
            IGMP, NetFlow, or NX-OS forwarding profiles before investigating.
          </p>
          <button type="button" onClick={refreshSources}>
            Refresh sources
          </button>
        </div>
      ) : (
        <>
          <form onSubmit={run} className="multicast-form">
            <label>
              Scope
              <select
                value={scope}
                onChange={(event) => editWindow(setScope, event.target.value)}
                required
              >
                <option value="">Select a scope</option>
                {scopes.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label>
              From (UTC)
              <input
                type="datetime-local"
                step="1"
                value={earliest}
                onChange={(event) =>
                  editWindow(setEarliest, event.target.value)
                }
                required
              />
            </label>
            <label>
              To (UTC)
              <input
                type="datetime-local"
                step="1"
                value={latest}
                onChange={(event) => editWindow(setLatest, event.target.value)}
                required
              />
            </label>
            <div className="multicast-actions">
              <button
                type="submit"
                disabled={
                  overview.status === "loading" || overview.status === "stale"
                }
              >
                Investigate
              </button>
              {overview.status === "loading" && (
                <button type="button" onClick={cancelScope}>
                  Cancel
                </button>
              )}
            </div>
          </form>
          <p>Times are entered in UTC. Maximum window: one hour.</p>
          {error && <p role="alert">{error}</p>}
          <section
            id={`${tabsId}-panel`}
            role="tabpanel"
            aria-labelledby={`${tabsId}-${view}`}
          >
            {detail ? (
              <section className="mc-detail" aria-label="Group detail">
                <div className="mc-detail-header">
                  <button type="button" onClick={() => showView(view)}>
                    Back to {VIEW_LABEL[view]}
                  </button>
                  <form onSubmit={runGroup} className="multicast-form">
                    <label>
                      Multicast group
                      <input
                        value={group}
                        onChange={(event) =>
                          editGroup(setGroup, event.target.value)
                        }
                        placeholder="239.1.2.3"
                        required
                      />
                    </label>
                    <label>
                      Sender (optional)
                      <input
                        value={sender}
                        onChange={(event) =>
                          editGroup(setSender, event.target.value)
                        }
                        placeholder="192.0.2.1"
                      />
                    </label>
                    <div className="multicast-actions">
                      <button
                        type="submit"
                        disabled={
                          investigation.status === "loading" ||
                          investigation.status === "stale"
                        }
                      >
                        Investigate group
                      </button>
                      {investigation.status === "loading" && (
                        <button type="button" onClick={cancelGroup}>
                          Cancel
                        </button>
                      )}
                    </div>
                  </form>
                </div>
                <StatusNotices
                  state={investigation}
                  refreshSources={refreshSources}
                />
                {investigation.status === "done" && (
                  <>
                    {(revision !== resultRevision ||
                      staleConfiguration(
                        investigation.value.configurationFingerprint,
                      )) && (
                      <p className="multicast-notice" role="status">
                        These results are stale for the current selection or
                        configuration. Run the investigation again.
                      </p>
                    )}
                    <MulticastResults
                      result={investigation.value}
                      timezone={timezone}
                    />
                    <IgmpTimeline
                      result={investigation.value}
                      timezone={timezone ?? "UTC"}
                    />
                    <QuerierStrip
                      result={investigation.value}
                      timezone={timezone ?? "UTC"}
                    />
                  </>
                )}
              </section>
            ) : (
              <>
                <StatusNotices
                  state={overview}
                  refreshSources={refreshSources}
                />
                {overview.status === "done" && (
                  <>
                    {staleConfiguration(
                      overview.value.configurationFingerprint,
                    ) && (
                      <p className="multicast-notice" role="status">
                        These results are stale for the current configuration.
                        Run the investigation again.
                      </p>
                    )}
                    {view === "overview" ? (
                      <OverviewView
                        result={overview.value}
                        onSelectGroup={openGroup}
                        onCompare={compare}
                        comparing={overview.comparing}
                        timezone={timezone}
                      />
                    ) : (
                      <MatrixView
                        result={overview.value}
                        configuration={configuration.value}
                        onSelectCell={openGroup}
                      />
                    )}
                  </>
                )}
              </>
            )}
          </section>
        </>
      )}
    </main>
  );
}
