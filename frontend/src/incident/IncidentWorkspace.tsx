import { useEffect, useRef, useState } from "react";
import { diffGraphs } from "../diff";
import type { Graph, GraphEdge } from "../graph";
import { formatInZone } from "../time";
import {
  adjacentBaseline,
  buildFindings,
  buildTimeline,
  coverageReasons,
  loadComparison,
  validateWindow,
  type Window,
} from "./model";
import "./incident.css";
import { InvestigationHandoff } from "../investigations/InvestigationHandoff";
import { comparisonReference } from "../investigations/reference";
import type { CaseClient } from "../investigations/caseClient";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";

export type IncidentWorkspaceProps = {
  /** The selected, fully returned incident map. Change the map selection in the parent to change this window. */
  incident: Graph;
  /** Load a graph in the same scope for the exact absolute half-open window. Honor cancellation. */
  loadWindow: (window: Window, signal: AbortSignal) => Promise<Graph>;
  timezone?: string;
  caseClient?: CaseClient;
  onBack?: () => void;
  /** Parent may highlight paths; it retains control of map selection. */
  onHighlight?: (edgeIds: string[]) => void;
};
type Result = { incident: Graph; baseline: Graph; recovery?: Graph };
type Tab = "Overview" | "Timeline" | "Connections" | "Notes";
const tabs: Tab[] = ["Overview", "Timeline", "Connections", "Notes"];
const displayedFields: Array<keyof GraphEdge> = [
  "acl_action",
  "acl_permits",
  "acl_drops",
  "contract",
  "contract_basis",
  "server_port",
  "transport",
  "direction_basis",
  "confidence",
];
const display = (value: unknown) =>
  value === undefined || value === null || value === ""
    ? "Not reported"
    : String(value);

/** Self-contained comparison; persistence and additional evidence must be supplied by the parent. */
export function IncidentWorkspace({
  incident,
  loadWindow,
  timezone,
  caseClient,
  onBack,
  onHighlight,
}: IncidentWorkspaceProps) {
  const root = useRef<HTMLElement>(null);
  const [baselineWindow, setBaselineWindow] = useState(() =>
    adjacentBaseline(incident.window),
  );
  const [recoveryEnabled, setRecoveryEnabled] = useState(false);
  const [recoveryWindow, setRecoveryWindow] = useState<Window>(() => ({
    start: incident.window.end,
    end: new Date(
      Date.parse(incident.window.end) +
        Date.parse(incident.window.end) -
        Date.parse(incident.window.start),
    ).toISOString(),
  }));
  const [storedResult, setResult] = useState<Result>();
  const result = storedResult?.incident === incident ? storedResult : undefined;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("Overview");
  const active = useRef<AbortController>();
  const generation = useRef(0);
  useEffect(() => {
    root.current?.focus();
  }, []);
  useEffect(() => {
    // A new selected capture invalidates both pending and completed comparisons.
    generation.current++;
    active.current?.abort();
    setBusy(false);
    setResult(undefined);
    setError("");
    try {
      setBaselineWindow(adjacentBaseline(incident.window));
      const start = Date.parse(incident.window.start),
        end = Date.parse(incident.window.end);
      setRecoveryWindow({
        start: incident.window.end,
        end: new Date(end + end - start).toISOString(),
      });
    } catch {
      setError("The selected incident window is invalid.");
    }
    setRecoveryEnabled(false);
    return () => {
      active.current?.abort();
    };
  }, [incident]);
  const compare = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const token = ++generation.current;
    setBusy(true);
    setError("");
    try {
      validateWindow(incident.window);
      validateWindow(baselineWindow);
      if (Date.parse(baselineWindow.end) > Date.parse(incident.window.start))
        throw new Error(
          "The baseline must end before the incident window starts.",
        );
      if (recoveryEnabled) {
        validateWindow(recoveryWindow);
        if (Date.parse(recoveryWindow.start) < Date.parse(incident.window.end))
          throw new Error(
            "The recovery window must start after the incident window ends.",
          );
      }
      const { baseline, recovery } = await loadComparison(
        incident,
        baselineWindow,
        recoveryEnabled ? recoveryWindow : undefined,
        loadWindow,
        controller.signal,
      );
      if (!controller.signal.aborted && token === generation.current)
        setResult({ incident, baseline, recovery });
    } catch (reason) {
      if (!controller.signal.aborted && token === generation.current)
        setError(
          reason instanceof Error ? reason.message : "Comparison failed.",
        );
    } finally {
      if (!controller.signal.aborted && token === generation.current)
        setBusy(false);
    }
  };
  const cancel = () => {
    generation.current++;
    active.current?.abort();
    setBusy(false);
  };
  const diff = result && diffGraphs(result.baseline, incident);
  const findings =
    result && diff ? buildFindings(result.baseline, incident, diff) : [];
  const timeline =
    result && diff ? buildTimeline(result.baseline, incident, diff) : [];
  const reasons = result
    ? [
        ...new Set([
          ...coverageReasons(result.baseline),
          ...coverageReasons(incident),
          ...(result.recovery ? coverageReasons(result.recovery) : []),
        ]),
      ]
    : [];
  const shownWindow = (window: Window) =>
    `${formatInZone(window.start, timezone)} – ${formatInZone(window.end, timezone)}`;
  return (
    <section
      ref={root}
      tabIndex={-1}
      className="atlas-incident"
      aria-label="Incident investigation"
    >
      <header className="atlas-incident-header">
        <div>
          <h2>Investigate {incident.boundary.service}</h2>
          <p>Incident: {shownWindow(incident.window)}</p>
        </div>
        {onBack && (
          <button type="button" className="secondary-button" onClick={onBack}>
            Back to map
          </button>
        )}
      </header>
      <details className="atlas-incident-windows">
        <summary>Comparison windows</summary>
        <p>
          Enter absolute timestamps with a timezone, such as
          2026-11-04T15:00:00Z. The map controls select the incident window.
        </p>
        <div className="atlas-incident-window-row">
          <label>
            Baseline start
            <input
              value={baselineWindow.start}
              onChange={(event) =>
                setBaselineWindow({
                  ...baselineWindow,
                  start: event.target.value,
                })
              }
            />
          </label>
          <label>
            Baseline end
            <input
              value={baselineWindow.end}
              onChange={(event) =>
                setBaselineWindow({
                  ...baselineWindow,
                  end: event.target.value,
                })
              }
            />
          </label>
        </div>
        <label>
          <input
            type="checkbox"
            checked={recoveryEnabled}
            onChange={(event) => setRecoveryEnabled(event.target.checked)}
          />{" "}
          Include recovery window
        </label>
        {recoveryEnabled && (
          <div className="atlas-incident-window-row">
            <label>
              Recovery start
              <input
                value={recoveryWindow.start}
                onChange={(event) =>
                  setRecoveryWindow({
                    ...recoveryWindow,
                    start: event.target.value,
                  })
                }
              />
            </label>
            <label>
              Recovery end
              <input
                value={recoveryWindow.end}
                onChange={(event) =>
                  setRecoveryWindow({
                    ...recoveryWindow,
                    end: event.target.value,
                  })
                }
              />
            </label>
          </div>
        )}
        {busy && (
          <button type="button" className="secondary-button" onClick={cancel}>
            Cancel
          </button>
        )}
      </details>
      <p>Baseline window: {shownWindow(baselineWindow)}</p>
      <button
        type="button"
        className="primary-button"
        onClick={compare}
        disabled={busy}
      >
        {busy ? "Comparing…" : "Compare windows"}
      </button>
      {busy && (
        <p role="status">
          Updating comparison… Previous results remain visible.
        </p>
      )}
      {error && <p role="alert">{error}</p>}
      {result && (
        <>
          <p>
            Baseline: {shownWindow(result.baseline.window)}
            {result.recovery && (
              <> · Recovery: {shownWindow(result.recovery.window)}</>
            )}
          </p>
          {reasons.length > 0 && (
            <details open>
              <summary>Partial or uncertain evidence</summary>
              <ul>
                {reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </details>
          )}
          <nav
            aria-label="Investigation sections"
            className="atlas-incident-tabs"
          >
            {tabs.map((item) => (
              <button
                key={item}
                type="button"
                aria-current={tab === item ? "page" : undefined}
                onClick={() => setTab(item)}
              >
                {item}
              </button>
            ))}
          </nav>
          {tab === "Overview" && (
            <div>
              <h3>Relevant findings</h3>
              {findings.length === 0 ? (
                <p>
                  No matching changes were found in these snapshots. Review
                  source coverage before interpreting an absence.
                </p>
              ) : (
                findings.map((finding) => (
                  <details key={finding.id} className="atlas-incident-finding">
                    <summary>
                      <strong>{finding.title}</strong> · {finding.status}
                    </summary>
                    <p>{finding.supports[0]}</p>
                    {(
                      [
                        ["Supports", finding.supports],
                        ["Contradicts", finding.contradicts],
                        ["Missing", finding.missing],
                      ] as const
                    ).map(([title, list]) => (
                      <div key={title}>
                        <h4>{title}</h4>
                        {list.length ? (
                          <ul>
                            {list.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ul>
                        ) : (
                          <p>None reported.</p>
                        )}
                      </div>
                    ))}
                    <p>
                      <strong>Next check:</strong> {finding.next}
                    </p>
                    {onHighlight && finding.edgeIds.length > 0 && (
                      <button
                        type="button"
                        className="secondary-button"
                        onClick={() => onHighlight(finding.edgeIds)}
                      >
                        Highlight connections
                      </button>
                    )}
                  </details>
                ))
              )}
            </div>
          )}
          {tab === "Timeline" && (
            <div>
              <h3>Evidence timeline</h3>
              <p>
                Snapshot differences indicate an interval; native records retain
                their event time.
              </p>
              {timeline.length ? (
                <ol className="atlas-incident-timeline">
                  {timeline.map((item) => (
                    <li key={item.id}>
                      <strong>{item.title}</strong>
                      <span>
                        {item.kind === "snapshot"
                          ? `Changed between ${formatInZone(item.start, timezone)} and ${formatInZone(item.end!, timezone)}`
                          : formatInZone(item.start, timezone)}
                      </span>
                      <p>{item.detail}</p>
                    </li>
                  ))}
                </ol>
              ) : (
                <p>No matching evidence in these windows.</p>
              )}
            </div>
          )}
          {tab === "Connections" && diff && (
            <div>
              <h3>Connections</h3>
              <JourneyLazyEvidence
                kind="baseline"
                window={{
                  start: Date.parse(incident.window.start) / 1000,
                  end: Date.parse(incident.window.end) / 1000,
                }}
                mapWarnings={coverageReasons(incident)}
              />
              <p>
                {diff.addedEdges.length} newly observed ·{" "}
                {diff.removedEdges.length} not observed ·{" "}
                {diff.changedEdges.length} changed records
              </p>
              {diff.changedEdges.length ? (
                <ul>
                  {diff.changedEdges.map(({ id, previous, current }) => (
                    <li key={id}>
                      <strong>{id}</strong>
                      <ul>
                        {displayedFields
                          .filter((field) => previous[field] !== current[field])
                          .map((field) => (
                            <li key={field}>
                              {field}: {display(previous[field])} →{" "}
                              {display(current[field])}
                            </li>
                          ))}
                      </ul>
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No matching changed connection records.</p>
              )}
              <p>
                Counts and evidence can vary between windows. An absent
                connection is not proof it was removed.
              </p>
            </div>
          )}
          <div hidden={tab !== "Notes"}>
            <InvestigationHandoff
              key={incident.snapshot_id}
              comparison={result}
            />
            <JourneyLazyEvidence
              kind="cases"
              client={caseClient}
              window={incident.window}
              comparisonReference={comparisonReference(result)}
            />
          </div>
          {result.recovery && (
            <details>
              <summary>Recovery comparison</summary>
              <p>
                {diffGraphs(incident, result.recovery).addedEdges.length}{" "}
                connections newly observed ·{" "}
                {diffGraphs(incident, result.recovery).removedEdges.length} not
                observed ·{" "}
                {diffGraphs(incident, result.recovery).changedEdges.length}{" "}
                changed records.
              </p>
            </details>
          )}
        </>
      )}
    </section>
  );
}
