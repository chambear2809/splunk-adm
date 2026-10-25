import { useCallback, useEffect, useRef, useState } from "react";
import type { ServiceHealthSelection } from "./data/evidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import {
  DETECTOR_COVERAGE,
  loadDetectorEvents,
  type DetectorResult,
} from "./data/o11yDetectorEvents";
import { observabilityOrigin } from "./data/o11yHealth";
import type { SearchClient } from "./data/searchClient";

export function O11yDetectorEventsPanel({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: ServiceHealthSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<DetectorResult>();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string>();
  const generation = useRef(0),
    active = useRef<AbortController>();
  const identity = JSON.stringify(selection);
  const cancel = useCallback(() => {
    generation.current++;
    active.current?.abort();
  }, []);
  useEffect(() => {
    cancel();
    setResult(undefined);
    setBusy(false);
    setError(undefined);
    return cancel;
  }, [identity, client, configurationClient, cancel]);
  const load = async () => {
    cancel();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await loadDetectorEvents(
        client,
        selection,
        controller.signal,
        configurationClient,
      );
      if (current === generation.current && !controller.signal.aborted)
        setResult(next);
    } catch {
      if (current === generation.current)
        setError(
          "Detector events unavailable. Refresh the selection or check optional source configuration and permissions.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  const capture = result?.capture;
  const origin = capture
    ? observabilityOrigin(capture.realm, capture.origin)
    : undefined;
  return (
    <section
      className="inspector-body"
      aria-label="Observability detector event evidence"
    >
      <h3>Observability detector events</h3>
      <p>
        Events observed in the selected interval for detectors explicitly bound
        to this cluster and routing scope. This binding does not establish that
        an event belongs to the selected service.
      </p>
      <button type="button" onClick={() => void load()} disabled={busy}>
        {result ? "Refresh detector events" : "Inspect detector events"}
      </button>
      {busy && (
        <button
          type="button"
          onClick={() => {
            cancel();
            setBusy(false);
            setError(
              "Detector search cancelled. You can inspect events again.",
            );
          }}
        >
          Cancel detector search
        </button>
      )}
      <p role="status">
        {busy
          ? "Loading a completed indexed detector capture…"
          : (error ??
            result?.error ??
            (result
              ? `Detector source: ${result.state}`
              : "No detector search has run. An administrator must select and qualify this optional source."))}
      </p>
      {result?.state === "complete" && !capture && (
        <p>
          No recent completed capture matched this interval and detector
          binding. Missing data is unknown.
        </p>
      )}
      {capture && (
        <>
          <p>
            Completed capture {capture.captureId}; captured{" "}
            {new Date(capture.capturedAt * 1000).toISOString()}; organization{" "}
            {capture.organizationId}, realm {capture.realm}, observer{" "}
            {capture.observer}.
          </p>
          <p>Configured detector IDs: {capture.detectorIds.join(", ")}</p>
          {origin && (
            <p>
              <a href={origin} target="_blank" rel="noreferrer">
                Open Observability Cloud
              </a>{" "}
              — locate the native IDs below; no time or service filters are
              applied.
            </p>
          )}
          {capture.events.length === 0 ? (
            <p>
              No events were returned in this completed interval. Alert silence
              is not service health.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <caption>Observed detector events</caption>
                <thead>
                  <tr>
                    <th scope="col">Event time</th>
                    <th scope="col">Detector / rule</th>
                    <th scope="col">Event / incident</th>
                    <th scope="col">Source values</th>
                    <th scope="col">Source details</th>
                  </tr>
                </thead>
                <tbody>
                  {capture.events.map((event) => (
                    <tr key={event.recordId}>
                      <td>{new Date(event.timestampMs).toISOString()}</td>
                      <td>
                        {event.detectorId}
                        <br />
                        {event.ruleId ?? "Rule not reported"}
                        {event.label ? ` (${event.label})` : ""}
                      </td>
                      <td>
                        {event.eventId ?? "Event ID not reported"}
                        <br />
                        {event.incidentId ?? "Incident ID not reported"}
                      </td>
                      <td>
                        {[event.type, event.anomalyState, event.severity]
                          .filter(Boolean)
                          .join("; ") || "Not reported"}
                      </td>
                      <td>
                        <details>
                          <summary>Native event and dimensions</summary>
                          <pre>
                            {JSON.stringify(event.sourceEvent, null, 2)}
                          </pre>
                        </details>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      <details>
        <summary>Coverage and limits</summary>
        {DETECTOR_COVERAGE.map((item) => (
          <p key={item}>{item}</p>
        ))}
      </details>
    </section>
  );
}
