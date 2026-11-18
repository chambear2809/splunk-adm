import { useState } from "react";
import { downloadBlob } from "../download";
import type { AuditResult } from "./audit";
import type { TimelineItem, Window } from "./model";

export type AuditState =
  | { status: "unavailable" }
  | { status: "loading" }
  | { status: "cancelled" }
  | { status: "failed" }
  | { status: "available"; result: AuditResult };

/** This export contains only admitted events and their binding evidence. */
export function auditExport(
  state: Extract<AuditState, { status: "available" }>,
  window: Window,
  timeline: TimelineItem[],
) {
  return {
    schemaVersion: 1,
    requestedWindow: window,
    producerId: state.result.producerId,
    applicationId: state.result.applicationId,
    coverage: state.result.projection.coverage,
    withheld: state.result.projection.withheld,
    withheldReasons: state.result.projection.withheldReasons,
    events: state.result.projection.events,
    timeline: timeline.filter((item) => item.id.startsWith("audit:")),
  };
}

export function AuditEvidence({
  state,
  window,
  timeline,
  onCancel,
}: {
  state: AuditState;
  window: Window;
  timeline: TimelineItem[];
  onCancel?: () => void;
}) {
  const [exportError, setExportError] = useState(false);
  if (state.status === "unavailable")
    return (
      <p>
        Audit evidence is unavailable: no qualified historical
        object-to-application source is connected.
      </p>
    );
  if (state.status === "loading")
    return (
      <p role="status">
        Loading audit evidence…{" "}
        {onCancel && (
          <button type="button" className="secondary-button" onClick={onCancel}>
            Cancel audit request
          </button>
        )}
      </p>
    );
  if (state.status === "cancelled")
    return (
      <p>Audit request cancelled. The graph comparison remains available.</p>
    );
  if (state.status === "failed")
    return (
      <p role="status">
        Audit evidence is unavailable: the source request failed, timed out or
        returned invalid evidence. The graph comparison remains available.
      </p>
    );
  const { projection, producerId, applicationId } = state.result;
  return (
    <section aria-label="Audit source coverage">
      <h4>Audit source coverage</h4>
      <p>
        Producer: {producerId} · Application identity: {applicationId}
      </p>
      <p>
        Reported coverage: {projection.coverage.start} to{" "}
        {projection.coverage.end} (end exclusive). Coverage is a source report,
        not proof of completeness.
      </p>
      {(Date.parse(projection.coverage.start) > Date.parse(window.start) ||
        Date.parse(projection.coverage.end) < Date.parse(window.end)) && (
        <p>
          The reported coverage does not span the requested incident window.
        </p>
      )}
      {projection.coverage.gaps.length ? (
        <>
          <p>Reported gaps:</p>
          <ul>
            {projection.coverage.gaps.map((gap, i) => (
              <li key={i}>{gap}</li>
            ))}
          </ul>
        </>
      ) : (
        <p>
          No gaps were reported; this does not establish complete collection.
        </p>
      )}
      <p>
        {projection.events.length} associated events · {projection.withheld}{" "}
        withheld records. Withholding does not establish absence.
      </p>
      {projection.withheld > 0 && (
        <ul>
          {Object.entries(projection.withheldReasons).map(([reason, count]) => (
            <li key={reason}>
              {reason}: {count}
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        className="secondary-button"
        onClick={() => {
          try {
            downloadBlob(
              "incident-audit-evidence.json",
              "application/json",
              JSON.stringify(auditExport(state, window, timeline), null, 2),
            );
            setExportError(false);
          } catch {
            setExportError(true);
          }
        }}
      >
        Download audit evidence
      </button>
      {exportError && <p role="alert">Could not download audit evidence.</p>}
    </section>
  );
}
