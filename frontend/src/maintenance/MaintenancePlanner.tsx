import { useState } from "react";
import { MaintenanceAssessment } from "./MaintenanceAssessment";
import {
  assessMaintenance,
  compareAssessments,
  type Assessment,
  type AssessmentInput,
} from "./model";
import "./maintenance.css";

type Capture = { input: AssessmentInput; assessment: Assessment };

/** The caller supplies trusted, scoped evidence. This component never imports evidence. */
export function MaintenancePlanner({
  input,
  description,
  unavailableReason,
}: {
  input: AssessmentInput;
  description?: string;
  unavailableReason?: string;
}) {
  const [before, setBefore] = useState<Capture>();
  const [after, setAfter] = useState<Capture>();
  const [sequence, setSequence] = useState(0);
  const [includeSource, setIncludeSource] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const current = assessMaintenance(input);
  const capture = (): Capture => {
    // Detach both the evidence and assessment from future caller mutations.
    const copy = structuredClone(input);
    copy.id = `${input.id}#capture-${sequence + 1}`;
    setSequence((n) => n + 1);
    return { input: copy, assessment: assessMaintenance(copy) };
  };
  const comparison =
    before && after && compareAssessments(before.assessment, after.assessment);
  const download = () => {
    setDownloadError("");
    let url: string | undefined;
    try {
      const exportCapture = (value: Capture | undefined) =>
        value
          ? {
              assessment: value.assessment,
              ...(includeSource ? { input: value.input } : {}),
            }
          : null;
      const payload = {
        schema: "application-atlas-maintenance-evidence",
        version: 1,
        exportedAt: new Date().toISOString(),
        includesSourceEvidence: includeSource,
        before: exportCapture(before),
        after: exportCapture(after),
        comparison: comparison || null,
      };
      const json = JSON.stringify(payload, null, 2);
      if (new TextEncoder().encode(json).byteLength > 8 * 1024 * 1024) {
        throw new Error("Evidence exceeds the 8 MiB download limit.");
      }
      url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "maintenance-evidence-v1.json";
      link.click();
    } catch (error) {
      setDownloadError(
        error instanceof Error
          ? error.message
          : "Could not prepare the evidence download.",
      );
    } finally {
      if (url) {
        const objectUrl = url;
        setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      }
    }
  };
  return (
    <section
      className="atlas-maintenance-planner"
      aria-label="Maintenance planning"
    >
      <h2>Maintenance planning</h2>
      {unavailableReason && <p role="status">{unavailableReason}</p>}
      <p>
        {description ??
          "Assess the selected elements using the evidence supplied by this view."}
      </p>
      <p>
        Owner information is imported context. This assessment does not change
        infrastructure.
      </p>
      {input.services.some(
        (service) =>
          service.topology?.value === "exposed" && !service.topology.qualified,
      ) && (
        <p>
          Impact analysis reports potential exposure for{" "}
          {input.services
            .filter(
              (service) =>
                service.topology?.value === "exposed" &&
                !service.topology.qualified,
            )
            .map((service) => service.name)
            .join(", ")}
          . This observation is not qualified for the assessment window and
          scope.
        </p>
      )}
      <MaintenanceAssessment assessment={current} />
      <p>
        Captures are kept only in this page's memory. They are not shared or
        saved unless you download them, and they are lost when you leave the
        page.
      </p>
      <div className="atlas-maintenance-actions">
        <button
          type="button"
          disabled={!!unavailableReason}
          onClick={() => {
            setIncludeSource(false);
            setDownloadError("");
            setBefore(capture());
            setAfter(undefined);
          }}
        >
          Capture before
        </button>
        <button
          type="button"
          disabled={!before || !!unavailableReason}
          onClick={() => {
            setIncludeSource(false);
            setDownloadError("");
            setAfter(capture());
          }}
        >
          Capture after
        </button>
        <button type="button" disabled={!before && !after} onClick={download}>
          Download evidence
        </button>
      </div>
      <label>
        <input
          type="checkbox"
          checked={includeSource}
          disabled={!before && !after}
          onChange={(event) => setIncludeSource(event.target.checked)}
        />
        Include source evidence in the download
      </label>
      <p>
        The download contains assessment details, which may include names,
        addresses and owners. Source evidence may include additional sensitive
        details.
      </p>
      {downloadError && <p role="alert">{downloadError}</p>}
      {before && (
        <details>
          <summary>Before capture</summary>
          <MaintenanceAssessment assessment={before.assessment} />
        </details>
      )}
      {after && (
        <details>
          <summary>After capture</summary>
          <MaintenanceAssessment assessment={after.assessment} />
        </details>
      )}
      {comparison && (
        <section aria-label="Capture comparison">
          <h3>Before and after</h3>
          {!comparison.comparable ? (
            <p>
              These captures cannot be compared. Use the same selection, service
              scopes and window duration, and capture the later evidence after
              the earlier evidence.
            </p>
          ) : comparison.changed.length ? (
            <ul>
              {comparison.changed.map((change, index) => (
                <li key={`${change}-${index}`}>{change}</li>
              ))}
            </ul>
          ) : (
            <p>No assessment changes identified.</p>
          )}
          <p>Each capture retains its original absolute evidence window.</p>
        </section>
      )}
    </section>
  );
}
