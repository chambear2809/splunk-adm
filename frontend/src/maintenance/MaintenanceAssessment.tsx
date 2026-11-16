import { useId } from "react";
import type { Assessment, AlternativeAssessment, Check } from "./model";
import "./maintenance.css";

const label: Record<Check, string> = {
  confirmed: "Confirmed",
  blocked: "Blocker",
  unknown: "Unknown",
};
const alternativeSummary = (a: AlternativeAssessment) => {
  const checks = [
    a.reachability,
    a.health,
    a.readiness,
    a.substitution,
    a.failureDomain,
    a.capacity,
  ];
  return checks.includes("unknown")
    ? "Candidate alternative — readiness unknown"
    : checks.includes("blocked")
      ? "Candidate alternative — blocker identified"
      : "Candidate alternative — checks confirmed";
};
const date = (seconds: number) =>
  Number.isFinite(seconds) && Math.abs(seconds) <= 8640000000000
    ? new Date(seconds * 1000).toISOString()
    : "Unavailable";

/** Render a read-only capture. The caller owns capture and save actions. */
export function MaintenanceAssessment({
  assessment,
}: {
  assessment: Assessment;
}) {
  const hint = useId();
  return (
    <section className="atlas-maintenance" aria-label="Maintenance assessment">
      <h2>{assessment.headline}</h2>
      <p>
        Captured {date(assessment.capturedAt)} · Window{" "}
        {date(assessment.window.start)} – {date(assessment.window.end)} UTC
      </p>
      <p>
        Selected elements: {assessment.selectedElements.join(", ") || "None"}
      </p>
      {!assessment.services.length ? (
        <p>No service evidence is available for this selection.</p>
      ) : (
        <>
          <p id={hint}>Scroll horizontally to see all assessment columns.</p>
          <div
            className="atlas-maintenance-table"
            role="region"
            aria-label="Maintenance assessment table"
            aria-describedby={hint}
            tabIndex={0}
          >
            <table>
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Topology exposure</th>
                  <th scope="col">Alternative readiness</th>
                  <th scope="col">Shared failure domain</th>
                  <th scope="col">Capacity</th>
                </tr>
              </thead>
              <tbody>
                {assessment.services.map((s) => (
                  <tr key={s.id}>
                    <th scope="row">{s.name}</th>
                    <td>{s.owner || "Unknown"}</td>
                    <td>
                      {s.topology === "exposed"
                        ? "Exposed"
                        : s.topology === "not_exposed"
                          ? "Not exposed in this evidence"
                          : "Unknown"}
                    </td>
                    <td>
                      {s.alternatives.length
                        ? s.alternatives.map((a, i) => (
                            <details key={`${a.name}-${i}`}>
                              <summary>
                                {a.name}: {alternativeSummary(a)}
                              </summary>
                              <dl>
                                <dt>Reachability</dt>
                                <dd>{label[a.reachability]}</dd>
                                <dt>Health</dt>
                                <dd>{label[a.health]}</dd>
                                <dt>Readiness</dt>
                                <dd>{label[a.readiness]}</dd>
                                <dt>Functional substitution</dt>
                                <dd>{label[a.substitution]}</dd>
                              </dl>
                            </details>
                          ))
                        : "Unknown"}
                    </td>
                    <td>
                      {s.alternatives.length
                        ? s.alternatives.map((a, i) => (
                            <div key={`${a.name}-${i}`}>
                              {a.name}:{" "}
                              {a.failureDomain === "confirmed"
                                ? "Independent"
                                : a.failureDomain === "blocked"
                                  ? "Shared domain"
                                  : "Unknown"}
                            </div>
                          ))
                        : "Unknown"}
                    </td>
                    <td>
                      {s.alternatives.length
                        ? s.alternatives.map((a, i) => (
                            <div key={`${a.name}-${i}`}>
                              {a.name}: {label[a.capacity]}
                              {a.capacityEvidence && (
                                <details>
                                  <summary>Capacity evidence</summary>
                                  <p>
                                    {a.capacityEvidence.value}{" "}
                                    {a.capacityEvidence.unit} ·{" "}
                                    {date(a.capacityEvidence.interval.start)} –{" "}
                                    {date(a.capacityEvidence.interval.end)} UTC
                                  </p>
                                  <p>
                                    Direction: {a.capacityEvidence.direction};
                                    sampling: {a.capacityEvidence.sampling};
                                    deduplication:{" "}
                                    {a.capacityEvidence.deduplication}; capacity
                                    source: {a.capacityEvidence.capacitySource}.
                                  </p>
                                  <p>
                                    Assumptions:{" "}
                                    {a.capacityEvidence.assumptions.join("; ")}
                                  </p>
                                </details>
                              )}
                            </div>
                          ))
                        : "Unknown"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <p>
        Topology candidates do not establish health, readiness, capacity, or
        functional substitution.
      </p>
    </section>
  );
}
