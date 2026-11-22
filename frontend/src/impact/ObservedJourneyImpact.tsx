import { traceURL } from "../pages/ExploreTools";
import type {
  ObservedImpactEvidence,
  ObservedImpactTrial,
} from "./observedEvidence";
import type { JourneyImpact } from "./observedImpact";

function evidenceLink(
  trial: ObservedImpactTrial,
  scope: string,
  src: string,
  dst: string,
) {
  return traceURL(
    src,
    dst,
    new URLSearchParams({
      mode: "live",
      earliest: String(trial.start),
      latest: String(trial.end),
    }),
    scope,
  );
}

export function ObservedJourneyImpact({
  cohort,
  journeys,
  selectedDevices,
}: {
  cohort: ObservedImpactEvidence;
  journeys: JourneyImpact[];
  selectedDevices: string[];
}) {
  const selected = new Set(selectedDevices);
  const nameById = new Map(cohort.devices.map((d) => [d.id, d.name]));
  return (
    <section
      aria-labelledby="atlas-observed-journeys-title"
      className="atlas-impact-observed"
    >
      <h2 id="atlas-observed-journeys-title">Observed journey impact</h2>
      <p>
        ADM excludes a sample when one of its verified legs touches a selected
        device. Remaining samples need request and reply evidence at each
        selected tier. Failure outcomes remain unverified.
      </p>
      <div className="atlas-impact-observed-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Application</th>
              <th scope="col">User journey</th>
              <th scope="col">Samples on selection</th>
              <th scope="col">Remaining bidirectional samples</th>
              <th scope="col">Incomplete coverage</th>
              <th scope="col">Evidence at selection</th>
            </tr>
          </thead>
          <tbody>
            {journeys.map((journey) => (
              <tr key={journey.trials[0].id}>
                <td>{journey.app}</td>
                <th scope="row">
                  {journey.journey}{" "}
                  <span className="muted small">
                    · {journey.actor === "browser" ? "Browser" : "Operator"}
                  </span>
                </th>
                <td>
                  {journey.exposed.length} of {journey.trials.length}
                </td>
                <td>
                  {journey.remaining.length}
                  {journey.remainingDevices.size > 0 && (
                    <>
                      {" · "}
                      {[...journey.remainingDevices]
                        .map((id) => nameById.get(id) ?? id)
                        .join(", ")}
                    </>
                  )}
                </td>
                <td>{journey.incomplete.length}</td>
                <td>
                  {journey.exposed.length === 0 && "—"}
                  {journey.exposed.map((trial) => {
                    const request = trial.observations.forward.some((id) =>
                      selected.has(id),
                    );
                    const reply = trial.observations.reverse.some((id) =>
                      selected.has(id),
                    );
                    return (
                      <div key={trial.id} title={trial.outcome}>
                        {(request || reply) && (
                          <div>
                            TCP {trial.source_port}{" "}
                            {request && (
                              <a
                                href={evidenceLink(
                                  trial,
                                  cohort.scope,
                                  trial.src,
                                  trial.dst,
                                )}
                              >
                                Request
                              </a>
                            )}{" "}
                            {reply && (
                              <a
                                href={evidenceLink(
                                  trial,
                                  cohort.scope,
                                  trial.dst,
                                  trial.src,
                                )}
                              >
                                Reply
                              </a>
                            )}
                          </div>
                        )}
                        {trial.linkedCaptures
                          .filter((capture) => selected.has(capture.device))
                          .map((capture) => (
                            <div key={capture.capture}>
                              <a
                                href={evidenceLink(
                                  trial,
                                  cohort.scope,
                                  capture.src,
                                  capture.dst,
                                )}
                              >
                                TCP {capture.source_port} downstream
                              </a>
                            </div>
                          ))}
                      </div>
                    );
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">
        {cohort.receipts.size} scoped Trace receipts · {cohort.native.length}{" "}
        native device records
      </p>
    </section>
  );
}
