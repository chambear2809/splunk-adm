import {
  compare,
  eligibility,
  type Baseline,
  type Capture,
  type WatchDefinition,
} from "./model";

/** Read-only review; persistence and authorization belong to the host. */
export function BaselineReview({
  baselines,
  current,
  watches = [],
}: {
  baselines: Baseline[];
  current: Capture;
  watches?: WatchDefinition[];
}) {
  const reasons = eligibility(current);
  return (
    <section aria-label="Evidence review">
      <h3>Evidence review</h3>
      {reasons.length ? (
        <>
          <p>Current evidence is not eligible for a baseline.</p>
          <ul>
            {reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </>
      ) : (
        <p>Current evidence meets the supplied coverage requirements.</p>
      )}
      <p>
        Baseline storage and source entitlement must be checked by the
        deployment.
      </p>
      {!baselines.length ? (
        <p>No baseline selected for comparison.</p>
      ) : (
        baselines.map((baseline) => {
          const result = compare(baseline.capture, current);
          return (
            <details key={`${baseline.id}:${baseline.version}`}>
              <summary>
                {baseline.name} · version {baseline.version}
              </summary>
              {!result.comparable ? (
                <>
                  <p>Not comparable</p>
                  <ul>
                    {result.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </>
              ) : result.findings.length ? (
                <ul>
                  {result.findings.map((finding) => (
                    <li key={`${finding.kind}:${finding.signature}`}>
                      {finding.description}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No structural differences observed.</p>
              )}
            </details>
          );
        })
      )}
      <h4>Watchlist</h4>
      {watches.length ? (
        <ul>
          {watches.map((watch) => (
            <li key={watch.id}>
              {watch.id} · threshold {watch.threshold} · cooldown{" "}
              {watch.cooldownSeconds} seconds
            </li>
          ))}
        </ul>
      ) : (
        <p>No watch definitions.</p>
      )}
      <p>
        Watch definitions are passive; no schedule or notification is enabled.
      </p>
    </section>
  );
}
