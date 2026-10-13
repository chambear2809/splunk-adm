import { useEffect, useState } from "react";
import { RefreshCw, X } from "lucide-react";
import {
  loadHealth,
  jobStatus,
  sourceStatus,
  type HealthReport,
} from "./health";
import type { SearchConstructor } from "./provider";
import { formatUtc } from "./time";
const time = (value?: number) =>
  value
    ? `${formatUtc(new Date(value * 1000).toISOString())} UTC`
    : "Not observed";
export function HealthResults({ report }: { report: HealthReport }) {
  return (
    <>
      <p className="muted small">
        Checked {time(report.checkedAt)}. App-wide evidence from the last 24
        hours; independent of map filters.
      </p>
      {report.warnings.length > 0 && (
        <div role="alert">
          <b>Health check is incomplete</b>
          <ul>
            {report.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}
      <h3>Data sources</h3>
      <p className="muted small">
        Quiet or optional sources may have no recent events. Missing results can
        also mean missing index permissions; they do not confirm an outage.
      </p>
      <div className="health-table">
        <table>
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">Observation</th>
              <th scope="col">Latest event / received</th>
              <th scope="col">Events / max delay</th>
            </tr>
          </thead>
          <tbody>
            {report.sources.map((s) => (
              <tr key={s.name}>
                <th scope="row">{s.name}</th>
                <td>{sourceStatus(s, report.checkedAt)}</td>
                <td>
                  {time(s.latestEvent)}
                  <br />
                  {time(s.latestIndexed)}
                </td>
                <td>
                  {s.records ?? "Unknown"}
                  <br />
                  {s.maxIngestLag === undefined
                    ? "Unknown"
                    : `${Math.round(s.maxIngestLag)}s`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">
        Delay is the largest nonnegative difference between event time and index
        time in this window. It includes exporter delay and clock differences.
      </p>
      <h3>Flow data quality</h3>
      <p className="muted small">
        {report.quality.evaluated === undefined
          ? "Quality information is unavailable."
          : report.quality.evaluated === 0
            ? "No candidate flows are visible in this check."
            : `${report.quality.evaluated} candidate flow records checked; ${report.quality.excluded ?? "unknown"} excluded from rollup.`}{" "}
        This checks visible flow candidates received in 24 hours, after
        source-specific eligibility filters. Missing index access can hide data.
      </p>
      {report.quality.issues.length > 0 && (
        <div className="health-table">
          <table>
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Reason</th>
                <th scope="col">Treatment</th>
                <th scope="col">Records</th>
              </tr>
            </thead>
            <tbody>
              {report.quality.issues.map((q, i) => (
                <tr key={`${q.source}-${q.reason}-${q.status}-${i}`}>
                  <th scope="row">{q.source}</th>
                  <td>{q.reason}</td>
                  <td>{q.status}</td>
                  <td>{q.records}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">
        A record can have several reasons, so reason counts overlap. Missing
        measurements and assumed sampling are not proof of zero traffic or exact
        volume. Excluded records remain in the source indexes for investigation.
      </p>
      <h3>Scheduled searches</h3>
      <p className="muted small">
        Run history requires access to scheduler logs in the internal index. A
        missing run is unconfirmed, not a successful run.
      </p>
      <div className="health-table">
        <table>
          <thead>
            <tr>
              <th scope="col">Search</th>
              <th scope="col">Observation</th>
              <th scope="col">Last run / success</th>
              <th scope="col">Failures / skips</th>
            </tr>
          </thead>
          <tbody>
            {report.jobs.map((j) => (
              <tr key={j.name}>
                <th scope="row">{j.name.replace(/^ADM - /, "")}</th>
                <td>{jobStatus(j, report.checkedAt)}</td>
                <td>
                  {time(j.lastRun)}
                  <br />
                  {time(j.lastSuccess)}
                </td>
                <td>
                  {j.failures ?? "Unknown"} / {j.skips ?? "Unknown"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
export function HealthPanel({
  SearchManager,
  release,
  live,
  close,
}: {
  SearchManager?: SearchConstructor;
  release?: (id: string) => void;
  live: boolean;
  close: () => void;
}) {
  const [report, setReport] = useState<HealthReport>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!live || !SearchManager) return;
    const controller = new AbortController();
    setBusy(true);
    setError("");
    setReport(undefined);
    loadHealth(SearchManager, controller.signal, release)
      .then((result) => {
        if (!controller.signal.aborted) setReport(result);
      })
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "Health check failed.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [SearchManager, release, live, revision]);
  return (
    <section className="popover health" aria-label="Pipeline health">
      <div className="popover-head">
        <h2>Pipeline health</h2>
        <button
          className="icon-button"
          aria-label="Close pipeline health"
          onClick={close}
        >
          <X size={16} />
        </button>
      </div>
      {!live ? (
        <p>
          Synthetic demo data cannot establish pipeline health. Switch to Splunk
          to check live data and scheduled searches.
        </p>
      ) : (
        <>
          <button
            className="secondary-button"
            onClick={() => setRevision((n) => n + 1)}
            disabled={busy || !SearchManager}
          >
            <RefreshCw size={15} /> {busy ? "Checking…" : "Check again"}
          </button>
          {busy && (
            <p role="status">
              Checking data sources, flow quality and scheduled searches…
            </p>
          )}
          {error && <p role="alert">{error}</p>}
          {report && <HealthResults report={report} />}
        </>
      )}
    </section>
  );
}
