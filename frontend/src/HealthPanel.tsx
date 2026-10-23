import { pageURL } from "./app/urlState";
import { useEffect, useState } from "react";
import TableExport from "@splunk/react-ui/Table";
import { toolkitDefault } from "./app/interop";
import { RefreshCw, X } from "lucide-react";
import {
  loadHealth,
  jobStatus,
  sourceStatus,
  type HealthReport,
} from "./health";
import type { SearchClient } from "./data/searchClient";
import { formatUtc } from "./time";
import { useHealthStatus } from "./data/healthStatus";
const time = (value?: number) =>
  value
    ? `${formatUtc(new Date(value * 1000).toISOString())} UTC`
    : "Not observed";
const ToolkitTable = toolkitDefault(TableExport);

type HealthTableProps = {
  headers: string[];
  rows: { key: string; cells: string[] }[];
};
function HealthTable({ headers, rows }: HealthTableProps) {
  return (
    <div className="health-table" style={{ overflowX: "auto" }}>
      <ToolkitTable>
        <ToolkitTable.Head>
          {headers.map((header) => (
            <ToolkitTable.HeadCell
              key={header}
              scope="col"
              style={{ minWidth: 150 }}
            >
              {header}
            </ToolkitTable.HeadCell>
          ))}
        </ToolkitTable.Head>
        <ToolkitTable.Body>
          {rows.map((row) => (
            <ToolkitTable.Row key={row.key}>
              {row.cells.map((cell, index) => (
                <ToolkitTable.Cell
                  key={`${row.key}-${index}`}
                  style={{ whiteSpace: "pre-line" }}
                >
                  {cell}
                </ToolkitTable.Cell>
              ))}
            </ToolkitTable.Row>
          ))}
        </ToolkitTable.Body>
      </ToolkitTable>
    </div>
  );
}
export function HealthResults({ report }: { report: HealthReport }) {
  return (
    <>
      <p className="muted small">
        Checked {time(report.checkedAt)}. App-wide evidence from the last 24
        hours for quality and seven days for source receipt and scheduled runs;
        independent of map filters.
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
      {report.deployment?.state !== "configured" && (
        <p role="status">
          Deployment expectations are unknown. An administrator can select
          active and staged sources in Setup.
        </p>
      )}
      {report.deployment?.error && (
        <p role="alert">{report.deployment.error}</p>
      )}
      {report.deployment?.state === "configured" &&
        !report.deployment.activeContract && (
          <p role="status">
            The active data contract could not be verified. Health remains
            unknown.
          </p>
        )}
      <h3>Data sources</h3>
      <p className="muted small">
        Source receipt is evaluated against administrator expectations. Quiet
        sources can have no recent events; collection health remains unknown.
        Missing results can also mean missing index permissions; they do not
        confirm an outage.
      </p>
      <HealthTable
        headers={[
          "Source",
          "Observation",
          "Latest event / received",
          "Events / max delay",
          "Scope and identity",
        ]}
        rows={report.sources.map((s) => ({
          key: s.name,
          cells: [
            s.name,
            `${sourceStatus(s, report.checkedAt)}${s.staleAfterSeconds ? ` (freshness ${s.staleAfterSeconds}s)` : ""}`,
            `${time(s.latestEvent)}\n${time(s.latestIndexed)}`,
            `${s.records ?? "Unknown"} / ${s.maxIngestLag === undefined ? "Unknown" : `${Math.round(s.maxIngestLag)}s`}`,
            [
              s.unmapped === undefined ? undefined : `${s.unmapped} unmapped`,
              s.unresolved === undefined
                ? undefined
                : `${s.unresolved} unresolved`,
              s.warning,
            ]
              .filter(Boolean)
              .join(" · ") || "—",
          ],
        }))}
      />
      {report.optionalEvidence.length > 0 && (
        <section aria-labelledby="optional-source-health">
          <h3 id="optional-source-health">Optional evidence sources</h3>
          <p className="muted small">
            This view checks source selection and index configuration. It does
            not run source searches or treat a quiet optional feed as a core
            readiness failure.
          </p>
          <p>
            <a href={pageURL("endpoints")}>
              Open endpoint investigations to inspect scoped evidence
            </a>
          </p>
          <HealthTable
            headers={["Source", "Status", "Receipt", "Diagnostic"]}
            rows={report.optionalEvidence.map((item) => ({
              key: item.id,
              cells: [
                item.name,
                item.status === "configured"
                  ? "Selected; runtime diagnostics not run"
                  : item.status === "not_configured"
                    ? "Selected; index selector not configured"
                    : item.status === "unavailable"
                      ? "Selected; index configuration unavailable"
                      : item.status === "staged"
                        ? "Staged; not expected to collect"
                        : item.status === "not_selected"
                          ? "Not selected"
                          : "Configuration unknown",
                "Not checked; requires an explicit scoped investigation",
                `${item.diagnostic} Receipt health stays unknown until a scoped diagnostic is requested.`,
              ],
            }))}
          />
        </section>
      )}
      <p className="muted small">
        Delay is the largest nonnegative difference between event time and index
        time in this window. It includes exporter delay and clock differences.
      </p>
      <p className="muted small">
        Source receipt does not verify API permissions, collector process
        health, or ingestion checkpoints. Those checks remain unknown until an
        operator verifies them.
      </p>
      <h3>Data quality</h3>
      <p className="muted small">
        {report.qualityRequired === false
          ? "No active source requires candidate quality checks."
          : report.quality.evaluated === undefined || report.quality.incomplete
            ? "Quality information is unavailable."
            : report.quality.evaluated === 0
              ? "No candidate records are visible in this check."
              : `${report.quality.evaluated} candidate records evaluated; ${report.quality.excluded ?? "unknown"} excluded.`}{" "}
        This checks visible source candidates received in 24 hours, after
        source-specific eligibility filters. Missing index access can hide data.
      </p>
      <p className="muted small">
        Quality totals include evaluated rows for the active selected source
        families and active data contract. Missing evaluation evidence remains
        unknown.
      </p>
      {report.quality.issues.length > 0 && (
        <HealthTable
          headers={["Source", "Reason", "Treatment", "Records"]}
          rows={report.quality.issues.map((q, i) => ({
            key: `${q.source}-${q.reason}-${i}`,
            cells: [q.source, q.reason, q.status, String(q.records)],
          }))}
        />
      )}
      <p className="muted small">
        A record can have several reasons, so reason counts overlap. Missing
        measurements and assumed sampling are not proof of zero traffic or exact
        volume. Original evidence remains in the source indexes for
        investigation.
      </p>
      <h3>Scheduled searches</h3>
      <p className="muted small">
        Run history requires access to scheduler logs in the internal index. A
        missing run is unconfirmed, not a successful run.
      </p>
      <HealthTable
        headers={[
          "Search",
          "Observation",
          "Last run / success",
          "Failures / skips",
        ]}
        rows={report.jobs.map((j) => ({
          key: j.name,
          cells: [
            j.name.replace(/^ADM - /, ""),
            jobStatus(j, report.checkedAt),
            `${time(j.lastRun)}\n${time(j.lastSuccess)}`,
            `${j.failures ?? "Unknown"} / ${j.skips ?? "Unknown"}`,
          ],
        }))}
      />
    </>
  );
}
export function useHealthData(client?: SearchClient, live = false) {
  const shared = useHealthStatus();
  const [report, setReport] = useState<HealthReport>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (shared) return;
    if (!live || !client) {
      setReport(undefined);
      setBusy(false);
      return;
    }
    const controller = new AbortController();
    setBusy(true);
    setError("");
    setReport(undefined);
    loadHealth(client, controller.signal)
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
  }, [client, live, revision, shared]);
  return {
    report: shared?.report ?? report,
    error: shared?.error ?? error,
    busy: shared?.busy ?? busy,
    checkAgain: () =>
      shared ? shared.refresh() : setRevision((value) => value + 1),
  };
}

export function HealthPanel({
  client,
  live,
  close,
  onReport,
}: {
  client?: SearchClient;
  live: boolean;
  close: () => void;
  onReport?: (report: HealthReport | undefined) => void;
}) {
  const { report, error, busy, checkAgain } = useHealthData(client, live);
  useEffect(() => onReport?.(report), [onReport, report]);
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
            onClick={checkAgain}
            disabled={busy || !client}
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
