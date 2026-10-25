import { useCallback, useEffect, useRef, useState } from "react";
import {
  loadO11yHealthEvidence,
  observabilityOrigin,
  type O11yHealthObservation,
  type O11yHealthResult,
} from "./data/o11yHealth";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import type { ServiceHealthSelection } from "./data/evidence";
import type { SearchClient } from "./data/searchClient";

function metricTitle(record: O11yHealthObservation): string {
  switch (record.signalLabel) {
    case "request_count":
      return "Service requests";
    case "request_errors":
      return "Service errors";
    case "request_latency_p90":
      return "Request duration p90";
    case "container_cpu_utilization":
      return "Container CPU utilization";
    case "jvm_memory_used":
      return "JVM memory used";
    default:
      return "Unknown metric";
  }
}

function MetricRows({ records }: { records: O11yHealthObservation[] }) {
  const metrics = records
    .filter(
      (
        record,
      ): record is O11yHealthObservation & {
        signalLabel: NonNullable<O11yHealthObservation["signalLabel"]>;
        value: number;
        logicalTimestamp: number;
        unit: string;
      } => record.kind === "metric" && record.value !== undefined,
    )
    .sort(
      (left, right) =>
        (right.logicalTimestamp ?? 0) - (left.logicalTimestamp ?? 0),
    );
  if (metrics.length === 0)
    return (
      <p role="status">
        No metric samples were included in this completed export.
      </p>
    );
  return (
    <div className="table-wrap">
      <table>
        <caption>Measured Observability Cloud service health</caption>
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">Value</th>
            <th scope="col">Logical time</th>
            <th scope="col">Aggregation</th>
            <th scope="col">Source identity</th>
          </tr>
        </thead>
        <tbody>
          {metrics.map((record) => (
            <tr key={`${record.index}:${record.eventFingerprint}`}>
              <th scope="row">{metricTitle(record)}</th>
              <td>
                {record.value} {record.unit}
              </td>
              <td>
                {new Date((record.logicalTimestamp ?? 0) * 1000).toISOString()}
              </td>
              <td>
                {record.statistic}; {record.resolutionSeconds}s resolution
              </td>
              <td>
                service.namespace={record.sourceDimensions?.serviceNamespace}
                {record.sourceDimensions?.sfMmsId
                  ? `; sf_mms_id=${record.sourceDimensions.sfMmsId}; sf_dimensionalized=${record.sourceDimensions.sfDimensionalized}`
                  : ""}
                {record.sourceDimensions?.podUid
                  ? `; pod UID=${record.sourceDimensions.podUid}`
                  : ""}
                {record.sourceDimensions?.containerName
                  ? `; container=${record.sourceDimensions.containerName}`
                  : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function O11yHealthPanel({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: ServiceHealthSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<O11yHealthResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const generation = useRef(0);
  const active = useRef<AbortController>();
  const identity = JSON.stringify(selection);
  const cancel = useCallback(() => {
    generation.current++;
    active.current?.abort();
  }, []);
  const cancelCurrent = () => {
    cancel();
    setBusy(false);
    setError("Health search cancelled. You can inspect this service again.");
  };

  useEffect(() => {
    generation.current++;
    active.current?.abort();
    setResult(undefined);
    setError(undefined);
    setBusy(false);
    return cancel;
  }, [identity, client, configurationClient, cancel]);

  const load = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await loadO11yHealthEvidence(
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
          controller.signal.aborted
            ? "Cancelled. No partial health result was retained."
            : "Observability Cloud health unavailable. Refresh the service selection or check optional source configuration and permissions.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };

  const completion = result?.records.find(
    (record) => record.kind === "export_completion",
  );
  const url = result
    ? observabilityOrigin(completion?.realm ?? "", result.observabilityOrigin)
    : undefined;
  return (
    <section
      className="o11y-health inspector-body"
      aria-label="Observability Cloud service health evidence"
    >
      <h3>Observability Cloud service health</h3>
      <p>
        Historical measured service and runtime metrics for the exact selected
        service, environment, cluster and Kubernetes namespace. This context
        does not establish a network cause.
      </p>
      <p>
        Each row is the latest time-aligned sample in the selected window for
        that output series. Request and error counts describe one SignalFlow
        resolution bucket, not totals for the entire window.
      </p>
      <button type="button" onClick={() => void load()} disabled={busy}>
        {result ? "Refresh service health" : "Inspect service health"}
      </button>
      {busy && (
        <button type="button" onClick={cancelCurrent}>
          Cancel health search
        </button>
      )}
      <p role="status">
        {busy
          ? "Loading an indexed, completed Observability Cloud export…"
          : (error ??
            (result
              ? `Health source: ${result.state}${result.configurationChanged ? " · configuration changed" : ""}${result.error ? ` · ${result.error}` : ""}`
              : "This optional source runs only when an administrator has selected and qualified it."))}
      </p>
      {result?.state === "staged" && (
        <p role="status">
          Observability Cloud export is staged for qualification and was not
          queried.
        </p>
      )}
      {result?.state === "complete" && result.records.length === 0 && (
        <p role="status">
          No recent completed export matched this exact service and time window.
          Missing data is not zero or healthy.
        </p>
      )}
      {result?.replayDuplicates ? (
        <p role="status">
          Ignored {result.replayDuplicates} exact repeated health record
          {result.replayDuplicates === 1 ? "" : "s"} from HEC replay.
        </p>
      ) : null}
      {completion && (
        <div>
          <p role="status">
            Completed capture {completion.captureId}; expected{" "}
            {completion.expectedRecordCount} metric samples from{" "}
            {completion.signalsWithData} signals. Detector alerts were not
            queried.
          </p>
          {url && (
            <p>
              <a href={url} target="_blank" rel="noreferrer">
                {result?.observabilityOrigin
                  ? "Open configured Observability Cloud origin"
                  : `Open Observability Cloud realm ${completion.realm}`}
              </a>
            </p>
          )}
        </div>
      )}
      {result?.state === "complete" && result.records.length > 0 && (
        <>
          <dl>
            <dt>Organization</dt>
            <dd>{result.records[0].organizationId}</dd>
            <dt>OTel service namespace</dt>
            <dd>
              {result.records
                .filter((record) => record.kind === "metric")
                .map((record) => record.sourceDimensions?.serviceNamespace)
                .filter((value): value is string => Boolean(value))
                .filter((value, index, all) => all.indexOf(value) === index)
                .join(", ") || "Not reported"}
            </dd>
          </dl>
          <MetricRows records={result.records} />
          <p>
            Missing metric samples mean telemetry was unavailable for that
            signal. They are not interpreted as a zero or healthy value.
          </p>
        </>
      )}
      {result?.coverage.map((item) => (
        <p key={item}>{item}</p>
      ))}
    </section>
  );
}
