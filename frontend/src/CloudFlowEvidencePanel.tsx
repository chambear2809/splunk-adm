import { useEffect, useRef, useState } from "react";
import {
  loadCloudFlowEvidence,
  type CloudFlowResult,
} from "./data/cloudFlowEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import type { EvidenceSelection } from "./data/evidence";
import type { SearchClient } from "./data/searchClient";

function timestamp(value: number): string {
  return new Date(value * 1000).toISOString();
}

export function CloudFlowEvidencePanel({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<CloudFlowResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const generation = useRef(0);
  const active = useRef<AbortController>();
  const identity = JSON.stringify(selection);

  useEffect(() => {
    generation.current++;
    active.current?.abort();
    setResult(undefined);
    setError(undefined);
    setBusy(false);
    return () => {
      active.current?.abort();
    };
  }, [identity, client, configurationClient]);

  const load = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await loadCloudFlowEvidence(
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
            ? "Cancelled. Native cleanup may remain pending."
            : "AWS VPC Flow Logs evidence unavailable. Refresh the selection or check the source mapping and permissions.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };

  const capture = result?.captureStatus;
  const records = [...(result?.records ?? []), ...(capture?.records ?? [])];
  const statusCounts = capture?.records.reduce(
    (counts, record) => {
      if (record.logStatus === "NODATA") counts.noData++;
      if (record.logStatus === "SKIPDATA") counts.skipData++;
      return counts;
    },
    { noData: 0, skipData: 0 },
  );

  return (
    <section
      className="dns-evidence inspector-body"
      aria-label="Optional AWS VPC Flow Logs evidence"
    >
      <h3>AWS VPC Flow Logs</h3>
      <button type="button" onClick={() => void load()} disabled={busy}>
        {result ? "Refresh Flow Logs evidence" : "Inspect Flow Logs evidence"}
      </button>{" "}
      {busy && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel search
        </button>
      )}
      <p role="status">
        {busy
          ? "Loading optional evidence…"
          : (error ??
            (result
              ? result.state === "complete"
                ? `${result.records.length} visible endpoint flow records; ${result.inputCount} flow inputs.`
                : "Source state: " + result.state + "."
              : "AWS VPC Flow Logs remain off unless an administrator activates a schema-qualified source."))}
      </p>
      {result && (
        <>
          {result.configurationChanged && (
            <p role="alert">
              Configuration changed or became unreadable after capture; refresh
              before using this result.
            </p>
          )}
          {!result.schemaQualified && (
            <p role="alert">
              The exact producer schema is not qualified. Records are shown as
              context only and are not attributed to a workload.
            </p>
          )}
          {result.state === "complete" && (
            <p>
              Input cap: {result.inputCapped ? "reached" : "not reached"}.
              Display cap: {result.outputCapped ? "reached" : "not reached"}.
              Rejected flow rows: {result.rejected}. Oversized rows:{" "}
              {result.oversized}.
            </p>
          )}
          {capture && (
            <p>
              Capture-wide status:{" "}
              {capture.state === "complete"
                ? `${capture.inputCount} inputs, input cap ${capture.inputCapped ? "reached" : "not reached"}, display cap ${capture.outputCapped ? "reached" : "not reached"}. Visible NODATA: ${statusCounts?.noData ?? 0}. Visible SKIPDATA: ${statusCounts?.skipData ?? 0}. Rejected: ${capture.rejected}.`
                : "unavailable."}
            </p>
          )}
          <p>
            Captured {timestamp(result.capturedAt)}; inspected through{" "}
            {timestamp(result.inspectedWindow.end)}. Configuration{" "}
            {result.configurationFingerprint.slice(0, 12)}.
          </p>
          {records.length ? (
            <div className="dns-table-scroll">
              <table>
                <caption>AWS VPC Flow Logs source records</caption>
                <thead>
                  <tr>
                    <th>Record / interval</th>
                    <th>Interface and packet addresses</th>
                    <th>Action / status</th>
                    <th>Source counters</th>
                    <th>Capture identity / limits</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((record, index) => (
                    <tr
                      key={
                        record.authority +
                        ":" +
                        record.eventFingerprint +
                        ":" +
                        index
                      }
                    >
                      <td>
                        {record.recordClass === "capture_status"
                          ? "Capture status"
                          : "Flow interval"}
                        <br />
                        {timestamp(record.interval.start)} –{" "}
                        {timestamp(record.interval.end)}
                        <br />
                        {record.flowDirection} · protocol{" "}
                        {record.protocol ?? "—"}
                      </td>
                      <td>
                        Interface: {record.interfaceAddresses.source ?? "—"}:
                        {record.sourcePort ?? "—"} →{" "}
                        {record.interfaceAddresses.destination ?? "—"}:
                        {record.destinationPort ?? "—"}
                        <br />
                        Packet: {record.packetAddresses.source ?? "—"} →{" "}
                        {record.packetAddresses.destination ?? "—"}
                        {record.matchedAddressFields.length > 0 && (
                          <>
                            <br />
                            Selected address matched{" "}
                            {record.matchedAddressFields.join(", ")}
                          </>
                        )}
                      </td>
                      <td>
                        {record.action} · {record.logStatus}
                        <br />
                        {record.action === "ACCEPT"
                          ? "Allowed at this policy point."
                          : record.action === "REJECT"
                            ? "Rejected at this policy point."
                            : "No action value reported."}
                      </td>
                      <td>
                        {record.packets ?? "—"} packets · {record.bytes ?? "—"}{" "}
                        bytes
                        <br />
                        {record.sourcePort ?? "—"} →{" "}
                        {record.destinationPort ?? "—"}
                      </td>
                      <td>
                        {record.authority} · {record.scope}
                        <br />
                        {record.accountId ?? "account unavailable"} ·{" "}
                        {record.region ?? "Region unavailable"} ·{" "}
                        {record.vpcId ?? "VPC unavailable"}
                        <br />
                        ENI {record.interfaceId ?? "—"} · instance{" "}
                        {record.instanceId ?? "—"}
                        <br />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>No endpoint flows or capture status returned.</p>
          )}
          <ul>
            {result.coverage.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
