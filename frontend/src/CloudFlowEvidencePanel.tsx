import { useEffect, useRef, useState } from "react";
import { loadCloudFlowEvidence } from "./data/cloudFlowEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import type { CloudFlowObservation } from "./data/cloudFlowEvidence";
import type { EvidenceSelection } from "./data/evidence";
import type { SupplementalResult } from "./data/supplementalEvidence";
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
  const [result, setResult] =
    useState<SupplementalResult<CloudFlowObservation>>();
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

  const statusCounts = result?.records.reduce(
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
      <p>
        On-demand, scoped network observations. Flow records describe an
        aggregation interval; accepted traffic does not prove application
        success, and these records do not establish historical resource
        ownership.
      </p>
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
                ? result.records.length +
                  " visible source records; " +
                  result.inputCount +
                  " matching or capture-status inputs."
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
              Rejected rows: {result.rejected}. Oversized rows:{" "}
              {result.oversized}. NODATA records: {statusCounts?.noData ?? 0}.
              SKIPDATA records: {statusCounts?.skipData ?? 0}.
            </p>
          )}
          <p>
            Captured {timestamp(result.capturedAt)}; inspected through{" "}
            {timestamp(result.inspectedWindow.end)}. Configuration{" "}
            {result.configurationFingerprint.slice(0, 12)}.
          </p>
          {result.records.length ? (
            <div className="dns-table-scroll">
              <table>
                <caption>
                  AWS VPC Flow Logs source records. Counters remain per record.
                </caption>
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
                  {result.records.map((record, index) => (
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
                          ? "Allowed at the recorded network policy point; application outcome unknown."
                          : record.action === "REJECT"
                            ? "Rejected at a network policy point; exact cause and application outcome unknown."
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
                        Context only · historical ENI ownership unavailable
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>
              No visible matching flow or capture-status records. This does not
              establish that the selected endpoint had no traffic.
            </p>
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
