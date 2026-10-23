import { useEffect, useRef, useState } from "react";
import type { EvidenceSelection } from "./data/evidence";
import type { EvidenceConfigClient } from "./data/evidenceConfig";
import {
  loadAssetHistoryEvidence,
  type AssetHistoryRecord,
  type AssetHistoryResult,
} from "./data/inventoryEvidence";
import type { SearchClient } from "./data/searchClient";

export interface InventoryEvidencePanelProps {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}

function time(value: number): string {
  return new Date(value * 1000).toISOString();
}

function interval(record: AssetHistoryRecord): string {
  const end =
    record.validTo === undefined
      ? "open in source through snapshot " + time(record.snapshotAt)
      : time(record.validTo) + " (exclusive)";
  return "[" + time(record.validFrom) + ", " + end + ")";
}

function attributionText(
  record: AssetHistoryRecord,
  complete: boolean,
): string {
  if (record.conflict) return "Ambiguous overlapping asset or context claims";
  if (record.validityBasis === "snapshot_current")
    return "Snapshot context only; does not attribute earlier traffic";
  if (!complete) return "History may be incomplete; ownership is unverified";
  if (record.windowCoverage === "full")
    return "Source interval covers the selected window";
  if (record.windowCoverage === "partial")
    return "Source interval covers part of the selected window";
  return "Context only";
}

export function InventoryEvidencePanel({
  selection,
  client,
  configurationClient,
}: InventoryEvidencePanelProps) {
  const [result, setResult] = useState<AssetHistoryResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controller = useRef<AbortController>();
  const selectionKey =
    selection.selectionId + ":" + selection.configurationFingerprint;

  useEffect(() => {
    controller.current?.abort();
    controller.current = undefined;
    setResult(undefined);
    setError(undefined);
    setBusy(false);
  }, [selectionKey]);

  useEffect(
    () => () => {
      controller.current?.abort();
    },
    [],
  );

  const inspect = async () => {
    controller.current?.abort();
    const active = new AbortController();
    controller.current = active;
    setBusy(true);
    setError(undefined);
    setResult(undefined);
    try {
      setResult(
        await loadAssetHistoryEvidence(
          client,
          selection,
          active.signal,
          configurationClient,
        ),
      );
    } catch (cause) {
      if (!active.signal.aborted)
        setError(
          cause instanceof Error
            ? cause.message
            : "Asset history could not be inspected.",
        );
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  };

  const cancel = () => {
    controller.current?.abort();
    controller.current = undefined;
    setBusy(false);
  };

  const complete =
    !!result &&
    result.state === "complete" &&
    result.schemaQualified &&
    !result.configurationChanged &&
    !result.inputCapped &&
    !result.outputCapped &&
    result.rejected === 0;

  return (
    <section aria-labelledby="inventory-evidence-title">
      <h2 id="inventory-evidence-title">Asset history</h2>
      <p>
        Optional inventory evidence for the selected scoped addresses and time
        window. It does not create traffic relationships or application edges.
      </p>
      <button type="button" onClick={() => void inspect()} disabled={busy}>
        {busy ? "Inspecting asset history…" : "Inspect asset history"}
      </button>{" "}
      {busy && (
        <button type="button" onClick={cancel}>
          Cancel
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {result && (
        <div aria-live="polite">
          <p>
            Capture: {time(result.capturedAt)} · state: {result.state} · history
            is independent of the traffic capture.
          </p>
          {!complete && (
            <p role="status">
              History completeness or configuration could not be verified. No
              unique asset attribution is available.
            </p>
          )}
          {result.inputCapped && (
            <p role="status">
              More than 10,000 matching history rows were present; the result is
              incomplete.
            </p>
          )}
          {result.outputCapped && (
            <p role="status">
              The display is capped at 64 rows; the result cannot establish a
              unique owner.
            </p>
          )}
          {result.rejected > 0 && (
            <p role="status">
              {result.rejected} source row(s) failed validation and were
              omitted.
            </p>
          )}
          {result.configurationChanged && (
            <p role="status">
              Source configuration changed or became unreadable after capture;
              refresh before using these records.
            </p>
          )}
          {result.records.length === 0 ? (
            <p>
              No matching asset-history records were visible. This does not
              prove that the source has no records or complete coverage.
            </p>
          ) : (
            <div className="dns-table-scroll">
              <table>
                <caption>Scoped asset-history evidence</caption>
                <thead>
                  <tr>
                    <th>Asset / service</th>
                    <th>Scope / IP</th>
                    <th>Validity / snapshot</th>
                    <th>Evidence status</th>
                  </tr>
                </thead>
                <tbody>
                  {result.records.map((record) => (
                    <tr
                      key={
                        record.authority +
                        ":" +
                        record.recordId +
                        ":" +
                        record.revision
                      }
                    >
                      <td>
                        {record.assetName ?? record.assetId}
                        <br />
                        Asset ID: {record.assetId}
                        {record.serviceId && (
                          <>
                            <br />
                            Service: {record.serviceName ??
                              record.serviceId} · {record.serviceId}
                          </>
                        )}
                        {record.environment && (
                          <>
                            <br />
                            Environment: {record.environment}
                          </>
                        )}
                        {record.ownerId && (
                          <>
                            <br />
                            Owner: {record.ownerName ?? record.ownerId} ·{" "}
                            {record.ownerId}
                          </>
                        )}
                        {record.networkId && (
                          <>
                            <br />
                            Network: {record.networkId}
                          </>
                        )}
                      </td>
                      <td>
                        {record.scope}
                        <br />
                        {record.ip}
                      </td>
                      <td>
                        {record.validityBasis === "source_interval"
                          ? interval(record)
                          : "Current snapshot; point-in-time context only"}
                        <br />
                        Authority: {record.authority}
                        <br />
                        Snapshot {record.snapshotId}: {time(record.snapshotAt)}{" "}
                        · {record.freshness} ·{" "}
                        {record.snapshotComplete
                          ? "complete export"
                          : "partial export"}{" "}
                        · revision {record.revision}
                        {record.retiredAt !== undefined && (
                          <>
                            <br />
                            Explicitly retired: {time(record.retiredAt)}
                          </>
                        )}
                      </td>
                      <td>
                        {attributionText(record, complete)}
                        {record.conflictReason && (
                          <>
                            <br />
                            {record.conflictReason}
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ul>
            {result.coverage.map((item, index) => (
              <li key={index + ":" + item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
