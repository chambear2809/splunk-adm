import { useEffect, useRef, useState } from "react";
import {
  checkEcosystemReceipt,
  ECOSYSTEM_RECEIPT_SOURCES,
  type EcosystemReceipt,
} from "./ecosystemReceipt";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "../data/evidenceConfig";
import { receiptContract } from "./ecosystemReceipt";
import type { SearchClient } from "../data/searchClient";

const time = (value?: number) =>
  value === undefined ? "Not observed" : new Date(value * 1000).toISOString();

export function receiptText(receipt: EcosystemReceipt): string {
  if (receipt.state === "not_selected") return "Not selected in Setup.";
  if (receipt.state === "unavailable")
    return receipt.error ?? "Receipt could not be verified.";
  const bound = receipt.inputCapped
    ? " (newest 10,000 checked; lower bounds)"
    : "";
  const counts = `${receipt.records} records from ${receipt.hosts} hosts in the last 7 days of indexing${bound}; ${receipt.validRecords} readable by the adapter's extraction; ${receipt.mappedRecords} from verified observers.`;
  const status =
    receipt.status === "no_visible_records"
      ? "No visible records. This is not proof of a collection outage."
      : receipt.status === "quality_gaps"
        ? "Some records lack required fields, use unrecognized values or an unsupported event shape; those rows are rejected during investigation."
        : receipt.status === "unmapped_hosts"
          ? "Some records come from hosts without a verified observer mapping; those rows are excluded."
          : receipt.status === "stale"
            ? "Newest indexed record is older than the configured freshness."
            : "Receipt observed for the caller.";
  return `${counts} ${status}`;
}

/** On-demand receipt and field-quality checks; nothing here runs on load or on a timer. */
export function EcosystemReceiptPanel({
  client,
  configurationClient = evidenceConfigClient,
}: {
  client?: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [receipts, setReceipts] = useState<EcosystemReceipt[]>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const active = useRef<AbortController>();
  useEffect(() => () => active.current?.abort(), []);

  const check = async () => {
    if (!client) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(undefined);
    setReceipts(undefined);
    try {
      const next: EcosystemReceipt[] = [];
      for (const source of ECOSYSTEM_RECEIPT_SOURCES)
        next.push(
          await checkEcosystemReceipt(
            client,
            source,
            controller.signal,
            configurationClient,
          ),
        );
      if (!controller.signal.aborted) setReceipts(next);
    } catch {
      setError(
        controller.signal.aborted
          ? "Cancelled."
          : "Ecosystem receipt checks could not be completed.",
      );
    } finally {
      if (active.current === controller) setBusy(false);
    }
  };

  return (
    <section
      aria-labelledby="ecosystem-receipt-health"
      className="ecosystem-evidence"
    >
      <h3 id="ecosystem-receipt-health">Ecosystem TA traffic receipt</h3>
      <p className="muted small">
        Optional firewall, load balancer and cloud flow log sources (Palo Alto
        Networks, FortiGate, F5 BIG-IP, AWS ALB/NLB, Azure VNet, GCP VPC) are
        unqualified until validated on your deployment. This check runs only
        when requested, with your Splunk permissions, over the newest 10,000
        events indexed in the last 7 days. It does not affect core readiness.
      </p>
      <button
        type="button"
        onClick={() => void check()}
        disabled={busy || !client}
      >
        {busy ? "Checking receipt…" : "Check ecosystem receipt"}
      </button>
      {busy && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {receipts && (
        <div className="dns-table-scroll">
          <table>
            <caption>Ecosystem TA traffic receipt</caption>
            <thead>
              <tr>
                <th>Source</th>
                <th>Qualification</th>
                <th>Receipt and field quality</th>
                <th>Newest event / indexed</th>
              </tr>
            </thead>
            <tbody>
              {receipts.map((receipt) => (
                <tr key={receipt.source}>
                  <td>{receiptContract(receipt.source).label}</td>
                  <td>
                    {receipt.schemaQualified
                      ? "Schema flag set by administrator"
                      : "Unqualified"}
                    {receipt.state === "staged" ? " · staged" : ""}
                  </td>
                  <td>{receiptText(receipt)}</td>
                  <td>
                    {time(receipt.latestEvent)}
                    <br />
                    {time(receipt.latestIndexed)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
