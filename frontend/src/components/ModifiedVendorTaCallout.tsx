import { useEffect, useState } from "react";
import type { SearchClient } from "../data/searchClient";
import {
  loadModifiedVendorTaReport,
  type ModifiedVendorTaReport,
} from "../data/vendorTaCheck";

export function ModifiedVendorTaCallout({
  client,
  live,
  refresh,
}: {
  client?: SearchClient;
  live: boolean;
  refresh?: unknown;
}) {
  const [report, setReport] = useState<ModifiedVendorTaReport>();
  useEffect(() => {
    if (!live) return;
    const ctrl = new AbortController();
    void loadModifiedVendorTaReport(client, ctrl.signal).then((next) => {
      if (!ctrl.signal.aborted) setReport(next);
    });
    return () => ctrl.abort();
  }, [client, live, refresh]);

  if (!live || !report) return null;
  const { findings, unavailable } = report;
  if (findings.length === 0 && unavailable.length === 0) return null;

  if (findings.length === 0) {
    return (
      <p className="muted small" role="status">
        Modified vendor TA check unavailable ({unavailable.join(", ")}).
      </p>
    );
  }

  return (
    <section
      className="callout warn"
      role="status"
      aria-labelledby="modified-vendor-ta-title"
    >
      <h3 id="modified-vendor-ta-title">Modified vendor TA detected</h3>
      <p>
        Migrate to official unmodified Splunkbase add-ons; custom vendor TA
        builds are deprecated.
      </p>
      <ul>
        {findings.map((f, i) => (
          <li key={`${f.app}-${f.input}-${f.evidence}-${i}`}>
            <strong>{f.app}</strong> ({f.input}:{" "}
            {f.evidence === "installed_input"
              ? "custom input installed"
              : (f.detail ?? "recent custom events")}
            ) — migrate to {f.official}.
          </li>
        ))}
      </ul>
      {unavailable.length > 0 && (
        <p className="muted small">
          Partial check unavailable: {unavailable.join(", ")}.
        </p>
      )}
    </section>
  );
}
