import { useState } from "react";
import { previewBusinessServiceImport, type ImportPreview } from "./import";

/** Local validation only. Persistence must independently validate and authorize. */
export function BusinessServiceImport({
  onPreview,
}: {
  onPreview?: (preview: ImportPreview | undefined) => void;
}) {
  const [input, setInput] = useState("");
  const [preview, setPreview] = useState<ImportPreview>();
  const validate = () => {
    const next = previewBusinessServiceImport(input);
    setPreview(next);
    onPreview?.(next);
  };
  return (
    <section aria-labelledby="business-service-import-title">
      <h2 id="business-service-import-title">Import business services</h2>
      <p>
        Paste a version 1 JSON export to review its claims. This does not save
        or verify them.
      </p>
      <label htmlFor="business-service-import-json">JSON import</label>
      <textarea
        id="business-service-import-json"
        rows={8}
        value={input}
        onChange={(event) => {
          setInput(event.target.value);
          setPreview(undefined);
          onPreview?.(undefined);
        }}
      />
      <div>
        <button type="button" onClick={validate} disabled={!input.trim()}>
          Preview import
        </button>
      </div>
      {preview && (
        <div aria-live="polite">
          {preview.errors.length ? (
            <>
              <p>Import has errors. No rows are ready to apply.</p>
              <ul>
                {preview.errors.map((error, i) => (
                  <li key={i}>
                    {error.row ? `Row ${error.row}: ` : ""}
                    {error.message}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              <p>
                {preview.claims.length} claims ready for review. These are
                imported assertions.
              </p>
              {preview.conflictCount > 0 && (
                <>
                  <p>
                    Ownership conflict: {preview.conflictCount} conflicting
                    pairs. All claims are retained.
                  </p>
                  <ul>
                    {preview.conflicts.map((conflict, i) => (
                      <li key={i}>
                        Rows {conflict.rows.join(" and ")}: {conflict.reason}
                      </li>
                    ))}
                  </ul>
                  {preview.conflictCount > preview.conflicts.length && (
                    <p>
                      Showing the first {preview.conflicts.length} conflicting
                      pairs.
                    </p>
                  )}
                </>
              )}
              <ul>
                {preview.claims.map((claim, i) => (
                  <li key={i}>
                    <strong>{claim.serviceName}</strong> ({claim.serviceId}) ·{" "}
                    {claim.teamName} · {claim.criticality}
                    <div>
                      {claim.memberKind}: {claim.memberId} · scope:{" "}
                      {claim.scope}
                    </div>
                    <div>
                      {claim.validity.basis === "snapshot_current"
                        ? "Current ownership; historical membership unavailable"
                        : `Source interval from ${new Date(claim.validity.from * 1000).toISOString()}${claim.validity.to === undefined ? "; no recorded end" : ` to ${new Date(claim.validity.to * 1000).toISOString()} (exclusive)`}`}
                    </div>
                    <div>
                      Source: {claim.authority} · snapshot {claim.snapshotId}
                    </div>
                    {claim.runbook && (
                      <div>
                        Runbook: {claim.runbook.label} ({claim.runbook.url})
                      </div>
                    )}
                    {claim.escalation && (
                      <div>
                        Escalation: {claim.escalation.label} (
                        {claim.escalation.url})
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}
