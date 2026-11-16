import { useState } from "react";
import { previewBusinessServiceImport, type ImportPreview } from "./import";
import {
  browserLocalStorage,
  clearLocalImport,
  saveLocalImport,
  type LocalImportResult,
} from "./localImport";

/** Local validation only. Persistence must independently validate and authorize. */
export function BusinessServiceImport({
  onPreview,
  onLocalChange,
}: {
  onPreview?: (preview: ImportPreview | undefined) => void;
  onLocalChange?: (result: LocalImportResult) => void;
}) {
  const [input, setInput] = useState("");
  const [preview, setPreview] = useState<ImportPreview>();
  const [localResult, setLocalResult] = useState<LocalImportResult>();
  const updateLocal = (result: LocalImportResult) => {
    setLocalResult(result);
    onLocalChange?.(result);
  };
  const validate = () => {
    const next = previewBusinessServiceImport(input);
    setPreview(next);
    onPreview?.(next);
  };
  return (
    <section
      className="atlas-business-import"
      aria-labelledby="business-service-import-title"
    >
      <h2 id="business-service-import-title">Import business services</h2>
      <p>
        Paste a version 1 or 2 JSON export to review its claims and bindings.
        This does not save or verify them.
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
      <p>
        Optional browser-local storage is limited to this browser and is not
        shared or durable collaboration. Save only data appropriate for this
        browser; the full import is stored.
      </p>
      <button
        type="button"
        disabled={!preview || preview.errors.length > 0}
        onClick={() =>
          updateLocal(saveLocalImport(browserLocalStorage(), input))
        }
      >
        Save locally
      </button>{" "}
      <button
        type="button"
        onClick={() => updateLocal(clearLocalImport(browserLocalStorage()))}
      >
        Clear local import
      </button>
      {localResult && (
        <p role="status">
          {localResult.status === "ready"
            ? "Import saved in this browser only."
            : localResult.status === "empty"
              ? "Local import cleared."
              : localResult.status === "uncertain"
                ? "Local import could not be validated; ownership is uncertain."
                : "Browser-local storage is unavailable."}
        </p>
      )}
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
              {preview.bindings.length > 0 && (
                <details>
                  <summary>
                    {preview.bindings.length} asserted technical bindings
                  </summary>
                  <p>
                    Bindings are imported assertions; they do not verify
                    business ownership or grant source access.
                  </p>
                  {preview.bindingConflictCount > 0 && (
                    <p>
                      {preview.bindingConflictCount} conflicting bindings
                      require review.
                    </p>
                  )}
                  <ul>
                    {preview.bindings.slice(0, 50).map((binding, i) => (
                      <li key={i}>
                        Claim {binding.claim.authority} /{" "}
                        {binding.claim.recordId} / revision{" "}
                        {binding.claim.revision} · {binding.claim.memberKind}:{" "}
                        {binding.claim.memberId} · claim scope:{" "}
                        {binding.claim.scope}
                        <div>
                          Technical service: {binding.target.key.service} ·{" "}
                          {binding.target.key.environment} ·{" "}
                          {binding.target.key.cluster} ·{" "}
                          {binding.target.key.namespace}
                        </div>
                        <div>
                          Native authority: {binding.target.authority} · scope:{" "}
                          {binding.target.scope} · configuration:{" "}
                          {binding.target.configRevision}
                        </div>
                        <div>
                          Binding source: {binding.authority} ·{" "}
                          {binding.recordId} / revision {binding.revision} ·
                          snapshot: {binding.snapshotId} · proof reference:{" "}
                          {binding.proofReference}
                        </div>
                        <div>
                          {binding.validity.basis === "snapshot_current"
                            ? `Binding reported only at ${new Date(binding.validity.at * 1000).toISOString()}`
                            : `Binding interval from ${new Date(binding.validity.from * 1000).toISOString()}${binding.validity.to === undefined ? "; no recorded end" : ` to ${new Date(binding.validity.to * 1000).toISOString()} (exclusive)`}; observed through ${new Date(binding.snapshotAt * 1000).toISOString()}`}
                        </div>
                      </li>
                    ))}
                  </ul>
                  {preview.bindings.length > 50 && (
                    <p>Showing the first 50 bindings.</p>
                  )}
                </details>
              )}
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
