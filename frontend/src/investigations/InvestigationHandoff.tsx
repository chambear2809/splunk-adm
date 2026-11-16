import { useId, useState } from "react";
import type { Graph } from "../graph";
import {
  captureComparison,
  readableHandoff,
  reviseNotes,
  serializeInvestigation,
  type PortableInvestigation,
} from "./portable";

export function InvestigationHandoff({
  comparison,
}: {
  comparison: { baseline: Graph; incident: Graph; recovery?: Graph };
}) {
  const fieldId = useId();
  const [draft, setDraft] = useState<PortableInvestigation>();
  const [notes, setNotes] = useState("");
  const [hypotheses, setHypotheses] = useState("");
  const [questions, setQuestions] = useState("");
  const [includeEvidence, setIncludeEvidence] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const record = () => {
    try {
      const base = draft ?? captureComparison(comparison, crypto.randomUUID());
      setDraft(reviseNotes(base, { notes, hypotheses, questions }));
      setError("");
      setStatus(
        "Revision recorded in this open investigation. Download a handoff to keep it.",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Capture failed.");
    }
  };
  const download = () => {
    if (!draft) return;
    let url: string | undefined;
    try {
      // Record current edits before exporting so the handoff cannot silently omit them.
      const latest = draft.revisions.at(-1);
      const next =
        latest?.notes === notes &&
        latest.hypotheses === hypotheses &&
        latest.questions === questions
          ? draft
          : reviseNotes(draft, { notes, hypotheses, questions });
      const content = includeEvidence
        ? serializeInvestigation(next)
        : readableHandoff(next);
      url = URL.createObjectURL(
        new Blob([content], {
          type: includeEvidence ? "application/json" : "text/plain",
        }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `atlas-investigation-${next.id}.${includeEvidence ? "json" : "txt"}`;
      link.click();
      setDraft(next);
      setError("");
      setStatus(
        "Download requested. This investigation has not been saved to a shared case store.",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Download failed.");
    } finally {
      if (url) {
        const objectURL = url;
        setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
      }
    }
  };
  return (
    <section aria-label="Investigation handoff">
      <h3>Investigation handoff</h3>
      <p>
        Record notes with a fixed copy of this comparison. Closing this
        investigation loses the open record; download it to keep it.
      </p>
      {draft && (
        <p>
          {draft.captures.length} captured windows · {draft.revisions.length}{" "}
          {draft.revisions.length === 1 ? "note revision" : "note revisions"} ·
          captured {draft.createdAt}. Later comparisons do not replace these
          captures.
        </p>
      )}
      <div>
        <label htmlFor={`${fieldId}-notes`}>Notes</label>
        <textarea
          id={`${fieldId}-notes`}
          value={notes}
          maxLength={20000}
          onChange={(event) => setNotes(event.target.value)}
        />
      </div>
      <div>
        <label htmlFor={`${fieldId}-hypotheses`}>Hypotheses</label>
        <textarea
          id={`${fieldId}-hypotheses`}
          value={hypotheses}
          maxLength={20000}
          onChange={(event) => setHypotheses(event.target.value)}
        />
      </div>
      <div>
        <label htmlFor={`${fieldId}-questions`}>Unresolved questions</label>
        <textarea
          id={`${fieldId}-questions`}
          value={questions}
          maxLength={20000}
          onChange={(event) => setQuestions(event.target.value)}
        />
      </div>
      <button type="button" className="secondary-button" onClick={record}>
        Record revision
      </button>
      <label>
        <input
          type="checkbox"
          checked={includeEvidence}
          onChange={(event) => setIncludeEvidence(event.target.checked)}
        />{" "}
        Include full captured graph evidence as JSON. It may contain sensitive
        addresses, identities and supplemental source fields; review recipient
        access before sharing.
      </label>
      <button
        type="button"
        className="secondary-button"
        onClick={download}
        disabled={!draft}
      >
        Download {includeEvidence ? "evidence package" : "readable handoff"}
      </button>
      {error && <p role="alert">{error}</p>}
      {status && <p role="status">{status}</p>}
    </section>
  );
}
