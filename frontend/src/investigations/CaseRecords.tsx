import { entryHistories } from "./entryHistory";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { caseHandoff } from "./caseHandoff";
import {
  CaseEvidence,
  ComparisonSummary,
  isComparisonReference,
} from "./CaseEvidence";
import {
  CaseError,
  type CaseClient,
  type CaseCapabilities,
  type CaseEntry,
  type CaseReceipt,
  type CaseMutation,
  type CaseRecord,
  type CaseWindow,
} from "./caseClient";

/** Optional shared notes workflow; portable graph evidence is never sent here. */
export function CaseRecords({
  client,
  window,
  comparisonReference,
}: {
  client?: CaseClient;
  window: CaseWindow;
  comparisonReference?: string;
}) {
  return (
    <CaseRecordsContents
      key={caseClientKey(client ?? unavailableClient)}
      client={client}
      window={window}
      comparisonReference={comparisonReference}
    />
  );
}

const unavailableClient = {};
let nextInstance = 0;
const instanceKeys = new WeakMap<object, number>();
function caseClientKey(instance: object): number {
  let key = instanceKeys.get(instance);
  if (key === undefined) {
    key = ++nextInstance;
    instanceKeys.set(instance, key);
  }
  return key;
}

function CaseRecordsContents({
  client,
  window,
  comparisonReference,
}: {
  client?: CaseClient;
  window: CaseWindow;
  comparisonReference?: string;
}) {
  const field = useId();
  const [capabilities, setCapabilities] = useState<CaseCapabilities>();
  const [capabilityFailed, setCapabilityFailed] = useState(false);
  const [capabilityAttempt, setCapabilityAttempt] = useState(0);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<CaseRecord>();
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>();
  const [title, setTitle] = useState("");
  const [noteDrafts, setNoteDrafts] = useState<
    Record<string, { type: CaseEntry["type"]; text: string }>
  >({});
  const [editing, setEditing] = useState<{
    caseId: string;
    entry: CaseEntry;
    text: string;
  }>();
  const activeEdit = editing?.caseId === selected?.id ? editing : undefined;
  const draft = selected ? noteDrafts[selected.id] : undefined;
  const entryType = activeEdit?.entry.type ?? draft?.type ?? "note";
  const entryText = activeEdit?.text ?? draft?.text ?? "";
  const editHistory =
    activeEdit && selected
      ? entryHistories(selected.entries)?.find((history) =>
          history.some((entry) => entry.id === activeEdit.entry.id),
        )
      : undefined;
  const latestEditHead = editHistory?.[editHistory.length - 1];
  const editNeedsRebase =
    !!activeEdit && latestEditHead?.id !== activeEdit.entry.id;
  const [member, setMember] = useState("");
  const [captureConsent, setCaptureConsent] = useState(false);
  const [attachmentConsent, setAttachmentConsent] = useState(false);
  const [attachmentEntryId, setAttachmentEntryId] = useState("");
  const [exportConsent, setExportConsent] = useState(false);
  const [captureLabel, setCaptureLabel] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [focusIntent, setFocusIntent] = useState<"heading" | "note">();
  const [listed, setListed] = useState(false);
  const listButton = useRef<HTMLButtonElement>(null);
  const caseHeading = useRef<HTMLHeadingElement>(null);
  const noteInput = useRef<HTMLTextAreaElement>(null);
  const retryButton = useRef<HTMLButtonElement>(null);
  const [pending, setPending] = useState<{
    operation: CaseMutation<CaseRecord | CaseReceipt>;
    submittedNote?: string;
    submittedEditId?: string;
  }>();
  const active = useRef<AbortController>();
  const serial = useRef(0);
  useEffect(() => {
    if (!client) return;
    const controller = new AbortController();
    client
      .capabilities(controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setCapabilities(result);
      })
      .catch(() => {
        if (!controller.signal.aborted) setCapabilityFailed(true);
      });
    return () => controller.abort();
  }, [client, capabilityAttempt]);
  useLayoutEffect(() => {
    if (!focusIntent || busy) return;
    const target =
      focusIntent === "heading" ? caseHeading.current : noteInput.current;
    if (!target) return;
    target.focus();
    setFocusIntent(undefined);
  }, [busy, focusIntent, selected, editing]);
  useEffect(() => {
    if (pending && !busy) retryButton.current?.focus();
  }, [pending, busy]);
  useEffect(
    () => () => {
      serial.current++;
      active.current?.abort();
    },
    [client],
  );

  useEffect(() => {
    setCaptureConsent(false);
    setAttachmentConsent(false);
    setExportConsent(false);
  }, [
    selected?.id,
    selected?.revision,
    selectedCaptureId,
    comparisonReference,
  ]);

  function reportError(reason: unknown, fallback: string) {
    setStatus("");
    if (
      reason instanceof CaseError &&
      [401, 403, 404].includes(reason.status ?? 0)
    ) {
      setSelected(undefined);
      setSelectedCaptureId(undefined);
      setCases([]);
      setNext(null);
    }
    setError(reason instanceof Error ? reason.message : fallback);
  }

  async function load(after?: string) {
    if (!client) return;
    setFocusIntent(undefined);
    if (!after) {
      setSelected(undefined);
      setSelectedCaptureId(undefined);
    }
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++serial.current;
    setBusy(true);
    setError("");
    try {
      const result = await client.list(controller.signal, after);
      if (current !== serial.current) return;
      setCases((previous) =>
        after ? [...previous, ...result.items] : result.items,
      );
      setNext(result.next);
      if (after)
        setSelected((old) =>
          old ? (result.items.find((item) => item.id === old.id) ?? old) : old,
        );
      setListed(true);
      setStatus(
        `${result.items.length} shared ${result.items.length === 1 ? "case" : "cases"} loaded.`,
      );
      requestAnimationFrame(() => listButton.current?.focus());
    } catch (reason) {
      if (current === serial.current && !controller.signal.aborted)
        reportError(reason, "Unable to load cases.");
    } finally {
      if (current === serial.current) setBusy(false);
    }
  }
  async function open(id: string, captureId?: string) {
    if (!client) return;
    setFocusIntent(undefined);
    setSelected(undefined);
    setSelectedCaptureId(undefined);
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++serial.current;
    setBusy(true);
    setError("");
    try {
      const value = await client.get(id, controller.signal, captureId);
      if (current === serial.current) {
        setSelected(value);
        setSelectedCaptureId(
          captureId ??
            value.captures.find((capture) =>
              value.capture_ids?.includes(capture.id),
            )?.id,
        );
        setFocusIntent("heading");
      }
    } catch (reason) {
      if (current === serial.current && !controller.signal.aborted)
        reportError(reason, "Unable to open case.");
    } finally {
      if (current === serial.current) setBusy(false);
    }
  }
  async function save(
    operation: CaseMutation<CaseRecord | CaseReceipt>,
    submittedNote?: string,
    submittedEditId?: string,
  ) {
    if (!capabilities?.available && !pending) return;
    const current = ++serial.current;
    setFocusIntent(undefined);
    setBusy(true);
    setError("");
    setStatus("");
    try {
      const value = await operation.execute();
      if (current !== serial.current) return;
      setPending(undefined);
      if (!("schema_version" in value)) {
        // A revocation receipt confirms the write; a failed refresh must never retry it.
        setSelected(undefined);
        setSelectedCaptureId(undefined);
        setCases((previous) => previous.filter((item) => item.id !== value.id));
        setStatus("Access change saved. Refreshing the case.");
        try {
          const refreshed = await client!.get(value.id);
          if (current !== serial.current) return;
          setSelected(refreshed);
          setCases((previous) => [
            refreshed,
            ...previous.filter((item) => item.id !== refreshed.id),
          ]);
        } catch (reason) {
          if (current !== serial.current) return;
          reportError(
            reason,
            "Access changed, but the case could not be refreshed.",
          );
          setStatus("Access change saved.");
          return;
        }
      } else {
        setSelected(value);
        setSelectedCaptureId((previous) =>
          previous &&
          value.capture_ids?.includes(previous) &&
          value.captures.some((capture) => capture.id === previous)
            ? previous
            : undefined,
        );
        setCases((previous) => [
          value,
          ...previous.filter((item) => item.id !== value.id),
        ]);
      }
      if (submittedNote !== undefined) {
        if (submittedEditId) {
          setEditing((previous) =>
            previous?.entry.id === submittedEditId &&
            previous.text === submittedNote
              ? undefined
              : previous,
          );
        } else {
          setNoteDrafts((previous) => {
            if (previous[value.id]?.text !== submittedNote) return previous;
            return {
              ...previous,
              [value.id]: { ...previous[value.id], text: "" },
            };
          });
        }
      }
      setStatus("Shared case saved.");
      setFocusIntent(submittedNote === undefined ? "heading" : "note");
    } catch (reason) {
      if (current !== serial.current) return;
      if (reason instanceof CaseError && reason.uncertain)
        setPending({
          operation,
          submittedNote,
          submittedEditId,
        });
      else if (
        pending &&
        reason instanceof CaseError &&
        [401, 403, 404].includes(reason.status ?? 0)
      ) {
        setPending(pending);
        reportError(reason, "Unable to save case.");
        setError(
          "The previous write outcome remains unconfirmed. Retry the same request when access is restored.",
        );
        return;
      } else setPending(undefined);
      reportError(reason, "Unable to save case.");
    } finally {
      if (current === serial.current) setBusy(false);
    }
  }
  async function exportCase(id: string, format: "json" | "handoff") {
    if (!client) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++serial.current;
    setBusy(true);
    setError("");
    try {
      const value = await client.export(
        id,
        controller.signal,
        selectedCaptureId,
      );
      if (current !== serial.current) return;
      setSelected(value);
      setCases((previous) =>
        previous.map((item) => (item.id === value.id ? value : item)),
      );
      const content =
        format === "json" ? JSON.stringify(value, null, 2) : caseHandoff(value);
      if (new TextEncoder().encode(content).byteLength > 8 * 1024 * 1024)
        throw new Error("The export exceeds the 8 MiB download limit.");
      const url = URL.createObjectURL(
        new Blob([content], {
          type:
            format === "json"
              ? "application/json"
              : "text/markdown;charset=utf-8",
        }),
      );
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = `atlas-case-${value.id}.${format === "json" ? "json" : "md"}`;
        link.click();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setStatus("Case export requested.");
    } catch (reason) {
      if (current === serial.current && !controller.signal.aborted)
        reportError(reason, "Unable to export case.");
    } finally {
      if (current === serial.current) setBusy(false);
    }
  }
  if (!client)
    return (
      <section aria-label="Shared investigation cases">
        <h3>Shared cases</h3>
        <p>
          Shared case storage is unavailable. Use the portable handoff to keep
          this investigation.
        </p>
      </section>
    );
  if (!capabilities?.available)
    return (
      <section
        className="atlas-shared-cases"
        aria-label="Shared investigation cases"
      >
        <h3>Shared cases</h3>
        <p role="status">
          {!capabilities && !capabilityFailed
            ? "Checking shared case availability…"
            : "Shared case storage is unavailable. Use the portable handoff to keep this investigation."}
        </p>
        {(capabilityFailed || capabilities) && (
          <button
            type="button"
            disabled={busy || !!pending}
            onClick={() => {
              setCapabilities(undefined);
              setCapabilityFailed(false);
              setCapabilityAttempt((n) => n + 1);
            }}
          >
            Retry availability check
          </button>
        )}
        {pending && (
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void save(
                pending.operation,
                pending.submittedNote,
                pending.submittedEditId,
              )
            }
          >
            Retry same request
          </button>
        )}
      </section>
    );
  return (
    <section
      className="atlas-shared-cases"
      aria-label="Shared investigation cases"
    >
      <h3>Shared cases</h3>
      {!capabilities.qualified && (
        <p>
          The case service reports that this runtime has not been independently
          qualified.
        </p>
      )}
      {!capabilities.evidenceWrites && (
        <p>
          Comparison evidence saving is unavailable. Shared notes remain
          available.
        </p>
      )}
      <button
        type="button"
        disabled={busy || !!pending}
        onClick={() => {
          setCapabilities(undefined);
          setCapabilityFailed(false);
          setSelected(undefined);
          setSelectedCaptureId(undefined);
          setCaptureConsent(false);
          setExportConsent(false);
          setCapabilityAttempt((n) => n + 1);
        }}
      >
        Refresh availability
      </button>
      <p>
        Shared cases store notes and the selected time window. You can
        explicitly save a source-rechecked comparison to an open case. Portable
        handoff notes are not copied; add shared entries after creating or
        opening a case.
      </p>
      <p>
        New cases are private to you. Sharing lets a member read the case, add
        entries and export it. Only the owner can change access or delete it.
      </p>
      <button
        ref={listButton}
        type="button"
        className="secondary-button"
        disabled={busy || !!pending}
        onClick={() => void load()}
      >
        List shared cases
      </button>
      {listed && !cases.length && <p>No shared cases found.</p>}
      {cases.length > 0 && (
        <ul>
          {cases.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                disabled={busy || !!pending}
                onClick={() => void open(item.id)}
              >
                {item.title}
              </button>
            </li>
          ))}
        </ul>
      )}
      {next && (
        <button
          type="button"
          disabled={busy || !!pending}
          onClick={() => void load(next)}
        >
          Load more cases
        </button>
      )}
      <div>
        <label htmlFor={`${field}-title`}>New case title</label>
        <input
          id={`${field}-title`}
          maxLength={256}
          disabled={busy || !!pending}
          value={title}
          onChange={(event) => setTitle(event.target.value)}
        />
      </div>
      <button
        type="button"
        disabled={busy || !!pending || !title.trim()}
        onClick={() => void save(client.create(title.trim(), window))}
      >
        Create shared case
      </button>
      {editing && editing.caseId !== selected?.id && (
        <div role="status">
          <p>
            An unsaved edit from another case is retained. Return to that case
            to continue, or discard the edit to work on another entry.
          </p>
          <button
            type="button"
            disabled={busy || !!pending}
            onClick={() => setEditing(undefined)}
          >
            Discard retained edit
          </button>
        </div>
      )}
      {selected && (
        <div>
          <h4 ref={caseHeading} tabIndex={-1}>
            {selected.title}
          </h4>
          <p>
            Revision {selected.revision} · {selected.window.start} to{" "}
            {selected.window.end}
          </p>
          {selected.entries.length > 0 && (
            <ul>
              {(entryHistories(selected.entries) ?? []).map((history) => {
                const entry = history[history.length - 1];
                return (
                  <li key={history[0].id}>
                    <strong>{entry.type}</strong>: {entry.text}{" "}
                    <small>
                      ({entry.author}, {entry.created_at}
                      {history.length > 1
                        ? ` · Edited · version ${history.length}`
                        : ""}
                      )
                    </small>{" "}
                    <button
                      type="button"
                      disabled={busy || !!pending || !!editing}
                      onClick={() => {
                        setEditing({
                          caseId: selected.id,
                          entry,
                          text: entry.text,
                        });
                        requestAnimationFrame(() => noteInput.current?.focus());
                      }}
                    >
                      Edit {entry.type}
                    </button>
                    {selected.attachments
                      .filter(
                        (attachment) =>
                          attachment.kind === "capture_reference" &&
                          attachment.entry_id === entry.id,
                      )
                      .map((attachment) => (
                        <p key={attachment.id}>
                          <button
                            type="button"
                            disabled={busy || !!pending}
                            onClick={() =>
                              void open(
                                selected.id,
                                String(attachment.capture_id),
                              )
                            }
                          >
                            View attached evidence
                          </button>
                        </p>
                      ))}
                    {history.length > 1 && (
                      <details>
                        <summary>History ({history.length} versions)</summary>
                        <ol>
                          {history.map((version, index) => (
                            <li key={version.id}>
                              Version {index + 1} · {version.author} ·{" "}
                              {version.created_at}: {version.text}
                              {version.id !== entry.id &&
                                selected.attachments
                                  .filter(
                                    (attachment) =>
                                      attachment.kind === "capture_reference" &&
                                      attachment.entry_id === version.id,
                                  )
                                  .map((attachment) => (
                                    <button
                                      key={attachment.id}
                                      type="button"
                                      disabled={busy || !!pending}
                                      onClick={() =>
                                        void open(
                                          selected.id,
                                          String(attachment.capture_id),
                                        )
                                      }
                                    >
                                      View attached evidence
                                    </button>
                                  ))}
                            </li>
                          ))}
                        </ol>
                      </details>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
          {selected.capture_ids && selected.capture_ids.length > 0 && (
            <section aria-label="Capture selection">
              <h5 style={{ fontSize: "1rem" }}>Recheck saved captures</h5>
              <p>
                Each recheck and export requests one capture. Other captures are
                withheld from that response, not deleted.
              </p>
              <p>
                {selectedCaptureId &&
                selected.capture_ids.includes(selectedCaptureId)
                  ? `Selected capture: ${selected.capture_ids.indexOf(selectedCaptureId) + 1} of ${selected.capture_ids.length}`
                  : "No capture selected."}
              </p>
              {selected.capture_ids.map((captureId, index) => (
                <button
                  type="button"
                  key={captureId}
                  disabled={busy || !!pending}
                  aria-pressed={selectedCaptureId === captureId}
                  onClick={() => void open(selected.id, captureId)}
                >
                  Recheck capture {index + 1} of {selected.capture_ids!.length}
                </button>
              ))}
            </section>
          )}
          <CaseEvidence record={selected} />
          {selected.entries.length > 0 && (
            <section aria-label="Attach saved comparison evidence">
              <h5 style={{ fontSize: "1rem" }}>
                Attach saved comparison evidence
              </h5>
              <p>
                Choose an entry and an authorized saved capture. Attachments do
                not grant source access.
              </p>
              <label htmlFor={`${field}-attachment-entry`}>Entry</label>
              <select
                id={`${field}-attachment-entry`}
                value={attachmentEntryId}
                disabled={busy || !!pending}
                onChange={(event) => {
                  setAttachmentEntryId(event.target.value);
                  setAttachmentConsent(false);
                }}
              >
                <option value="">Choose an entry</option>
                {(entryHistories(selected.entries) ?? []).map((history) => {
                  const entry = history[history.length - 1];
                  return (
                    <option key={entry.id} value={entry.id}>
                      {entry.type}: {entry.text.slice(0, 80)}
                    </option>
                  );
                })}
              </select>
              <label>
                <input
                  type="checkbox"
                  style={{ width: "auto", display: "inline-block" }}
                  checked={attachmentConsent}
                  disabled={busy || !!pending}
                  onChange={(event) =>
                    setAttachmentConsent(event.target.checked)
                  }
                />{" "}
                I understand this links the selected saved capture to the entry.
              </label>
              <button
                type="button"
                disabled={
                  busy ||
                  !!pending ||
                  !attachmentConsent ||
                  !attachmentEntryId ||
                  !(entryHistories(selected.entries) ?? []).some(
                    (history) =>
                      history[history.length - 1].id === attachmentEntryId,
                  ) ||
                  !selectedCaptureId ||
                  !selected.captures.some(
                    (capture) => capture.id === selectedCaptureId,
                  )
                }
                onClick={() => {
                  if (!selectedCaptureId) return;
                  void save(
                    client.attach(
                      selected.id,
                      selected.revision,
                      attachmentEntryId,
                      selectedCaptureId,
                    ),
                  );
                }}
              >
                Attach saved comparison evidence
              </button>
              {!selectedCaptureId ||
              !selected.captures.some(
                (capture) => capture.id === selectedCaptureId,
              ) ? (
                <p>Recheck a saved capture before attaching it.</p>
              ) : null}
            </section>
          )}
          <p>
            Saving a comparison asks the server to recheck the source and fetch
            its evidence; it does not copy the displayed graph. Shared case
            members need their own source access to see it.
          </p>
          {isComparisonReference(comparisonReference) && (
            <ComparisonSummary data={JSON.parse(comparisonReference)} />
          )}
          <label htmlFor={`${field}-capture-label`}>
            Comparison label (optional)
          </label>
          <input
            id={`${field}-capture-label`}
            value={captureLabel}
            maxLength={256}
            disabled={busy || !!pending}
            onChange={(event) => setCaptureLabel(event.target.value)}
          />
          <label>
            <input
              type="checkbox"
              style={{ width: "auto", display: "inline-block" }}
              checked={captureConsent}
              disabled={
                busy ||
                !!pending ||
                !capabilities.evidenceWrites ||
                !isComparisonReference(comparisonReference)
              }
              onChange={(event) => setCaptureConsent(event.target.checked)}
            />{" "}
            I understand this saves source evidence to the shared case.
          </label>
          <button
            type="button"
            disabled={
              busy ||
              !!pending ||
              !captureConsent ||
              !capabilities.evidenceWrites ||
              !isComparisonReference(comparisonReference)
            }
            onClick={() => {
              if (
                !capabilities.evidenceWrites ||
                !isComparisonReference(comparisonReference)
              )
                return;
              void save(
                client.capture(
                  selected.id,
                  selected.revision,
                  comparisonReference,
                  captureLabel.trim() || undefined,
                ),
              );
            }}
          >
            Save comparison to shared case
          </button>
          {!isComparisonReference(comparisonReference) && (
            <p>
              A supported comparison source and absolute windows are required to
              save evidence.
            </p>
          )}
          <label htmlFor={`${field}-type`}>Entry type</label>
          <select
            id={`${field}-type`}
            value={entryType}
            disabled={busy || !!pending || !!activeEdit}
            onChange={(event) => {
              const type = event.target.value as CaseEntry["type"];
              setNoteDrafts((previous) => ({
                ...previous,
                [selected.id]: { type, text: entryText },
              }));
            }}
          >
            <option value="note">Note</option>
            <option value="hypothesis">Hypothesis</option>
            <option value="question">Question</option>
          </select>
          <label htmlFor={`${field}-note`}>
            {activeEdit ? `Edit ${activeEdit.entry.type}` : `Add ${entryType}`}
          </label>
          <textarea
            ref={noteInput}
            id={`${field}-note`}
            maxLength={10000}
            disabled={busy || !!pending}
            value={entryText}
            onChange={(event) => {
              const text = event.target.value;
              if (activeEdit) setEditing({ ...activeEdit, text });
              else
                setNoteDrafts((previous) => ({
                  ...previous,
                  [selected.id]: { type: entryType, text },
                }));
            }}
          />
          <button
            type="button"
            disabled={busy || !!pending || editNeedsRebase || !entryText.trim()}
            onClick={() => {
              void save(
                client.append(
                  selected.id,
                  selected.revision,
                  entryType,
                  entryText,
                  activeEdit?.entry.id,
                ),
                entryText,
                activeEdit?.entry.id,
              );
            }}
          >
            {activeEdit ? "Save revision" : `Save ${entryType}`}
          </button>
          {activeEdit && editNeedsRebase && (
            <p role="status">
              This entry changed. Your draft is preserved.
              {latestEditHead && (
                <button
                  type="button"
                  disabled={busy || !!pending}
                  onClick={() =>
                    setEditing({ ...activeEdit, entry: latestEditHead })
                  }
                >
                  Apply draft to latest version
                </button>
              )}
            </p>
          )}
          {activeEdit && (
            <button
              type="button"
              disabled={busy || !!pending}
              onClick={() => {
                setEditing(undefined);
                requestAnimationFrame(() => noteInput.current?.focus());
              }}
            >
              Cancel editing
            </button>
          )}
          <div>
            <p>
              Only the case owner can change access. Shared case exports can
              contain sensitive information.
            </p>
            <label htmlFor={`${field}-member`}>Member username</label>
            <input
              id={`${field}-member`}
              maxLength={256}
              disabled={busy || !!pending}
              value={member}
              onChange={(event) => setMember(event.target.value)}
            />
            <button
              type="button"
              disabled={busy || !!pending || !member.trim()}
              onClick={() =>
                void save(
                  client.share(
                    selected.id,
                    selected.revision,
                    member.trim(),
                    true,
                  ),
                )
              }
            >
              Share case
            </button>
            <button
              type="button"
              disabled={busy || !!pending || !member.trim()}
              onClick={() =>
                void save(
                  client.share(
                    selected.id,
                    selected.revision,
                    member.trim(),
                    false,
                  ),
                )
              }
            >
              Revoke access
            </button>
            <label>
              <input
                type="checkbox"
                style={{ width: "auto", display: "inline-block" }}
                checked={exportConsent}
                disabled={busy || !!pending}
                onChange={(event) => setExportConsent(event.target.checked)}
              />{" "}
              I understand this export can contain sensitive case evidence.
            </label>
            <button
              type="button"
              disabled={
                busy ||
                !!pending ||
                !exportConsent ||
                (!!selected.capture_ids?.length && !selectedCaptureId)
              }
              onClick={() => void exportCase(selected.id, "json")}
            >
              Export shared case
            </button>
            <button
              type="button"
              disabled={
                busy ||
                !!pending ||
                !exportConsent ||
                (!!selected.capture_ids?.length && !selectedCaptureId)
              }
              onClick={() => void exportCase(selected.id, "handoff")}
            >
              Download readable handoff
            </button>
            <p>
              {selected.capture_ids?.length && !selectedCaptureId
                ? "Select a capture to recheck before exporting. "
                : ""}
              JSON includes permitted source rows. The readable handoff omits
              source rows but can still contain sensitive case details.
            </p>
          </div>
        </div>
      )}
      {pending && (
        <button
          type="button"
          disabled={busy}
          ref={retryButton}
          onClick={() =>
            void save(
              pending.operation,
              pending.submittedNote,
              pending.submittedEditId,
            )
          }
        >
          Retry same request
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {status && <p role="status">{status}</p>}
    </section>
  );
}
