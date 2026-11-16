import { useEffect, useId, useRef, useState } from "react";
import { caseHandoff } from "./caseHandoff";
import {
  CaseEvidence,
  ComparisonSummary,
  isComparisonReference,
} from "./CaseEvidence";
import {
  CaseError,
  type CaseClient,
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
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<CaseRecord>();
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>();
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");
  const [entryType, setEntryType] = useState<CaseEntry["type"]>("note");
  const [member, setMember] = useState("");
  const [captureConsent, setCaptureConsent] = useState(false);
  const [exportConsent, setExportConsent] = useState(false);
  const [captureLabel, setCaptureLabel] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [listed, setListed] = useState(false);
  const listButton = useRef<HTMLButtonElement>(null);
  const caseHeading = useRef<HTMLHeadingElement>(null);
  const noteInput = useRef<HTMLTextAreaElement>(null);
  const retryButton = useRef<HTMLButtonElement>(null);
  const [pending, setPending] = useState<{
    operation: CaseMutation<CaseRecord | CaseReceipt>;
    submittedNote?: string;
  }>();
  const active = useRef<AbortController>();
  const serial = useRef(0);
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
    setExportConsent(false);
  }, [
    selected?.id,
    selected?.revision,
    selectedCaptureId,
    comparisonReference,
  ]);

  function reportError(reason: unknown, fallback: string) {
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
        requestAnimationFrame(() => caseHeading.current?.focus());
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
  ) {
    const current = ++serial.current;
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
          selected?.id === value.id &&
          previous &&
          value.capture_ids?.includes(previous) &&
          value.captures.some((capture) => capture.id === previous)
            ? previous
            : value.captures.find((capture) =>
                value.capture_ids?.includes(capture.id),
              )?.id,
        );
        setCases((previous) => [
          value,
          ...previous.filter((item) => item.id !== value.id),
        ]);
      }
      if (submittedNote !== undefined)
        setNote((previous) => (previous === submittedNote ? "" : previous));
      setStatus("Shared case saved.");
      requestAnimationFrame(() =>
        submittedNote === undefined
          ? caseHeading.current?.focus()
          : noteInput.current?.focus(),
      );
    } catch (reason) {
      if (current !== serial.current) return;
      if (reason instanceof CaseError && reason.uncertain)
        setPending({ operation, submittedNote });
      else setPending(undefined);
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
  return (
    <section
      className="atlas-shared-cases"
      aria-label="Shared investigation cases"
    >
      <h3>Shared cases</h3>
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
              {selected.entries.map((entry) => (
                <li key={entry.id}>
                  <strong>{entry.type}</strong>: {entry.text}{" "}
                  <small>
                    ({entry.author}, {entry.created_at})
                  </small>
                </li>
              ))}
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
                busy || !!pending || !isComparisonReference(comparisonReference)
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
              !isComparisonReference(comparisonReference)
            }
            onClick={() => {
              if (!isComparisonReference(comparisonReference)) return;
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
            disabled={busy || !!pending}
            onChange={(event) =>
              setEntryType(event.target.value as CaseEntry["type"])
            }
          >
            <option value="note">Note</option>
            <option value="hypothesis">Hypothesis</option>
            <option value="question">Question</option>
          </select>
          <label htmlFor={`${field}-note`}>Add {entryType}</label>
          <textarea
            ref={noteInput}
            id={`${field}-note`}
            maxLength={10000}
            disabled={busy || !!pending}
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
          <button
            type="button"
            disabled={busy || !!pending || !note.trim()}
            onClick={() =>
              void save(
                client.append(selected.id, selected.revision, entryType, note),
                note,
              )
            }
          >
            Save {entryType}
          </button>
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
          onClick={() => void save(pending.operation, pending.submittedNote)}
        >
          Retry same request
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {status && <p role="status">{status}</p>}
    </section>
  );
}
