import { useEffect, useId, useRef, useState } from "react";
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
}: {
  client?: CaseClient;
  window: CaseWindow;
}) {
  return (
    <CaseRecordsContents
      key={caseClientKey(client ?? unavailableClient)}
      client={client}
      window={window}
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
}: {
  client?: CaseClient;
  window: CaseWindow;
}) {
  const field = useId();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<CaseRecord>();
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");
  const [entryType, setEntryType] = useState<CaseEntry["type"]>("note");
  const [member, setMember] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [listed, setListed] = useState(false);
  const listButton = useRef<HTMLButtonElement>(null);
  const caseHeading = useRef<HTMLHeadingElement>(null);
  const noteInput = useRef<HTMLTextAreaElement>(null);
  const [pending, setPending] = useState<{
    operation: CaseMutation<CaseRecord | CaseReceipt>;
    submittedNote?: string;
  }>();
  const active = useRef<AbortController>();
  const serial = useRef(0);
  useEffect(
    () => () => {
      serial.current++;
      active.current?.abort();
    },
    [client],
  );

  function reportError(reason: unknown, fallback: string) {
    if (reason instanceof CaseError && reason.status === 403) {
      setSelected(undefined);
      setCases([]);
      setNext(null);
    }
    setError(reason instanceof Error ? reason.message : fallback);
  }

  async function load(after?: string) {
    if (!client) return;
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
  async function open(id: string) {
    if (!client) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++serial.current;
    setBusy(true);
    setError("");
    try {
      const value = await client.get(id, controller.signal);
      if (current === serial.current) {
        setSelected(value);
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
  async function exportCase(id: string) {
    if (!client) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++serial.current;
    setBusy(true);
    setError("");
    try {
      const value = await client.export(id, controller.signal);
      if (current !== serial.current) return;
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(value, null, 2)], {
          type: "application/json",
        }),
      );
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = `atlas-case-${value.id}.json`;
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
        Shared cases store notes and the selected time window. Graph evidence
        remains in the portable handoff. Portable handoff notes are not copied;
        add shared entries after creating or opening a case.
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
            <button
              type="button"
              disabled={busy || !!pending}
              onClick={() => void exportCase(selected.id)}
            >
              Export shared case
            </button>
          </div>
        </div>
      )}
      {pending && (
        <button
          type="button"
          disabled={busy}
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
