import { useEffect, useMemo, useRef, useState } from "react";
import { Download, RefreshCw, X } from "lucide-react";
import type { SearchClient } from "../data/searchClient";
import { downloadBlob } from "../download";
import { traceURL } from "../pages/ExploreTools";
import {
  AssertionClient,
  storeMessage,
  type AssertionsDocument,
} from "./assertionClient";
import {
  BASIS_LABEL,
  canonicalIp,
  describeAssertion,
  isScope,
  KIND_LABEL,
  MAX_ASSERTIONS,
  MAX_RUN_ASSERTIONS,
  tally,
  validateAssertion,
  windowErrors,
  windowsAround,
  type Assertion,
  type AssertionKind,
  type ChangeWindows,
  type Status,
  type TimeWindow,
  type Transport,
} from "./model";
import { runVerification, type VerificationRun } from "./searches";
import { CHANGE_NUMBER, lookupChange, type ChangeRecord } from "./serviceNow";
import {
  iso,
  span,
  verificationCsv,
  verificationJson,
  verificationMarkdown,
  windowText,
  type LinkFor,
} from "./exports";
import "./changeVerification.css";

export interface AssertionCandidate {
  name: string;
  src: string;
  dst: string;
  transport: Transport;
  port: number;
}

export const MAX_CANDIDATE_DRAFTS = 5;
const SPANS = [
  [900, "15 min"],
  [3600, "1 hour"],
  [4 * 3600, "4 hours"],
] as const;
const STATUS_CLASS: Record<Status, string> = {
  pass: "pass",
  fail: "fail",
  unknown: "unknown",
};

const token = () =>
  `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
/** datetime-local value read as UTC. */
const fromInput = (value: string) =>
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)
    ? Date.parse(`${value}:00Z`) / 1000
    : NaN;
const toInput = (seconds: number) => iso(seconds).slice(0, 16);

export const linkFor: LinkFor = (r, w: TimeWindow) =>
  traceURL(
    r.assertion.src,
    r.assertion.dst,
    new URLSearchParams([
      ["earliest", String(Math.floor(w.start))],
      ["latest", String(Math.floor(w.end))],
    ]),
    r.assertion.scope,
  );

/** Drafts from Impact rows; only exact IP pairs with a tcp/udp/sctp port qualify. */
export function candidateDrafts(
  candidates: AssertionCandidate[],
  scope: string,
): Assertion[] {
  const out: Assertion[] = [];
  const seen = new Set<string>();
  for (const c of candidates) {
    if (out.length >= MAX_CANDIDATE_DRAFTS) break;
    const k = `${c.src}|${c.dst}|${c.transport}|${c.port}`;
    if (seen.has(k)) continue;
    seen.add(k);
    try {
      out.push(
        validateAssertion({
          id: `draft-${token()}`,
          name: c.name.slice(0, 80),
          kind: "reaches",
          scope,
          src: c.src,
          dst: c.dst,
          transport: c.transport,
          port: c.port,
        }),
      );
    } catch {
      // Rows without canonical addresses or a mapped scope are skipped.
    }
  }
  return out;
}

function StatusBadge({
  status,
  inferred,
}: {
  status: Status;
  inferred?: boolean;
}) {
  return (
    <span className={`atlas-verify-status ${STATUS_CLASS[status]}`}>
      {status}
      {inferred ? " · inferred" : ""}
    </span>
  );
}

function NewAssertion({
  scope,
  onAdd,
}: {
  scope: string;
  onAdd: (a: Assertion) => void;
}) {
  const [kind, setKind] = useState<AssertionKind>("reaches");
  const [name, setName] = useState("");
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [transport, setTransport] = useState<Transport>("tcp");
  const [port, setPort] = useState("");
  const [min, setMin] = useState("2");
  const [error, setError] = useState<string>();
  return (
    <form
      className="atlas-verify-new"
      aria-label="New assertion"
      onSubmit={(e) => {
        e.preventDefault();
        try {
          const a = validateAssertion({
            id: `draft-${token()}`,
            name: name.trim() || `${src.trim()} → ${dst.trim()}`,
            kind,
            scope,
            src: canonicalIp(src) ?? src.trim(),
            dst: canonicalIp(dst) ?? dst.trim(),
            ...(kind === "no_new_blocked"
              ? {}
              : {
                  transport,
                  port: /^\d{1,5}$/.test(port) ? Number(port) : NaN,
                }),
            ...(kind === "redundant" ? { minObservers: Number(min) } : {}),
          });
          onAdd(a);
          setError(undefined);
          setName("");
        } catch (err) {
          setError(err instanceof Error ? err.message : "Invalid assertion.");
        }
      }}
    >
      <select
        aria-label="Assertion kind"
        className="atlas-input"
        value={kind}
        onChange={(e) => setKind(e.target.value as AssertionKind)}
      >
        {(Object.keys(KIND_LABEL) as AssertionKind[]).map((k) => (
          <option key={k} value={k}>
            {KIND_LABEL[k]}
          </option>
        ))}
      </select>
      <input
        aria-label="Source IP"
        className="atlas-input"
        placeholder="Source IP"
        spellCheck={false}
        value={src}
        onChange={(e) => setSrc(e.target.value)}
      />
      <input
        aria-label="Destination IP"
        className="atlas-input"
        placeholder="Destination IP"
        spellCheck={false}
        value={dst}
        onChange={(e) => setDst(e.target.value)}
      />
      {kind !== "no_new_blocked" && (
        <>
          <select
            aria-label="Transport"
            className="atlas-input"
            value={transport}
            onChange={(e) => setTransport(e.target.value as Transport)}
          >
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="sctp">sctp</option>
          </select>
          <input
            aria-label="Port"
            className="atlas-input atlas-verify-port"
            placeholder="Port"
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </>
      )}
      {kind === "redundant" && (
        <label>
          Min observers
          <input
            className="atlas-input atlas-verify-port"
            type="number"
            min={2}
            max={8}
            value={min}
            onChange={(e) => setMin(e.target.value)}
          />
        </label>
      )}
      <input
        aria-label="Assertion name"
        className="atlas-input"
        placeholder="Name (optional)"
        maxLength={80}
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <button type="submit" className="secondary-button">
        Add draft
      </button>
      {error && (
        <span role="alert" className="atlas-verify-error">
          {error}
        </span>
      )}
    </form>
  );
}

type Run =
  | { status: "idle" }
  | { status: "running"; done: number; total: number }
  | { status: "error"; error: string }
  | { status: "done"; run: VerificationRun };

export function ChangeVerification({
  client,
  live,
  scope: pageScope,
  editableScope = false,
  candidates = [],
  open,
  onToggle,
  store,
}: {
  client?: SearchClient;
  live: boolean;
  scope: string;
  editableScope?: boolean;
  candidates?: AssertionCandidate[];
  open: boolean;
  onToggle: (open: boolean) => void;
  store?: AssertionClient;
}) {
  const api = useMemo(() => store ?? new AssertionClient(), [store]);
  const [scopeText, setScopeText] = useState(pageScope);
  const scope = editableScope ? scopeText : pageScope;
  const [doc, setDoc] = useState<AssertionsDocument>();
  const [storeNote, setStoreNote] = useState<string>();
  const [drafts, setDrafts] = useState<Assertion[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [spanSeconds, setSpanSeconds] = useState(3600);
  const [change, setChange] = useState<ChangeRecord>();
  const [number, setNumber] = useState("");
  const [lookup, setLookup] = useState<{ busy?: boolean; error?: string }>({});
  const [run, setRun] = useState<Run>({ status: "idle" });
  const abort = useRef<AbortController>();

  useEffect(() => {
    if (!open || !live || doc) return;
    const controller = new AbortController();
    api
      .load(controller.signal)
      .then((loaded) => !controller.signal.aborted && setDoc(loaded))
      .catch(
        (e: unknown) =>
          !controller.signal.aborted &&
          setStoreNote(`Saved assertions unavailable: ${storeMessage(e)}`),
      );
    return () => controller.abort();
  }, [open, live, doc, api]);
  useEffect(() => () => abort.current?.abort(), []);

  const saved = doc?.assertions ?? [];
  const all = [...saved, ...drafts];
  const chosen = all.filter((a) => selected.includes(a.id));
  const startAt = fromInput(start);
  const endAt = fromInput(end);
  const windows: ChangeWindows | undefined =
    Number.isFinite(startAt) && Number.isFinite(endAt)
      ? {
          ...windowsAround(startAt, endAt, spanSeconds),
          basis: change ? change.basis : "manual",
          ...(change
            ? {
                change: {
                  number: change.number,
                  sysId: change.sysId,
                  ...(change.state ? { state: change.state } : {}),
                },
              }
            : {}),
        }
      : undefined;
  const windowProblem = windows
    ? windowErrors(windows)[0]
    : "Enter the change start and end (UTC).";
  const toggle = (id: string) =>
    setSelected((s) =>
      s.includes(id)
        ? s.filter((x) => x !== id)
        : s.length < MAX_RUN_ASSERTIONS
          ? [...s, id]
          : s,
    );
  const addDrafts = (rows: Assertion[]) => {
    const room = MAX_ASSERTIONS - all.length;
    const added = rows.slice(0, Math.max(0, room));
    setDrafts((d) => [...d, ...added]);
    setSelected((s) =>
      [...s, ...added.map((a) => a.id)].slice(0, MAX_RUN_ASSERTIONS),
    );
  };
  const persist = async (next: Assertion[], label: string) => {
    setStoreNote(`${label}…`);
    try {
      const result = await api.save(next, doc?.revision ?? null, token());
      setDoc(result);
      return result;
    } catch (e) {
      setStoreNote(`${label} did not complete. ${storeMessage(e)}`);
      return undefined;
    }
  };
  const saveDrafts = async () => {
    const result = await persist(
      [
        ...saved,
        ...drafts.map(({ id, ...rest }) => ({
          ...rest,
          id: id.replace(/^draft-/, "a-"),
        })),
      ],
      "Saving",
    );
    if (!result) return;
    const names = new Set(drafts.map((d) => d.name));
    const kept = result.assertions
      .filter((a) => names.has(a.name))
      .map((a) => a.id);
    setDrafts([]);
    setSelected((s) =>
      [...s.filter((id) => !id.startsWith("draft-")), ...kept].slice(
        0,
        MAX_RUN_ASSERTIONS,
      ),
    );
    setStoreNote(
      `Saved ${drafts.length} shared assertion${drafts.length === 1 ? "" : "s"}.`,
    );
  };
  const remove = async (a: Assertion) => {
    if (a.id.startsWith("draft-")) {
      setDrafts((d) => d.filter((x) => x.id !== a.id));
    } else {
      const result = await persist(
        saved.filter((x) => x.id !== a.id),
        "Removing",
      );
      if (result) setStoreNote(`Removed ${a.name}.`);
    }
    setSelected((s) => s.filter((x) => x !== a.id));
  };
  const runLookup = async () => {
    if (!client || !CHANGE_NUMBER.test(number)) return;
    setLookup({ busy: true });
    try {
      const record = await lookupChange(
        client,
        number,
        new AbortController().signal,
      );
      setChange(record);
      setStart(toInput(record.start));
      setEnd(toInput(record.end));
      setLookup({});
    } catch (e) {
      setChange(undefined);
      setLookup({
        error: e instanceof Error ? e.message : "ServiceNow lookup failed.",
      });
    }
  };
  const verify = async () => {
    if (!client || !windows || windowProblem || !chosen.length) return;
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setRun({ status: "running", done: 0, total: chosen.length });
    try {
      const result = await runVerification(
        client,
        chosen,
        windows,
        controller.signal,
        Date.now() / 1000,
        (done, total) =>
          !controller.signal.aborted &&
          setRun({ status: "running", done, total }),
      );
      if (!controller.signal.aborted) setRun({ status: "done", run: result });
    } catch (e) {
      if (!controller.signal.aborted)
        setRun({
          status: "error",
          error: e instanceof Error ? e.message : "Verification failed.",
        });
    }
  };
  const done = run.status === "done" ? run.run : undefined;
  const counts = done
    ? tally(done.results.map((r) => r.verdict.status))
    : undefined;
  const file = `atlas-change-verification${done?.windows.change ? `-${done.windows.change.number}` : ""}`;

  return (
    <details
      id="atlas-verify-change"
      className="atlas-verify"
      open={open}
      onToggle={(e) => onToggle((e.currentTarget as HTMLDetailsElement).open)}
    >
      <summary>
        <h2>Verify change</h2>
        <span className="muted small">
          Saved dependency assertions over a before and after window
        </span>
      </summary>
      {open && (
        <div className="atlas-verify-body">
          <p className="muted small">
            Results are pass, fail or unknown. Unknown whenever coverage,
            observers or search results are incomplete; nothing passes on
            missing evidence. Evaluation reads the scoped Trace observations as
            you, with your index permissions.
          </p>
          {!live && (
            <p className="callout" role="status">
              Verification runs against live Splunk data only. Drafts and
              windows can be prepared here; the demo has no searches to run.
            </p>
          )}
          {editableScope && (
            <label className="atlas-verify-scope">
              Routing scope
              <input
                className="atlas-input"
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                autoComplete="off"
              />
            </label>
          )}
          {!isScope(scope) && (
            <p role="status">
              Enter a mapped routing scope to create assertions.
            </p>
          )}

          <section aria-label="Assertions" className="atlas-verify-step">
            <h3>1 · Assertions</h3>
            {all.length ? (
              <ul className="atlas-verify-list">
                {all.map((a) => (
                  <li key={a.id}>
                    <label>
                      <input
                        type="checkbox"
                        checked={selected.includes(a.id)}
                        onChange={() => toggle(a.id)}
                      />
                      <b>{a.name}</b>{" "}
                      <span className="muted small">
                        {describeAssertion(a)} · {a.scope}
                        {a.id.startsWith("draft-")
                          ? " · draft (not saved)"
                          : a.owner
                            ? ` · ${a.owner}`
                            : ""}
                      </span>
                    </label>
                    <button
                      type="button"
                      className="atlas-verify-remove"
                      aria-label={`Remove ${a.name}`}
                      onClick={() => void remove(a)}
                    >
                      <X size={12} aria-hidden />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted small">No assertions yet.</p>
            )}
            <p className="atlas-verify-actions">
              {candidates.length > 0 && (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={!isScope(scope)}
                  onClick={() => addDrafts(candidateDrafts(candidates, scope))}
                >
                  From impact selection (
                  {Math.min(candidates.length, MAX_CANDIDATE_DRAFTS)})
                </button>
              )}
              {live && drafts.length > 0 && (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void saveDrafts()}
                >
                  Save drafts as shared
                </button>
              )}
              <span className="muted small">
                {selected.length}/{MAX_RUN_ASSERTIONS} selected
                {storeNote ? ` · ${storeNote}` : ""}
              </span>
            </p>
            {isScope(scope) && (
              <NewAssertion scope={scope} onAdd={(a) => addDrafts([a])} />
            )}
          </section>

          <section aria-label="Change window" className="atlas-verify-step">
            <h3>2 · Change window</h3>
            <div className="atlas-verify-window">
              {live && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runLookup();
                  }}
                >
                  <input
                    aria-label="ServiceNow change number"
                    className="atlas-input"
                    placeholder="CHG0030001"
                    spellCheck={false}
                    value={number}
                    onChange={(e) => setNumber(e.target.value.trim())}
                  />
                  <button
                    type="submit"
                    className="secondary-button"
                    disabled={
                      !client || !CHANGE_NUMBER.test(number) || lookup.busy
                    }
                  >
                    Look up
                  </button>
                </form>
              )}
              <label>
                Start (UTC)
                <input
                  type="datetime-local"
                  className="atlas-input"
                  value={start}
                  onChange={(e) => {
                    setStart(e.target.value);
                    setChange(undefined);
                  }}
                />
              </label>
              <label>
                End (UTC)
                <input
                  type="datetime-local"
                  className="atlas-input"
                  value={end}
                  onChange={(e) => {
                    setEnd(e.target.value);
                    setChange(undefined);
                  }}
                />
              </label>
              <label>
                Compare
                <select
                  className="atlas-input"
                  value={spanSeconds}
                  onChange={(e) => setSpanSeconds(Number(e.target.value))}
                >
                  {SPANS.map(([s, text]) => (
                    <option key={s} value={s}>
                      {text} each side
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {lookup.error && (
              <p role="alert" className="atlas-verify-error">
                {lookup.error}
              </p>
            )}
            {windows && !windowProblem ? (
              <p className="muted small">
                {BASIS_LABEL[windows.basis]}
                {change
                  ? ` · ${change.number}${change.state ? ` (${change.state})` : ""}`
                  : ""}{" "}
                · before {span(windows.before)} · after {span(windows.after)}
              </p>
            ) : (
              <p className="muted small">{windowProblem}</p>
            )}
          </section>

          <section aria-label="Results" className="atlas-verify-step">
            <h3>3 · Run</h3>
            <p className="atlas-verify-actions">
              <button
                type="button"
                className="atlas-button"
                disabled={
                  !live ||
                  !client ||
                  !!windowProblem ||
                  !chosen.length ||
                  run.status === "running"
                }
                onClick={() => void verify()}
              >
                Run verification
              </button>
              {run.status === "running" && (
                <span className="muted small" role="status">
                  <RefreshCw size={13} className="spin" aria-hidden />{" "}
                  {run.done} of {run.total}
                </span>
              )}
              {run.status === "error" && (
                <span role="alert" className="atlas-verify-error">
                  {run.error}
                </span>
              )}
            </p>
            {done && counts && (
              <>
                <p className="atlas-verify-headline" aria-live="polite">
                  <StatusBadge status="pass" /> {counts.pass}{" "}
                  <StatusBadge status="fail" /> {counts.fail}{" "}
                  <StatusBadge status="unknown" /> {counts.unknown}
                  <span className="muted small">
                    {" "}
                    · {BASIS_LABEL[done.windows.basis]}
                  </span>
                </p>
                <table className="atlas-verify-table">
                  <thead>
                    <tr>
                      <th>Result</th>
                      <th>Assertion</th>
                      <th>Why</th>
                      <th>Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {done.results.map((r) => (
                      <tr key={r.assertion.id}>
                        <td>
                          <StatusBadge
                            status={r.verdict.status}
                            inferred={r.verdict.basis === "inferred"}
                          />
                        </td>
                        <td>
                          <b>{r.assertion.name}</b>
                          <div className="muted small">
                            {describeAssertion(r.assertion)}
                          </div>
                        </td>
                        <td>
                          {r.verdict.reason}
                          <div
                            className="muted small"
                            title={windowText(r.verdict.before)}
                          >
                            Before: {windowText(r.verdict.before)}
                          </div>
                        </td>
                        <td className="atlas-verify-links">
                          <a href={linkFor(r, r.before.window)}>Before</a>
                          <a href={linkFor(r, r.after.window)}>After</a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="atlas-impact-foot muted small">
                  {(
                    [
                      ["JSON", "json", "application/json", verificationJson],
                      ["CSV", "csv", "text/csv;charset=utf-8", verificationCsv],
                      [
                        "Markdown",
                        "md",
                        "text/markdown;charset=utf-8",
                        verificationMarkdown,
                      ],
                    ] as const
                  ).map(([label, ext, type, render]) => (
                    <button
                      key={ext}
                      type="button"
                      className="secondary-button"
                      onClick={() =>
                        downloadBlob(
                          `${file}.${ext}`,
                          type,
                          render(done, linkFor),
                        )
                      }
                    >
                      <Download size={13} aria-hidden /> {label}
                    </button>
                  ))}
                  <span>
                    Draft export · observed vs inferred labelled · links open
                    Trace for each window
                  </span>
                </p>
              </>
            )}
          </section>
        </div>
      )}
    </details>
  );
}
