import { useId, useMemo, useState, type FormEvent } from "react";
import { splunkCaseClient } from "../investigations/caseClient";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";

const DEFAULT_START = "2026-01-01T00:00:00Z";
const DEFAULT_END = "2026-01-01T01:00:00Z";

/** User-entered absolute UTC window; this does not claim captured evidence. */
export function validCasesWindow(start: string, end: string): boolean {
  const parse = (value: string) => {
    const match =
      /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(
        value,
      );
    if (!match || Number(match[1]) < 1) return;
    const [, year, month, day, hour, minute, second, fraction = ""] = match;
    const millis = Number(fraction.padEnd(3, "0"));
    const date = new Date(0);
    date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    date.setUTCHours(Number(hour), Number(minute), Number(second), millis);
    if (
      date.getUTCFullYear() !== Number(year) ||
      date.getUTCMonth() !== Number(month) - 1 ||
      date.getUTCDate() !== Number(day) ||
      date.getUTCHours() !== Number(hour) ||
      date.getUTCMinutes() !== Number(minute) ||
      date.getUTCSeconds() !== Number(second) ||
      date.getUTCMilliseconds() !== millis
    )
      return;
    return date.getTime();
  };
  const from = parse(start);
  const to = parse(end);
  return from !== undefined && to !== undefined && from < to;
}

export function CasesPage() {
  const id = useId();
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [window, setWindow] = useState<{ start: string; end: string }>();
  const [error, setError] = useState("");
  const client = useMemo(() => splunkCaseClient(), []);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!validCasesWindow(start, end)) {
      setWindow(undefined);
      setError(
        "Enter an absolute UTC window, with start before end (for example 2026-01-01T00:00:00Z).",
      );
      return;
    }
    setError("");
    setWindow({ start, end });
  };
  return (
    <main className="atlas-page atlas-page-wide">
      <h1>Shared cases</h1>
      <p>
        Add and share notes for a time window. Notes do not include source
        evidence.
      </p>
      <form
        className="atlas-cases-window"
        onSubmit={submit}
        aria-label="Case window"
      >
        <label htmlFor={`${id}-start`}>Case window start (UTC)</label>
        <input
          id={`${id}-start`}
          value={start}
          disabled={!!window}
          placeholder={DEFAULT_START}
          onChange={(event) => setStart(event.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
        <label htmlFor={`${id}-end`}>Case window end (UTC)</label>
        <input
          id={`${id}-end`}
          value={end}
          disabled={!!window}
          placeholder={DEFAULT_END}
          onChange={(event) => setEnd(event.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
        <button type="submit" disabled={!!window}>
          Open shared cases
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {window && (
        <p role="status">
          This time window stays fixed while the page is open: {window.start} to{" "}
          {window.end}.
        </p>
      )}
      {window && (
        <JourneyLazyEvidence
          kind="cases"
          client={client}
          window={window}
          initiallyOpen
        />
      )}
    </main>
  );
}
