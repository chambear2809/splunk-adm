import { useEffect, useRef, useState, type ReactNode } from "react";
import type { EvidenceConfigClient } from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import type { SupplementalResult } from "../data/supplementalEvidence";

export function timestamp(value: number): string {
  return new Date(value * 1000).toISOString();
}

export function socketText(value?: { ip?: string; port?: number }): string {
  if (!value?.ip) return "—";
  const ip = value.ip.includes(":") ? `[${value.ip}]` : value.ip;
  return value.port === undefined
    ? `${ip} (port not reported)`
    : `${ip}:${value.port}`;
}

/**
 * Explicit, cancellable on-demand search. The result resets whenever the
 * selection, client or configuration client changes; nothing runs on render.
 */
export function OnDemandEvidencePanel<T>({
  label,
  noun,
  resetKey,
  client,
  configurationClient,
  load,
  summary,
  children,
}: {
  label: string;
  noun: string;
  resetKey: string;
  client: SearchClient;
  configurationClient: EvidenceConfigClient;
  load: (signal: AbortSignal) => Promise<SupplementalResult<T>>;
  summary: (result: SupplementalResult<T>) => string;
  children: (result: SupplementalResult<T>) => ReactNode;
}) {
  const [result, setResult] = useState<SupplementalResult<T>>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const generation = useRef(0);
  const active = useRef<AbortController>();

  useEffect(() => {
    generation.current++;
    active.current?.abort();
    setResult(undefined);
    setError(undefined);
    setBusy(false);
    return () => {
      active.current?.abort();
    };
  }, [resetKey, client, configurationClient]);

  const run = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await load(controller.signal);
      if (current === generation.current && !controller.signal.aborted)
        setResult(next);
    } catch {
      if (current === generation.current)
        setError(
          controller.signal.aborted
            ? "Cancelled. Native cleanup may remain pending."
            : `${label} evidence unavailable. Refresh the selection or check the source mapping and permissions.`,
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };

  return (
    <section
      className="dns-evidence inspector-body ecosystem-evidence"
      aria-label={`Optional ${label} evidence`}
    >
      <h3>{label}</h3>
      <button type="button" onClick={() => void run()} disabled={busy}>
        {result ? `Refresh ${noun} evidence` : `Inspect ${noun} evidence`}
      </button>{" "}
      {busy && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel search
        </button>
      )}
      <p role="status">
        {busy
          ? "Loading optional evidence…"
          : (error ??
            (result
              ? result.state === "complete"
                ? summary(result)
                : "Source state: " + result.state + "."
              : `${label} stays off unless an administrator activates a schema-qualified source. Not live-validated.`))}
      </p>
      {result && children(result)}
    </section>
  );
}

/** Qualification, caps, rejection and capture metadata common to every result. */
export function ResultHeader<T>({
  result,
  rejectedHint,
}: {
  result: SupplementalResult<T>;
  rejectedHint: string;
}) {
  return (
    <>
      {result.configurationChanged && (
        <p role="alert">
          Configuration changed or became unreadable after capture; refresh
          before using this result.
        </p>
      )}
      {!result.schemaQualified && (
        <p role="alert">
          The producer schema is not qualified on this deployment. Records are
          context only and are not attributed to a workload.
        </p>
      )}
      {result.state === "complete" && (
        <p>
          Input cap: {result.inputCapped ? "reached" : "not reached"}. Display
          cap: {result.outputCapped ? "reached" : "not reached"}. Rejected rows:{" "}
          {result.rejected}. Oversized rows: {result.oversized}.
          {result.rejected > 0 && " " + rejectedHint}
        </p>
      )}
      <p>
        Captured {timestamp(result.capturedAt)}; inspected{" "}
        {timestamp(result.inspectedWindow.start)} –{" "}
        {timestamp(result.inspectedWindow.end)}. Configuration{" "}
        {result.configurationFingerprint.slice(0, 12)}.
      </p>
    </>
  );
}

export function CoverageList({ items }: { items: readonly string[] }) {
  return (
    <ul>
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}
