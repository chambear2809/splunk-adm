import { useCallback, useEffect, useId, useRef, useState } from "react";
import { BaselineReview } from "./BaselineReview";
import { eligibility, type WatchDefinition } from "./model";
import {
  BaselineWriteError,
  checkedCapture,
  type BaselineMetadata,
  type BaselineReceipt,
  type BaselineRecord,
  type BaselineRepository,
  type CaptureReference,
  type DependencySource,
  type WatchWithVersion,
  type Occurrence,
  type WatchStatus,
} from "./client";
import "./monitor.css";

type Mutation = { requestId: string; run: () => Promise<BaselineReceipt> };
/** The host owns source identity/entitlement. A displayed map never becomes a baseline. */
type Props = {
  window: { start: number; end: number };
  source?: DependencySource;
  repository?: BaselineRepository;
  mapWarnings?: string[];
};
export function DependencyMonitor(props: Props) {
  return <DependencyMonitorContents {...props} />;
}
function DependencyMonitorContents({
  window,
  source,
  repository,
  mapWarnings = [],
}: Props) {
  const field = useId();
  const [current, setCurrent] = useState<CaptureReference>();
  const [items, setItems] = useState<BaselineMetadata[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<BaselineRecord>();
  const [chosen, setChosen] = useState<BaselineMetadata>();
  const [versions, setVersions] = useState<number[]>([]);
  const [versionNext, setVersionNext] = useState<number | null>(null);
  const [watchNext, setWatchNext] = useState<string | null>(null);
  const [occurrences, setOccurrences] = useState<Occurrence[]>([]);
  const [occurrenceNext, setOccurrenceNext] = useState<number | null>(null);
  const [occurrenceWatch, setOccurrenceWatch] = useState("");
  const [watchStatus, setWatchStatus] = useState<{
    signature: string;
    at: number;
    value: WatchStatus;
  }>();
  const clearOccurrences = useCallback(() => {
    setOccurrences([]);
    setOccurrenceNext(null);
    setOccurrenceWatch("");
    setWatchStatus(undefined);
  }, []);
  const [watches, setWatches] = useState<WatchDefinition[]>([]);
  const [name, setName] = useState("");
  const [threshold, setThreshold] = useState("2");
  const [cooldown, setCooldown] = useState("3600");
  const [expectedStart, setExpectedStart] = useState("");
  const [expectedEnd, setExpectedEnd] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Mutation>();
  const generation = useRef(0);
  const active = useRef<AbortController>();
  const mutationInFlight = useRef(false);
  const retryButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (pending && !busy) retryButton.current?.focus();
  }, [pending, busy]);
  useEffect(
    () => () => {
      generation.current++;
      active.current?.abort();
    },
    [],
  );
  const context = JSON.stringify(window);
  const [capturedContext, setCapturedContext] = useState("");
  const capture = capturedContext === context ? current : undefined;
  useEffect(() => {
    if (!mutationInFlight.current) {
      generation.current++;
      active.current?.abort();
      setBusy(false);
    }
    setCurrent(undefined);
    setSelected(undefined);
    setChosen(undefined);
    setVersions([]);
    setWatches([]);
    clearOccurrences();
    setWatchStatus(undefined);
    setItems([]);
    setNext(null);
    setStatus("");
  }, [source, context, repository, clearOccurrences]);
  const read = async (operation: (signal: AbortSignal) => Promise<void>) => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const serial = ++generation.current;
    setBusy(true);
    setError("");
    setStatus("");
    setWatchStatus(undefined);
    try {
      await operation(controller.signal);
    } catch (reason) {
      if (serial === generation.current && !controller.signal.aborted) {
        setCurrent(undefined);
        setSelected(undefined);
        setChosen(undefined);
        setVersions([]);
        clearOccurrences();
        setWatchStatus(undefined);
        setWatches([]);
        setItems([]);
        setNext(null);
        setError(
          reason instanceof Error
            ? reason.message
            : "Dependency evidence is unavailable.",
        );
      }
    } finally {
      if (serial === generation.current) setBusy(false);
    }
  };
  const mutate = async (operation: Mutation) => {
    active.current?.abort();
    mutationInFlight.current = true;
    const serial = ++generation.current;
    setBusy(true);
    setStatus("");
    setPending(operation);
    setError("");
    try {
      const metadata = await operation.run();
      if (serial !== generation.current) return;
      setPending(undefined);
      setItems((old) =>
        old.map((item) =>
          item.id === metadata.id
            ? {
                ...item,
                revision: metadata.revision,
                ...(metadata.version ? { version: metadata.version } : {}),
              }
            : item,
        ),
      );
      setSelected(undefined);
      setChosen(undefined);
      clearOccurrences();
      setWatches([]);
      setStatus(
        metadata.resultWithheld
          ? "Evaluation was committed; its earlier result is withheld. Reopen authorized history for current details."
          : metadata.inserted !== undefined && metadata.surfaced !== undefined
            ? `Evaluation saved: ${metadata.inserted} observations recorded, ${metadata.surfaced} surfaced.`
            : "Baseline change saved. List baselines and open the record to read its current revision.",
      );
    } catch (reason) {
      if (serial !== generation.current) return;
      if (
        reason instanceof BaselineWriteError &&
        !reason.uncertain &&
        !pending
      ) {
        setPending(undefined);
        setCurrent(undefined);
        setSelected(undefined);
        setChosen(undefined);
        setVersions([]);
        clearOccurrences();
        setWatchStatus(undefined);
        setWatches([]);
        setItems([]);
        setNext(null);
      } else {
        setPending(operation);
        setCurrent(undefined);
        setSelected(undefined);
        setChosen(undefined);
        clearOccurrences();
        setWatchStatus(undefined);
        setWatches([]);
      }
      setError(
        reason instanceof Error ? reason.message : "Baseline change failed.",
      );
    } finally {
      mutationInFlight.current = false;
      if (serial === generation.current) setBusy(false);
    }
  };
  const reasons = capture ? eligibility(capture.capture) : [];
  return (
    <section
      className="atlas-dependency-monitor"
      aria-label="Dependency monitoring"
    >
      <h2>Dependency baselines</h2>
      <p>
        Use a complete, authorized dependency capture. The displayed map may be
        sampled or ranked and cannot establish a baseline.
      </p>
      {mapWarnings.length > 0 && (
        <details>
          <summary>Map coverage</summary>
          <ul>
            {mapWarnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </details>
      )}
      {!source ? (
        <p>
          A qualified complete dependency source is unavailable for this
          selection.
        </p>
      ) : (
        <button
          type="button"
          disabled={busy || !!pending}
          onClick={() =>
            void read(async (signal) => {
              const result = await source.capture(window, signal);
              const checked = checkedCapture(result.capture);
              if (signal.aborted) return;
              if (
                typeof result.reference !== "string" ||
                !result.reference.trim() ||
                result.reference.length > 4096 ||
                checked.coverage.requested.start !== window.start ||
                checked.coverage.requested.end !== window.end
              )
                throw new Error(
                  "The returned dependency window or capture reference differs from the selection.",
                );
              setCurrent({ reference: result.reference, capture: checked });
              setCapturedContext(context);
              setStatus(
                "Dependency capture returned; review its eligibility below.",
              );
            })
          }
        >
          Read complete dependency evidence
        </button>
      )}
      {busy && !pending && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel read
        </button>
      )}
      {!repository && (
        <p>
          Shared baseline storage is unavailable. No baseline or watch has been
          saved.
        </p>
      )}
      {repository && (
        <>
          <button
            type="button"
            disabled={busy || !!pending}
            onClick={() =>
              void read(async (signal) => {
                const result = await repository.list(signal);
                if (!signal.aborted) {
                  setItems(result.items);
                  setNext(result.next);
                  setStatus(`${result.items.length} baseline records loaded.`);
                }
              })
            }
          >
            List baselines
          </button>
          {items.length > 0 && (
            <ul>
              {items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    disabled={busy || !!pending}
                    onClick={() =>
                      void read(async (signal) => {
                        const history = repository.versions
                          ? await repository.versions(item.id, signal)
                          : { items: [{ version: item.version }], next: null };
                        const definitions = repository.watchPage
                          ? await repository.watchPage(item.id, signal)
                          : {
                              items: await repository.watches(item.id, signal),
                              next: null,
                            };
                        const result = source
                          ? await repository.get(item.id, signal)
                          : undefined;
                        if (!signal.aborted) {
                          setChosen(
                            result
                              ? {
                                  id: result.id,
                                  name: result.name,
                                  revision: result.revision,
                                  version: item.version,
                                }
                              : item,
                          );
                          setVersions(
                            history.items.map((entry) => entry.version),
                          );
                          setVersionNext(history.next);
                          setWatches(definitions.items);
                          setWatchNext(definitions.next);
                          clearOccurrences();
                          setSelected(
                            result
                              ? {
                                  ...result,
                                  capture: checkedCapture(result.capture),
                                }
                              : undefined,
                          );
                        }
                      })
                    }
                  >
                    {item.name} · version {item.version}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {next && (
            <button
              type="button"
              disabled={busy || !!pending}
              onClick={() =>
                void read(async (signal) => {
                  const result = await repository.list(signal, next);
                  if (!signal.aborted) {
                    setItems((old) => [...old, ...result.items]);
                    setNext(result.next);
                  }
                })
              }
            >
              Load more baselines
            </button>
          )}
          {chosen && (
            <section aria-label="Baseline versions and watches">
              <h3>{chosen.name} · version history</h3>
              <p>
                Version and watch metadata is listed separately from protected
                source evidence.
              </p>
              {versions.map((version) => (
                <button
                  type="button"
                  key={version}
                  disabled={busy || !!pending || !source}
                  onClick={() =>
                    void read(async (signal) => {
                      const result = await repository.get(
                        chosen.id,
                        signal,
                        version,
                      );
                      if (!signal.aborted) {
                        setSelected({
                          ...result,
                          capture: checkedCapture(result.capture),
                        });
                        clearOccurrences();
                      }
                    })
                  }
                >
                  Open version {version}
                </button>
              ))}
              {versionNext && repository.versions && (
                <button
                  type="button"
                  disabled={busy || !!pending}
                  onClick={() =>
                    void read(async (signal) => {
                      const result = await repository.versions!(
                        chosen.id,
                        signal,
                        versionNext,
                      );
                      if (!signal.aborted) {
                        setVersions((old) => [
                          ...old,
                          ...result.items.map((entry) => entry.version),
                        ]);
                        setVersionNext(result.next);
                      }
                    })
                  }
                >
                  Load more versions
                </button>
              )}
              <h3>Saved passive watches</h3>
              {!watches.length && <p>No watch definitions.</p>}
              {watches.map((definition) => {
                const pinned = (definition as Partial<WatchWithVersion>)
                  .baselineVersion;
                return (
                  <div key={definition.id}>
                    <p>
                      Watch {definition.id} · baseline version{" "}
                      {pinned ?? "Unavailable"} · threshold{" "}
                      {definition.threshold} · cooldown{" "}
                      {definition.cooldownSeconds} seconds.
                    </p>
                    <p>
                      Expected windows:{" "}
                      {definition.expectedWindows.length
                        ? definition.expectedWindows
                            .map(
                              (w) =>
                                `${new Date(w.start * 1000).toISOString()} – ${new Date(w.end * 1000).toISOString()} UTC`,
                            )
                            .join("; ")
                        : "None"}
                    </p>
                    {repository.evaluate && (
                      <button
                        type="button"
                        disabled={
                          busy ||
                          !!pending ||
                          !capture ||
                          !!reasons.length ||
                          !pinned
                        }
                        onClick={() => {
                          if (!capture || !pinned) return;
                          const requestId = crypto.randomUUID();
                          void mutate({
                            requestId,
                            run: () =>
                              repository.evaluate!(
                                chosen.id,
                                definition.id,
                                chosen.revision,
                                pinned,
                                capture.reference,
                                requestId,
                              ),
                          });
                        }}
                      >
                        Evaluate current evidence
                      </button>
                    )}
                    {repository.occurrences && (
                      <button
                        type="button"
                        disabled={busy || !!pending || !source}
                        onClick={() =>
                          void read(async (signal) => {
                            clearOccurrences();
                            const result = await repository.occurrences!(
                              chosen.id,
                              definition.id,
                              signal,
                            );
                            if (!signal.aborted) {
                              setOccurrenceWatch(definition.id);
                              setOccurrences(result.items);
                              setOccurrenceNext(result.next);
                            }
                          })
                        }
                      >
                        Read watch occurrences
                      </button>
                    )}
                  </div>
                );
              })}
              {watchNext && repository.watchPage && (
                <button
                  type="button"
                  disabled={busy || !!pending}
                  onClick={() =>
                    void read(async (signal) => {
                      const result = await repository.watchPage!(
                        chosen.id,
                        signal,
                        watchNext,
                      );
                      if (!signal.aborted) {
                        setWatches((old) => [...old, ...result.items]);
                        setWatchNext(result.next);
                      }
                    })
                  }
                >
                  Load more watches
                </button>
              )}
              {occurrenceWatch && (
                <section aria-label="Watch occurrences">
                  <h4>Authorized occurrences for {occurrenceWatch}</h4>
                  {occurrences.length ? (
                    <ul>
                      {occurrences.map((item) => (
                        <li key={item.seq}>
                          {item.signature} ·{" "}
                          {new Date(item.window.start * 1000).toISOString()} –{" "}
                          {new Date(item.window.end * 1000).toISOString()} UTC ·
                          observed{" "}
                          {new Date(item.observedAt * 1000).toISOString()}
                          {repository.watchStatus && (
                            <button
                              type="button"
                              disabled={busy || !!pending}
                              onClick={() =>
                                void read(async (signal) => {
                                  const at = Math.floor(Date.now() / 1000);
                                  const value = await repository.watchStatus!(
                                    chosen.id,
                                    occurrenceWatch,
                                    item.signature,
                                    at,
                                    signal,
                                  );
                                  if (!signal.aborted)
                                    setWatchStatus({
                                      signature: item.signature,
                                      at,
                                      value,
                                    });
                                })
                              }
                            >
                              Read status
                            </button>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No occurrences in this page.</p>
                  )}
                  {watchStatus && (
                    <p>
                      Authorized status for {watchStatus.signature} at{" "}
                      {new Date(watchStatus.at * 1000).toISOString()}:{" "}
                      {watchStatus.value.count} observations; threshold{" "}
                      {watchStatus.value.thresholdMet ? "met" : "not met"};
                      expected window{" "}
                      {watchStatus.value.expected ? "active" : "inactive"};
                      cooldown{" "}
                      {watchStatus.value.coolingDown ? "active" : "inactive"}.
                    </p>
                  )}
                  {occurrenceNext && repository.occurrences && (
                    <button
                      type="button"
                      disabled={busy || !!pending}
                      onClick={() =>
                        void read(async (signal) => {
                          const result = await repository.occurrences!(
                            chosen.id,
                            occurrenceWatch,
                            signal,
                            occurrenceNext,
                          );
                          if (!signal.aborted) {
                            setOccurrences((old) => [...old, ...result.items]);
                            setOccurrenceNext(result.next);
                          }
                        })
                      }
                    >
                      Load more occurrences
                    </button>
                  )}
                </section>
              )}
            </section>
          )}
          <label htmlFor={`${field}-name`}>Baseline name</label>
          <input
            id={`${field}-name`}
            value={name}
            maxLength={256}
            disabled={busy || !!pending}
            onChange={(event) => setName(event.target.value)}
          />
          <button
            type="button"
            disabled={
              busy || !!pending || !capture || !!reasons.length || !name.trim()
            }
            onClick={() => {
              if (!capture) return;
              const reference = capture.reference,
                title = name.trim(),
                requestId = crypto.randomUUID();
              void mutate({
                requestId,
                run: () => repository.create(title, reference, requestId),
              });
            }}
          >
            Save new baseline
          </button>
          {selected && (
            <button
              type="button"
              disabled={busy || !!pending || !capture || !!reasons.length}
              onClick={() => {
                if (!capture) return;
                const reference = capture.reference,
                  id = selected.id,
                  revision = selected.revision,
                  requestId = crypto.randomUUID();
                void mutate({
                  requestId,
                  run: () =>
                    repository.version(id, revision, reference, requestId),
                });
              }}
            >
              Save next version
            </button>
          )}
          {selected && (
            <details>
              <summary>Passive watch</summary>
              <p>
                A new watch is pinned to the latest saved baseline version.
                Findings are reviewed here. No schedule, action or notification
                is enabled.
              </p>
              <label htmlFor={`${field}-threshold`}>
                Distinct observation windows required
              </label>
              <input
                id={`${field}-threshold`}
                type="number"
                min={1}
                max={100}
                value={threshold}
                onChange={(event) => setThreshold(event.target.value)}
                disabled={busy || !!pending}
              />
              <label htmlFor={`${field}-cooldown`}>Cooldown seconds</label>
              <input
                id={`${field}-cooldown`}
                type="number"
                min={0}
                max={604800}
                value={cooldown}
                onChange={(event) => setCooldown(event.target.value)}
                disabled={busy || !!pending}
              />
              <label htmlFor={`${field}-expected-start`}>
                Expected change start (optional UTC timestamp)
              </label>
              <input
                id={`${field}-expected-start`}
                value={expectedStart}
                maxLength={64}
                disabled={busy || !!pending}
                onChange={(event) => setExpectedStart(event.target.value)}
                placeholder="2026-11-16T12:00:00Z"
              />
              <label htmlFor={`${field}-expected-end`}>
                Expected change end
              </label>
              <input
                id={`${field}-expected-end`}
                value={expectedEnd}
                maxLength={64}
                disabled={busy || !!pending}
                onChange={(event) => setExpectedEnd(event.target.value)}
                placeholder="2026-11-16T13:00:00Z"
              />
              <button
                type="button"
                disabled={busy || !!pending}
                onClick={() => {
                  const count = Number(threshold),
                    seconds = Number(cooldown);
                  if (
                    !Number.isInteger(count) ||
                    count < 1 ||
                    count > 100 ||
                    !Number.isInteger(seconds) ||
                    seconds < 0 ||
                    seconds > 604800
                  ) {
                    setError(
                      "Enter a threshold from 1 to 100 and a cooldown from 0 to 604800 seconds.",
                    );
                    return;
                  }
                  const expectedWindows: WatchDefinition["expectedWindows"] =
                    [];
                  if (expectedStart || expectedEnd) {
                    const start = Date.parse(expectedStart) / 1000,
                      end = Date.parse(expectedEnd) / 1000;
                    if (
                      ![expectedStart, expectedEnd].every((value) =>
                        /(?:Z|[+-]\d{2}:\d{2})$/i.test(value),
                      ) ||
                      !Number.isFinite(start) ||
                      !Number.isFinite(end) ||
                      start < 0 ||
                      end <= start
                    ) {
                      setError(
                        "Expected changes need a valid absolute start and end with timezone, or leave both empty.",
                      );
                      return;
                    }
                    expectedWindows.push({ start, end });
                  }
                  const id = selected.id,
                    revision = selected.revision,
                    requestId = crypto.randomUUID(),
                    definition = {
                      id: crypto.randomUUID(),
                      threshold: count,
                      cooldownSeconds: seconds,
                      expectedWindows,
                    };
                  void mutate({
                    requestId,
                    run: () =>
                      repository.setWatch(id, revision, definition, requestId),
                  });
                }}
              >
                Save passive watch
              </button>
            </details>
          )}
        </>
      )}
      {capture && (
        <BaselineReview
          current={capture.capture}
          baselines={
            selected
              ? [
                  {
                    id: selected.id,
                    name: selected.name,
                    version: selected.version,
                    capture: selected.capture,
                  },
                ]
              : []
          }
          watches={watches}
        />
      )}
      {selected && !capture && (
        <p>
          Selected {selected.name}, version {selected.version}. Read current
          complete evidence to compare.
        </p>
      )}
      {pending && (
        <>
          <p>
            The write outcome is unknown. Keep this view open and retry the same
            request before starting another change.
          </p>
          <button
            type="button"
            disabled={busy}
            ref={retryButton}
            onClick={() => void mutate(pending)}
          >
            Retry same baseline request
          </button>
        </>
      )}
      {error && <p role="alert">{error}</p>}
      {status && <p role="status">{status}</p>}
    </section>
  );
}
