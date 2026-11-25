import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SearchClient } from "../data/searchClient";
import { SearchAccessDeniedError } from "../data/searchClient";
import { canonicalJson } from "./canonicalJson";
import {
  attributeChangeRow,
  countTimelineExclusions,
  filterTimelineRows,
  loadChangeTimeline,
  viewsForTimelineResult,
} from "./history";
import { reportedChronology } from "./chronology";
import { changeTimelineCsv, changeTimelineJson } from "./exports";
import type {
  ChangeTimelineContext,
  ChangeTimelineComparison,
  ChangeTimelineResult,
  ChangeTimelineSelection,
  ChangeTimelineWindow,
  ChangeTimelineRecordView,
} from "./types";
import "./changeTimeline.css";

interface LiveTimelineProps {
  mode: "live";
  enabled: boolean;
  client: SearchClient;
  selection?: ChangeTimelineSelection;
  context?: ChangeTimelineContext;
  selectedIds?: ReadonlySet<string>;
  onToggleSelected?: (recordId: string) => void;
}

interface ResultTimelineProps {
  mode: "result";
  result: ChangeTimelineResult;
  view: { scope: string; window: ChangeTimelineWindow };
  comparison?: ChangeTimelineComparison;
  context?: ChangeTimelineContext;
  selectedIds?: ReadonlySet<string>;
  onToggleSelected?: (recordId: string) => void;
}

export type ChangeTimelineProps = LiveTimelineProps | ResultTimelineProps;

type RequestState = {
  key: string;
  state: "loading" | "error" | "cancelled";
  message?: string;
};

function currentKey(props: ChangeTimelineProps): string {
  if (props.mode === "result")
    return JSON.stringify([
      props.mode,
      props.result.provenance,
      props.result.manifest.generation_id,
      props.view.scope,
      props.view.window.start,
      props.view.window.end,
    ]);
  if (!props.selection) return JSON.stringify([props.mode, null]);
  return JSON.stringify([
    props.mode,
    props.selection.activation.index,
    props.selection.activation.activation_id,
    props.selection.activation.generation_id,
    props.selection.scope,
    props.selection.window.start,
    props.selection.window.end,
  ]);
}

function timeText(value: number | null): string {
  if (value === null) return "Unavailable";
  try {
    return `${new Date(value * 1000).toISOString().replace("T", " ").replace("Z", " UTC")}`;
  } catch {
    return "Unavailable";
  }
}

function jsonValue(value: unknown): string {
  if (typeof value === "string") return value === "" ? '""' : value;
  try {
    return canonicalJson(value);
  } catch {
    return "Unavailable";
  }
}

function formatInterval(row: ChangeTimelineRecordView["row"]): string {
  if (row.earliest_at !== null && row.latest_at !== null) {
    return `${timeText(row.earliest_at)} to ${timeText(row.latest_at)}${row.clock_uncertainty_unknown ? " (clock uncertainty unknown)" : ""}`;
  }
  if (row.event_at !== null)
    return `${timeText(row.event_at)} (reported source time${row.clock_uncertainty_unknown ? " / clock uncertainty unknown" : ""})`;
  if (row.observed_at !== null)
    return `${timeText(row.observed_at)} (observation time${row.clock_uncertainty_unknown ? " / clock uncertainty unknown" : ""})`;
  return "Unknown time; retained as context";
}

function displayRecordType(record: ChangeTimelineRecordView["row"]) {
  if (
    record.product === "atlas" &&
    record.family === "relationship_attestation"
  )
    return "Administrator potential-dependency attestation";
  if (record.record_type === "change")
    return `Configuration change${record.change_type ? ` · ${record.change_type}` : ""}`;
  if (record.record_type === "baseline") return "Configuration baseline";
  if (record.record_type === "coverage") return "Collection coverage";
  return "Source observation";
}

function downloadFile(name: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function accessFailure(cause: unknown): string {
  if (
    cause instanceof SearchAccessDeniedError ||
    (cause instanceof Error && cause.name === "SearchAccessDeniedError")
  )
    return "Change history index access denied.";
  if (cause instanceof Error && /cancel/i.test(cause.message))
    return "History search cancelled; optional search cleanup may be pending.";
  return "History unavailable. Check permissions, activation, and search completion.";
}

function hasVisibleGap(records: ChangeTimelineRecordView[]) {
  return records.some(
    ({ row }) =>
      row.record_type === "coverage" ||
      row.gap ||
      !row.coverage_complete ||
      row.clock_uncertainty_unknown,
  );
}

function RecordDetails({
  record,
}: {
  record: ChangeTimelineRecordView["row"];
}) {
  return (
    <details className="change-timeline__details">
      <summary>Evidence details</summary>
      <dl>
        <dt>Product and authority</dt>
        <dd>
          {record.product} · {record.authority}
        </dd>
        <dt>Object and revision</dt>
        <dd>
          {record.object_id ?? "Object identity unavailable"}
          {record.revision ? ` · revision ${record.revision}` : ""}
        </dd>
        <dt>Source interval</dt>
        <dd>{formatInterval(record)}</dd>
        <dt>Reported source event time</dt>
        <dd>{timeText(record.event_at)}</dd>
        <dt>Effective time (source-reported)</dt>
        <dd>{timeText(record.effective_at)}</dd>
        <dt>Observation time</dt>
        <dd>{timeText(record.observed_at)}</dd>
        <dt>History receipt time</dt>
        <dd>{timeText(record.received_at)}</dd>
        <dt>Time qualification</dt>
        <dd>{record.time_qualification}</dd>
        <dt>Clock uncertainty</dt>
        <dd>
          {record.clock_uncertainty_unknown ? "Unknown" : "Source qualified"}
        </dd>
        <dt>Collection completeness</dt>
        <dd>
          {record.coverage_complete
            ? "Reported complete for this partition"
            : "Completeness unverified"}
          {record.gap ? " · coverage gap reported" : ""}
        </dd>
        <dt>Qualification</dt>
        <dd>{record.qualification}</dd>
        <dt>Projection qualification</dt>
        <dd>{record.projection_qualification}</dd>
        <dt>Native sample</dt>
        <dd>
          {record.native_sample_unqualified
            ? "Native sample unqualified"
            : "Native sample qualified"}
        </dd>
        {record.actor !== null && (
          <>
            <dt>Actor</dt>
            <dd>{record.actor}</dd>
          </>
        )}
        {record.field_diffs.length > 0 && (
          <>
            <dt>Allowlisted field differences</dt>
            <dd>
              <ul>
                {record.field_diffs.map((diff, index) => (
                  <li key={`${diff.field}:${index}`}>
                    <strong>{diff.field}</strong>:{" "}
                    {diff.before_present
                      ? jsonValue(diff.before)
                      : "Not present"}
                    {" → "}
                    {diff.after_present ? jsonValue(diff.after) : "Not present"}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {Object.keys(record.attributes).length > 0 && (
          <>
            <dt>Allowlisted projected attributes</dt>
            <dd>
              <ul>
                {Object.entries(record.attributes)
                  .sort(([left], [right]) =>
                    left < right ? -1 : left > right ? 1 : 0,
                  )
                  .map(([key, value]) => (
                    <li key={key}>
                      <strong>{key}</strong>: {jsonValue(value)}
                    </li>
                  ))}
              </ul>
            </dd>
          </>
        )}
        <dt>Native source references</dt>
        <dd>
          {record.source_refs.length ? (
            <ul>
              {record.source_refs.map((reference) => (
                <li key={reference}>{reference}</li>
              ))}
            </ul>
          ) : (
            "Unavailable"
          )}
        </dd>
      </dl>
    </details>
  );
}

function TimelineRows({
  records,
  onToggle,
}: {
  records: ChangeTimelineRecordView[];
  onToggle(id: string): void;
}) {
  if (!records.length)
    return (
      <p className="change-timeline__empty" role="status">
        No caller-visible history records match this selected scope and time
        window. This view does not establish that no changes occurred.
      </p>
    );
  return (
    <div className="change-timeline__scroll">
      <table className="change-timeline__table">
        <thead>
          <tr>
            <th scope="col">Select</th>
            <th scope="col">Record</th>
            <th scope="col">Reported time</th>
            <th scope="col">Application relevance</th>
          </tr>
        </thead>
        <tbody>
          {records.map(({ row, attribution, selected, chronology }) => (
            <tr
              key={row.record_id}
              className={
                selected ? "change-timeline__row--selected" : undefined
              }
              aria-selected={selected}
            >
              <td>
                <input
                  className="change-timeline__checkbox"
                  type="checkbox"
                  checked={selected}
                  aria-label={`Select ${displayRecordType(row)} ${row.record_id}`}
                  onChange={() => onToggle(row.record_id)}
                />
              </td>
              <td>
                <span className="change-timeline__title">
                  {displayRecordType(row)}
                </span>
                <span>
                  {row.product} · {row.family}
                  {row.kind ? ` · ${row.kind}` : ""}
                </span>
                <div className="change-timeline__chips">
                  <span className="change-timeline__chip">
                    {row.coverage_complete
                      ? "Collection reported complete"
                      : "Completeness unknown"}
                  </span>
                  {row.gap && (
                    <span className="change-timeline__chip change-timeline__chip--warning">
                      Coverage gap
                    </span>
                  )}
                  {row.clock_uncertainty_unknown && (
                    <span className="change-timeline__chip change-timeline__chip--warning">
                      Clock uncertainty unknown
                    </span>
                  )}
                  {row.context_only && (
                    <span className="change-timeline__chip">
                      Source projection is context only
                    </span>
                  )}
                </div>
                <RecordDetails record={row} />
              </td>
              <td>
                {formatInterval(row)}
                {chronology && (
                  <p>
                    Reported interval: {chronology.graph_phase} graph phase;{" "}
                    {chronology.reported_observation} selected observation.{" "}
                    {!chronology.ordering_qualified &&
                      "Cross-source ordering is unqualified."}
                  </p>
                )}
              </td>
              <td>
                <strong>
                  {attribution.attribution_class.replaceAll("_", " ")}
                </strong>
                <br />
                <code>{attribution.reason}</code>
                {(attribution.chains?.length ?? 0) > 0 && (
                  <details className="change-timeline__details">
                    <summary>
                      Potential dependency chains (
                      {attribution.chains?.length ?? 0})
                    </summary>
                    <ol>
                      {(attribution.chains ?? []).map((chain, chainIndex) => (
                        <li
                          key={`${chain.target.authority}:${chain.target.type}:${chain.target.id}:${chainIndex}`}
                        >
                          <strong>
                            {chain.target_class.replaceAll("_", " ")}:{" "}
                            {chain.target.authority}/{chain.target.type}/
                            {chain.target.id}
                          </strong>
                          <ol>
                            {chain.links.map((link, linkIndex) => (
                              <li key={`${link.evidence_id}:${linkIndex}`}>
                                {link.from_authority}/{link.from_type}/
                                {link.from_id}
                                {" → "}
                                {link.to_authority}/{link.to_type}/{link.to_id}
                                {` · ${link.basis} · ${link.semantics ?? "caller-verified relationship"} · evidence ${link.evidence_id}`}
                                {link.issuer && ` · issuer ${link.issuer}`}
                                {link.attestation_version &&
                                  ` · attestation ${link.attestation_version}`}
                                {link.actor && ` · actor ${link.actor}`}
                                {link.proof &&
                                  ` · unverified proof reference ${link.proof}`}
                                {link.qualification &&
                                  ` · ${link.qualification}`}
                                {link.target_binding && (
                                  <div>
                                    Captured graph edge{" "}
                                    {link.target_binding.edge_id}; query{" "}
                                    {link.target_binding.query_sha256}; traffic
                                    contract{" "}
                                    {
                                      link.target_binding
                                        .active_traffic_contract_sha256
                                    }
                                    ; indexed receipts{" "}
                                    {link.target_binding.receipt_fingerprints.join(
                                      ", ",
                                    )}
                                    ; receipt basis{" "}
                                    {link.target_binding.receipt_basis};
                                    query-level eligible input superset, not
                                    per-edge event lineage; coverage SHA-256{" "}
                                    {
                                      link.target_binding
                                        .query_input_coverage_sha256
                                    }
                                  </div>
                                )}
                              </li>
                            ))}
                          </ol>
                        </li>
                      ))}
                    </ol>
                  </details>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ChangeTimeline(props: ChangeTimelineProps) {
  const selectionKey = currentKey(props);
  const client = props.mode === "live" ? props.client : undefined;
  const context = props.context;
  const comparison = props.mode === "result" ? props.comparison : undefined;
  const liveScope = props.mode === "live" ? props.selection?.scope : undefined;
  const liveWindow =
    props.mode === "live" ? props.selection?.window : undefined;
  const resultView = props.mode === "result" ? props.view : undefined;
  const view = useMemo(() => {
    if (props.mode === "result") return resultView;
    if (liveScope === undefined || liveWindow === undefined) return undefined;
    return { scope: liveScope, window: liveWindow };
  }, [liveScope, liveWindow, props.mode, resultView]);
  const [loaded, setLoaded] = useState<{
    key: string;
    client?: SearchClient;
    result: ChangeTimelineResult;
  }>();
  const [requestState, setRequestState] = useState<RequestState>();
  const [internalSelectedIds, setInternalSelectedIds] = useState<Set<string>>(
    () => new Set(),
  );
  const selectedIds = props.selectedIds ?? internalSelectedIds;
  const active = useRef<AbortController>();
  const activeToken = useRef<symbol>();

  const invalidate = useCallback(() => {
    activeToken.current = undefined;
    active.current?.abort();
    active.current = undefined;
  }, []);

  useEffect(() => {
    invalidate();
    setLoaded(undefined);
    setRequestState(undefined);
    setInternalSelectedIds(new Set());
    const onPageHide = () => {
      if (!active.current) return;
      invalidate();
      setRequestState({
        key: selectionKey,
        state: "cancelled",
        message:
          "History search cancelled; optional search cleanup may be pending.",
      });
    };
    window.addEventListener("pagehide", onPageHide);
    return () => {
      invalidate();
      window.removeEventListener("pagehide", onPageHide);
    };
  }, [client, invalidate, selectionKey]);

  const live = props.mode === "live" ? props : undefined;
  const resultMode = props.mode === "result";
  const busy =
    requestState?.key === selectionKey && requestState.state === "loading";
  const liveResult =
    live && loaded?.key === selectionKey && loaded.client === live.client
      ? loaded.result
      : undefined;
  const visibleResult = props.mode === "result" ? props.result : liveResult;
  const visibleMessage =
    requestState?.key === selectionKey ? requestState.message : undefined;
  const exclusions = useMemo(() => {
    if (!view || !visibleResult)
      return {
        different_verified_scope: 0,
        outside_selected_interval: 0,
        unknown_time_unpositioned: 0,
      };
    return visibleResult.provenance === "validated_live"
      ? visibleResult.exclusions
      : countTimelineExclusions(visibleResult.rows, view);
  }, [view, visibleResult]);
  const baseRecords = useMemo(() => {
    if (!view || !visibleResult) return [];
    if (resultMode) return viewsForTimelineResult(visibleResult, view, context);
    return filterTimelineRows(visibleResult.rows, view).map((row) => ({
      row,
      attribution: attributeChangeRow(
        row,
        view,
        context,
        visibleResult.retained_relationships ?? [],
        visibleResult.relationship_evidence_complete ?? true,
        visibleResult.relationship_evidence_reason,
      ),
      selected: false,
    }));
  }, [context, resultMode, view, visibleResult]);
  const records = useMemo(
    () =>
      baseRecords.map((record) => ({
        ...record,
        selected: selectedIds.has(record.row.record_id),
        ...(comparison
          ? { chronology: reportedChronology(record.row, comparison) }
          : {}),
      })),
    [baseRecords, selectedIds, comparison],
  );

  const runSearch = async () => {
    if (!live?.selection || busy) return;
    invalidate();
    const controller = new AbortController();
    active.current = controller;
    const token = Symbol("change-timeline-search");
    activeToken.current = token;
    setLoaded(undefined);
    setRequestState({ key: selectionKey, state: "loading" });
    try {
      const result = await loadChangeTimeline(
        live.client,
        live.selection,
        controller.signal,
      );
      if (activeToken.current === token && !controller.signal.aborted) {
        setLoaded({ key: selectionKey, client: live.client, result });
        setRequestState(undefined);
      }
    } catch (cause) {
      if (activeToken.current === token && !controller.signal.aborted)
        setRequestState({
          key: selectionKey,
          state: "error",
          message: accessFailure(cause),
        });
    } finally {
      if (activeToken.current === token && active.current === controller) {
        active.current = undefined;
        activeToken.current = undefined;
      }
    }
  };

  const cancel = () => {
    activeToken.current = undefined;
    active.current?.abort();
    active.current = undefined;
    setRequestState({
      key: selectionKey,
      state: "cancelled",
      message:
        "History search cancelled; optional search cleanup may be pending.",
    });
  };

  const toggle = (recordId: string) => {
    if (props.onToggleSelected) {
      props.onToggleSelected(recordId);
      return;
    }
    setInternalSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(recordId)) next.delete(recordId);
      else next.add(recordId);
      return next;
    });
  };

  if (props.mode === "live" && !props.enabled)
    return (
      <section
        className="change-timeline"
        aria-label="Optional configuration change timeline"
      >
        <h3>Configuration change timeline</h3>
        <p className="change-timeline__notice">
          This optional history source is off. An administrator must select and
          activate a derived history index before it can be inspected.
        </p>
      </section>
    );

  if (props.mode === "live" && !props.selection)
    return (
      <section
        className="change-timeline"
        aria-label="Optional configuration change timeline"
      >
        <h3>Configuration change timeline</h3>
        <p className="change-timeline__notice" role="status">
          Select an application or endpoint and a verified routing scope to
          inspect change history.
        </p>
      </section>
    );

  if (!view) return null;

  const result = visibleResult;
  const exportContext = result
    ? {
        provenance: result.provenance,
        index:
          result.provenance === "validated_live"
            ? result.activation.index
            : undefined,
        activation:
          result.provenance === "validated_live"
            ? result.activation
            : undefined,
        manifest: result.manifest,
        scope: view.scope,
        window: view.window,
        ...(comparison ? { comparison } : {}),
        exclusions,
        relationship_evidence_complete:
          result.relationship_evidence_complete ?? true,
        relationship_evidence_reason:
          result.relationship_evidence_reason ?? null,
        demo_handoff: context?.demo_handoff,
      }
    : undefined;

  const exportJson = () => {
    if (!exportContext || !result) return;
    downloadFile(
      "configuration-change-history.json",
      "application/json;charset=utf-8",
      changeTimelineJson(exportContext, records),
    );
  };
  const exportCsv = () => {
    if (!exportContext || !result) return;
    downloadFile(
      "configuration-change-history.csv",
      "text/csv;charset=utf-8",
      changeTimelineCsv(exportContext, records),
    );
  };

  return (
    <section
      className="change-timeline"
      aria-label="Optional configuration change timeline"
    >
      <h3>Configuration change timeline</h3>
      {props.mode === "result" &&
      props.result.provenance === "synthetic_demo" ? (
        <p className="change-timeline__demo" role="status">
          SYNTHETIC DEMO · {props.result.label}
        </p>
      ) : null}
      <p className="change-timeline__intro">
        Projected history for this scope and interval. A related change alone
        proves neither enforcement nor cause.
      </p>
      {live && (
        <div className="change-timeline__actions">
          <button
            type="button"
            onClick={() => void runSearch()}
            disabled={busy}
          >
            {busy
              ? "Searching configuration history…"
              : result
                ? "Refresh configuration history"
                : requestState?.key === selectionKey &&
                    requestState.state === "error"
                  ? "Retry configuration history"
                  : "Inspect configuration history"}
          </button>
          {busy && (
            <button type="button" onClick={cancel}>
              Cancel history search
            </button>
          )}
          <span role={requestState?.state === "error" ? "alert" : "status"}>
            {busy
              ? "Loading and validating the full activated generation…"
              : (visibleMessage ?? "History has not been queried.")}
          </span>
        </div>
      )}
      {result && exportContext ? (
        <>
          {result.provenance === "validated_live" ? (
            <p className="change-timeline__notice" role="status">
              Full-generation integrity verified for{" "}
              {result.validation.row_count.toLocaleString()} rows. Activation
              retains the derived-index viewer entitlement attestation; live
              collection and universal coverage remain unqualified.
            </p>
          ) : null}
          {result.provenance === "synthetic_demo" ? (
            <p className="change-timeline__notice change-timeline__notice--warning">
              Synthetic scenario data; installed replay and live history require
              separate verification.
            </p>
          ) : null}
          {hasVisibleGap(records) && (
            <p
              className="change-timeline__notice change-timeline__notice--warning"
              role="status"
            >
              Collection gaps, unknown timing, or coverage limits apply. Empty
              searches and missing records do not prove no changes.
            </p>
          )}
          {result.relationship_evidence_complete === false && (
            <p
              className="change-timeline__notice change-timeline__notice--warning"
              role="status"
            >
              Incomplete relationship evidence; attribution remains context
              only. Reason: {result.relationship_evidence_reason ?? "unknown"}.
            </p>
          )}
          <div className="change-timeline__meta">
            <span>Scope: {view.scope}</span>
            <span>
              {comparison ? "Configuration history: full incident" : "Window"}:{" "}
              {timeText(view.window.start)} to {timeText(view.window.end)}
            </span>
            {comparison && (
              <>
                <span>
                  Observed graph: selected phase{" "}
                  {timeText(comparison.graph_window.start)} to{" "}
                  {timeText(comparison.graph_window.end)}
                </span>
                <span>
                  Selected observation:{" "}
                  {comparison.reported_observation_interval
                    ? `${timeText(comparison.reported_observation_interval.start)} to ${timeText(comparison.reported_observation_interval.end)} (reported clocks; uncertainty unknown)`
                    : "Observation interval unknown; ordering unknown."}
                </span>
                <span>
                  Restoration cannot explain earlier impact. Phase overlap
                  proves neither event order nor cause.
                </span>
              </>
            )}
            <span>Generation: {result.manifest.generation_id}</span>
            {result.provenance === "validated_live" && (
              <span>Activation: {result.activation.activation_id}</span>
            )}
            {context?.application && (
              <span>
                Application context: {context.application.service} ·{" "}
                {context.application.environment} ·{" "}
                {context.application.cluster}/{context.application.namespace}
              </span>
            )}
            <span>{records.length} visible record(s)</span>
            <span>
              {records.filter((record) => record.selected).length} selected
            </span>
            <span>
              Excluded from this view: {exclusions.different_verified_scope}{" "}
              different scope, {exclusions.outside_selected_interval} outside
              interval, {exclusions.unknown_time_unpositioned} without a usable
              position.
            </span>
          </div>
          <div className="change-timeline__actions">
            <button type="button" onClick={exportJson}>
              Export all visible records as JSON
            </button>
            <button type="button" onClick={exportCsv}>
              Export all visible records as CSV
            </button>
            <span className="change-timeline__muted">
              Exports retain all visible records and selections.
            </span>
          </div>
          <TimelineRows records={records} onToggle={toggle} />
        </>
      ) : (
        <>
          {live && busy && (
            <p role="status">Loading optional configuration history…</p>
          )}
        </>
      )}
    </section>
  );
}
