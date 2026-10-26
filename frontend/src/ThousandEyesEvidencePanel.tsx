import {
  Fragment,
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import type { EvidenceSelection, EvidenceWindow } from "./data/evidence";
import type { EvidenceConfigClient } from "./data/evidenceConfig";
import type { SearchClient } from "./data/searchClient";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesComparison,
  ThousandEyesEvidenceResult,
  ThousandEyesFamily,
  ThousandEyesHop,
} from "./data/thousandEyesTypes";
import "./thousandeyes.css";

export type ThousandEyesEvidenceLoader = (
  client: SearchClient,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient?: EvidenceConfigClient,
) => Promise<ThousandEyesEvidenceResult>;

export type ThousandEyesMeasurementComparator = (
  records: readonly ThousandEyesAttributedObservation[],
  before: EvidenceWindow,
  after: EvidenceWindow,
) => ThousandEyesComparison[];

const MAX_VISIBLE_RECORDS = 64;

interface InspectionExecutionKey {
  selectionKey: string;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
  loadEvidence: ThousandEyesEvidenceLoader;
}

export function ThousandEyesEvidencePanel({
  result,
  compareMeasurements,
}: {
  result: ThousandEyesEvidenceResult;
  compareMeasurements?: ThousandEyesMeasurementComparator;
}) {
  const [testFilter, setTestFilter] = useState("");
  const [agentFilter, setAgentFilter] = useState("");
  const [locationFilter, setLocationFilter] = useState("");
  const [selectedRecordKey, setSelectedRecordKey] = useState("");
  const [groupBy, setGroupBy] = useState<
    "test" | "agent" | "location" | "family"
  >("test");
  const visibleRecords = useMemo(
    () => result.records.slice(0, MAX_VISIBLE_RECORDS),
    [result.records],
  );
  const filteredRecords = useMemo(
    () =>
      visibleRecords
        .map((record, index) => ({
          record,
          key: observationKey(record, index),
        }))
        .filter(
          ({ record }) =>
            (!testFilter || testKey(record) === testFilter) &&
            (!agentFilter || agentKey(record) === agentFilter) &&
            (!locationFilter || locationKey(record) === locationFilter),
        ),
    [visibleRecords, testFilter, agentFilter, locationFilter],
  );
  const comparisonRecords = useMemo(
    () => filteredRecords.map((entry) => entry.record),
    [filteredRecords],
  );
  const groups = new Map<string, typeof filteredRecords>();
  for (const entry of filteredRecords) {
    const record = entry.record;
    const key =
      groupBy === "test"
        ? testKey(record)
        : groupBy === "agent"
          ? agentKey(record)
          : groupBy === "location"
            ? locationKey(record)
            : record.family;
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  }
  const selectedEntry =
    filteredRecords.find((entry) => entry.key === selectedRecordKey) ??
    filteredRecords[0];

  const globalIssues = resultIssues(result, visibleRecords);
  const hasRecords = result.state === "complete" && result.records.length > 0;

  return (
    <section
      className="thousandeyes-evidence"
      aria-label="Optional ThousandEyes evidence"
    >
      <h3>ThousandEyes synthetic test evidence</h3>
      <p className="te-intro">
        Metrics, probe paths, and traces describe synthetic test observations;
        events, alerts, and activity remain ThousandEyes-source context. These
        records do not create passive traffic, service calls, dependency edges,
        or a general infrastructure health claim.
      </p>
      <p className="te-status" role="status" aria-live="polite">
        {resultStatus(result)}
      </p>

      {globalIssues.length > 0 && (
        <ul className="te-quality-list" aria-label="Evidence quality notices">
          {globalIssues.map((issue) => (
            <li key={issue}>{issue}</li>
          ))}
        </ul>
      )}

      {result.coverage.length > 0 && (
        <details className="te-coverage">
          <summary>Source coverage and limits</summary>
          <ul>
            {result.coverage
              .slice(0, MAX_VISIBLE_RECORDS)
              .map((item, index) => (
                <li key={`${index}:${item}`}>{item}</li>
              ))}
          </ul>
          {result.coverage.length > MAX_VISIBLE_RECORDS && (
            <p>
              Showing the first {MAX_VISIBLE_RECORDS} of{" "}
              {result.coverage.length} coverage notes.
            </p>
          )}
        </details>
      )}

      {result.state === "complete" && !result.records.length && (
        <p className="te-empty">
          No visible ThousandEyes observations were returned. This does not
          prove that no tests ran, that collection succeeded, or that the source
          contains no other history.
        </p>
      )}

      {hasRecords && (
        <>
          <div className="te-result-meta">
            <span>
              Capture:{" "}
              <time dateTime={isoTime(result.capturedAt)}>
                {isoTime(result.capturedAt)}
              </time>
            </span>
            <span>
              Native measurement window:{" "}
              {epochTime(result.selection.window.start)} to{" "}
              {epochTime(result.selection.window.end)}
            </span>
            <span>
              Configuration fingerprint: {result.configurationFingerprint}
            </span>
            <span>
              {result.selection.workflow === "application"
                ? "Application-scoped selection"
                : "Endpoint-scoped selection"}
            </span>
            <span>Selected scope: {result.selection.scope}</span>
            <span>
              Selected addresses:{" "}
              {result.selection.addresses.join(", ") || "Not supplied"}
            </span>
            {result.selection.application && (
              <span>
                Application: {result.selection.application.service} ·{" "}
                {result.selection.application.environment} ·{" "}
                {result.selection.application.cluster} ·{" "}
                {result.selection.application.namespace}
              </span>
            )}
          </div>
          <details className="te-coverage">
            <summary>Retained-index scan diagnostics</summary>
            <p>
              Splunk _time scan bounds: {result.inspectedWindow.start} to{" "}
              {result.inspectedWindow.end} epoch seconds. These broad search
              bounds locate retained index rows; they are not the ThousandEyes
              measurement window or coverage period.
            </p>
          </details>

          <fieldset className="te-filters">
            <legend>Filter and group observations</legend>
            <label>
              Test
              <select
                value={testFilter}
                onChange={(event) => setTestFilter(event.target.value)}
              >
                <option value="">All tests</option>
                {filterOptions(visibleRecords, testKey, testLabel).map(
                  (option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              Agent
              <select
                value={agentFilter}
                onChange={(event) => setAgentFilter(event.target.value)}
              >
                <option value="">All agents</option>
                {filterOptions(visibleRecords, agentKey, agentLabel).map(
                  (option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              Agent location
              <select
                value={locationFilter}
                onChange={(event) => setLocationFilter(event.target.value)}
              >
                <option value="">All locations</option>
                {filterOptions(visibleRecords, locationKey, locationLabel).map(
                  (option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              Group by
              <select
                value={groupBy}
                onChange={(event) =>
                  setGroupBy(event.target.value as typeof groupBy)
                }
              >
                <option value="test">Test</option>
                <option value="agent">Agent</option>
                <option value="location">Agent location</option>
                <option value="family">Evidence family</option>
              </select>
            </label>
            {(testFilter || agentFilter || locationFilter) && (
              <button
                type="button"
                onClick={() => {
                  setTestFilter("");
                  setAgentFilter("");
                  setLocationFilter("");
                }}
              >
                Clear filters
              </button>
            )}
          </fieldset>

          <p className="te-record-count" role="status">
            Showing {filteredRecords.length} of {result.records.length} returned
            observation{result.records.length === 1 ? "" : "s"}.
            {result.outputCapped || result.records.length > MAX_VISIBLE_RECORDS
              ? " The displayed set is capped."
              : ""}
          </p>
          {filteredRecords.length === 0 ? (
            <p>No observations match these filters.</p>
          ) : (
            <div className="te-groups">
              {[...groups.entries()].map(([key, records]) => (
                <section
                  className="te-group"
                  key={key}
                  aria-label={`${groupLabel(groupBy)}: ${groupTitle(groupBy, records[0].record)}`}
                >
                  <h4>
                    {groupLabel(groupBy)}:{" "}
                    {groupTitle(groupBy, records[0].record)}
                    <span className="te-count">{records.length}</span>
                  </h4>
                  <div
                    className="te-table-scroll"
                    tabIndex={0}
                    aria-label="Scrollable ThousandEyes observation summaries"
                  >
                    <table>
                      <caption>
                        Observation summaries; select one row for bounded detail
                      </caption>
                      <thead>
                        <tr>
                          <th scope="col">Family</th>
                          <th scope="col">Test</th>
                          <th scope="col">Agent / location</th>
                          <th scope="col">Target</th>
                          <th scope="col">Event time</th>
                          <th scope="col">Reported outcome</th>
                          <th scope="col">Detail</th>
                        </tr>
                      </thead>
                      <tbody>
                        {records.map(({ record, key: recordKey }) => (
                          <tr
                            key={recordKey}
                            aria-selected={selectedEntry?.key === recordKey}
                          >
                            <td>{familyLabel(record.family)}</td>
                            <td>{testLabel(record)}</td>
                            <td>
                              {agentLabel(record)} · {locationLabel(record)}
                            </td>
                            <td>{targetText(record.target)}</td>
                            <td>{isoTime(record.eventTime)}</td>
                            <td>{record.outcome}</td>
                            <td>
                              <button
                                type="button"
                                aria-pressed={selectedEntry?.key === recordKey}
                                onClick={() => setSelectedRecordKey(recordKey)}
                              >
                                {selectedEntry?.key === recordKey
                                  ? "Selected observation"
                                  : "Inspect observation"}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ))}
            </div>
          )}

          {selectedEntry && (
            <section aria-label="Selected ThousandEyes observation detail">
              <h4>Selected observation detail</h4>
              <ObservationCard record={selectedEntry.record} result={result} />
            </section>
          )}

          {compareMeasurements &&
            result.state === "complete" &&
            filteredRecords.length > 0 && (
              <ComparisonSection
                key={`${result.selection.selectionId}:${result.capturedAt}:${result.selection.window.start}:${result.selection.window.end}`}
                records={comparisonRecords}
                nativeMeasurementWindow={result.selection.window}
                compareMeasurements={compareMeasurements}
                blockedReason={comparisonBlockedReason(
                  result,
                  filteredRecords.map((entry) => entry.record),
                )}
              />
            )}
        </>
      )}
    </section>
  );
}

/** Search is deliberately user-triggered; stale requests are invalidated on scope/config changes. */
export function ThousandEyesEvidenceInspection({
  selection,
  client,
  configurationClient,
  loadEvidence,
  compareMeasurements,
}: {
  selection?: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
  loadEvidence: ThousandEyesEvidenceLoader;
  compareMeasurements?: ThousandEyesMeasurementComparator;
}) {
  const selectionKey = selection
    ? JSON.stringify(selection)
    : "unselected-selection";
  const executionKey = useMemo<InspectionExecutionKey>(
    () => ({ selectionKey, client, configurationClient, loadEvidence }),
    [selectionKey, client, configurationClient, loadEvidence],
  );
  const [loaded, setLoaded] = useState<{
    key: InspectionExecutionKey;
    result: ThousandEyesEvidenceResult;
  }>();
  const [requestState, setRequestState] = useState<{
    key: InspectionExecutionKey;
    state: "loading" | "error" | "cancelled";
    message?: string;
  }>();
  const active = useRef<AbortController>();
  const activeToken = useRef<symbol>();

  useEffect(() => {
    activeToken.current = undefined;
    active.current?.abort();
    active.current = undefined;
    setLoaded(undefined);
    setRequestState(undefined);
    const onPageHide = () => {
      if (!active.current) return;
      activeToken.current = undefined;
      active.current?.abort();
      active.current = undefined;
      setRequestState({
        key: executionKey,
        state: "cancelled",
        message:
          "Search cancelled as navigation started. Optional search cleanup may still be pending.",
      });
    };
    window.addEventListener("pagehide", onPageHide);
    return () => {
      activeToken.current = undefined;
      active.current?.abort();
      active.current = undefined;
      window.removeEventListener("pagehide", onPageHide);
    };
  }, [executionKey]);

  const busy =
    requestState?.key === executionKey && requestState.state === "loading";
  const visibleResult =
    loaded?.key === executionKey ? loaded.result : undefined;
  const visibleMessage =
    requestState?.key === executionKey ? requestState.message : undefined;

  const inspect = async () => {
    if (!selection || busy) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const token = Symbol("thousandeyes-search");
    activeToken.current = token;
    setLoaded(undefined);
    setRequestState({ key: executionKey, state: "loading" });
    try {
      const next = await loadEvidence(
        client,
        selection,
        controller.signal,
        configurationClient,
      );
      if (activeToken.current === token && !controller.signal.aborted) {
        setLoaded({ key: executionKey, result: next });
        setRequestState(undefined);
      }
    } catch (cause) {
      if (activeToken.current === token && !controller.signal.aborted) {
        setRequestState({
          key: executionKey,
          state: "error",
          message:
            cause instanceof Error && cause.name === "SearchAccessDeniedError"
              ? "Access to the selected ThousandEyes evidence search was denied."
              : "ThousandEyes evidence is unavailable. Check source configuration, caller permissions and search completion.",
        });
      }
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
      key: executionKey,
      state: "cancelled",
      message:
        "Search cancelled. Optional search cleanup may still be pending.",
    });
  };

  if (visibleResult)
    return (
      <div className="thousandeyes-inspection">
        <ThousandEyesEvidencePanel
          key={`${visibleResult.selection.selectionId}:${visibleResult.capturedAt}`}
          result={visibleResult}
          compareMeasurements={compareMeasurements}
        />
        <button type="button" onClick={() => void inspect()} disabled={busy}>
          {busy
            ? "Searching ThousandEyes evidence…"
            : "Refresh ThousandEyes evidence"}
        </button>
        {busy && (
          <button type="button" onClick={cancel}>
            Cancel ThousandEyes search
          </button>
        )}
        {busy && <p role="status">Refreshing ThousandEyes evidence…</p>}
        {visibleMessage && <p role="status">{visibleMessage}</p>}
      </div>
    );

  return (
    <section
      className="thousandeyes-evidence thousandeyes-inspection"
      aria-label="Optional ThousandEyes evidence inspection"
    >
      <h3>ThousandEyes synthetic test evidence</h3>
      <p className="te-intro">
        Inspect bounded caller-visible ThousandEyes observations for this scoped
        selection. The search is separate from passive traffic evidence.
      </p>
      {!selection ? (
        <p role="status">No application or endpoint selection is active.</p>
      ) : (
        <>
          <button type="button" onClick={() => void inspect()} disabled={busy}>
            {busy
              ? "Searching ThousandEyes evidence…"
              : requestState?.key === executionKey &&
                  requestState.state === "error"
                ? "Retry ThousandEyes search"
                : "Inspect ThousandEyes evidence"}
          </button>
          {busy && (
            <button type="button" onClick={cancel}>
              Cancel ThousandEyes search
            </button>
          )}
          <p role={requestState?.state === "error" ? "alert" : "status"}>
            {busy
              ? "Loading optional ThousandEyes evidence…"
              : (visibleMessage ??
                "No ThousandEyes search has run. The source remains off unless an administrator selects it.")}
          </p>
        </>
      )}
    </section>
  );
}

function ObservationCard({
  record,
  result,
}: {
  record: ThousandEyesAttributedObservation;
  result: ThousandEyesEvidenceResult;
}) {
  const [copyState, setCopyState] = useState("");
  const exactContext = exactContextText(record);
  const attributionQualified =
    result.state === "complete" &&
    result.schemaQualified &&
    !result.configurationChanged &&
    !result.inputCapped &&
    !result.sourceScanCapped &&
    record.attribution.state === "bound" &&
    !record.quality.stale &&
    record.quality.complete &&
    !record.quality.conflicting &&
    !record.quality.truncated;
  const origin = safeConfiguredOrigin(record.navigationOrigin);
  return (
    <article className="te-observation">
      <header>
        <h5>{familyLabel(record.family)} observation</h5>
        <span className={`te-outcome te-outcome-${record.outcome}`}>
          Reported outcome: {record.outcome}
        </span>
      </header>
      <dl className="te-identity">
        <dt>Authority</dt>
        <dd>
          {record.authority} ({record.authorityBasis.replaceAll("_", " ")})
        </dd>
        <dt>Account group ID</dt>
        <dd>{record.accountGroupId}</dd>
        {record.accountId && (
          <>
            <dt>Producer account ID</dt>
            <dd>{record.accountId}</dd>
          </>
        )}
        {record.organizationId && (
          <>
            <dt>Organization ID</dt>
            <dd>{record.organizationId}</dd>
          </>
        )}
        <dt>Test</dt>
        <dd>
          {record.testName ?? "Name not supplied"}
          {record.testId
            ? ` (ID ${record.testId})`
            : " (native ID not supplied)"}
        </dd>
        <dt>Test domain</dt>
        <dd>{record.testDomain?.toUpperCase() ?? "Not supplied"}</dd>
        {record.relatedTestIds && record.relatedTestIds.length > 0 && (
          <>
            <dt>Related test IDs</dt>
            <dd>
              {reportedIdList(record.relatedTestIds)} (reported; not used as a
              scalar identity join)
            </dd>
          </>
        )}
        <dt>Agent</dt>
        <dd>
          {record.agentName ?? "Name not supplied"}
          {record.agentId
            ? ` (ID ${record.agentId})`
            : " (native ID not supplied)"}
        </dd>
        <dt>Agent location</dt>
        <dd>{record.agentLocation ?? "Not supplied"}</dd>
        {record.relatedAgentIds && record.relatedAgentIds.length > 0 && (
          <>
            <dt>Related agent IDs</dt>
            <dd>
              {reportedIdList(record.relatedAgentIds)} (reported; not used as a
              scalar identity join)
            </dd>
          </>
        )}
        <dt>Stream ID</dt>
        <dd>{record.streamId ?? "Not supplied"}</dd>
        <dt>Monitor ID</dt>
        <dd>{record.monitorId ?? "Not supplied"}</dd>
        <dt>Target agent ID</dt>
        <dd>{record.targetAgentId ?? "Not supplied"}</dd>
        <dt>Target</dt>
        <dd>{targetText(record.target)}</dd>
        <dt>Reported path direction</dt>
        <dd>{record.pathDirection ?? "Not supplied"}</dd>
        <dt>Target proxy flag</dt>
        <dd>
          {record.targetIsProxy === undefined
            ? "Not supplied"
            : record.targetIsProxy
              ? "Yes (explicitly reported)"
              : "No (explicitly reported)"}
        </dd>
        <dt>Configuration ID</dt>
        <dd>{record.configurationId ?? "Not supplied"}</dd>
        <dt>Observation interval</dt>
        <dd>
          {epochTime(record.interval.start)} to {epochTime(record.interval.end)}
          {` · ${record.intervalBasis.replaceAll("_", " ")} basis`}
        </dd>
        <dt>Event time</dt>
        <dd>
          {isoTime(record.eventTime)} ({record.eventTime} epoch seconds)
        </dd>
        <dt>Indexed time</dt>
        <dd>
          {isoTime(record.indexedTime)} ({record.indexedTime} epoch seconds)
        </dd>
        {record.rowTime !== undefined && (
          <>
            <dt>Original Splunk row time (_time)</dt>
            <dd>
              {isoTime(record.rowTime)} ({record.rowTime} epoch seconds) · basis
              not qualified; not measurement time
            </dd>
          </>
        )}
        {record.receiptTime !== undefined && (
          <>
            <dt>Attested Splunk receipt time</dt>
            <dd>
              {isoTime(record.receiptTime)} ({record.receiptTime} epoch seconds;
              not measurement time)
            </dd>
          </>
        )}
        {record.collectionTime !== undefined && (
          <>
            <dt>Collection time</dt>
            <dd>
              {isoTime(record.collectionTime)} ({record.collectionTime} epoch
              seconds)
            </dd>
          </>
        )}
        <dt>Source record</dt>
        <dd>
          {record.index} · {record.source} · {record.sourcetype}
        </dd>
        <dt>Producer version / adapter contract / data model</dt>
        <dd>
          {record.producerVersion === "not_reported"
            ? "Not reported"
            : record.producerVersion}{" "}
          / {record.adapterVersion} / {record.dataModelVersion}
        </dd>
      </dl>
      <div className="te-copy-row">
        <button
          type="button"
          onClick={() => void copyExactContext(exactContext, setCopyState)}
        >
          Copy exact IDs and times
        </button>
        {origin && (
          <a href={origin} target="_blank" rel="noopener noreferrer">
            Open configured ThousandEyes origin
          </a>
        )}
        {copyState && <span role="status">{copyState}</span>}
      </div>

      <QualityFlags record={record} result={result} />
      <section
        className="te-attribution"
        aria-label="ThousandEyes observation attribution"
      >
        <h6>Configured-binding context</h6>
        <p>
          Attribution state:{" "}
          <strong>{record.attribution.state.replaceAll("_", " ")}</strong>
          {record.attribution.bindingIds.length > 0 && (
            <> · Binding IDs: {record.attribution.bindingIds.join(", ")}</>
          )}
        </p>
        <p>{record.attribution.reason}</p>
        <p>
          Attribution module observed-dependency flag:{" "}
          {record.attribution.observedDependency ? "true" : "false"}. This flag
          does not create a passive traffic edge.
        </p>
        <p>
          {attributionQualified
            ? "This observation is qualified only against the configured historical binding shown above; it does not create a passive traffic edge."
            : "Attribution is context only because source qualification, configuration, or record completeness is not established."}
        </p>
      </section>

      {record.measurements.length > 0 ? (
        <MeasurementTable measurements={record.measurements} />
      ) : record.family === "metric" ? (
        <p>No measurement values were supplied for this metric observation.</p>
      ) : null}

      {record.sourceTimes && record.sourceTimes.length > 0 && (
        <SourceTimeTable sourceTimes={record.sourceTimes} />
      )}

      {record.family === "path" && (
        <MeasuredPath
          hops={record.hops}
          direction={record.pathDirection}
          targetIsProxy={record.targetIsProxy}
        />
      )}
      {record.family === "trace" && <SyntheticTrace spans={record.spans} />}
      {(record.family === "event" || record.family === "alert") && (
        <Lifecycle lifecycle={record.lifecycle} family={record.family} />
      )}
      {record.family === "activity" && <Activity activity={record.activity} />}

      {record.limitations.length > 0 && (
        <details className="te-limitations">
          <summary>Observation limits ({record.limitations.length})</summary>
          <ul>
            {record.limitations
              .slice(0, MAX_VISIBLE_RECORDS)
              .map((item, index) => (
                <li key={`${index}:${item}`}>{item}</li>
              ))}
          </ul>
          {record.limitations.length > MAX_VISIBLE_RECORDS && (
            <p>
              Showing the first {MAX_VISIBLE_RECORDS} of{" "}
              {record.limitations.length} limitations.
            </p>
          )}
        </details>
      )}
    </article>
  );
}

function QualityFlags({
  record,
  result,
}: {
  record: ThousandEyesAttributedObservation;
  result: ThousandEyesEvidenceResult;
}) {
  const flags = [
    record.quality.stale
      ? "stale or cached measurement evidence"
      : "not marked stale/cached",
    record.quality.complete
      ? "record structurally complete"
      : "record incomplete",
    record.quality.conflicting
      ? "conflicting identity or content"
      : "no conflict marked",
    record.quality.truncated ? "record truncated" : "not marked truncated",
  ];
  if (result.configurationChanged)
    flags.push("configuration changed during search");
  if (result.inputCapped || result.sourceScanCapped)
    flags.push("input scan capped");
  if (result.outputCapped) flags.push("display output capped");
  if (!result.schemaQualified) flags.push("source schema unqualified");
  if (result.receiptFreshness?.state === "stale")
    flags.push("stale indexed-receipt age");
  return (
    <p className="te-record-quality" aria-label="Record quality">
      <strong>Quality:</strong> {flags.join(" · ")}
    </p>
  );
}

function MeasurementTable({
  measurements,
}: {
  measurements: ThousandEyesAttributedObservation["measurements"];
}) {
  const displayed = measurements.slice(0, MAX_VISIBLE_RECORDS);
  return (
    <div
      className="te-table-scroll"
      tabIndex={0}
      aria-label="Scrollable measurements table"
    >
      <table>
        <caption>Reported measurements, with native units and basis</caption>
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">Value</th>
            <th scope="col">Unit (source unit)</th>
            <th scope="col">Aggregation</th>
            <th scope="col">Direction</th>
            <th scope="col">Denominator</th>
            <th scope="col">Time basis</th>
          </tr>
        </thead>
        <tbody>
          {displayed.map((measurement, index) => (
            <tr key={`${measurement.name}:${index}`}>
              <th scope="row">{measurement.name}</th>
              <td>{finiteValue(measurement.value)}</td>
              <td>
                {measurement.unit}
                {measurement.sourceUnit ? ` (${measurement.sourceUnit})` : ""}
              </td>
              <td>{measurement.aggregation || "Not supplied"}</td>
              <td>{measurement.direction || "Not supplied"}</td>
              <td>{measurement.denominator || "Not supplied"}</td>
              <td>{measurement.timeBasis || "Not supplied"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {measurements.length > displayed.length && (
        <p>
          Showing {displayed.length} of {measurements.length} supplied
          measurements.
        </p>
      )}
    </div>
  );
}

function SourceTimeTable({
  sourceTimes,
}: {
  sourceTimes: NonNullable<ThousandEyesAttributedObservation["sourceTimes"]>;
}) {
  const displayed = sourceTimes.slice(0, MAX_VISIBLE_RECORDS);
  return (
    <section
      className="te-source-times"
      aria-label="Exact normalized source timestamps"
    >
      <h6>Source timestamps</h6>
      <p>
        Values are copied from the normalized record with their source units;
        they are not converted or substituted for the inspected receipt time.
      </p>
      <div
        className="te-table-scroll"
        tabIndex={0}
        aria-label="Scrollable source timestamp table"
      >
        <table>
          <caption>Timestamp field values and units</caption>
          <thead>
            <tr>
              <th scope="col">Source field</th>
              <th scope="col">Exact value</th>
              <th scope="col">Unit</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((item, index) => (
              <tr key={`${item.field}:${index}`}>
                <th scope="row">{item.field}</th>
                <td>
                  <code>{item.value}</code>
                </td>
                <td>{item.unit}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {sourceTimes.length > displayed.length && (
          <p>
            Showing {displayed.length} of {sourceTimes.length} source
            timestamps.
          </p>
        )}
      </div>
    </section>
  );
}

function MeasuredPath({
  hops,
  direction,
  targetIsProxy,
}: {
  hops: ThousandEyesHop[];
  direction?: "to-target" | "from-target";
  targetIsProxy?: boolean;
}) {
  const sorted = hops
    .map((hop, index) => ({ hop, index }))
    .sort(
      (left, right) =>
        (left.hop.pathId ?? "").localeCompare(right.hop.pathId ?? "") ||
        left.hop.number - right.hop.number,
    );
  const ordered = sorted.slice(0, MAX_VISIBLE_RECORDS);
  const pathGroups = new Map<string | undefined, typeof ordered>();
  for (const entry of ordered) {
    const path = entry.hop.pathId;
    pathGroups.set(path, [...(pathGroups.get(path) ?? []), entry]);
  }
  return (
    <section
      className="te-measured-path"
      aria-label="Measured ThousandEyes probe path"
    >
      <h6>Measured probe path</h6>
      <p>
        These are ordered probe observations for this test and interval. They
        are not an inventory candidate route; missing hops do not establish
        forwarding loss or a complete network route.
      </p>
      <p>Reported path direction: {direction ?? "Not supplied"}.</p>
      {targetIsProxy === true && (
        <p className="te-notice">
          The target is explicitly marked as a proxy. This result characterizes
          only the reported probe target; downstream path coverage is unknown.
        </p>
      )}
      {ordered.length === 0 ? (
        <p>No path hops were supplied for this observation.</p>
      ) : (
        <div
          className="te-table-scroll"
          tabIndex={0}
          aria-label="Scrollable measured path table"
        >
          <table>
            <caption>
              Path iterations and probe-reported hop measurements
            </caption>
            <thead>
              <tr>
                <th scope="col">Hop</th>
                <th scope="col">Path ID</th>
                <th scope="col">Reported address / name</th>
                <th scope="col">Prefix / network</th>
                <th scope="col">Latency (ms)</th>
                <th scope="col">Loss (%)</th>
                <th scope="col">Availability</th>
              </tr>
            </thead>
            <tbody>
              {[...pathGroups.entries()].map(([pathId, entries]) => (
                <Fragment key={pathId ?? "path-id-unavailable"}>
                  <tr className="te-path-iteration">
                    <th scope="rowgroup" colSpan={7}>
                      {pathId === undefined
                        ? "Path iteration ID not supplied; these are unassigned hops, not one inferred route"
                        : `Path iteration ID ${pathId}`}
                    </th>
                  </tr>
                  {entries.map(({ hop, index }) => (
                    <tr
                      key={`${hop.number}:${hop.ip ?? hop.name ?? "missing"}:${index}`}
                    >
                      <th scope="row">{hop.number}</th>
                      <td>{hop.pathId ?? "Not supplied"}</td>
                      <td>{hop.ip ?? hop.name ?? "Address not supplied"}</td>
                      <td>
                        {[hop.prefix, hop.network]
                          .filter(Boolean)
                          .join(" · ") || "Not supplied"}
                      </td>
                      <td>{finiteValue(hop.latencyMilliseconds)}</td>
                      <td>{finiteValue(hop.lossPercent)}</td>
                      <td>
                        {hop.missing ? "Hop marked missing" : "Hop reported"}
                      </td>
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
          {sorted.length > ordered.length && (
            <p>
              Showing {ordered.length} of {sorted.length} supplied hops.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function SyntheticTrace({
  spans,
}: {
  spans: ThousandEyesAttributedObservation["spans"];
}) {
  const displayed = spans.slice(0, MAX_VISIBLE_RECORDS);
  return (
    <section className="te-trace" aria-label="Synthetic trace spans">
      <h6>Synthetic trace spans</h6>
      <p>
        These spans come from a ThousandEyes synthetic test. They are not
        production service-call edges. Start and end values retain the
        normalized source time basis; no conversion is inferred here.
      </p>
      {spans.length === 0 ? (
        <p>No spans were supplied for this trace observation.</p>
      ) : (
        <div
          className="te-table-scroll"
          tabIndex={0}
          aria-label="Scrollable synthetic spans table"
        >
          <table>
            <caption>Span hierarchy identifiers and source times</caption>
            <thead>
              <tr>
                <th scope="col">Trace ID</th>
                <th scope="col">Span</th>
                <th scope="col">Parent span</th>
                <th scope="col">Name</th>
                <th scope="col">Start (normalized value)</th>
                <th scope="col">End (normalized value)</th>
                <th scope="col">Source start (Unix ns)</th>
                <th scope="col">Source end (Unix ns)</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map((span, index) => (
                <tr key={`${span.traceId}:${span.spanId}:${index}`}>
                  <td>
                    <code>{span.traceId}</code>
                  </td>
                  <td>
                    <code>{span.spanId}</code>
                  </td>
                  <td>
                    <code>{span.parentSpanId ?? "Not supplied"}</code>
                  </td>
                  <td>{span.name}</td>
                  <td>{span.start}</td>
                  <td>{span.end}</td>
                  <td>
                    <code>{span.startTimeUnixNano ?? "Not supplied"}</code>
                  </td>
                  <td>
                    <code>{span.endTimeUnixNano ?? "Not supplied"}</code>
                  </td>
                  <td>{span.status ?? "Not supplied"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {spans.length > displayed.length && (
            <p>
              Showing {displayed.length} of {spans.length} supplied spans.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function Lifecycle({
  lifecycle,
  family,
}: {
  lifecycle: ThousandEyesAttributedObservation["lifecycle"];
  family: "event" | "alert";
}) {
  return (
    <section
      className="te-lifecycle"
      aria-label="ThousandEyes event and alert lifecycle"
    >
      <h6>
        {family === "event" ? "Detected event lifecycle" : "Alert lifecycle"}
      </h6>
      {!lifecycle ? (
        <p>No lifecycle details were supplied for this observation.</p>
      ) : (
        <dl>
          <dt>Lifecycle ID</dt>
          <dd>{lifecycle.id}</dd>
          <dt>Type / state</dt>
          <dd>
            {lifecycle.type ?? "Not supplied"} /{" "}
            {lifecycle.state ?? "Not supplied"}
          </dd>
          <dt>Severity</dt>
          <dd>{lifecycle.severity ?? "Not supplied"}</dd>
          <dt>Title</dt>
          <dd>{lifecycle.title ?? "Not supplied"}</dd>
          <dt>Started</dt>
          <dd>
            {lifecycle.startedAt === undefined
              ? "Not supplied"
              : epochTime(lifecycle.startedAt)}
          </dd>
          <dt>Ended</dt>
          <dd>
            {lifecycle.endedAt === undefined
              ? "Not supplied"
              : epochTime(lifecycle.endedAt)}
          </dd>
          <dt>History flag</dt>
          <dd>
            {lifecycle.historyComplete
              ? "Source reports this record's history complete"
              : "Source history is incomplete or unverified"}
          </dd>
        </dl>
      )}
      <p>
        Silence or an absent lifecycle record does not establish that no event
        or alert occurred.
      </p>
    </section>
  );
}

function Activity({
  activity,
}: {
  activity: ThousandEyesAttributedObservation["activity"];
}) {
  return (
    <section className="te-activity" aria-label="ThousandEyes activity">
      <h6>ThousandEyes-only activity</h6>
      {!activity ? (
        <p>No activity details were supplied for this observation.</p>
      ) : (
        <dl>
          <dt>Action</dt>
          <dd>{activity.action}</dd>
          <dt>Actor</dt>
          <dd>{activity.actor ?? "Not supplied"}</dd>
          <dt>Object</dt>
          <dd>
            {activity.objectType ?? "Type not supplied"} ·{" "}
            {activity.objectId ?? "ID not supplied"}
          </dd>
          <dt>Activity ID</dt>
          <dd>{activity.id ?? "Not supplied"}</dd>
        </dl>
      )}
      <p>
        These are changes reported by ThousandEyes; they are not general
        infrastructure change history.
      </p>
    </section>
  );
}

function ComparisonSection({
  records,
  nativeMeasurementWindow,
  compareMeasurements,
  blockedReason,
}: {
  records: readonly ThousandEyesAttributedObservation[];
  nativeMeasurementWindow: EvidenceWindow;
  compareMeasurements: ThousandEyesMeasurementComparator;
  blockedReason?: string;
}) {
  const midpoint =
    nativeMeasurementWindow.start +
    (nativeMeasurementWindow.end - nativeMeasurementWindow.start) / 2;
  const [before, setBefore] = useState<EvidenceWindow>({
    start: nativeMeasurementWindow.start,
    end: midpoint,
  });
  const [after, setAfter] = useState<EvidenceWindow>({
    start: midpoint,
    end: nativeMeasurementWindow.end,
  });
  const [comparisonSnapshot, setComparisonSnapshot] = useState<{
    records: readonly ThousandEyesAttributedObservation[];
    comparator: ThousandEyesMeasurementComparator;
    values: ThousandEyesComparison[];
  }>();
  const comparisons =
    comparisonSnapshot?.records === records &&
    comparisonSnapshot.comparator === compareMeasurements
      ? comparisonSnapshot.values
      : undefined;
  const [error, setError] = useState("");
  const valid =
    validWindow(before) &&
    validWindow(after) &&
    before.end <= after.start &&
    before.start >= nativeMeasurementWindow.start &&
    before.end <= nativeMeasurementWindow.end &&
    after.start >= nativeMeasurementWindow.start &&
    after.end <= nativeMeasurementWindow.end;
  const update = (
    setter: Dispatch<SetStateAction<EvidenceWindow>>,
    edge: "start" | "end",
    value: string,
  ) => {
    const seconds = Date.parse(value) / 1000;
    if (!Number.isFinite(seconds)) return;
    setter((previous) => ({ ...previous, [edge]: seconds }));
    setComparisonSnapshot(undefined);
    setError("");
  };
  const run = () => {
    if (!valid) return;
    try {
      setComparisonSnapshot({
        records,
        comparator: compareMeasurements,
        values: compareMeasurements(records, before, after),
      });
      setError("");
    } catch {
      setComparisonSnapshot(undefined);
      setError(
        "The supplied comparator could not produce a defensible comparison for these windows.",
      );
    }
  };
  return (
    <section
      className="te-comparison"
      aria-label="ThousandEyes before and after measurement comparison"
    >
      <h4>Before / after measurement comparison</h4>
      <p>
        Comparison uses only the injected ThousandEyes comparator and
        observations matching the current filters in this result. Both windows
        must stay inside the native measurement window; no values or missing
        test coverage are filled in. Window inputs use the browser's local time
        and are passed to the comparator as epoch seconds.
      </p>
      {blockedReason ? (
        <p className="te-notice" role="status">
          Comparison unavailable: {blockedReason}
        </p>
      ) : (
        <>
          <WindowEditor
            label="Before window"
            value={before}
            onChange={(edge, value) => update(setBefore, edge, value)}
          />
          <WindowEditor
            label="After window"
            value={after}
            onChange={(edge, value) => update(setAfter, edge, value)}
          />
          {!valid && (
            <p className="te-notice" role="status">
              Choose ordered, non-overlapping windows inside the native
              measurement window ({epochTime(nativeMeasurementWindow.start)} to{" "}
              {epochTime(nativeMeasurementWindow.end)}).
            </p>
          )}
          <button type="button" onClick={run} disabled={!valid}>
            Compare loaded measurements
          </button>
          {error && <p role="alert">{error}</p>}
          {comparisons &&
            (comparisons.length === 0 ? (
              <p role="status">
                No comparable measurement groups were returned for these
                windows.
              </p>
            ) : (
              <div
                className="te-table-scroll"
                tabIndex={0}
                aria-label="Scrollable before and after comparison table"
              >
                <table>
                  <caption>
                    Comparator results by authority, account group, test domain,
                    native identity, metric and unit
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Authority / account group</th>
                      <th scope="col">Test domain / ID</th>
                      <th scope="col">Agent ID / location</th>
                      <th scope="col">Metric / unit</th>
                      <th scope="col">Before mean / count</th>
                      <th scope="col">After mean / count</th>
                      <th scope="col">Delta</th>
                      <th scope="col">Comparability</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisons.slice(0, MAX_VISIBLE_RECORDS).map((item) => (
                      <tr key={item.key}>
                        <td>
                          {item.authority} / {item.accountGroupId}
                        </td>
                        <td>
                          {item.testDomain?.toUpperCase() ??
                            "Domain not supplied"}{" "}
                          / {item.testId}
                        </td>
                        <td>
                          {item.agentId}
                          {item.agentLocation ? ` · ${item.agentLocation}` : ""}
                        </td>
                        <td>
                          {item.metric} ({item.unit})
                        </td>
                        <td>
                          {finiteValue(item.beforeMean)} / {item.beforeCount}
                        </td>
                        <td>
                          {finiteValue(item.afterMean)} / {item.afterCount}
                        </td>
                        <td>
                          {finiteValue(item.delta)}
                          {item.delta !== undefined ? ` ${item.unit}` : ""}
                        </td>
                        <td>
                          {item.comparable ? "Comparable" : "Not comparable"}
                          {item.reasons.length > 0 && (
                            <ul>
                              {item.reasons
                                .slice(0, MAX_VISIBLE_RECORDS)
                                .map((reason, index) => (
                                  <li key={`${index}:${reason}`}>{reason}</li>
                                ))}
                            </ul>
                          )}
                          {item.reasons.length > MAX_VISIBLE_RECORDS && (
                            <p>
                              Showing the first {MAX_VISIBLE_RECORDS} comparison
                              reasons.
                            </p>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {comparisons.length > MAX_VISIBLE_RECORDS && (
                  <p>
                    Showing {MAX_VISIBLE_RECORDS} of {comparisons.length}{" "}
                    comparator rows.
                  </p>
                )}
              </div>
            ))}
        </>
      )}
    </section>
  );
}

function WindowEditor({
  label,
  value,
  onChange,
}: {
  label: string;
  value: EvidenceWindow;
  onChange: (edge: "start" | "end", value: string) => void;
}) {
  return (
    <fieldset className="te-window-editor">
      <legend>{label} (browser local time)</legend>
      <label>
        Start
        <input
          type="datetime-local"
          step="0.001"
          value={localDateTime(value.start)}
          onChange={(event) => onChange("start", event.target.value)}
        />
      </label>
      <label>
        End
        <input
          type="datetime-local"
          step="0.001"
          value={localDateTime(value.end)}
          onChange={(event) => onChange("end", event.target.value)}
        />
      </label>
    </fieldset>
  );
}

function resultStatus(result: ThousandEyesEvidenceResult): string {
  if (result.state === "not_selected")
    return "ThousandEyes source not selected. An administrator must select and qualify it before evidence can be searched.";
  if (result.state === "staged")
    return "ThousandEyes source is staged; no search was run.";
  if (result.errorCode === "denied")
    return "Access denied while reading ThousandEyes evidence. The source was not available to this caller.";
  if (
    result.state === "unavailable" &&
    (result.errorCode === "completion" || result.errorCode === "normalization")
  )
    return "ThousandEyes evidence is incomplete; search completion or record normalization could not be verified.";
  if (result.state === "unavailable" && !result.schemaQualified)
    return "ThousandEyes source is unqualified and unavailable; its records cannot support attribution.";
  if (result.state === "unavailable")
    return "ThousandEyes evidence is unavailable. Search completion, permissions, or source configuration could not be verified.";
  const count = `${result.records.length} returned observation${result.records.length === 1 ? "" : "s"}`;
  const qualifiers = [
    result.configurationChanged ? "configuration changed" : "",
    result.inputCapped || result.sourceScanCapped ? "input scan capped" : "",
    result.outputCapped ? "display capped" : "",
    result.rejected
      ? `${result.rejected} malformed or conflicting rows rejected`
      : "",
    !result.schemaQualified ? "schema unqualified" : "",
  ].filter(Boolean);
  return `Search complete: ${count}${qualifiers.length ? `; ${qualifiers.join("; ")}` : ""}.`;
}

function resultIssues(
  result: ThousandEyesEvidenceResult,
  displayedRecords: readonly ThousandEyesAttributedObservation[],
): string[] {
  const issues: string[] = [];
  if (result.configurationChanged)
    issues.push(
      "Configuration changed during the search; displayed records are stale context until refreshed.",
    );
  if (result.inputCapped || result.sourceScanCapped)
    issues.push(
      "The input scan was capped; the returned observations are an incomplete subset.",
    );
  if (result.outputCapped)
    issues.push(
      "The display result was capped; other matching observations may be omitted.",
    );
  if (result.sourceScanInvalidCount)
    issues.push(
      `${result.sourceScanInvalidCount} source-scan records were invalid or could not be normalized.`,
    );
  if (result.oversized)
    issues.push(
      `${result.oversized} oversized source record(s) were excluded.`,
    );
  if (result.rejected)
    issues.push(
      `${result.rejected} malformed or conflicting record(s) were rejected.`,
    );
  if (!result.schemaQualified)
    issues.push(
      "Source schema is not qualified; records remain source context only.",
    );
  if (displayedRecords.some((record) => record.quality.stale))
    issues.push(
      "At least one observation is explicitly marked stale or cached; affected records remain context only.",
    );
  if (displayedRecords.some((record) => !record.quality.complete))
    issues.push("At least one observation is structurally incomplete.");
  if (displayedRecords.some((record) => record.quality.conflicting))
    issues.push(
      "At least one observation has conflicting identity or content.",
    );
  if (displayedRecords.some((record) => record.quality.truncated))
    issues.push("At least one observation was truncated.");
  if (result.records.length > MAX_VISIBLE_RECORDS)
    issues.push(
      `The display is limited to ${MAX_VISIBLE_RECORDS} observations; additional records in the result were not rendered.`,
    );
  if (
    displayedRecords.some((record) => record.attribution.state === "ambiguous")
  )
    issues.push(
      "At least one observation has ambiguous configured-binding attribution.",
    );
  if (result.receiptFreshness?.state === "stale") {
    const latest = result.receiptFreshness.latestIndexedTime;
    const age =
      latest === undefined
        ? ""
        : ` Latest selected evidence-index receipt: ${epochTime(latest)}.`;
    issues.push(
      `The selected evidence-index receipt is stale as of ${epochTime(result.receiptFreshness.assessedAt)}.${age} This is receipt-age context only and does not invalidate historical measurements or their time-qualified comparisons.`,
    );
  } else if (result.receiptFreshness?.state === "historical") {
    issues.push(
      "The selected evidence-index receipt is historical. Historical age alone does not invalidate time-qualified measurement comparisons.",
    );
  } else if (result.receiptFreshness?.state === "unknown") {
    issues.push(
      "Freshness of the selected evidence-index receipt could not be assessed.",
    );
  } else if (result.receiptFreshness?.state === "observed_receipt") {
    issues.push(
      "A selected evidence-index receipt was observed. This does not establish collection health or upstream history coverage.",
    );
  }
  return issues;
}

function validWindow(window: EvidenceWindow): boolean {
  return (
    Number.isFinite(window.start) &&
    Number.isFinite(window.end) &&
    window.start >= 0 &&
    window.end > window.start
  );
}

function comparisonBlockedReason(
  result: ThousandEyesEvidenceResult,
  displayedRecords: readonly ThousandEyesAttributedObservation[],
): string | undefined {
  if (!result.schemaQualified) return "the source schema is unqualified.";
  if (result.configurationChanged)
    return "the source configuration changed during the search.";
  if (result.inputCapped || result.sourceScanCapped)
    return "the input scan was capped.";
  if (result.outputCapped || result.records.length > MAX_VISIBLE_RECORDS)
    return "the result set is capped.";
  if (result.rejected || result.oversized || result.sourceScanInvalidCount)
    return "some source records were rejected, oversized, or not normalized.";
  if (
    displayedRecords.some(
      (record) =>
        record.quality.stale ||
        !record.quality.complete ||
        record.quality.conflicting ||
        record.quality.truncated,
    )
  )
    return "one or more observations are stale, incomplete, conflicting, or truncated.";
  return undefined;
}

function familyLabel(family: ThousandEyesFamily): string {
  const labels: Record<ThousandEyesFamily, string> = {
    metric: "Metric",
    path: "Path",
    trace: "Trace",
    event: "Detected event",
    alert: "Alert",
    activity: "Activity",
  };
  return labels[family];
}

function observationKey(
  record: ThousandEyesAttributedObservation,
  index: number,
): string {
  return `${record.family}:${record.fingerprint}:${record.eventTime}:${index}`;
}

function testKey(record: ThousandEyesAttributedObservation): string {
  const scope = `${record.authority}:${record.accountGroupId}:${record.testDomain ?? "unknown-domain"}`;
  return record.testId
    ? `${scope}:id:${record.testId}`
    : record.testName
      ? `${scope}:name:${record.testName}`
      : `${scope}:unknown-test`;
}
function agentKey(record: ThousandEyesAttributedObservation): string {
  const scope = `${record.authority}:${record.accountGroupId}`;
  return record.agentId
    ? `${scope}:id:${record.agentId}`
    : record.agentName
      ? `${scope}:name:${record.agentName}`
      : `${scope}:unknown-agent`;
}
function locationKey(record: ThousandEyesAttributedObservation): string {
  return record.agentLocation ?? "unknown:location";
}
function testLabel(record: ThousandEyesAttributedObservation): string {
  return `${record.testName ?? "Test name not supplied"} (${record.testDomain?.toUpperCase() ?? "domain not supplied"} ${record.testId ? `ID ${record.testId}` : "native ID not supplied"}) · ${record.authority} / group ${record.accountGroupId}`;
}
function agentLabel(record: ThousandEyesAttributedObservation): string {
  return `${record.agentName ?? "Agent name not supplied"} (${record.agentId ? `ID ${record.agentId}` : "native ID not supplied"}) · ${record.authority} / group ${record.accountGroupId}`;
}
function locationLabel(record: ThousandEyesAttributedObservation): string {
  return record.agentLocation ?? "Location not supplied";
}
function filterOptions(
  records: readonly ThousandEyesAttributedObservation[],
  keyFor: (record: ThousandEyesAttributedObservation) => string,
  labelFor: (record: ThousandEyesAttributedObservation) => string,
): { value: string; label: string }[] {
  const byKey = new Map<string, string>();
  for (const record of records) byKey.set(keyFor(record), labelFor(record));
  return [...byKey.entries()]
    .map(([value, label]) => ({ value, label }))
    .sort((left, right) => left.label.localeCompare(right.label));
}
function groupLabel(groupBy: "test" | "agent" | "location" | "family"): string {
  return groupBy === "test"
    ? "Test"
    : groupBy === "agent"
      ? "Agent"
      : groupBy === "location"
        ? "Agent location"
        : "Family";
}
function groupTitle(
  groupBy: "test" | "agent" | "location" | "family",
  record: ThousandEyesAttributedObservation,
): string {
  return groupBy === "test"
    ? testLabel(record)
    : groupBy === "agent"
      ? agentLabel(record)
      : groupBy === "location"
        ? locationLabel(record)
        : familyLabel(record.family);
}
function targetText(
  target: ThousandEyesAttributedObservation["target"],
): string {
  const rawHost = target.ip ?? target.hostname ?? "Not supplied";
  const host =
    rawHost.includes(":") && !rawHost.startsWith("[")
      ? `[${rawHost}]`
      : rawHost;
  return `${host}${target.protocol ? ` · ${target.protocol}` : ""}${target.port ? ` · port ${target.port}` : ""}`;
}
function reportedIdList(values: readonly string[]): string {
  const displayed = values.slice(0, MAX_VISIBLE_RECORDS);
  return `${displayed.join(", ")}${values.length > displayed.length ? ` (showing ${displayed.length} of ${values.length})` : ""}`;
}
function finiteValue(value: number | undefined): string {
  return value !== undefined && Number.isFinite(value)
    ? String(value)
    : "Not supplied";
}
function isoTime(value: number): string {
  const date = new Date(value * 1000);
  return Number.isFinite(date.getTime())
    ? date.toISOString()
    : "Time unavailable";
}
function epochTime(value: number): string {
  return `${isoTime(value)} (${value} epoch seconds)`;
}
function localDateTime(value: number): string {
  const date = new Date(value * 1000);
  if (!Number.isFinite(date.getTime())) return "";
  const pad = (number: number) => String(number).padStart(2, "0");
  const milliseconds = date.getMilliseconds();
  const fraction = milliseconds
    ? `.${String(milliseconds).padStart(3, "0")}`
    : "";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${fraction}`;
}
function safeConfiguredOrigin(value?: string): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (value !== url.origin && value !== `${url.origin}/`)
    )
      return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}
function exactContextText(record: ThousandEyesAttributedObservation): string {
  const lines = [
    `Family: ${record.family}`,
    `Authority: ${record.authority}`,
    `Authority basis: ${record.authorityBasis}`,
    `Account group ID: ${record.accountGroupId}`,
    `Producer account ID: ${record.accountId ?? "not supplied"}`,
    `Organization ID: ${record.organizationId ?? "not supplied"}`,
    `Test domain: ${record.testDomain ?? "not supplied"}`,
    `Test ID: ${record.testId ?? "not supplied"}`,
    `Related test IDs: ${reportedIdList(record.relatedTestIds ?? []) || "not supplied"}`,
    `Agent ID: ${record.agentId ?? "not supplied"}`,
    `Related agent IDs: ${reportedIdList(record.relatedAgentIds ?? []) || "not supplied"}`,
    `Stream ID: ${record.streamId ?? "not supplied"}`,
    `Monitor ID: ${record.monitorId ?? "not supplied"}`,
    `Target agent ID: ${record.targetAgentId ?? "not supplied"}`,
    `Reported path direction: ${record.pathDirection ?? "not supplied"}`,
    `Target proxy flag: ${record.targetIsProxy === undefined ? "not supplied" : record.targetIsProxy}`,
    `Path IDs: ${
      [
        ...new Set(
          record.hops
            .slice(0, MAX_VISIBLE_RECORDS)
            .map((hop) => hop.pathId)
            .filter((id): id is string => !!id),
        ),
      ].join(", ") || "not supplied"
    }`,
    `Configuration ID: ${record.configurationId ?? "not supplied"}`,
    `Record fingerprint: ${record.fingerprint}`,
    `Event time epoch seconds: ${record.eventTime}`,
    `Event time UTC: ${isoTime(record.eventTime)}`,
    `Indexed time epoch seconds: ${record.indexedTime}`,
    `Indexed time UTC: ${isoTime(record.indexedTime)}`,
    `Original Splunk row time _time epoch seconds: ${record.rowTime ?? "not supplied"}`,
    ...(record.rowTime === undefined
      ? []
      : [
          `Original Splunk row time basis: unqualified; ${isoTime(record.rowTime)}`,
        ]),
    `Attested Splunk receipt time epoch seconds: ${record.receiptTime ?? "not supplied"}`,
    ...(record.receiptTime === undefined
      ? []
      : [`Attested Splunk receipt time UTC: ${isoTime(record.receiptTime)}`]),
    `Interval start epoch seconds: ${record.interval.start}`,
    `Interval end epoch seconds: ${record.interval.end}`,
    `Interval basis: ${record.intervalBasis}`,
    `Source timestamps: ${
      (record.sourceTimes ?? [])
        .slice(0, MAX_VISIBLE_RECORDS)
        .map((item) => `${item.field}=${item.value} ${item.unit}`)
        .join("; ") || "not supplied"
    }`,
    `Lifecycle ID: ${record.lifecycle?.id ?? "not supplied"}`,
    `Activity ID: ${record.activity?.id ?? "not supplied"}`,
    `Trace IDs: ${[...new Set(record.spans.slice(0, MAX_VISIBLE_RECORDS).map((span) => span.traceId))].join(", ") || "not supplied"}`,
    `Span IDs: ${
      record.spans
        .slice(0, MAX_VISIBLE_RECORDS)
        .map((span) => span.spanId)
        .join(", ") || "not supplied"
    }`,
    `Parent span IDs: ${
      [
        ...new Set(
          record.spans
            .slice(0, MAX_VISIBLE_RECORDS)
            .map((span) => span.parentSpanId)
            .filter((id): id is string => !!id),
        ),
      ].join(", ") || "not supplied"
    }`,
    `Span source times: ${
      record.spans
        .slice(0, MAX_VISIBLE_RECORDS)
        .map(
          (span) =>
            `${span.spanId}: ${span.startTimeUnixNano ?? span.start} to ${span.endTimeUnixNano ?? span.end}`,
        )
        .join("; ") || "not supplied"
    }`,
  ];
  return lines.join("\n");
}
async function copyExactContext(
  value: string,
  setState: (message: string) => void,
) {
  try {
    if (!navigator.clipboard?.writeText)
      throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(value);
    setState("Exact IDs and epoch times copied.");
  } catch {
    setState("Copy unavailable. The exact values remain selectable above.");
  }
}
