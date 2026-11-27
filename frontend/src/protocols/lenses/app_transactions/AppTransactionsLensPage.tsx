import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
  ProtocolTimelineEvent,
} from "../../shared/contract";
import {
  formatBytes,
  formatCount,
  formatDurationMs,
} from "../../shared/format";
import {
  checkStreamEstimateMode,
  type StreamReadinessEntry,
} from "../../shared/streamReadiness";
import {
  CopyableIp,
  DistributionBar,
  HeatMatrix,
  ProtocolLensLayout,
  StatusChip,
  SwimlaneTimeline,
  type BannerState,
  type ProtocolTableColumn,
} from "../../shared/ui";
import {
  APP_TRANSACTIONS_STREAM_IDS,
  buildAppTransactionsRawEventsUrl,
  investigateAppTransactions,
  resolveAppTransactionsThresholds,
  type AppTransactionsInvestigationResult,
  type AppTransactionsServiceRow,
  type AppTransactionsSourcetype,
  type AppTransactionsStreamId,
} from "./adapter";

export interface AppTransactionsLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: AppTransactionsInvestigationResult;
  /** Optional override to skip live KVStore config recheck in isolated test harnesses. */
  skipConfigRecheck?: boolean;
}

interface QueryStamp {
  scope: string;
  earliest: number;
  latest: number;
  filterKey: string;
}

function serializeFilter(filter: ProtocolLensComponentProps["filter"]): string {
  if (!filter) return "";
  return JSON.stringify(
    Object.entries(filter)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b)),
  );
}

function safeRawEventsUrl(options: {
  index: string;
  serverIp: string;
  destPort?: number;
  sourcetypes: readonly AppTransactionsSourcetype[];
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildAppTransactionsRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

function streamIdsForProfiles(
  profiles: readonly { extra?: Record<string, unknown> }[],
): AppTransactionsStreamId[] {
  const ids = new Set<AppTransactionsStreamId>();
  for (const p of profiles) {
    const sk = resolveAppTransactionsThresholds(p).sourceKind;
    if (sk === "http" || sk === "auto") ids.add("http");
    if (sk === "db" || sk === "auto") {
      ids.add("mysql");
      ids.add("postgres");
      ids.add("tds");
      ids.add("tns");
    }
  }
  return ids.size ? [...ids] : [...APP_TRANSACTIONS_STREAM_IDS];
}

function summarizeStreamEntries(entries: readonly StreamReadinessEntry[]): {
  hasEstimateOnly: boolean;
  hasEnabled: boolean;
  detail: string;
  names: string;
} {
  const estimate = entries.filter((e) => e.state === "estimate_only");
  const enabled = entries.filter((e) => e.state === "enabled");
  if (estimate.length > 0) {
    const names = estimate.map((e) => e.streamId).join(", ");
    const detail =
      estimate.length === 1
        ? estimate[0].detail
        : `Stream ${names} are in Estimate mode (statsOnly=true); switch to Enabled to index transaction events.`;
    return {
      hasEstimateOnly: true,
      hasEnabled: enabled.length > 0,
      detail,
      names,
    };
  }
  return {
    hasEstimateOnly: false,
    hasEnabled: enabled.length > 0,
    detail:
      entries[0]?.detail ??
      "No recent stream:stats telemetry observed for configured transaction streams.",
    names: "",
  };
}

export function AppTransactionsLensPage({
  client,
  live,
  scope,
  scopes,
  earliest,
  latest,
  view,
  filter,
  selectedItem,
  configuration,
  profileValidators,
  onChangeParams,
  onBackToHub,
  onRefreshConfig,
  initialResult,
  skipConfigRecheck,
}: AppTransactionsLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: AppTransactionsInvestigationResult } | undefined
  >(() =>
    initialResult
      ? { stamp: currentStampKey, value: initialResult }
      : undefined,
  );
  const stampedResultRef = useRef(stampedResult);
  stampedResultRef.current = stampedResult;
  const [streamModeNotice, setStreamModeNotice] = useState<
    { state: BannerState; reason: string; verdict?: string } | undefined
  >();
  const [missingCell, setMissingCell] = useState<
    { row: string; col: string; status: ProtocolStatus } | undefined
  >();
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (initialResult) {
      setStampedResult({
        stamp: currentStampRef.current,
        value: initialResult,
      });
    } else {
      setStampedResult(undefined);
    }
  }, [initialResult]);

  // Abort any in-flight search whenever scope, UTC window, or filters change.
  const prevStampRef = useRef<string>(currentStampKey);
  useEffect(() => {
    if (prevStampRef.current !== currentStampKey) {
      prevStampRef.current = currentStampKey;
      abortRef.current?.abort();
      abortRef.current = null;
      setBusy(false);
      setMissingCell(undefined);
      setStreamModeNotice(undefined);
      if (!initialResult) {
        setStampedResult(undefined);
      }
    }
  }, [currentStampKey, initialResult]);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const result =
    stampedResult && stampedResult.stamp === currentStampKey
      ? stampedResult.value
      : undefined;

  const scopedProfiles = useMemo(
    () =>
      configuration.profiles.filter(
        (p) => p.lens === "app_transactions" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const configuredStreamIds = useMemo(
    () => streamIdsForProfiles(scopedProfiles),
    [scopedProfiles],
  );

  const selectedRow = useMemo(
    () =>
      selectedItem && result
        ? result.rows.find((r) => r.id === selectedItem)
        : undefined,
    [result, selectedItem],
  );

  const selectedCell = useMemo(() => {
    if (selectedRow) {
      const topClient = selectedRow.topClients[0]?.clientIp;
      if (topClient) {
        return { row: topClient, col: selectedRow.serverMatrixLabel };
      }
    }
    return missingCell
      ? { row: missingCell.row, col: missingCell.col }
      : undefined;
  }, [selectedRow, missingCell]);

  const handleInvestigate = async () => {
    if (!client || busy) return;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const requestStamp: QueryStamp = { scope, earliest, latest, filterKey };
    const stampKey = `${requestStamp.scope}|${requestStamp.earliest}|${requestStamp.latest}|${requestStamp.filterKey}`;
    setBusy(true);
    setMissingCell(undefined);
    setStreamModeNotice(undefined);
    try {
      const next = await investigateAppTransactions(
        client,
        {
          version: 1,
          lens: "app_transactions",
          scope,
          earliest,
          latest,
          ...(filter ? { filter } : {}),
        },
        configuration,
        controller.signal,
        { skipConfigRecheck, profileValidators },
      );
      if (!controller.signal.aborted && currentStampRef.current === stampKey) {
        setStampedResult({ stamp: stampKey, value: next });
      }
    } catch (error) {
      if (!controller.signal.aborted && currentStampRef.current === stampKey) {
        const message =
          error instanceof Error
            ? error.message
            : "HTTP & DB transaction investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            hasActiveHttp: false,
            hasActiveDb: false,
            kpis: [],
            rows: [],
            matrixRows: [],
            matrixCols: [],
            matrixCells: [],
            distribution: [],
            timelineEvents: [],
            timelineRowByEventId: {},
            outcomes: [],
            capped: false,
            sourceMode: "none",
            bannerState: "unavailable",
            bannerReason: message,
            checkedAt: Math.floor(Date.now() / 1000),
          },
        });
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setBusy(false);
      }
    }
  };

  const handleCheckStreamMode = async () => {
    if (!client || busy) return;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const stampKey = currentStampRef.current;
    setBusy(true);
    try {
      const entries = await checkStreamEstimateMode(
        client,
        configuredStreamIds,
        controller.signal,
      );
      if (
        controller.signal.aborted ||
        !entries.length ||
        currentStampRef.current !== stampKey
      ) {
        return;
      }
      const summary = summarizeStreamEntries(entries);
      const current = stampedResultRef.current;
      if (!current || current.stamp !== stampKey) {
        setStreamModeNotice({
          state: summary.hasEstimateOnly ? "estimate_only" : "unavailable",
          reason: summary.detail,
          ...(summary.hasEstimateOnly
            ? {
                verdict: `Stream ${summary.names} in Estimate mode (statsOnly=true); no transaction events are indexed.`,
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: AppTransactionsInvestigationResult["bannerState"] =
          summary.hasEstimateOnly
            ? "estimate_only"
            : prev.value.rows.length === 0
              ? "empty"
              : prev.value.bannerState;
        return {
          stamp: prev.stamp,
          value: {
            ...prev.value,
            streamReadiness: entries,
            bannerState: nextBannerState,
            bannerReason: summary.detail,
            ...(summary.hasEstimateOnly && prev.value.rows.length === 0
              ? {
                  verdict: `Stream ${summary.names} in Estimate mode (statsOnly=true); no transaction events are indexed.`,
                  verdictStatus: "unknown" as ProtocolStatus,
                  coverageStatus: "unknown" as ProtocolStatus,
                  coverageLabel: "Estimate mode",
                }
              : {}),
          },
        };
      });
    } catch (error) {
      if (!controller.signal.aborted && currentStampRef.current === stampKey) {
        setStreamModeNotice({
          state: "unavailable",
          reason:
            error instanceof Error
              ? error.message
              : "Could not inspect Splunk Stream mode.",
        });
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setBusy(false);
      }
    }
  };

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const columns: ProtocolTableColumn<AppTransactionsServiceRow>[] = [
    {
      key: "server",
      header: "Server/Service",
      render: (r) => (
        <span className="pl-cell-stack">
          <CopyableIp value={r.serverIp} label="server" />
          {r.serviceName ? (
            <span className="pl-muted-note pl-mono">{r.serviceName}</span>
          ) : null}
        </span>
      ),
    },
    {
      key: "protocol",
      header: "Protocol/DB",
      render: (r) => <span className="pl-mono">{r.protocolDisplay}</span>,
    },
    {
      key: "txns",
      header: "Txns",
      align: "right",
      render: (r) => formatCount(r.txnCount),
    },
    {
      key: "errorPct",
      header: "Error %",
      align: "right",
      render: (r) =>
        r.errorPct !== undefined ? (
          <span className="pl-mono">{`${r.errorPct.toFixed(1)}%`}</span>
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "latencyP95",
      header: "p95 Latency",
      align: "right",
      render: (r) =>
        r.latencyP95Ms !== undefined ? (
          <span className="pl-mono">{formatDurationMs(r.latencyP95Ms)}</span>
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "status",
      header: "Status",
      render: (r) => (
        <StatusChip
          status={r.status}
          title={r.reasons.length ? r.reasons.join("; ") : undefined}
        />
      ),
    },
  ];

  let banner:
    | {
        state: BannerState;
        reason?: string;
        onAction?: () => void;
        actionLabel?: string;
      }
    | undefined;

  if (busy) {
    banner = { state: "loading" };
  } else if (result?.bannerState) {
    if (result.bannerState === "stale_config") {
      banner = {
        state: "stale_config",
        reason: result.bannerReason,
        onAction: () => {
          onRefreshConfig();
        },
        actionLabel: "Refresh sources",
      };
    } else if (
      (result.bannerState === "empty" ||
        result.bannerState === "estimate_only") &&
      scopedProfiles.length > 0 &&
      client
    ) {
      banner = {
        state: result.bannerState,
        reason: result.bannerReason,
        onAction: () => void handleCheckStreamMode(),
        actionLabel:
          result.bannerState === "estimate_only"
            ? "Re-check Stream mode"
            : "Check Stream mode",
      };
    } else {
      banner = {
        state: result.bannerState,
        reason: result.bannerReason,
      };
    }
  } else if (streamModeNotice) {
    banner = {
      state: streamModeNotice.state,
      reason: streamModeNotice.reason,
      ...(scopedProfiles.length > 0 && client
        ? {
            onAction: () => void handleCheckStreamMode(),
            actionLabel: "Re-check Stream mode",
          }
        : {}),
    };
  } else if (!result && scopedProfiles.length === 0) {
    banner = {
      state: "unavailable",
      reason: live
        ? `Not covered — no app_transactions profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured app_transactions profile to investigate.",
    };
  }

  const coverageStatus: ProtocolStatus = result
    ? result.coverageStatus
    : streamModeNotice?.state === "estimate_only"
      ? "unknown"
      : scopedProfiles.length > 0
        ? "unknown"
        : "not_covered";
  const coverageLabel = result
    ? result.coverageLabel
    : streamModeNotice?.state === "estimate_only"
      ? "Estimate mode"
      : scopedProfiles.length > 0
        ? "Not checked"
        : "Not covered";
  const verdict = result
    ? result.verdict
    : streamModeNotice?.verdict
      ? streamModeNotice.verdict
      : scopedProfiles.length > 0
        ? "Click Investigate to inspect HTTP and SQL transaction health without query text."
        : "No active source profile covers this scope.";
  const verdictStatus: ProtocolStatus = result
    ? result.verdictStatus
    : streamModeNotice?.state === "estimate_only"
      ? "unknown"
      : scopedProfiles.length > 0
        ? "unknown"
        : "not_covered";

  const drawerOpen = Boolean(selectedRow || missingCell);

  const rawEventsLink = selectedRow
    ? safeRawEventsUrl({
        index: selectedRow.indexName,
        serverIp: selectedRow.serverIp,
        destPort: selectedRow.destPort,
        sourcetypes: selectedRow.sourcetypes,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus =
    result?.capped || result?.bannerState === "partial"
      ? "unknown"
      : "none_observed";

  const handleSelectTimelineEvent = (ev: ProtocolTimelineEvent) => {
    if (!result) return;
    const rowId = result.timelineRowByEventId[ev.id];
    if (rowId && result.rows.some((r) => r.id === rowId)) {
      setMissingCell(undefined);
      onChangeParams({ item: rowId });
    }
  };

  return (
    <ProtocolLensLayout
      title="HTTP & DB Transactions"
      scope={scope}
      scopes={scopes.length ? scopes : scope ? [scope] : ["unconfigured"]}
      earliest={earliest}
      latest={latest}
      view={view}
      coverageStatus={coverageStatus}
      coverageLabel={coverageLabel}
      verdict={verdict}
      verdictStatus={verdictStatus}
      kpis={result?.kpis ?? []}
      banner={banner}
      rows={result?.rows ?? []}
      columns={columns}
      busy={busy}
      matrixView={
        result ? (
          <HeatMatrix
            title="Client × server transaction health"
            rowHeader="Client"
            rows={result.matrixRows}
            columns={result.matrixCols}
            cells={result.matrixCells}
            missingStatus={matrixMissingStatus}
            selectedCell={selectedCell}
            onSelectCell={(cell: ProtocolMatrixCell) => {
              if (cell.itemId) {
                setMissingCell(undefined);
                onChangeParams({ item: cell.itemId });
              } else {
                onChangeParams({ item: undefined });
                setMissingCell({
                  row: cell.row,
                  col: cell.col,
                  status: cell.status,
                });
              }
            }}
          />
        ) : undefined
      }
      extraOverview={
        result &&
        (result.distribution.length > 0 || result.timelineEvents.length > 0) ? (
          <>
            {result.distribution.length > 0 ? (
              <DistributionBar
                title="Latency p50/p95"
                items={result.distribution}
              />
            ) : null}
            {result.timelineEvents.length > 0 ? (
              <SwimlaneTimeline
                title="Error timeline"
                earliest={earliest}
                latest={latest}
                events={result.timelineEvents}
                onSelectEvent={handleSelectTimelineEvent}
              />
            ) : null}
          </>
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.protocolLabel} · ${selectedRow.serverMatrixLabel}`
          : missingCell
            ? `${missingCell.row} → ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            {selectedRow.protocolLabel} ·{" "}
            <CopyableIp value={selectedRow.serverIp} label="server" />
            {selectedRow.destPort !== undefined
              ? `:${selectedRow.destPort}`
              : ""}
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="client" /> →{" "}
            <span className="pl-mono">{missingCell.col}</span>
          </span>
        ) : undefined
      }
      drawerOpen={drawerOpen}
      drawerBody={
        selectedRow ? (
          <dl className="pl-kv">
            <dt>Status</dt>
            <dd>
              <StatusChip status={selectedRow.status} />
            </dd>
            <dt>Server IP</dt>
            <dd>
              <CopyableIp value={selectedRow.serverIp} label="server" />
            </dd>
            <dt>Protocol / DB</dt>
            <dd className="pl-mono">{selectedRow.protocolDisplay}</dd>
            {selectedRow.serviceName ? (
              <>
                <dt>{selectedRow.kind === "http" ? "Site" : "Database"}</dt>
                <dd className="pl-mono">{selectedRow.serviceName}</dd>
              </>
            ) : null}
            <dt>Transactions</dt>
            <dd className="pl-mono">{formatCount(selectedRow.txnCount)}</dd>
            <dt>Error rate</dt>
            <dd className="pl-mono">
              {selectedRow.errorPct !== undefined
                ? selectedRow.kind === "http"
                  ? `${selectedRow.errorPct.toFixed(1)}% (${selectedRow.http5xxCount} 5xx · ${selectedRow.http4xxCount} 4xx)`
                  : `${selectedRow.errorPct.toFixed(1)}% (${selectedRow.sqlErrorCount} SQL errors)`
                : "Not covered"}
            </dd>
            <dt>Latency (p50 / p95 / max)</dt>
            <dd className="pl-mono">
              {selectedRow.latencyP95Ms !== undefined
                ? `${formatDurationMs(selectedRow.latencyP50Ms)} / ${formatDurationMs(selectedRow.latencyP95Ms)} / ${formatDurationMs(selectedRow.latencyMaxMs)}`
                : "Not covered"}
            </dd>
            {selectedRow.totalBytesIn > 0 || selectedRow.totalBytesOut > 0 ? (
              <>
                <dt>Volume</dt>
                <dd className="pl-mono">
                  {`${formatBytes(selectedRow.totalBytesIn)} in · ${formatBytes(selectedRow.totalBytesOut)} out`}
                </dd>
              </>
            ) : null}
            {selectedRow.totalRowsReturned !== undefined ? (
              <>
                <dt>Rows returned</dt>
                <dd className="pl-mono">
                  {formatCount(selectedRow.totalRowsReturned)}
                </dd>
              </>
            ) : null}
            {selectedRow.topPathsOrDatabases.length ? (
              <>
                <dt>
                  {selectedRow.kind === "http"
                    ? "Top URI paths"
                    : "Top databases"}
                </dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.topPathsOrDatabases.map((entry) => (
                      <li key={entry.label} className="pl-mono">
                        {`${entry.label} · ${entry.count} ${entry.count === 1 ? "txn" : "txns"}${entry.errorCount > 0 ? ` (${entry.errorCount} err)` : ""}`}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            {selectedRow.topErrors.length ? (
              <>
                <dt>Error codes</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.topErrors.map((err) => (
                      <li key={err.code} className="pl-mono">
                        {`${err.code} × ${err.count}`}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            {selectedRow.topClients.length ? (
              <>
                <dt>Top clients</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.topClients.map((c) => (
                      <li key={c.clientIp}>
                        <CopyableIp value={c.clientIp} label="client" />{" "}
                        <span className="pl-mono">
                          {`· ${c.count} ${c.count === 1 ? "txn" : "txns"}${c.errorCount > 0 ? ` (${c.errorCount} err)` : ""}`}
                        </span>
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            {selectedRow.reasons.length ? (
              <>
                <dt>Exceptions</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            <dt>Privacy boundary</dt>
            <dd>
              SQL query text, bind values, HTTP query strings, form data, and
              cookies are excluded from collection and display.
            </dd>
          </dl>
        ) : missingCell ? (
          <dl className="pl-kv">
            <dt>Observation</dt>
            <dd>
              <StatusChip status={missingCell.status} />
            </dd>
            <dt>Detail</dt>
            <dd>
              {missingCell.status === "unknown"
                ? "Result hit the search row cap or partial source — this client and server pair may have unseen transactions outside the capped rows."
                : "No transactions observed between this client and server in the selected UTC window."}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      onScopeChange={(nextScope) => {
        abortRef.current?.abort();
        abortRef.current = null;
        setBusy(false);
        setMissingCell(undefined);
        setStreamModeNotice(undefined);
        setStampedResult(undefined);
        onChangeParams({ scope: nextScope, item: undefined });
      }}
      onViewChange={(nextView) => onChangeParams({ view: nextView })}
      onInvestigate={() => void handleInvestigate()}
      onCancel={handleCancel}
      onBackToHub={onBackToHub}
      onSelectRow={(row) => {
        setMissingCell(undefined);
        onChangeParams({ item: row.id });
      }}
      onCloseDrawer={() => {
        setMissingCell(undefined);
        onChangeParams({ item: undefined });
      }}
    />
  );
}

export default AppTransactionsLensPage;
