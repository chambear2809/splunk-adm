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
  buildLbHealthRawEventsUrl,
  investigateLbHealth,
  isIpLiteral,
  shortenDeviceLabel,
  type LbHealthInvestigationResult,
  type LbHealthPoolMemberRow,
  type LbHealthSourcetype,
} from "./adapter";

export interface LbHealthLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: LbHealthInvestigationResult;
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
  sourcetypes: readonly LbHealthSourcetype[];
  vip: string;
  memberIp?: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildLbHealthRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function LbHealthLensPage({
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
}: LbHealthLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: LbHealthInvestigationResult } | undefined
  >(() =>
    initialResult
      ? { stamp: currentStampKey, value: initialResult }
      : undefined,
  );
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
        (p) => p.lens === "lb_health" && p.scope === scope,
      ),
    [configuration.profiles, scope],
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
      return {
        row: shortenDeviceLabel(selectedRow.vipDisplay),
        col: selectedRow.memberIp
          ? selectedRow.memberLabel
          : `${selectedRow.poolDisplay} · ${selectedRow.memberLabel}`,
      };
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
    try {
      const next = await investigateLbHealth(
        client,
        {
          version: 1,
          lens: "lb_health",
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
            : "Load balancer health investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            hasTargetTelemetry: false,
            kpis: [],
            distribution: [],
            rows: [],
            matrixRows: [],
            matrixCols: [],
            matrixCells: [],
            timelineEvents: [],
            timelineRowByEventId: {},
            outcomes: [],
            capped: false,
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

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const columns: ProtocolTableColumn<LbHealthPoolMemberRow>[] = [
    {
      key: "vip",
      header: "VIP / Balancer",
      render: (r) =>
        isIpLiteral(r.vipDisplay) ? (
          <CopyableIp value={r.vipDisplay} label="VIP" />
        ) : (
          <span className="pl-mono" title={r.vip}>
            {r.vipDisplay}
          </span>
        ),
    },
    {
      key: "pool",
      header: "Pool / Target Group",
      render: (r) => (
        <span className="pl-mono" title={r.pool}>
          {r.poolDisplay}
        </span>
      ),
    },
    {
      key: "member",
      header: "Member",
      render: (r) =>
        r.memberIp ? (
          <span
            className="pl-mono"
            style={{ display: "inline-flex", alignItems: "baseline" }}
          >
            <CopyableIp value={r.memberIp} label="member" />
            {r.memberPort !== undefined ? (
              <span style={{ marginLeft: "-4px" }}>:{r.memberPort}</span>
            ) : null}
          </span>
        ) : (
          <span className="pl-mono">{r.memberLabel}</span>
        ),
    },
    {
      key: "requests",
      header: "Requests",
      align: "right",
      render: (r) => formatCount(r.requestCount),
    },
    {
      key: "balancerErrors",
      header: "Balancer errors",
      align: "right",
      render: (r) => formatCount(r.balancerErrorCount),
    },
    {
      key: "targetErrors",
      header: "Target errors",
      align: "right",
      render: (r) =>
        r.targetErrorsCovered ? (
          formatCount(r.targetErrorCount)
        ) : (
          <StatusChip
            status="not_covered"
            title="NLB TLS access logs do not report backend target status"
          />
        ),
    },
    {
      key: "latency",
      header: "p95 Latency",
      align: "right",
      render: (r) =>
        r.p95LatencyMs !== undefined ? formatDurationMs(r.p95LatencyMs) : "—",
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
    } else {
      banner = {
        state: result.bannerState,
        reason: result.bannerReason,
      };
    }
  } else if (!result && scopedProfiles.length === 0) {
    banner = {
      state: "unavailable",
      reason: live
        ? `Not covered — no lb_health profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured lb_health profile to investigate.",
    };
  }

  const coverageStatus: ProtocolStatus = result
    ? result.coverageStatus
    : scopedProfiles.length > 0
      ? "unknown"
      : "not_covered";
  const coverageLabel = result
    ? result.coverageLabel
    : scopedProfiles.length > 0
      ? "Not checked"
      : "Not covered";
  const verdict = result
    ? result.verdict
    : scopedProfiles.length > 0
      ? "Click Investigate to inspect F5 LTM, AWS ALB, and AWS NLB pool health."
      : "No active source profile covers this scope.";
  const verdictStatus: ProtocolStatus = result
    ? result.verdictStatus
    : scopedProfiles.length > 0
      ? "unknown"
      : "not_covered";

  const drawerOpen = Boolean(selectedRow || missingCell);

  const rawEventsLink = selectedRow
    ? safeRawEventsUrl({
        index: selectedRow.indexName,
        sourcetypes: selectedRow.sourcetypes,
        vip: selectedRow.vip,
        memberIp: selectedRow.memberIp,
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

  const extraOverview =
    result &&
    (result.distribution.length > 0 || result.timelineEvents.length > 0) ? (
      <>
        {result.distribution.length > 0 ? (
          <DistributionBar title="Error split" items={result.distribution} />
        ) : null}
        {result.timelineEvents.length > 0 ? (
          <SwimlaneTimeline
            title="Failure timeline"
            earliest={earliest}
            latest={latest}
            events={result.timelineEvents}
            onSelectEvent={handleSelectTimelineEvent}
          />
        ) : null}
      </>
    ) : undefined;

  return (
    <ProtocolLensLayout
      title="Load Balancer Pool Health"
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
            title="VIP × Pool Member health"
            rowHeader="VIP / Balancer"
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
      extraOverview={extraOverview}
      drawerTitle={
        selectedRow
          ? `${selectedRow.vipDisplay} · ${selectedRow.memberLabel}`
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            {isIpLiteral(selectedRow.vipDisplay) ? (
              <CopyableIp value={selectedRow.vipDisplay} label="VIP" />
            ) : (
              <span className="pl-mono">{selectedRow.vipDisplay}</span>
            )}{" "}
            ·{" "}
            {selectedRow.memberIp ? (
              <span
                className="pl-mono"
                style={{ display: "inline-flex", alignItems: "baseline" }}
              >
                <CopyableIp value={selectedRow.memberIp} label="member" />
                {selectedRow.memberPort !== undefined ? (
                  <span style={{ marginLeft: "-4px" }}>
                    :{selectedRow.memberPort}
                  </span>
                ) : null}
              </span>
            ) : (
              <span className="pl-mono">{selectedRow.memberLabel}</span>
            )}
          </span>
        ) : missingCell ? (
          <span>
            {isIpLiteral(missingCell.row) ? (
              <CopyableIp value={missingCell.row} label="VIP" />
            ) : (
              <span className="pl-mono">{missingCell.row}</span>
            )}{" "}
            · <span className="pl-mono">{missingCell.col}</span>
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
            <dt>Source</dt>
            <dd className="pl-mono">{selectedRow.sourceLabel}</dd>
            <dt>VIP / Balancer</dt>
            <dd>
              {isIpLiteral(selectedRow.vip) ? (
                <CopyableIp value={selectedRow.vip} label="VIP" />
              ) : (
                <>
                  <span className="pl-mono">{selectedRow.vip}</span>
                  {selectedRow.vipIp ? (
                    <>
                      {" "}
                      (<CopyableIp value={selectedRow.vipIp} label="VIP node" />
                      )
                    </>
                  ) : null}
                </>
              )}
            </dd>
            <dt>Pool / Target Group</dt>
            <dd className="pl-mono">{selectedRow.pool}</dd>
            <dt>Member</dt>
            <dd>
              {selectedRow.memberIp ? (
                <span
                  className="pl-mono"
                  style={{ display: "inline-flex", alignItems: "baseline" }}
                >
                  <CopyableIp value={selectedRow.memberIp} label="member" />
                  {selectedRow.memberPort !== undefined ? (
                    <span style={{ marginLeft: "-4px" }}>
                      :{selectedRow.memberPort}
                    </span>
                  ) : null}
                </span>
              ) : (
                <span className="pl-mono">{selectedRow.memberLabel}</span>
              )}
            </dd>
            <dt>Requests</dt>
            <dd className="pl-mono">{formatCount(selectedRow.requestCount)}</dd>
            <dt>Error split</dt>
            <dd>
              <ul className="pl-kv-list">
                <li className="pl-mono">
                  Balancer errors: {formatCount(selectedRow.balancerErrorCount)}{" "}
                  ({selectedRow.balancerErrorPct.toFixed(1)}%)
                  {selectedRow.lbFailedCount > 0
                    ? ` · ${selectedRow.lbFailedCount} LB_FAILED`
                    : ""}
                  {selectedRow.nlbTlsFailureCount > 0
                    ? ` · ${selectedRow.nlbTlsFailureCount} TLS fail`
                    : ""}
                </li>
                <li className="pl-mono">
                  Target errors:{" "}
                  {selectedRow.targetErrorsCovered ? (
                    `${formatCount(selectedRow.targetErrorCount)} (${selectedRow.targetErrorPct.toFixed(1)}%)`
                  ) : (
                    <StatusChip
                      status="not_covered"
                      title="NLB TLS omits target status"
                    />
                  )}
                </li>
                <li className="pl-mono">
                  Healthy: {formatCount(selectedRow.healthyCount)}
                </li>
              </ul>
            </dd>
            {selectedRow.p95LatencyMs !== undefined ? (
              <>
                <dt>Latency</dt>
                <dd className="pl-mono">
                  p50 {formatDurationMs(selectedRow.p50LatencyMs)} · p95{" "}
                  {formatDurationMs(selectedRow.p95LatencyMs)}
                  {selectedRow.avgConnectionTimeMs !== undefined
                    ? ` (avg conn ${formatDurationMs(selectedRow.avgConnectionTimeMs)})`
                    : ""}
                </dd>
              </>
            ) : null}
            {selectedRow.bytesIn > 0 || selectedRow.bytesOut > 0 ? (
              <>
                <dt>Volume</dt>
                <dd className="pl-mono">
                  {formatBytes(selectedRow.bytesIn)} in ·{" "}
                  {formatBytes(selectedRow.bytesOut)} out
                </dd>
              </>
            ) : null}
            {selectedRow.errorReasons.length ||
            selectedRow.tlsAlerts.length ||
            selectedRow.verifyStatuses.length ? (
              <>
                <dt>Error & TLS details</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.errorReasons.map((r) => (
                      <li key={`reason:${r}`} className="pl-mono">
                        error_reason: {r}
                      </li>
                    ))}
                    {selectedRow.tlsAlerts.map((a) => (
                      <li key={`alert:${a}`} className="pl-mono">
                        tls_alert: {a}
                      </li>
                    ))}
                    {selectedRow.verifyStatuses.map((v) => (
                      <li key={`verify:${v}`} className="pl-mono">
                        verify_status: {v}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            <dt>TLS</dt>
            <dd className="pl-mono">
              {selectedRow.tlsProtocols.length
                ? selectedRow.tlsProtocols.join(", ")
                : selectedRow.family === "f5_ltm"
                  ? "TLS cipher/version not logged in F5 HTTP iRule"
                  : "No TLS metadata logged"}
            </dd>
            {selectedRow.findings.length || selectedRow.reasons.length ? (
              <>
                <dt>Findings</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {(selectedRow.findings.length
                      ? selectedRow.findings
                      : selectedRow.reasons
                    ).map((finding) => (
                      <li key={finding}>{finding}</li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
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
                ? "Result hit the search row cap or a partial source — this VIP and member pair may have unseen events outside the capped rows."
                : "No requests or failures observed for this VIP and member pair in the selected UTC window."}
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

export default LbHealthLensPage;
