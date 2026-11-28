import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolFilter,
  ProtocolFilterFieldSpec,
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
  ProtocolTimelineEvent,
} from "../../shared/contract";
import { collectFilterSuggestions } from "../../shared/filterSpl";
import {
  formatBytes,
  formatCount,
  formatUtcTimestamp,
} from "../../shared/format";
import { checkStreamEstimateMode } from "../../shared/streamReadiness";
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
  buildMgmtPlaneRawEventsUrl,
  investigateMgmtPlane,
  resolveMgmtPlaneThresholds,
  shortenDeviceLabel,
  type MgmtPlaneFindingRow,
  type MgmtPlaneInvestigationResult,
  type MgmtPlaneSourcetype,
} from "./adapter";

export interface MgmtPlaneLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: MgmtPlaneInvestigationResult;
  /** Optional override to skip live KVStore config recheck in isolated test harnesses. */
  skipConfigRecheck?: boolean;
}

interface QueryStamp {
  scope: string;
  earliest: number;
  latest: number;
  filterKey: string;
}

const IPV4_OR_IPV6_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})$/;

function isIpLike(value: string): boolean {
  return IPV4_OR_IPV6_RE.test(value.trim());
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
  sourcetypes: readonly MgmtPlaneSourcetype[];
  sourceManager: string;
  targetDevice: string;
  destPort?: number;
  isSyslog?: boolean;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildMgmtPlaneRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

const MGMT_PLANE_FILTER_FIELDS: readonly ProtocolFilterFieldSpec[] = [
  { key: "src", label: "Manager IP", placeholder: "Manager IP", primary: true },
  {
    key: "dst",
    label: "Target IP",
    placeholder: "Target IP",
    primary: true,
  },
  { key: "port", label: "Port", placeholder: "Port", primary: true },
  { key: "device", label: "Device", placeholder: "Device" },
];

export function MgmtPlaneLensPage({
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
}: MgmtPlaneLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: MgmtPlaneInvestigationResult } | undefined
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
  const pendingAutoInvestigateRef = useRef(false);
  const handleInvestigateRef = useRef<(force?: boolean) => Promise<void>>(
    async () => {},
  );
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
      if (pendingAutoInvestigateRef.current) {
        pendingAutoInvestigateRef.current = false;
        void handleInvestigateRef.current(true);
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
        (p) => p.lens === "mgmt_plane" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );

  const configuredStreamIds = useMemo(() => {
    const ids = new Set<"snmp" | "ftp">();
    for (const p of scopedProfiles) {
      const sk = resolveMgmtPlaneThresholds(p).sourceKind;
      if (sk === "stream_snmp" || sk === "auto") ids.add("snmp");
      if (sk === "stream_ftp" || sk === "auto") ids.add("ftp");
    }
    return [...ids];
  }, [scopedProfiles]);

  const hasStreamProfile = configuredStreamIds.length > 0;

  const selectedRow = useMemo(
    () =>
      selectedItem && result
        ? result.rows.find((r) => r.id === selectedItem)
        : undefined,
    [result, selectedItem],
  );

  const selectedCell = useMemo(() => {
    if (selectedRow) {
      const row =
        selectedRow.sourceManager === "Syslog peer baseline"
          ? "Syslog peer baseline"
          : shortenDeviceLabel(selectedRow.sourceManager);
      const col = shortenDeviceLabel(selectedRow.targetDevice);
      return { row, col };
    }
    return missingCell
      ? { row: missingCell.row, col: missingCell.col }
      : undefined;
  }, [selectedRow, missingCell]);

  const handleInvestigate = async (force = false) => {
    if (!client || (busy && !force)) return;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const requestStamp: QueryStamp = { scope, earliest, latest, filterKey };
    const stampKey = `${requestStamp.scope}|${requestStamp.earliest}|${requestStamp.latest}|${requestStamp.filterKey}`;
    setBusy(true);
    setMissingCell(undefined);
    setStreamModeNotice(undefined);
    try {
      const next = await investigateMgmtPlane(
        client,
        {
          version: 1,
          lens: "mgmt_plane",
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
            : "Management-plane hygiene investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            hasActiveSnmp: false,
            hasActiveFtp: false,
            hasActiveNetflow: false,
            hasSyslogBaseline: false,
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

  const handleCheckStreamMode = async () => {
    if (!client || busy) return;
    const streamIds = configuredStreamIds.length
      ? configuredStreamIds
      : (["snmp", "ftp"] as const);
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const stampKey = currentStampRef.current;
    setBusy(true);
    try {
      const entries = await checkStreamEstimateMode(
        client,
        streamIds,
        controller.signal,
      );
      if (controller.signal.aborted || currentStampRef.current !== stampKey) {
        return;
      }
      const estimateEntries = entries.filter(
        (e) => e.state === "estimate_only",
      );
      const anyEstimate = estimateEntries.length > 0;
      const summaryReason = anyEstimate
        ? `Estimate mode (statsOnly=true) on: ${estimateEntries.map((e) => e.streamId).join(", ")}.`
        : (entries[0]?.detail ??
          "Checked Stream readiness for snmp and ftp streams.");

      const current = stampedResultRef.current;
      if (!current || current.stamp !== stampKey) {
        setStreamModeNotice({
          state: anyEstimate ? "estimate_only" : "unavailable",
          reason: summaryReason,
          ...(anyEstimate
            ? {
                verdict: `Stream ${estimateEntries.map((e) => e.streamId).join(", ")} is in Estimate mode (statsOnly=true); no event rows are indexed.`,
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: MgmtPlaneInvestigationResult["bannerState"] =
          anyEstimate
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
            bannerReason: summaryReason,
            ...(anyEstimate && prev.value.rows.length === 0
              ? {
                  verdict: `Stream ${estimateEntries.map((e) => e.streamId).join(", ")} is in Estimate mode (statsOnly=true); no event rows are indexed.`,
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

  handleInvestigateRef.current = handleInvestigate;

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const columns: ProtocolTableColumn<MgmtPlaneFindingRow>[] = [
    {
      key: "finding",
      header: "Finding / Protocol",
      render: (r) => <span className="pl-mono">{r.findingLabel}</span>,
    },
    {
      key: "source",
      header: "Source / Manager",
      render: (r) =>
        isIpLike(r.sourceManager) ? (
          <CopyableIp value={r.sourceManager} label="manager" />
        ) : (
          <span className="pl-mono">{r.sourceManager}</span>
        ),
    },
    {
      key: "target",
      header: "Target / Device",
      render: (r) =>
        isIpLike(r.targetDevice) ? (
          <CopyableIp value={r.targetDevice} label="target" />
        ) : (
          <span className="pl-mono">{r.targetDevice}</span>
        ),
    },
    {
      key: "countOrGap",
      header: "Count / Gap",
      align: "right",
      render: (r) => <span className="pl-mono">{r.countOrGapLabel}</span>,
    },
    {
      key: "detail",
      header: "Detail",
      render: (r) => <span className="pl-mono">{r.detail}</span>,
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
      hasStreamProfile &&
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
      ...(hasStreamProfile && client
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
        ? `Not covered — no mgmt_plane profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured mgmt_plane profile to investigate.",
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
        ? "Click Investigate to inspect SNMPv1/v2c, cleartext management protocols, and syslog receipt gaps."
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
        sourcetypes: selectedRow.sourcetypes,
        sourceManager: selectedRow.sourceManager,
        targetDevice: selectedRow.rawTargetHost ?? selectedRow.targetDevice,
        destPort: selectedRow.destPort,
        isSyslog: selectedRow.isSyslog,
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
          <DistributionBar
            title="Findings by category"
            items={result.distribution}
            mode="count"
          />
        ) : null}
        {result.timelineEvents.length > 0 ? (
          <SwimlaneTimeline
            title="Management & receipt-gap timeline"
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
      title="Management-Plane Hygiene"
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
            title="Manager × target hygiene matrix"
            rowHeader="Manager / Source"
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
          ? `${selectedRow.findingLabel} · ${selectedRow.targetDevice}`
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <span>{selectedRow.findingLabel}</span> ·{" "}
            {isIpLike(selectedRow.targetDevice) ? (
              <CopyableIp value={selectedRow.targetDevice} label="target" />
            ) : (
              <span className="pl-mono">{selectedRow.targetDevice}</span>
            )}
          </span>
        ) : missingCell ? (
          <span>
            {isIpLike(missingCell.row) ? (
              <CopyableIp value={missingCell.row} label="manager" />
            ) : (
              <span className="pl-mono">{missingCell.row}</span>
            )}{" "}
            ·{" "}
            {isIpLike(missingCell.col) ? (
              <CopyableIp value={missingCell.col} label="target" />
            ) : (
              <span className="pl-mono">{missingCell.col}</span>
            )}
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
            <dt>Finding</dt>
            <dd className="pl-mono">{selectedRow.findingLabel}</dd>
            <dt>Source / Manager</dt>
            <dd>
              {isIpLike(selectedRow.sourceManager) ? (
                <CopyableIp value={selectedRow.sourceManager} label="manager" />
              ) : (
                <span className="pl-mono">{selectedRow.sourceManager}</span>
              )}
            </dd>
            <dt>Target / Device</dt>
            <dd>
              {isIpLike(selectedRow.targetDevice) ? (
                <CopyableIp value={selectedRow.targetDevice} label="target" />
              ) : (
                <span className="pl-mono">{selectedRow.targetDevice}</span>
              )}
            </dd>
            <dt>Sources</dt>
            <dd className="pl-mono">{selectedRow.sourcetypes.join(", ")}</dd>
            <dt>
              {selectedRow.gapMinutes !== undefined ? "Gap / Events" : "Volume"}
            </dt>
            <dd className="pl-mono">
              {selectedRow.gapMinutes !== undefined
                ? `${selectedRow.gapMinutes} min gap · ${formatCount(selectedRow.eventCount)} ${selectedRow.eventCount === 1 ? "event" : "events"}`
                : `${selectedRow.countOrGapLabel}${selectedRow.totalBytes > 0 ? ` · ${formatBytes(selectedRow.totalBytes)}` : ""}`}
            </dd>
            {selectedRow.firstSeen !== undefined ? (
              <>
                <dt>Observed</dt>
                <dd className="pl-mono">
                  {formatUtcTimestamp(selectedRow.firstSeen)}
                  {selectedRow.lastSeen !== undefined &&
                  selectedRow.lastSeen !== selectedRow.firstSeen
                    ? ` – ${formatUtcTimestamp(selectedRow.lastSeen)}`
                    : ""}
                </dd>
              </>
            ) : null}
            {selectedRow.reasons.length ? (
              <>
                <dt>Findings</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            <dt>Remediation</dt>
            <dd>{selectedRow.remediationNote}</dd>
            <dt>Privacy</dt>
            <dd>
              SNMP community strings and FTP credentials are never selected or
              stored by this lens.
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
                ? "Result hit the search row cap or partial coverage — this manager and target pair may have unseen management activity outside the capped rows."
                : "No management-plane findings or sessions observed between this manager and target in the selected UTC window."}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      filter={filter}
      filterFields={MGMT_PLANE_FILTER_FIELDS}
      supportsBidirectional
      filterSuggestions={{
        src: collectFilterSuggestions(
          (result?.rows ?? [])
            .filter((r) => r.sourceManager !== "Syslog peer baseline")
            .map((r) => r.sourceManager),
        ),
        dst: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.targetDevice),
        ),
        port: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.destPort),
        ),
        device: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.rawTargetHost ?? r.targetDevice),
        ),
      }}
      onApplyFilter={(next: ProtocolFilter | undefined) => {
        if (serializeFilter(next) !== filterKey) {
          pendingAutoInvestigateRef.current = Boolean(client);
          onChangeParams({ filter: next, item: undefined });
        } else {
          void handleInvestigate();
        }
      }}
      onWindowChange={(nextEarliest, nextLatest) => {
        if ((result || busy) && client)
          pendingAutoInvestigateRef.current = true;
        onChangeParams({
          earliest: nextEarliest,
          latest: nextLatest,
          item: undefined,
        });
      }}
      onFocusFlow={
        selectedRow
          ? () => {
              const next: ProtocolFilter = selectedRow.isSyslog
                ? {
                    device:
                      selectedRow.rawTargetHost ?? selectedRow.targetDevice,
                  }
                : {
                    ...(selectedRow.sourceManager !== "Syslog peer baseline"
                      ? { src: selectedRow.sourceManager }
                      : {}),
                    dst: selectedRow.targetDevice,
                    ...(selectedRow.destPort
                      ? { port: String(selectedRow.destPort) }
                      : {}),
                  };
              setMissingCell(undefined);
              if (serializeFilter(next) !== filterKey) {
                pendingAutoInvestigateRef.current = Boolean(client);
                onChangeParams({ filter: next, item: undefined });
              } else {
                onChangeParams({ item: undefined });
                void handleInvestigate();
              }
            }
          : undefined
      }
      onScopeChange={(nextScope) => {
        pendingAutoInvestigateRef.current = false;
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

export default MgmtPlaneLensPage;
