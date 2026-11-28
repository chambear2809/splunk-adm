import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolFilter,
  ProtocolFilterFieldSpec,
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
import { collectFilterSuggestions } from "../../shared/filterSpl";
import {
  formatBytes,
  formatCount,
  formatDurationMs,
} from "../../shared/format";
import { checkStreamEstimateMode } from "../../shared/streamReadiness";
import {
  CopyableIp,
  DistributionBar,
  HeatMatrix,
  ProtocolLensLayout,
  StatusChip,
  type BannerState,
  type ProtocolTableColumn,
} from "../../shared/ui";
import {
  buildEnterpriseL7RawEventsUrl,
  ENTERPRISE_L7_STREAM_IDS,
  fetchEnterpriseL7RowExpansion,
  investigateEnterpriseL7,
  type EnterpriseL7InvestigationResult,
  type EnterpriseL7RowExpansionResult,
  type EnterpriseL7ServiceRow,
  type EnterpriseL7Sourcetype,
} from "./adapter";

export interface EnterpriseL7LensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: EnterpriseL7InvestigationResult;
  /** Optional pre-populated single-row expansion result for tests. */
  initialExpansion?: {
    rowId: string;
    result: EnterpriseL7RowExpansionResult;
  };
  /** Optional override to skip live KVStore config recheck in isolated test harnesses. */
  skipConfigRecheck?: boolean;
}

export function describeRowExpansionOutcome(
  expansion: EnterpriseL7RowExpansionResult,
): {
  status: "ok" | "partial" | "none_observed" | "unknown";
  note?: string;
} {
  const { outcome, capped, values } = expansion;
  if (outcome.state === "blocked" || outcome.state === "unavailable") {
    return {
      status: "unknown",
      note:
        outcome.detail ??
        (outcome.state === "blocked"
          ? "Role cannot query this index."
          : "Source unavailable for this window."),
    };
  }
  if (values.length > 0) {
    return capped || outcome.state === "partial"
      ? {
          status: "partial",
          note: "Results capped; additional identities may exist.",
        }
      : { status: "ok" };
  }
  if (capped || outcome.state === "partial") {
    return {
      status: "unknown",
      note:
        outcome.detail ??
        "Search hit the row cap before any identity value was seen.",
    };
  }
  return { status: "none_observed" };
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

function formatLatencyPair(p50?: number, p95?: number): string {
  if (p50 === undefined && p95 === undefined) return "Not covered";
  return `${formatDurationMs(p50)} / ${formatDurationMs(p95)}`;
}

function safeRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly EnterpriseL7Sourcetype[];
  server: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildEnterpriseL7RawEventsUrl(options);
  } catch {
    return undefined;
  }
}

const ENTERPRISE_L7_FILTER_FIELDS: readonly ProtocolFilterFieldSpec[] = [
  { key: "src", label: "Client IP", placeholder: "Client IP", primary: true },
  { key: "dst", label: "Server IP", placeholder: "Server IP", primary: true },
  { key: "port", label: "Port", placeholder: "Port", primary: true },
  { key: "device", label: "Host or NAS", placeholder: "Host / NAS" },
];

export function EnterpriseL7LensPage({
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
  initialExpansion,
  skipConfigRecheck,
}: EnterpriseL7LensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: EnterpriseL7InvestigationResult } | undefined
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
  const [rowExpansionState, setRowExpansionState] = useState<
    | {
        rowId: string;
        loading: boolean;
        result?: EnterpriseL7RowExpansionResult;
        error?: string;
      }
    | undefined
  >(() =>
    initialExpansion
      ? {
          rowId: initialExpansion.rowId,
          loading: false,
          result: initialExpansion.result,
        }
      : undefined,
  );

  const abortRef = useRef<AbortController | null>(null);
  const expansionAbortRef = useRef<AbortController | null>(null);

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
      expansionAbortRef.current?.abort();
      expansionAbortRef.current = null;
      setBusy(false);
      setMissingCell(undefined);
      setStreamModeNotice(undefined);
      setRowExpansionState(undefined);
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
    expansionAbortRef.current?.abort();
    expansionAbortRef.current = null;
    setRowExpansionState(undefined);
  }, [selectedItem]);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      expansionAbortRef.current?.abort();
    };
  }, []);

  const result =
    stampedResult && stampedResult.stamp === currentStampKey
      ? stampedResult.value
      : undefined;

  const scopedProfiles = useMemo(
    () =>
      configuration.profiles.filter(
        (p) => p.lens === "enterprise_l7" && p.scope === scope,
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
      return { row: selectedRow.protocol, col: selectedRow.server };
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
    setRowExpansionState(undefined);
    try {
      const next = await investigateEnterpriseL7(
        client,
        {
          version: 1,
          lens: "enterprise_l7",
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
            : "Enterprise L7 investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            kpis: [],
            rows: [],
            matrixRows: [],
            matrixCols: [],
            matrixCells: [],
            distribution: [],
            outcomes: [],
            capped: false,
            configuredProtocols: [],
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
        ENTERPRISE_L7_STREAM_IDS,
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
          "Checked Stream readiness for SMB, NFS, LDAP, RADIUS, SIP, RTP, and RTCP.");

      const current = stampedResultRef.current;
      if (!current || current.stamp !== stampKey) {
        setStreamModeNotice({
          state: anyEstimate ? "estimate_only" : "unavailable",
          reason: summaryReason,
          ...(anyEstimate
            ? {
                verdict: `Stream ${estimateEntries.map((e) => e.streamId).join(", ")} in Estimate mode (statsOnly=true); no event rows are indexed.`,
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: EnterpriseL7InvestigationResult["bannerState"] =
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
                  verdict: `Stream ${estimateEntries.map((e) => e.streamId).join(", ")} in Estimate mode (statsOnly=true); no event rows are indexed.`,
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

  const handleLoadRowExpansion = async (row: EnterpriseL7ServiceRow) => {
    if (!client || (row.protocol !== "SMB" && row.protocol !== "RADIUS")) {
      return;
    }
    const profile =
      scopedProfiles.find((p) => p.index === row.indexName) ??
      scopedProfiles[0];
    if (!profile) return;
    expansionAbortRef.current?.abort();
    const controller = new AbortController();
    expansionAbortRef.current = controller;
    const stampKey = currentStampRef.current;
    const rowId = row.id;
    setRowExpansionState({ rowId, loading: true });
    try {
      const expansion = await fetchEnterpriseL7RowExpansion(client, {
        profile,
        protocol: row.protocol,
        server: row.server,
        earliest,
        latest,
        signal: controller.signal,
      });
      if (
        !controller.signal.aborted &&
        currentStampRef.current === stampKey &&
        selectedRow?.id === rowId
      ) {
        setRowExpansionState({
          rowId,
          loading: false,
          result: expansion,
        });
      }
    } catch (error) {
      if (!controller.signal.aborted && currentStampRef.current === stampKey) {
        setRowExpansionState({
          rowId,
          loading: false,
          error:
            error instanceof Error
              ? error.message
              : "Failed to inspect session identities.",
        });
      }
    }
  };

  handleInvestigateRef.current = handleInvestigate;

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  // <= 8 columns; NEVER includes user_id or calling_station_id.
  // Any column whose source metric was not collected renders <StatusChip status="not_covered" />.
  const columns: ProtocolTableColumn<EnterpriseL7ServiceRow>[] = [
    {
      key: "protocol",
      header: "Protocol",
      render: (r) => <span className="pl-mono">{r.protocol}</span>,
    },
    {
      key: "server",
      header: "Server",
      render: (r) => <CopyableIp value={r.server} label="server" />,
    },
    {
      key: "events",
      header: "Events",
      align: "right",
      render: (r) => formatCount(r.eventCount),
    },
    {
      key: "latency",
      header: "Latency p95",
      align: "right",
      render: (r) =>
        r.latencyP95Ms !== undefined ? (
          formatDurationMs(r.latencyP95Ms)
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "errors",
      header: "Errors",
      align: "right",
      render: (r) =>
        r.errorOrRejectCovered ? (
          r.errorOrRejectSummary
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "posture",
      header: "Posture",
      render: (r) =>
        r.authOrQualityCovered ? (
          <span className="pl-mono">{r.authOrQualitySummary}</span>
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
        ? `Not covered — no enterprise_l7 profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured enterprise_l7 profile to investigate.",
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
        ? "Click Investigate to inspect SMB, NFS, LDAP, RADIUS, and VoIP posture."
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
        server: selectedRow.server,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  const activeExpansion =
    selectedRow && rowExpansionState?.rowId === selectedRow.id
      ? rowExpansionState
      : undefined;

  return (
    <ProtocolLensLayout
      title="Enterprise L7"
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
            title="Protocol × server L7 health"
            rowHeader="Protocol"
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
        result?.distribution.length ? (
          <DistributionBar
            title="L7 response latency p50 / p95"
            items={result.distribution}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.protocol} ${selectedRow.server}`
          : missingCell
            ? `${missingCell.row} ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            {selectedRow.protocol}{" "}
            <CopyableIp value={selectedRow.server} label="server" />
          </span>
        ) : missingCell ? (
          <span>
            {missingCell.row}{" "}
            <CopyableIp value={missingCell.col} label="server" />
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
            <dt>Protocol</dt>
            <dd className="pl-mono">{selectedRow.protocol}</dd>
            <dt>Server</dt>
            <dd>
              <CopyableIp value={selectedRow.server} label="server" />
            </dd>
            <dt>Sources</dt>
            <dd className="pl-mono">{selectedRow.sourcetypes.join(", ")}</dd>
            <dt>Volume</dt>
            <dd className="pl-mono">
              {formatCount(selectedRow.eventCount)} events ·{" "}
              {formatBytes(selectedRow.totalBytes)}
            </dd>
            <dt>Latency (p50 / p95)</dt>
            <dd className="pl-mono">
              {selectedRow.latencyP95Ms !== undefined ? (
                formatLatencyPair(
                  selectedRow.latencyP50Ms,
                  selectedRow.latencyP95Ms,
                )
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>

            {selectedRow.protocol === "SMB" ? (
              <>
                <dt>Dialects</dt>
                <dd className="pl-mono">
                  {selectedRow.smbDialects.length ? (
                    selectedRow.smbDialects.join(", ")
                  ) : (
                    <StatusChip status="not_covered" />
                  )}
                </dd>
                {selectedRow.topNtStatuses.length ? (
                  <>
                    <dt>NT errors</dt>
                    <dd>
                      <ul className="pl-kv-list">
                        {selectedRow.topNtStatuses.map((s) => (
                          <li key={s.status} className="pl-mono">
                            {`${s.status} × ${s.count}`}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                ) : null}
              </>
            ) : null}

            {selectedRow.protocol === "NFS" ? (
              <>
                <dt>NFS version</dt>
                <dd className="pl-mono">
                  {selectedRow.nfsVersions.length ? (
                    `NFSv${selectedRow.nfsVersions.join(", v")}`
                  ) : (
                    <StatusChip status="not_covered" />
                  )}
                </dd>
                {selectedRow.topNfsErrors.length ? (
                  <>
                    <dt>NFS errors</dt>
                    <dd>
                      <ul className="pl-kv-list">
                        {selectedRow.topNfsErrors.map((e) => (
                          <li key={e.status} className="pl-mono">
                            {`${e.status} × ${e.count}`}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                ) : null}
              </>
            ) : null}

            {selectedRow.protocol === "LDAP" ? (
              <>
                <dt>Bind posture</dt>
                <dd className="pl-mono">
                  {selectedRow.authOrQualityCovered ? (
                    `${selectedRow.ldapSimpleCleartextCount} cleartext simple · ${selectedRow.ldapSaslCount} SASL · ${selectedRow.ldapSimpleTlsCount} LDAPS`
                  ) : (
                    <StatusChip status="not_covered" />
                  )}
                </dd>
              </>
            ) : null}

            {selectedRow.protocol === "RADIUS" ? (
              <>
                <dt>Decisions</dt>
                <dd className="pl-mono">
                  {selectedRow.errorOrRejectCovered ? (
                    `${selectedRow.radiusRejectCount} rejects · ${selectedRow.radiusAcceptCount} accepts`
                  ) : (
                    <StatusChip status="not_covered" />
                  )}
                </dd>
                {selectedRow.nasRejects.length ? (
                  <>
                    <dt>Rejects per NAS</dt>
                    <dd>
                      <ul className="pl-kv-list">
                        {selectedRow.nasRejects.map((n) => (
                          <li key={n.nasIp}>
                            <CopyableIp value={n.nasIp} label="NAS" />{" "}
                            <span className="pl-mono">
                              ({n.rejectCount} rejects / {n.totalCount} events)
                            </span>
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                ) : null}
              </>
            ) : null}

            {selectedRow.protocol === "VoIP" ? (
              <>
                <dt>Voice quality</dt>
                <dd className="pl-mono">
                  {selectedRow.authOrQualityCovered ? (
                    [
                      selectedRow.voipMinMos !== undefined
                        ? `min MOS ${selectedRow.voipMinMos.toFixed(1)}`
                        : null,
                      selectedRow.voipMaxJitterMs !== undefined
                        ? `max jitter ${Math.round(selectedRow.voipMaxJitterMs)} ms`
                        : null,
                      selectedRow.voipMaxPacketLossPct !== undefined
                        ? `max loss ${selectedRow.voipMaxPacketLossPct.toFixed(1)}%`
                        : null,
                    ]
                      .filter(Boolean)
                      .join(" · ")
                  ) : (
                    <StatusChip status="not_covered" />
                  )}
                </dd>
                {selectedRow.voipCodecs.length ? (
                  <>
                    <dt>Codecs</dt>
                    <dd className="pl-mono">
                      {selectedRow.voipCodecs.join(", ")}
                    </dd>
                  </>
                ) : null}
              </>
            ) : null}

            {(selectedRow.protocol === "SMB" ||
              selectedRow.protocol === "RADIUS") &&
            client ? (
              <>
                <dt>
                  {selectedRow.protocol === "SMB"
                    ? "User IDs (expansion)"
                    : "Calling stations (expansion)"}
                </dt>
                <dd>
                  {activeExpansion?.loading ? (
                    <span className="pl-mono">Loading…</span>
                  ) : activeExpansion?.error ? (
                    <span className="pl-mono">{activeExpansion.error}</span>
                  ) : activeExpansion?.result ? (
                    (() => {
                      const desc = describeRowExpansionOutcome(
                        activeExpansion.result,
                      );
                      if (desc.status === "unknown") {
                        return (
                          <div>
                            <StatusChip status="unknown" title={desc.note} />
                            {desc.note ? (
                              <span className="pl-mono">{` ${desc.note}`}</span>
                            ) : null}
                          </div>
                        );
                      }
                      if (activeExpansion.result.values.length) {
                        return (
                          <div>
                            <ul className="pl-kv-list">
                              {activeExpansion.result.values.map((val) => (
                                <li key={val} className="pl-mono">
                                  {val}
                                </li>
                              ))}
                            </ul>
                            {desc.status === "partial" && desc.note ? (
                              <span className="pl-mono">{desc.note}</span>
                            ) : null}
                          </div>
                        );
                      }
                      return <StatusChip status="none_observed" />;
                    })()
                  ) : (
                    <button
                      type="button"
                      className="pl-btn-secondary"
                      onClick={() => void handleLoadRowExpansion(selectedRow)}
                    >
                      {selectedRow.protocol === "SMB"
                        ? "Load user_id"
                        : "Load calling_station_id"}
                    </button>
                  )}
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
          </dl>
        ) : missingCell ? (
          <dl className="pl-kv">
            <dt>Observation</dt>
            <dd>
              <StatusChip status={missingCell.status} />
            </dd>
            <dt>Detail</dt>
            <dd>
              {missingCell.status === "not_covered"
                ? `${missingCell.row} stream is not configured or collected for this scope.`
                : missingCell.status === "unknown"
                  ? "Result hit the search row cap — this protocol/server pair may have unseen events outside the capped rows."
                  : `No ${missingCell.row} events observed for ${missingCell.col} in the selected UTC window.`}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      filter={filter}
      filterFields={ENTERPRISE_L7_FILTER_FIELDS}
      supportsBidirectional
      filterSuggestions={{
        dst: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.server),
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
              const next: ProtocolFilter = { dst: selectedRow.server };
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
        expansionAbortRef.current?.abort();
        expansionAbortRef.current = null;
        setBusy(false);
        setMissingCell(undefined);
        setStreamModeNotice(undefined);
        setRowExpansionState(undefined);
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

export default EnterpriseL7LensPage;
