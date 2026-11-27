import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
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
  buildTcpTlsRawEventsUrl,
  investigateTcpTls,
  resolveTcpTlsThresholds,
  type TcpTlsInvestigationResult,
  type TcpTlsPairRow,
} from "./adapter";

export interface TcpTlsLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: TcpTlsInvestigationResult;
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

function formatRttPair(p50?: number, p95?: number): string {
  if (p50 === undefined && p95 === undefined) return "Not covered";
  return `${formatDurationMs(p50)} / ${formatDurationMs(p95)}`;
}

function safeRawEventsUrl(options: {
  index: string;
  sourcetype: "stream:tcp" | "stream:netflow";
  client: string;
  server: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildTcpTlsRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function TcpTlsLensPage({
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
}: TcpTlsLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: TcpTlsInvestigationResult } | undefined
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
        (p) => p.lens === "tcp_tls" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const hasTcpProfile = useMemo(
    () =>
      scopedProfiles.some(
        (p) => resolveTcpTlsThresholds(p).sourcetype === "stream:tcp",
      ),
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
      return { row: selectedRow.client, col: selectedRow.server };
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
      const next = await investigateTcpTls(
        client,
        {
          version: 1,
          lens: "tcp_tls",
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
            : "TCP/TLS investigation failed.";
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
      const [entry] = await checkStreamEstimateMode(
        client,
        ["tcp"],
        controller.signal,
      );
      if (
        controller.signal.aborted ||
        !entry ||
        currentStampRef.current !== stampKey
      ) {
        return;
      }
      const current = stampedResultRef.current;
      if (!current || current.stamp !== stampKey) {
        // Do not synthesize a completed event search when none ran yet.
        setStreamModeNotice({
          state:
            entry.state === "estimate_only" ? "estimate_only" : "unavailable",
          reason: entry.detail,
          ...(entry.state === "estimate_only"
            ? {
                verdict:
                  "Stream tcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: TcpTlsInvestigationResult["bannerState"] =
          entry.state === "estimate_only"
            ? "estimate_only"
            : prev.value.rows.length === 0
              ? "empty"
              : prev.value.bannerState;
        return {
          stamp: prev.stamp,
          value: {
            ...prev.value,
            streamReadiness: entry,
            bannerState: nextBannerState,
            bannerReason: entry.detail,
            ...(entry.state === "estimate_only" && prev.value.rows.length === 0
              ? {
                  verdict:
                    "Stream tcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
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

  const isNetflowOnlyMode = result?.sourceMode === "netflow_only";

  const columns: ProtocolTableColumn<TcpTlsPairRow>[] = isNetflowOnlyMode
    ? [
        {
          key: "client",
          header: "Client",
          render: (r) => <CopyableIp value={r.client} label="client" />,
        },
        {
          key: "server",
          header: "Server",
          render: (r) => <CopyableIp value={r.server} label="server" />,
        },
        {
          key: "destPorts",
          header: "Dest ports",
          align: "right",
          render: (r) => (r.destPorts.length ? r.destPorts.join(", ") : "—"),
        },
        {
          key: "flows",
          header: "Flows",
          align: "right",
          render: (r) => formatCount(r.flowCount),
        },
        {
          key: "bytes",
          header: "Bytes",
          align: "right",
          render: (r) => formatBytes(r.totalBytes),
        },
        {
          key: "status",
          header: "RTT & TLS",
          render: (r) => (
            <StatusChip
              status={r.status}
              title={r.reasons.length ? r.reasons.join("; ") : undefined}
            />
          ),
        },
      ]
    : [
        {
          key: "client",
          header: "Client",
          render: (r) => <CopyableIp value={r.client} label="client" />,
        },
        {
          key: "server",
          header: "Server",
          render: (r) => <CopyableIp value={r.server} label="server" />,
        },
        {
          key: "serverRtt",
          header: "Server RTT p95",
          align: "right",
          render: (r) =>
            r.serverRttP95Ms !== undefined
              ? formatDurationMs(r.serverRttP95Ms)
              : "Not covered",
        },
        {
          key: "clientRtt",
          header: "Client RTT p95",
          align: "right",
          render: (r) =>
            r.clientRttP95Ms !== undefined
              ? formatDurationMs(r.clientRttP95Ms)
              : "Not covered",
        },
        {
          key: "retransResets",
          header: "Retrans / Resets",
          align: "right",
          render: (r) =>
            r.sourceKind === "netflow_only"
              ? "Not covered"
              : `${(r.retransmitPct ?? 0).toFixed(1)}% / ${r.resets}`,
        },
        {
          key: "tls",
          header: "TLS Posture",
          render: (r) => (
            <StatusChip
              status={r.tlsStatus}
              label={r.tlsPostureLabel}
              title={
                r.sslError ??
                r.certIssuer ??
                (r.hasTlsData ? undefined : "TLS metadata not present in feed")
              }
            />
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

  // Determine banner, verdict, and coverage without auto-searching on mount.
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
      hasTcpProfile &&
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
      ...(hasTcpProfile && client
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
        ? `Not covered — no tcp_tls profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured tcp_tls profile to investigate.",
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
        ? "Click Investigate to inspect TCP RTT, retransmits, and TLS posture."
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
        sourcetype:
          selectedRow.sourceKind === "netflow_only"
            ? "stream:netflow"
            : "stream:tcp",
        client: selectedRow.client,
        server: selectedRow.server,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  return (
    <ProtocolLensLayout
      title="TCP Health & TLS"
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
            title="Client × server TCP/TLS health"
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
        result?.distribution.length ? (
          <DistributionBar
            title="Server RTT p50 / p95"
            items={result.distribution}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.client} → ${selectedRow.server}`
          : missingCell
            ? `${missingCell.row} → ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <CopyableIp value={selectedRow.client} label="client" /> →{" "}
            <CopyableIp value={selectedRow.server} label="server" />
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="client" /> →{" "}
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
            <dt>Source</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "netflow_only"
                ? "stream:netflow (fallback)"
                : "stream:tcp"}
            </dd>
            <dt>Dest ports</dt>
            <dd className="pl-mono">
              {selectedRow.destPorts.length
                ? selectedRow.destPorts.join(", ")
                : "—"}
            </dd>
            <dt>Client RTT (p50 / p95)</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "netflow_only"
                ? "Not covered"
                : formatRttPair(
                    selectedRow.clientRttP50Ms,
                    selectedRow.clientRttP95Ms,
                  )}
            </dd>
            <dt>Server RTT (p50 / p95)</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "netflow_only"
                ? "Not covered"
                : formatRttPair(
                    selectedRow.serverRttP50Ms,
                    selectedRow.serverRttP95Ms,
                  )}
            </dd>
            <dt>Retransmits / Resets</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "netflow_only"
                ? "Not covered"
                : `${selectedRow.retransmits} (${(selectedRow.retransmitPct ?? 0).toFixed(1)}% ${selectedRow.retransmitBasis}) / ${selectedRow.resets} resets`}
            </dd>
            <dt>Bytes / Packets</dt>
            <dd className="pl-mono">
              {formatBytes(selectedRow.totalBytes)} /{" "}
              {formatCount(selectedRow.totalPackets)} pkts
            </dd>
            {selectedRow.hasTlsData ? (
              <>
                <dt>TLS version</dt>
                <dd className="pl-mono">{selectedRow.tlsVersion ?? "—"}</dd>
                <dt>Cipher suite</dt>
                <dd className="pl-mono">{selectedRow.cipher ?? "—"}</dd>
                <dt>Cert subject</dt>
                <dd className="pl-mono">{selectedRow.certSubject ?? "—"}</dd>
                <dt>Cert issuer</dt>
                <dd className="pl-mono">{selectedRow.certIssuer ?? "—"}</dd>
                <dt>Days remaining</dt>
                <dd className="pl-mono">
                  {selectedRow.certDaysRemaining !== undefined
                    ? `${selectedRow.certDaysRemaining}d`
                    : (selectedRow.certNotAfter ?? "—")}
                </dd>
                {selectedRow.sni ? (
                  <>
                    <dt>SNI</dt>
                    <dd className="pl-mono">{selectedRow.sni}</dd>
                  </>
                ) : null}
                {selectedRow.sslError ? (
                  <>
                    <dt>SSL error</dt>
                    <dd className="pl-mono">{selectedRow.sslError}</dd>
                  </>
                ) : null}
              </>
            ) : (
              <>
                <dt>TLS posture</dt>
                <dd>
                  <StatusChip status="not_covered" />
                </dd>
              </>
            )}
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
                ? "Result hit the search row cap — this pair may have unseen traffic outside the capped rows."
                : "No TCP or NetFlow events observed for this pair in the selected UTC window."}
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

export default TcpTlsLensPage;
