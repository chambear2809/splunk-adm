import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
import { formatCount, formatDurationMs } from "../../shared/format";
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
  buildDnsOpsRawEventsUrl,
  investigateDnsOps,
  resolveDnsOpsThresholds,
  type DnsOpsInvestigationResult,
  type DnsOpsPairRow,
  type DnsOpsSourcetype,
} from "./adapter";

export interface DnsOpsLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: DnsOpsInvestigationResult;
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

function formatLatencyPair(p50?: number, p95?: number): string {
  if (p50 === undefined && p95 === undefined) return "Not covered";
  return `${formatDurationMs(p50)} / ${formatDurationMs(p95)}`;
}

function safeRawEventsUrl(options: {
  index: string;
  sourcetype: DnsOpsSourcetype;
  client: string;
  resolver: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildDnsOpsRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function DnsOpsLensPage({
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
}: DnsOpsLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: DnsOpsInvestigationResult } | undefined
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
        (p) => p.lens === "dns_ops" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const hasStreamDnsProfile = useMemo(
    () =>
      scopedProfiles.some(
        (p) => resolveDnsOpsThresholds(p).sourcetype === "stream:dns",
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
      return { row: selectedRow.client, col: selectedRow.resolver };
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
      const next = await investigateDnsOps(
        client,
        {
          version: 1,
          lens: "dns_ops",
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
            : "DNS Operations investigation failed.";
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
        ["dns"],
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
        setStreamModeNotice({
          state:
            entry.state === "estimate_only" ? "estimate_only" : "unavailable",
          reason: entry.detail,
          ...(entry.state === "estimate_only"
            ? {
                verdict:
                  "Stream dns is in Estimate mode (statsOnly=true); no event rows are indexed.",
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: DnsOpsInvestigationResult["bannerState"] =
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
                    "Stream dns is in Estimate mode (statsOnly=true); no event rows are indexed.",
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

  const columns: ProtocolTableColumn<DnsOpsPairRow>[] = [
    {
      key: "client",
      header: "Client",
      render: (r) => <CopyableIp value={r.client} label="client" />,
    },
    {
      key: "resolver",
      header: "Resolver",
      render: (r) => <CopyableIp value={r.resolver} label="resolver" />,
    },
    {
      key: "queries",
      header: "Queries",
      align: "right",
      render: (r) => formatCount(r.queryCount),
    },
    {
      key: "latency",
      header: "Latency p95",
      align: "right",
      render: (r) =>
        r.latencyP95Ms !== undefined
          ? formatDurationMs(r.latencyP95Ms)
          : "Not covered",
    },
    {
      key: "nxdomain",
      header: "NXDOMAIN",
      align: "right",
      render: (r) =>
        r.nxdomainPct !== undefined
          ? `${r.nxdomainPct.toFixed(1)}%`
          : "Not covered",
    },
    {
      key: "servfail",
      header: "SERVFAIL",
      align: "right",
      render: (r) =>
        r.servfailPct !== undefined
          ? `${r.servfailPct.toFixed(1)}%`
          : "Not covered",
    },
    {
      key: "churn",
      header: "Churn",
      align: "right",
      render: (r) =>
        r.answerChurnCount > 0 ? formatCount(r.answerChurnCount) : "0",
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
      hasStreamDnsProfile &&
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
      ...(hasStreamDnsProfile && client
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
        ? `Not covered — no dns_ops profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured dns_ops profile to investigate.",
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
        ? "Click Investigate to inspect DNS errors, latency, and answer churn."
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
          selectedRow.sourceKind === "hubble_only"
            ? "cilium:hubble:flow"
            : "stream:dns",
        client: selectedRow.client,
        resolver: selectedRow.resolver,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  return (
    <ProtocolLensLayout
      title="DNS Operations"
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
            title="Client × resolver DNS health"
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
            title="Resolver latency p50 / p95"
            items={result.distribution}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.client} → ${selectedRow.resolver}`
          : missingCell
            ? `${missingCell.row} → ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <CopyableIp value={selectedRow.client} label="client" /> →{" "}
            <CopyableIp value={selectedRow.resolver} label="resolver" />
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="client" /> →{" "}
            <CopyableIp value={missingCell.col} label="resolver" />
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
            <dt>Client</dt>
            <dd>
              <CopyableIp value={selectedRow.client} label="client" />
            </dd>
            <dt>Resolver</dt>
            <dd>
              <CopyableIp value={selectedRow.resolver} label="resolver" />
            </dd>
            <dt>Source</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "hubble_only"
                ? "cilium:hubble:flow (fallback)"
                : "stream:dns"}
            </dd>
            <dt>Queries</dt>
            <dd className="pl-mono">
              {formatCount(selectedRow.queryCount)} ({selectedRow.nxdomainCount}{" "}
              NXDOMAIN · {selectedRow.servfailCount} SERVFAIL ·{" "}
              {selectedRow.refusedCount} REFUSED)
            </dd>
            <dt>Latency (p50 / p95)</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "hubble_only" &&
              selectedRow.latencyP95Ms === undefined
                ? "Not covered"
                : formatLatencyPair(
                    selectedRow.latencyP50Ms,
                    selectedRow.latencyP95Ms,
                  )}
            </dd>
            <dt>Answer churn</dt>
            <dd className="pl-mono">
              {selectedRow.answerChurnCount > 0
                ? `${selectedRow.answerChurnCount} ${selectedRow.answerChurnCount === 1 ? "domain" : "domains"} (${selectedRow.answerChurnSummary})`
                : "0"}
            </dd>
            {selectedRow.topFailingDomains.length ? (
              <>
                <dt>Top failing domains</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.topFailingDomains.map((d) => (
                      <li
                        key={`${d.query}-${d.rcode}`}
                        className="pl-mono"
                      >{`${d.query} (${d.rcode} × ${d.count})`}</li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            {selectedRow.searchSuffixHint ? (
              <>
                <dt>Suffix hint</dt>
                <dd>{selectedRow.searchSuffixHint}</dd>
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
                ? "Result hit the search row cap — this pair may have unseen DNS queries outside the capped rows."
                : "No DNS events observed for this client and resolver in the selected UTC window."}
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

export default DnsOpsLensPage;
