import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
  ProtocolTimelineEvent,
} from "../../shared/contract";
import { formatCount, formatBytes } from "../../shared/format";
import { checkStreamEstimateMode } from "../../shared/streamReadiness";
import {
  CopyableIp,
  HeatMatrix,
  ProtocolLensLayout,
  StatusChip,
  SwimlaneTimeline,
  type BannerState,
  type ProtocolTableColumn,
} from "../../shared/ui";
import {
  buildQosIcmpRawEventsUrl,
  formatDscpLabel,
  formatEcnLabel,
  investigateQosIcmp,
  resolveQosIcmpThresholds,
  type QosIcmpFlowRow,
  type QosIcmpInvestigationResult,
  type QosIcmpSourcetype,
} from "./adapter";

export interface QosIcmpLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: QosIcmpInvestigationResult;
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
  srcIp: string;
  dstIp: string;
  sourcetypes: readonly QosIcmpSourcetype[];
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildQosIcmpRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function QosIcmpLensPage({
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
}: QosIcmpLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: QosIcmpInvestigationResult } | undefined
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
        (p) => p.lens === "qos_icmp" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const hasStreamIcmpProfile = useMemo(
    () =>
      scopedProfiles.some((p) => {
        const sk = resolveQosIcmpThresholds(p).sourceKind;
        return sk === "stream_icmp" || sk === "auto";
      }),
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
      const firstExp = selectedRow.exporterObservations[0];
      if (firstExp) {
        const col =
          firstExp.dscps.length > 0
            ? formatDscpLabel(firstExp.dscps[0])
            : "Unmarked";
        return { row: firstExp.exporterIp, col };
      }
      if (selectedRow.hasNdData) {
        return {
          row: selectedRow.ndNodes[0] ?? selectedRow.ndHost ?? "nd-fabric",
          col: "ND Drops",
        };
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
      const next = await investigateQosIcmp(
        client,
        {
          version: 1,
          lens: "qos_icmp",
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
            : "QoS/DSCP & ICMP investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            hasActiveNetflow: false,
            netflowDegraded: false,
            hasActiveIcmp: false,
            hasActiveNd: false,
            kpis: [],
            rows: [],
            matrixRows: [],
            matrixCols: [],
            matrixCells: [],
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
      const [entry] = await checkStreamEstimateMode(
        client,
        ["icmp"],
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
                  "Stream icmp is in Estimate mode (statsOnly=true); no ICMP event rows are indexed.",
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: QosIcmpInvestigationResult["bannerState"] =
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
            hasActiveIcmp:
              prev.value.hasActiveIcmp || entry.state === "enabled",
            bannerState: nextBannerState,
            bannerReason: entry.detail,
            ...(entry.state === "estimate_only" && prev.value.rows.length === 0
              ? {
                  verdict:
                    "Stream icmp is in Estimate mode (statsOnly=true); no ICMP event rows are indexed.",
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

  const columns: ProtocolTableColumn<QosIcmpFlowRow>[] = [
    {
      key: "src",
      header: "Source",
      render: (r) => <CopyableIp value={r.srcIp} label="source" />,
    },
    {
      key: "dst",
      header: "Destination",
      render: (r) => <CopyableIp value={r.dstIp} label="destination" />,
    },
    {
      key: "flow",
      header: "Flow",
      render: (r) => <span className="pl-mono">{r.flowLabel}</span>,
    },
    {
      key: "dscp",
      header: "DSCP / ECN",
      render: (r) =>
        r.hasNetflowData ? (
          <span className="pl-mono">{r.dscpSummary}</span>
        ) : result?.netflowDegraded ? (
          <StatusChip
            status="unknown"
            title={result.netflowDegradedReason ?? "NetFlow sample capped"}
          />
        ) : result?.hasActiveNetflow ? (
          <StatusChip status="none_observed" />
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "icmp",
      header: "ICMP / PMTUD",
      render: (r) =>
        result?.hasActiveIcmp || r.hasIcmpData ? (
          <span className="pl-mono">
            {r.icmpSummary === "0" ? "0 events" : r.icmpSummary}
          </span>
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "drops",
      header: "Fabric Drops",
      align: "right",
      render: (r) =>
        result?.hasActiveNd || r.hasNdData ? (
          <span className="pl-mono">
            {r.dropPktCount > 0
              ? `${formatCount(r.dropPktCount)} pkts`
              : r.dropReasons.length > 0
                ? r.dropReasons[0]
                : "0 pkts"}
          </span>
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
      hasStreamIcmpProfile &&
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
      ...(hasStreamIcmpProfile && client
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
        ? `Not covered — no qos_icmp profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured qos_icmp profile to investigate.",
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
        ? "Click Investigate to inspect DSCP remarking, PMTUD candidates, and fabric drops."
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
        srcIp: selectedRow.srcIp,
        dstIp: selectedRow.dstIp,
        sourcetypes: selectedRow.sourcetypes,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
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
      title="QoS/DSCP & ICMP"
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
            title="Exporter × DSCP class matrix"
            rowHeader="Exporter"
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
        result?.timelineEvents.length ? (
          <SwimlaneTimeline
            title="ICMP & fabric drop timeline"
            earliest={earliest}
            latest={latest}
            events={result.timelineEvents}
            onSelectEvent={handleSelectTimelineEvent}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.srcIp} → ${selectedRow.dstIp}`
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <CopyableIp value={selectedRow.srcIp} label="source" /> →{" "}
            <CopyableIp value={selectedRow.dstIp} label="destination" />
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="exporter" /> ·{" "}
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
            <dt>Source IP</dt>
            <dd>
              <CopyableIp value={selectedRow.srcIp} label="source" />
            </dd>
            <dt>Destination IP</dt>
            <dd>
              <CopyableIp value={selectedRow.dstIp} label="destination" />
            </dd>
            <dt>Flow</dt>
            <dd className="pl-mono">{selectedRow.flowLabel}</dd>
            <dt>DSCP / ECN</dt>
            <dd className="pl-mono">
              {selectedRow.hasNetflowData ? (
                selectedRow.dscpSummary
              ) : result?.netflowDegraded ? (
                <StatusChip
                  status="unknown"
                  title={
                    result.netflowDegradedReason ?? "NetFlow sample capped"
                  }
                />
              ) : result?.hasActiveNetflow ? (
                <StatusChip status="none_observed" />
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>
            {selectedRow.minTtl !== undefined ? (
              <>
                <dt>Min TTL</dt>
                <dd className="pl-mono">{selectedRow.minTtl}</dd>
              </>
            ) : null}
            {selectedRow.totalBytes > 0 || selectedRow.totalPackets > 0 ? (
              <>
                <dt>Volume</dt>
                <dd className="pl-mono">
                  {`${formatBytes(selectedRow.totalBytes)} · ${formatCount(selectedRow.totalPackets)} pkts`}
                </dd>
              </>
            ) : null}
            {selectedRow.exporterObservations.length ? (
              <>
                <dt>Exporters</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.exporterObservations.map((exp) => {
                      const dscpStr = exp.dscps.length
                        ? exp.dscps.map((d) => formatDscpLabel(d)).join(", ")
                        : "Unmarked";
                      const ecnStr = exp.ecns.length
                        ? exp.ecns.map((e) => formatEcnLabel(e)).join(", ")
                        : "—";
                      return (
                        <li key={exp.exporterIp}>
                          <CopyableIp value={exp.exporterIp} label="exporter" />{" "}
                          <span className="pl-mono">
                            {`${dscpStr} · ECN ${ecnStr} · ${exp.flowCount} ${exp.flowCount === 1 ? "flow" : "flows"}`}
                            {exp.minTtl !== undefined
                              ? ` · min TTL ${exp.minTtl}`
                              : ""}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                </dd>
              </>
            ) : null}
            <dt>ICMP / PMTUD</dt>
            <dd className="pl-mono">
              {result?.hasActiveIcmp || selectedRow.hasIcmpData ? (
                `${selectedRow.icmpSummary} (PMTUD: ${selectedRow.pmtudCount} · TTL: ${selectedRow.ttlExceededCount} · Unreach: ${selectedRow.unreachableCount})`
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>
            <dt>Fabric Drops</dt>
            <dd className="pl-mono">
              {result?.hasActiveNd || selectedRow.hasNdData ? (
                `${formatCount(selectedRow.dropPktCount)} pkts${selectedRow.fabricName ? ` · ${selectedRow.fabricName}` : ""}`
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>
            {selectedRow.dropReasons.length ? (
              <>
                <dt>Drop reasons</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.dropReasons.map((reason) => (
                      <li key={reason} className="pl-mono">
                        {reason}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
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
                ? "Result hit the search row cap — this exporter and DSCP class may have unseen flows outside the capped rows."
                : "No flows observed for this exporter and DSCP class in the selected UTC window."}
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

export default QosIcmpLensPage;
