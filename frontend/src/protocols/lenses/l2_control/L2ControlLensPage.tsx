import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
import { formatCount, formatUtcTimestamp } from "../../shared/format";
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
  buildL2ControlRawEventsUrl,
  investigateL2Control,
  resolveL2ControlThresholds,
  type L2ControlInvestigationResult,
  type L2ControlRow,
  type L2Subsystem,
} from "./adapter";

export interface L2ControlLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: L2ControlInvestigationResult;
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

const IPV4_OR_IPV6_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})$/;

function isIpLike(value: string): boolean {
  return IPV4_OR_IPV6_RE.test(value.trim());
}

function formatLeaseDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(seconds % 3600 === 0 ? 0 : 1)} h`;
}

function safeRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly string[];
  device: string;
  subsystem: L2Subsystem;
  subject: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildL2ControlRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function L2ControlLensPage({
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
}: L2ControlLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: L2ControlInvestigationResult } | undefined
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
        (p) => p.lens === "l2_control" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const hasStreamProfile = useMemo(
    () =>
      scopedProfiles.some((p) => {
        const kind = resolveL2ControlThresholds(p).sourceKind;
        return kind === "stream_dhcp" || kind === "auto";
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
      return { row: selectedRow.device, col: selectedRow.subsystem };
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
      const next = await investigateL2Control(
        client,
        {
          version: 1,
          lens: "l2_control",
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
            : "L2 control investigation failed.";
        setStampedResult({
          stamp: stampKey,
          value: {
            verdict: message,
            verdictStatus: "unknown",
            coverageStatus: "unknown",
            coverageLabel: "Unavailable",
            kpis: [],
            rows: [],
            timeline: [],
            timelineItemMap: {},
            matrixRows: [],
            matrixCols: ["DHCP", "STP", "LACP", "ARP", "LLDP"],
            matrixCells: [],
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
        ["dhcp", "arp"],
        controller.signal,
      );
      const entry =
        entries.find((e) => e.state === "estimate_only") ?? entries[0];
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
                  "Stream dhcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: L2ControlInvestigationResult["bannerState"] =
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
                    "Stream dhcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
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

  const columns: ProtocolTableColumn<L2ControlRow>[] = [
    {
      key: "subsystem",
      header: "Subsystem",
      render: (r) => <span className="pl-mono">{r.subsystem}</span>,
    },
    {
      key: "device",
      header: "Device",
      render: (r) =>
        isIpLike(r.device) ? (
          <CopyableIp value={r.device} label="device" />
        ) : (
          <span className="pl-mono">{r.device}</span>
        ),
    },
    {
      key: "subject",
      header: "VLAN / Port",
      render: (r) => <span className="pl-mono">{r.subject}</span>,
    },
    {
      key: "events",
      header: "Events",
      align: "right",
      render: (r) => formatCount(r.eventCount),
    },
    {
      key: "anomalies",
      header: "Alerts",
      align: "right",
      render: (r) => formatCount(r.anomalyCount),
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
        ? `Not covered — no l2_control profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured l2_control profile to investigate.",
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
        ? "Click Investigate to inspect DHCP, STP, LACP, ARP, and LLDP control events."
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
        device: selectedRow.device,
        subsystem: selectedRow.subsystem,
        subject: selectedRow.subject,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  return (
    <ProtocolLensLayout
      title="L2 Control Plane"
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
            title="Device × L2 subsystem health"
            rowHeader="Device"
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
        result?.timeline.length ? (
          <SwimlaneTimeline
            title="L2 control timeline"
            earliest={earliest}
            latest={latest}
            events={result.timeline}
            onSelectEvent={(ev) => {
              const targetId = result.timelineItemMap[ev.id];
              if (targetId) {
                setMissingCell(undefined);
                onChangeParams({ item: targetId });
              }
            }}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.subsystem} · ${selectedRow.device} (${selectedRow.subject})`
          : missingCell
            ? `${missingCell.col} · ${missingCell.row}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            {selectedRow.subsystem} ·{" "}
            {isIpLike(selectedRow.device) ? (
              <CopyableIp value={selectedRow.device} label="device" />
            ) : (
              <span className="pl-mono">{selectedRow.device}</span>
            )}{" "}
            ({selectedRow.subject})
          </span>
        ) : missingCell ? (
          <span>
            {missingCell.col} ·{" "}
            {isIpLike(missingCell.row) ? (
              <CopyableIp value={missingCell.row} label="device" />
            ) : (
              <span className="pl-mono">{missingCell.row}</span>
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
            <dt>Subsystem</dt>
            <dd className="pl-mono">{selectedRow.subsystem}</dd>
            <dt>Device / Server</dt>
            <dd>
              {isIpLike(selectedRow.device) ? (
                <CopyableIp value={selectedRow.device} label="device" />
              ) : (
                <span className="pl-mono">{selectedRow.device}</span>
              )}
            </dd>
            <dt>VLAN / Interface</dt>
            <dd className="pl-mono">{selectedRow.subject}</dd>
            <dt>Sources</dt>
            <dd className="pl-mono">{selectedRow.sourcetypes.join(", ")}</dd>
            <dt>Events / Alerts</dt>
            <dd className="pl-mono">
              {formatCount(selectedRow.eventCount)} /{" "}
              {formatCount(selectedRow.anomalyCount)}
            </dd>
            {selectedRow.lastSeen ? (
              <>
                <dt>Last event</dt>
                <dd className="pl-mono">
                  {formatUtcTimestamp(selectedRow.lastSeen)}
                </dd>
              </>
            ) : null}
            {selectedRow.dhcpDetails ? (
              <>
                <dt>DHCP messages</dt>
                <dd className="pl-mono">
                  {`D:${selectedRow.dhcpDetails.discovers} O:${selectedRow.dhcpDetails.offers} R:${selectedRow.dhcpDetails.requests} A:${selectedRow.dhcpDetails.acks} N:${selectedRow.dhcpDetails.naks}`}
                </dd>
                <dt>Client MACs</dt>
                <dd className="pl-mono">
                  {selectedRow.dhcpDetails.clientMacs.length
                    ? selectedRow.dhcpDetails.clientMacs.join(", ")
                    : "—"}
                </dd>
                <dt>Assigned IPs (yiaddr)</dt>
                <dd>
                  {selectedRow.dhcpDetails.assignedIps.length ? (
                    selectedRow.dhcpDetails.assignedIps.map((ip, idx) => (
                      <span key={ip}>
                        {idx > 0 ? ", " : ""}
                        <CopyableIp value={ip} label="yiaddr" />
                      </span>
                    ))
                  ) : (
                    <span className="pl-mono">—</span>
                  )}
                </dd>
                <dt>Lease time</dt>
                <dd className="pl-mono">
                  {selectedRow.dhcpDetails.leaseTimesSec.length
                    ? selectedRow.dhcpDetails.leaseTimesSec
                        .map(formatLeaseDuration)
                        .join(", ")
                    : "—"}
                </dd>
              </>
            ) : null}
            {selectedRow.portChannel ? (
              <>
                <dt>Port-channel</dt>
                <dd className="pl-mono">{selectedRow.portChannel}</dd>
              </>
            ) : null}
            {selectedRow.memberInterfaces.length ? (
              <>
                <dt>Members</dt>
                <dd className="pl-mono">
                  {selectedRow.memberInterfaces.join(", ")}
                </dd>
              </>
            ) : null}
            {selectedRow.lacpState || selectedRow.operState ? (
              <>
                <dt>LACP / Oper state</dt>
                <dd className="pl-mono">
                  {[selectedRow.lacpState, selectedRow.operState]
                    .filter(Boolean)
                    .join(" / ")}
                </dd>
              </>
            ) : null}
            {selectedRow.stpRoot ? (
              <>
                <dt>STP root</dt>
                <dd className="pl-mono">{selectedRow.stpRoot}</dd>
              </>
            ) : null}
            {selectedRow.portRole || selectedRow.portState ? (
              <>
                <dt>Port role / state</dt>
                <dd className="pl-mono">
                  {[selectedRow.portRole, selectedRow.portState]
                    .filter(Boolean)
                    .join(" / ")}
                </dd>
              </>
            ) : null}
            {selectedRow.recentMnemonics.length ? (
              <>
                <dt>Recent mnemonics</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.recentMnemonics.map((mnem) => (
                      <li key={mnem} className="pl-mono">
                        {mnem}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            ) : null}
            <dt>Last detail</dt>
            <dd>{selectedRow.lastEventSummary}</dd>
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
              {missingCell.status === "not_covered"
                ? `${missingCell.col} is not collected by the active source profiles for this scope.`
                : missingCell.status === "unknown"
                  ? "Result hit the search row cap — this device and subsystem may have unseen events outside the capped rows."
                  : `No ${missingCell.col} control events observed on ${missingCell.row} in the selected UTC window.`}
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

export default L2ControlLensPage;
