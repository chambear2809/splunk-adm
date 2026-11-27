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
  formatUtcTimestamp,
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
  buildInterfaceRawEventsUrl,
  investigateInterfaceHealth,
  type InterfaceHealthInvestigationResult,
  type InterfaceHealthRow,
} from "./adapter";

export interface InterfaceHealthLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: InterfaceHealthInvestigationResult;
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
  device: string;
  iface: string;
  sourceMode: "dme" | "syslog" | "mixed";
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildInterfaceRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function InterfaceHealthLensPage({
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
}: InterfaceHealthLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: InterfaceHealthInvestigationResult } | undefined
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
        (p) => p.lens === "interface_health" && p.scope === scope,
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
      return { row: selectedRow.device, col: selectedRow.interface };
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
      const next = await investigateInterfaceHealth(
        client,
        {
          version: 1,
          lens: "interface_health",
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
            : "Interface health investigation failed.";
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
            distributionTitle: "",
            timelineEvents: [],
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

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const isSyslogOnlyMode =
    result?.sourceMode === "syslog_only" &&
    !result.rows.some((r) => r.hasCounterCoverage);

  const columns: ProtocolTableColumn<InterfaceHealthRow>[] = isSyslogOnlyMode
    ? [
        {
          key: "device",
          header: "Device",
          render: (r) => <CopyableIp value={r.device} label="device" />,
        },
        {
          key: "interface",
          header: "Interface",
          render: (r) => <span className="pl-mono">{r.interface}</span>,
        },
        {
          key: "flaps",
          header: "Flaps",
          align: "right",
          render: (r) =>
            r.flapCount !== undefined ? formatCount(r.flapCount) : "0",
        },
        {
          key: "lastMnemonic",
          header: "Last Mnemonic",
          render: (r) => (
            <span className="pl-mono">{r.lastMnemonic ?? "—"}</span>
          ),
        },
        {
          key: "counters",
          header: "Counters & Util",
          render: () => <StatusChip status="not_covered" />,
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
      ]
    : [
        {
          key: "device",
          header: "Device",
          render: (r) => <CopyableIp value={r.device} label="device" />,
        },
        {
          key: "interface",
          header: "Interface",
          render: (r) => <span className="pl-mono">{r.interface}</span>,
        },
        {
          key: "state",
          header: "Admin / Oper",
          render: (r) =>
            r.hasStateCoverage ? (
              <span className="pl-mono">
                {`${r.adminState ?? "—"} / ${r.operState ?? "—"}`}
              </span>
            ) : (
              "Not covered"
            ),
        },
        {
          key: "errors",
          header: "Errors",
          align: "right",
          render: (r) =>
            r.hasCounterCoverage && r.totalErrors !== undefined
              ? formatCount(r.totalErrors)
              : "Not covered",
        },
        {
          key: "discards",
          header: "Discards",
          align: "right",
          render: (r) =>
            r.hasCounterCoverage && r.totalDiscards !== undefined
              ? formatCount(r.totalDiscards)
              : "Not covered",
        },
        {
          key: "flaps",
          header: "Flaps",
          align: "right",
          render: (r) =>
            r.flapCount !== undefined
              ? formatCount(r.flapCount)
              : "Not covered",
        },
        {
          key: "util",
          header: "Util",
          align: "right",
          render: (r) =>
            r.utilizationPct !== undefined
              ? `${r.utilizationPct < 10 ? r.utilizationPct.toFixed(1) : Math.round(r.utilizationPct)}%`
              : "Not covered",
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
        ? `Not covered — no interface_health profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured interface_health profile to investigate.",
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
      ? "Click Investigate to inspect interface counters, state, and link flaps."
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
        device: selectedRow.device,
        iface: selectedRow.interface,
        sourceMode:
          selectedRow.sourceKind === "syslog_only"
            ? "syslog"
            : selectedRow.sourceKind === "dme_only"
              ? "dme"
              : "mixed",
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  const handleSelectTimelineEvent = (ev: ProtocolTimelineEvent) => {
    if (!result) return;
    const match = result.rows.find(
      (r) => `${r.device} ${r.interface}` === ev.lane,
    );
    if (match) {
      setMissingCell(undefined);
      onChangeParams({ item: match.id });
    }
  };

  return (
    <ProtocolLensLayout
      title="Interface & Link Health"
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
          <>
            <HeatMatrix
              title="Device × interface health"
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
            {result.timelineEvents.length > 0 ? (
              <SwimlaneTimeline
                title="Link flap & state timeline"
                earliest={earliest}
                latest={latest}
                events={result.timelineEvents}
                onSelectEvent={handleSelectTimelineEvent}
              />
            ) : null}
          </>
        ) : undefined
      }
      extraOverview={
        result?.distribution.length ? (
          <DistributionBar
            title={result.distributionTitle}
            items={result.distribution}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.device} · ${selectedRow.interface}`
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <CopyableIp value={selectedRow.device} label="device" /> ·{" "}
            <span className="pl-mono">{selectedRow.interface}</span>
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="device" /> ·{" "}
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
            <dt>Source</dt>
            <dd className="pl-mono">
              {selectedRow.sourceKind === "dme_and_syslog"
                ? "DME counters + NX-OS/ACI syslog"
                : selectedRow.sourceKind === "dme_only"
                  ? "DME / ND interface counters"
                  : "Syslog link events only"}
            </dd>
            {selectedRow.descr ? (
              <>
                <dt>Description</dt>
                <dd>{selectedRow.descr}</dd>
              </>
            ) : null}
            <dt>Admin / Oper</dt>
            <dd className="pl-mono">
              {selectedRow.hasStateCoverage
                ? `${selectedRow.adminState ?? "—"} / ${selectedRow.operState ?? "—"}`
                : "Not covered"}
            </dd>
            <dt>Speed / MTU</dt>
            <dd className="pl-mono">
              {selectedRow.speed || selectedRow.mtu !== undefined
                ? `${selectedRow.speed ?? "—"} / ${selectedRow.mtu ?? "—"}`
                : "Not covered"}
            </dd>
            <dt>Errors (CRC / In / Out)</dt>
            <dd className="pl-mono">
              {selectedRow.hasCounterCoverage
                ? `${selectedRow.crcErrors ?? "—"} / ${selectedRow.inErrors ?? "—"} / ${selectedRow.outErrors ?? "—"}`
                : "Not covered"}
            </dd>
            <dt>Discards / Drops (In / Out)</dt>
            <dd className="pl-mono">
              {selectedRow.hasCounterCoverage
                ? `${(selectedRow.inDiscards ?? 0) + (selectedRow.rxDrops ?? 0)} / ${(selectedRow.outDiscards ?? 0) + (selectedRow.txDrops ?? 0)}`
                : "Not covered"}
            </dd>
            <dt>Link flaps</dt>
            <dd className="pl-mono">
              {selectedRow.flapCount !== undefined
                ? formatCount(selectedRow.flapCount)
                : "Not covered"}
            </dd>
            <dt>Peak utilization</dt>
            <dd className="pl-mono">
              {selectedRow.utilizationPct !== undefined
                ? `${selectedRow.utilizationPct.toFixed(1)}%`
                : "Not covered"}
            </dd>
            {selectedRow.inOctets !== undefined ||
            selectedRow.outOctets !== undefined ? (
              <>
                <dt>Octets (RX / TX)</dt>
                <dd className="pl-mono">
                  {`${formatBytes(selectedRow.inOctets)} / ${formatBytes(selectedRow.outOctets)}`}
                </dd>
              </>
            ) : null}
            {selectedRow.recentSyslog.length ? (
              <>
                <dt>Recent syslog</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.recentSyslog.map((ev, i) => (
                      <li key={`${ev.timestamp}-${ev.mnemonic}-${i}`}>
                        <span className="pl-mono">
                          {formatUtcTimestamp(ev.timestamp)} {ev.mnemonic}
                        </span>
                        {ev.summary ? ` — ${ev.summary}` : ""}
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
                ? "Result hit the search row cap — this interface may have unseen events outside the capped rows."
                : "No DME counter snapshots or syslog link events observed for this device and interface in the selected UTC window."}
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

export default InterfaceHealthLensPage;
