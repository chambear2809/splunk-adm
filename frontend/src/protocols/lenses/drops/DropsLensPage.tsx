import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
import { formatCount, formatUtcTimestamp } from "../../shared/format";
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
  buildDropsRawEventsUrl,
  formatDropVolume,
  investigateDrops,
  type DropsEnforcerKind,
  type DropsInvestigationResult,
  type DropsPairRow,
} from "./adapter";

export interface DropsLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: DropsInvestigationResult;
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
  enforcerKind: DropsEnforcerKind;
  sourcetypes: readonly string[];
  srcIp: string;
  destIp: string;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildDropsRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

export function DropsLensPage({
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
}: DropsLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: DropsInvestigationResult } | undefined
  >(() =>
    initialResult
      ? { stamp: currentStampKey, value: initialResult }
      : undefined,
  );
  const stampedResultRef = useRef(stampedResult);
  stampedResultRef.current = stampedResult;

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
        (p) => p.lens === "drops" && p.scope === scope,
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
      return { row: selectedRow.srcIp, col: selectedRow.destIp };
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
      const next = await investigateDrops(
        client,
        {
          version: 1,
          lens: "drops",
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
            : "Blocked traffic investigation failed.";
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
            timelineEvents: [],
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

  const columns: ProtocolTableColumn<DropsPairRow>[] = [
    {
      key: "source",
      header: "Source",
      render: (r) => <CopyableIp value={r.srcIp} label="source" />,
    },
    {
      key: "destination",
      header: "Destination",
      render: (r) => <CopyableIp value={r.destIp} label="destination" />,
    },
    {
      key: "service",
      header: "Service / Port",
      render: (r) =>
        r.serviceLabel ? (
          <span className="pl-mono">{r.serviceLabel}</span>
        ) : (
          <StatusChip
            status="not_covered"
            title="Service/port not reported by this source"
          />
        ),
    },
    {
      key: "enforcer",
      header: "Enforcer",
      render: (r) => <span className="pl-mono">{r.enforcerLabel}</span>,
    },
    {
      key: "reason",
      header: "Native Reason / Rule",
      render: (r) =>
        r.attributed ? (
          <span>{r.primaryReason}</span>
        ) : (
          <StatusChip
            status="unknown"
            label="Unattributed"
            title={r.primaryReason}
          />
        ),
    },
    {
      key: "events",
      header: "Events",
      align: "right",
      render: (r) => formatCount(r.eventCount),
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
        ? `Not covered — no drops profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured drops profile to investigate.",
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
      ? "Click Investigate to inspect native firewall, Hubble, ND, and ACI drops."
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
        enforcerKind: selectedRow.enforcerKind,
        sourcetypes: selectedRow.sourcetypes,
        srcIp: selectedRow.srcIp,
        destIp: selectedRow.destIp,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  const volumeSummary = selectedRow
    ? formatDropVolume(selectedRow.packetCount, selectedRow.byteCount)
    : "";

  return (
    <ProtocolLensLayout
      title="Blocked Traffic & Drops"
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
            title="Source × destination drops"
            rowHeader="Source"
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
            title="Drops by enforcer"
            earliest={earliest}
            latest={latest}
            events={result.timelineEvents}
            onSelectEvent={(ev) => {
              const rowId = ev.id.split("\u001f")[0];
              if (rowId && result.rows.some((r) => r.id === rowId)) {
                setMissingCell(undefined);
                onChangeParams({ item: rowId });
              }
            }}
          />
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? `${selectedRow.srcIp} → ${selectedRow.destIp}`
          : missingCell
            ? `${missingCell.row} → ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            <CopyableIp value={selectedRow.srcIp} label="source" /> →{" "}
            <CopyableIp value={selectedRow.destIp} label="destination" />
          </span>
        ) : missingCell ? (
          <span>
            <CopyableIp value={missingCell.row} label="source" /> →{" "}
            <CopyableIp value={missingCell.col} label="destination" />
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
            <dd>
              <CopyableIp value={selectedRow.srcIp} label="source" />
              {selectedRow.srcPods.length ? (
                <div className="pl-mono">{selectedRow.srcPods.join(", ")}</div>
              ) : null}
            </dd>
            <dt>Destination</dt>
            <dd>
              <CopyableIp value={selectedRow.destIp} label="destination" />
              {selectedRow.destPods.length ? (
                <div className="pl-mono">{selectedRow.destPods.join(", ")}</div>
              ) : null}
            </dd>
            <dt>Enforcer</dt>
            <dd className="pl-mono">
              {selectedRow.enforcerLabel} · {selectedRow.devices.join(", ")}
            </dd>
            <dt>Service / Port</dt>
            <dd className="pl-mono">
              {selectedRow.serviceLabel ?? (
                <StatusChip
                  status="not_covered"
                  title="Service/port not reported by this source"
                />
              )}
            </dd>
            <dt>Drops</dt>
            <dd className="pl-mono">
              {formatCount(selectedRow.eventCount)}{" "}
              {selectedRow.eventCount === 1 ? "event" : "events"}
              {volumeSummary ? ` (${volumeSummary})` : ""}
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
            {selectedRow.nativeDetails.length ? (
              <>
                <dt>Native details</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.nativeDetails.map((detail) => (
                      <li key={detail} className="pl-mono">
                        {detail}
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
                ? "Result hit the search row cap — unseen drop events may exist for this source and destination outside the capped rows."
                : "No drops observed between this source and destination in the configured sources for this UTC window."}
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

export default DropsLensPage;
