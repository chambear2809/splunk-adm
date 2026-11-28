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
import { formatCount, formatUtcTimestamp } from "../../shared/format";
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
  buildStateEventsRawEventsUrl,
  investigateStateEvents,
  type StateEventDeviceRow,
  type StateEventsInvestigationResult,
} from "./adapter";

export interface StateEventsLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: StateEventsInvestigationResult;
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

function isIpLiteral(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

function renderDeviceLabel(device: string) {
  return isIpLiteral(device) ? (
    <CopyableIp value={device} label="device" />
  ) : (
    <span className="pl-mono">{device}</span>
  );
}

function safeRawEventsUrl(options: {
  index: string;
  rawHosts: readonly string[];
  sourceCoverage: StateEventDeviceRow["sourceCoverage"];
  includeAci: boolean;
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildStateEventsRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

const STATE_EVENTS_FILTER_FIELDS: readonly ProtocolFilterFieldSpec[] = [
  { key: "device", label: "Device", placeholder: "Device", primary: true },
  {
    key: "iface",
    label: "Interface or DN",
    placeholder: "Interface / DN",
    primary: true,
  },
];

export function StateEventsLensPage({
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
}: StateEventsLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: StateEventsInvestigationResult } | undefined
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
        (p) => p.lens === "state_events" && p.scope === scope,
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
        row: selectedRow.device,
        col: selectedRow.domains[0] ?? "Link",
      };
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
    try {
      const next = await investigateStateEvents(
        client,
        {
          version: 1,
          lens: "state_events",
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
            : "State-change investigation failed.";
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
            timelineRowByEventId: {},
            distribution: [],
            outcomes: [],
            capped: false,
            sourceMode: "none",
            includeAci: true,
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

  handleInvestigateRef.current = handleInvestigate;

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const columns: ProtocolTableColumn<StateEventDeviceRow>[] = [
    {
      key: "device",
      header: "Device",
      render: (r) => renderDeviceLabel(r.device),
    },
    {
      key: "events",
      header: "Events",
      align: "right",
      render: (r) => formatCount(r.eventCount),
    },
    {
      key: "critical",
      header: "Critical/Error",
      align: "right",
      render: (r) => formatCount(r.criticalErrorCount),
    },
    {
      key: "domains",
      header: "Domains",
      render: (r) => <span className="pl-mono">{r.domains.join(", ")}</span>,
    },
    {
      key: "topCode",
      header: "Top Mnemonic / Code",
      render: (r) => <span className="pl-mono">{r.topCode}</span>,
    },
    {
      key: "latest",
      header: "Latest",
      render: (r) => (
        <span className="pl-mono">{formatUtcTimestamp(r.latestTime)}</span>
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
        ? `Not covered — no state_events profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured state_events profile to investigate.",
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
      ? "Click Investigate to inspect network state changes across devices and domains."
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
        rawHosts: selectedRow.rawHosts,
        sourceCoverage: selectedRow.sourceCoverage,
        includeAci: result?.includeAci ?? true,
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
    const mappedId =
      result.timelineRowByEventId[ev.id] ?? ev.id.split("\u001f")[0];
    if (mappedId && result.rows.some((r) => r.id === mappedId)) {
      setMissingCell(undefined);
      onChangeParams({ item: mappedId });
    }
  };

  return (
    <ProtocolLensLayout
      title="State-Change Timeline"
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
            title="Device × operational domain"
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
        result &&
        (result.timelineEvents.length > 0 || result.distribution.length > 0) ? (
          <>
            {result.timelineEvents.length > 0 ? (
              <SwimlaneTimeline
                title="Device timeline"
                earliest={earliest}
                latest={latest}
                events={result.timelineEvents}
                onSelectEvent={handleSelectTimelineEvent}
              />
            ) : null}
            {result.distribution.length > 0 ? (
              <DistributionBar
                title="Operational domains"
                items={result.distribution}
                mode="count"
              />
            ) : null}
          </>
        ) : undefined
      }
      drawerTitle={
        selectedRow
          ? selectedRow.device
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          renderDeviceLabel(selectedRow.device)
        ) : missingCell ? (
          <span>
            {renderDeviceLabel(missingCell.row)} ·{" "}
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
            <dt>Device</dt>
            <dd>{renderDeviceLabel(selectedRow.device)}</dd>
            <dt>Events</dt>
            <dd className="pl-mono">
              {`${formatCount(selectedRow.eventCount)} total · ${formatCount(selectedRow.criticalErrorCount)} critical/error`}
            </dd>
            <dt>Domains</dt>
            <dd className="pl-mono">{selectedRow.domains.join(", ")}</dd>
            <dt>Source</dt>
            <dd className="pl-mono">
              {selectedRow.sourceCoverage === "syslog_and_aci_faults"
                ? "SC4S / NX-OS / ACI Syslog + ACI Faults/Events"
                : selectedRow.sourceCoverage === "aci_faults_only"
                  ? "ACI faultInst / eventRecord"
                  : "SC4S / NX-OS / ACI Syslog"}
            </dd>
            <dt>Qualification</dt>
            <dd>
              {selectedRow.hasHsrpVrrp
                ? "HSRP/VRRP transitions are qualified via syslog only (DME classes are not qualified in TA schema). Config-change and AAA/auth events are excluded."
                : selectedRow.sourceCoverage === "aci_faults_only"
                  ? "ACI faultInst/eventRecord records reflect APIC fault lifecycle and events. Config-change and AAA/auth categories are excluded."
                  : "HSRP/VRRP stays on the syslog path (DME classes not qualified in TA schema). Config-change and AAA/auth categories are excluded."}
            </dd>
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
            <dt>Recent transitions</dt>
            <dd>
              <ul className="pl-kv-list">
                {selectedRow.transitions.map((tr) => (
                  <li key={tr.id}>
                    <span className="pl-mono">
                      {formatUtcTimestamp(tr.timestamp)} · {tr.domainLabel} ·{" "}
                      {tr.severityLabel} · {tr.codeOrMnemonic}
                      {tr.interfaceOrDn ? ` (${tr.interfaceOrDn})` : ""}
                    </span>
                    {" — "}
                    {tr.summary}
                  </li>
                ))}
              </ul>
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
                ? "Search hit row cap or partial coverage — this device and domain may have unseen transitions outside the returned rows."
                : "No operational state transitions observed for this device and domain in the selected UTC window."}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      filter={filter}
      filterFields={STATE_EVENTS_FILTER_FIELDS}
      filterSuggestions={{
        device: collectFilterSuggestions(
          (result?.rows ?? []).flatMap((r) => [r.device, ...r.rawHosts]),
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
              const next: ProtocolFilter = {
                device: selectedRow.rawHosts[0] ?? selectedRow.device,
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
      focusFlowLabel="Focus device"
      onScopeChange={(nextScope) => {
        pendingAutoInvestigateRef.current = false;
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

export default StateEventsLensPage;
