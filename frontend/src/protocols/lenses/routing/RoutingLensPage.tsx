import { useEffect, useMemo, useRef, useState } from "react";
import type {
  ProtocolFilter,
  ProtocolFilterFieldSpec,
  ProtocolLensComponentProps,
  ProtocolMatrixCell,
  ProtocolStatus,
} from "../../shared/contract";
import { collectFilterSuggestions } from "../../shared/filterSpl";
import { formatCount, formatUtcTimestamp } from "../../shared/format";
import {
  AdjacencyOverlay,
  CopyableIp,
  HeatMatrix,
  ProtocolLensLayout,
  StatusChip,
  SwimlaneTimeline,
  type BannerState,
  type ProtocolTableColumn,
} from "../../shared/ui";
import {
  buildRoutingRawEventsUrl,
  investigateRouting,
  type RoutingInvestigationResult,
  type RoutingPeerRow,
} from "./adapter";

export interface RoutingLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: RoutingInvestigationResult;
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

function formatAsnSummary(peerAsn?: number, localAsn?: number): string {
  if (peerAsn !== undefined && localAsn !== undefined) {
    return `Peer AS ${peerAsn} · Local AS ${localAsn}`;
  }
  if (peerAsn !== undefined) return `Peer AS ${peerAsn}`;
  if (localAsn !== undefined) return `Local AS ${localAsn}`;
  return "Not covered";
}

function safeRawEventsUrl(options: {
  index: string;
  device: string;
  peerIp: string;
  sourceCoverage: RoutingPeerRow["sourceCoverage"];
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildRoutingRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

const ROUTING_FILTER_FIELDS: readonly ProtocolFilterFieldSpec[] = [
  { key: "device", label: "Device", placeholder: "Device", primary: true },
  { key: "dst", label: "Peer IP", placeholder: "Peer IP", primary: true },
  { key: "src", label: "Source IP", placeholder: "Source IP" },
];

export function RoutingLensPage({
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
}: RoutingLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: RoutingInvestigationResult } | undefined
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
        (p) => p.lens === "routing" && p.scope === scope,
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
      return { row: selectedRow.device, col: selectedRow.peerIp };
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
      const next = await investigateRouting(
        client,
        {
          version: 1,
          lens: "routing",
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
            : "Routing investigation failed.";
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
            adjacencyNodes: [],
            adjacencyEdges: [],
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

  handleInvestigateRef.current = handleInvestigate;

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
  };

  const hasAnyPrefixes = Boolean(
    result?.rows.some((r) => r.prefixesReceived !== undefined),
  );

  const columns: ProtocolTableColumn<RoutingPeerRow>[] = [
    {
      key: "device",
      header: "Device",
      render: (r) => <span className="pl-mono">{r.device}</span>,
    },
    {
      key: "peer",
      header: "Peer",
      render: (r) => <CopyableIp value={r.peerIp} label="peer" />,
    },
    {
      key: "protocol",
      header: "Protocol",
      render: (r) => <span className="pl-mono">{r.protocol}</span>,
    },
    {
      key: "vrf",
      header: "VRF",
      render: (r) => <span className="pl-mono">{r.vrf}</span>,
    },
    {
      key: "state",
      header: "State",
      render: (r) => (
        <StatusChip
          status={r.isDown ? "attention" : "ok"}
          label={r.currentState}
        />
      ),
    },
    {
      key: "flaps",
      header: "Flaps",
      align: "right",
      render: (r) => formatCount(r.flapCount),
    },
    ...(hasAnyPrefixes
      ? [
          {
            key: "prefixes",
            header: "Prefixes",
            align: "right" as const,
            render: (r: RoutingPeerRow) =>
              r.prefixesReceived !== undefined ? (
                formatCount(r.prefixesReceived)
              ) : (
                <StatusChip
                  status="not_covered"
                  title="Prefix counts require NX-OS DME state telemetry"
                />
              ),
          },
        ]
      : []),
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
        ? `Not covered — no routing profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured routing profile to investigate.",
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
      ? "Click Investigate to inspect BGP, OSPF, and BFD peer state and flaps."
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
        peerIp: selectedRow.peerIp,
        sourceCoverage: selectedRow.sourceCoverage,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  return (
    <ProtocolLensLayout
      title="Routing Control Plane"
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
            <AdjacencyOverlay
              title="Device ↔ peer adjacencies"
              nodes={result.adjacencyNodes}
              edges={result.adjacencyEdges}
              onSelectNode={(node) => {
                const match =
                  node.role === "device"
                    ? result.rows.find((r) => `dev:${r.device}` === node.id)
                    : result.rows.find((r) => `peer:${r.peerIp}` === node.id);
                if (match) {
                  setMissingCell(undefined);
                  onChangeParams({ item: match.id });
                }
              }}
            />
            <HeatMatrix
              title="Device × peer routing state"
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
          </>
        ) : undefined
      }
      extraOverview={
        result?.timelineEvents.length ? (
          <SwimlaneTimeline
            title="Adjacency transitions"
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
          ? `${selectedRow.device} ↔ ${selectedRow.peerIp}`
          : missingCell
            ? `${missingCell.row} ↔ ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          <span>
            {selectedRow.device} ↔{" "}
            <CopyableIp value={selectedRow.peerIp} label="peer" />
          </span>
        ) : missingCell ? (
          <span>
            {missingCell.row} ↔{" "}
            <CopyableIp value={missingCell.col} label="peer" />
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
            <dd className="pl-mono">{selectedRow.device}</dd>
            <dt>Peer IP</dt>
            <dd>
              <CopyableIp value={selectedRow.peerIp} label="peer" />
            </dd>
            <dt>Protocol</dt>
            <dd className="pl-mono">
              {selectedRow.protocol}
              {selectedRow.area ? ` (Area ${selectedRow.area})` : ""}
            </dd>
            <dt>VRF</dt>
            <dd className="pl-mono">{selectedRow.vrf}</dd>
            <dt>ASN</dt>
            <dd className="pl-mono">
              {formatAsnSummary(selectedRow.peerAsn, selectedRow.localAsn)}
            </dd>
            <dt>State</dt>
            <dd className="pl-mono">{selectedRow.currentState}</dd>
            <dt>Flap count</dt>
            <dd className="pl-mono">{formatCount(selectedRow.flapCount)}</dd>
            <dt>Prefixes</dt>
            <dd className="pl-mono">
              {selectedRow.prefixesReceived !== undefined
                ? formatCount(selectedRow.prefixesReceived)
                : "Not covered"}
            </dd>
            {selectedRow.iface ? (
              <>
                <dt>Interface</dt>
                <dd className="pl-mono">{selectedRow.iface}</dd>
              </>
            ) : null}
            {selectedRow.lastTransitionTime !== undefined ? (
              <>
                <dt>Last transition</dt>
                <dd className="pl-mono">
                  {formatUtcTimestamp(selectedRow.lastTransitionTime)}
                  {selectedRow.lastMnemonic
                    ? ` (${selectedRow.lastMnemonic})`
                    : ""}
                </dd>
              </>
            ) : null}
            {selectedRow.recentMnemonics.length ? (
              <>
                <dt>Recent mnemonics</dt>
                <dd>
                  <ul className="pl-kv-list">
                    {selectedRow.recentMnemonics.map((entry, idx) => (
                      <li key={`${idx}-${entry}`}>{entry}</li>
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
                ? "Result hit the search row cap — this peer may have unseen routing events outside the capped rows."
                : "No routing adjacency events observed between this device and peer in the selected UTC window."}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      filter={filter}
      filterFields={ROUTING_FILTER_FIELDS}
      filterSuggestions={{
        device: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.device),
        ),
        dst: collectFilterSuggestions(
          (result?.rows ?? []).map((r) => r.peerIp),
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
                device: selectedRow.device,
                dst: selectedRow.peerIp,
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
      focusFlowLabel="Focus peer"
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

export default RoutingLensPage;
