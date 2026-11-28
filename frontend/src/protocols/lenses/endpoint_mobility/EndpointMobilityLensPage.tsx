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
  buildEndpointMobilityRawEventsUrl,
  investigateEndpointMobility,
  resolveEndpointMobilityThresholds,
  type EndpointMobilityInvestigationResult,
  type EndpointMobilityRow,
} from "./adapter";

export interface EndpointMobilityLensPageProps extends ProtocolLensComponentProps {
  /** Optional pre-populated investigation result for tests and showcase harnesses. */
  initialResult?: EndpointMobilityInvestigationResult;
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
  return (
    IPV4_OR_IPV6_RE.test(value.trim()) &&
    !/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(value.trim())
  );
}

function safeRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly string[];
  macs: readonly string[];
  ips: readonly string[];
  switches: readonly string[];
  earliest: number;
  latest: number;
}): string | undefined {
  try {
    return buildEndpointMobilityRawEventsUrl(options);
  } catch {
    return undefined;
  }
}

const ENDPOINT_MOBILITY_FILTER_FIELDS: readonly ProtocolFilterFieldSpec[] = [
  {
    key: "src",
    label: "Endpoint IP or MAC",
    placeholder: "Endpoint IP / MAC",
    primary: true,
  },
  { key: "device", label: "Switch", placeholder: "Switch", primary: true },
  { key: "vni", label: "VXLAN VNI", placeholder: "VNI", primary: true },
];

export function EndpointMobilityLensPage({
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
}: EndpointMobilityLensPageProps) {
  const filterKey = serializeFilter(filter);
  const currentStampKey = `${scope}|${earliest}|${latest}|${filterKey}`;
  const currentStampRef = useRef<string>(currentStampKey);
  currentStampRef.current = currentStampKey;

  const [busy, setBusy] = useState(false);
  const [stampedResult, setStampedResult] = useState<
    { stamp: string; value: EndpointMobilityInvestigationResult } | undefined
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
        (p) => p.lens === "endpoint_mobility" && p.scope === scope,
      ),
    [configuration.profiles, scope],
  );
  const hasStreamArpProfile = useMemo(
    () =>
      scopedProfiles.some((p) => {
        const kind = resolveEndpointMobilityThresholds(p).sourceKind;
        return kind === "stream_arp" || kind === "auto";
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
    if (selectedRow && selectedRow.switches[0] && selectedRow.vlanVnis[0]) {
      return {
        row: selectedRow.switches[0],
        col: selectedRow.vlanVnis[0],
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
    setStreamModeNotice(undefined);
    try {
      const next = await investigateEndpointMobility(
        client,
        {
          version: 1,
          lens: "endpoint_mobility",
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
            : "Endpoint mobility investigation failed.";
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
            matrixCols: [],
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
        ["arp"],
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
                  "Stream arp is in Estimate mode (statsOnly=true); no ARP event rows are indexed.",
              }
            : {}),
        });
        return;
      }
      setStampedResult((prev) => {
        if (!prev || prev.stamp !== stampKey) return prev;
        const nextBannerState: EndpointMobilityInvestigationResult["bannerState"] =
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
                    "Stream arp is in Estimate mode (statsOnly=true); no ARP event rows are indexed.",
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

  const columns: ProtocolTableColumn<EndpointMobilityRow>[] = [
    {
      key: "endpoint",
      header: "Endpoint",
      render: (r) =>
        isIpLike(r.endpointLabel) ? (
          <CopyableIp value={r.endpointLabel} label="endpoint" />
        ) : (
          <span className="pl-mono">{r.endpointLabel}</span>
        ),
    },
    {
      key: "ips",
      header: "IPs",
      render: (r) => {
        if (!r.hasIpCoverage) return <StatusChip status="not_covered" />;
        if (!r.ips.length) return <StatusChip status="none_observed" />;
        return (
          <span>
            <CopyableIp value={r.ips[0]} label="endpoint IP" />
            {r.ips.length > 1 ? (
              <span className="pl-mono">{` (+${r.ips.length - 1})`}</span>
            ) : null}
          </span>
        );
      },
    },
    {
      key: "attachments",
      header: "Attachments",
      render: (r) => {
        if (!r.hasAttachmentCoverage) {
          return <StatusChip status="not_covered" />;
        }
        if (!r.attachments.length) {
          return <StatusChip status="none_observed" />;
        }
        return (
          <span className="pl-mono">
            {r.attachments.slice(0, 2).join(" → ")}
          </span>
        );
      },
    },
    {
      key: "moves",
      header: "Moves",
      align: "right",
      render: (r) =>
        r.hasMoveCoverage ? (
          formatCount(r.moveCount)
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "arp",
      header: "ARP",
      align: "right",
      render: (r) =>
        r.hasArpCoverage ? (
          formatCount(r.arpCount)
        ) : (
          <StatusChip status="not_covered" />
        ),
    },
    {
      key: "flaps",
      header: "Flaps",
      align: "right",
      render: (r) =>
        r.hasFlapCoverage ? (
          formatCount(r.portFlapCount)
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
      hasStreamArpProfile &&
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
      ...(hasStreamArpProfile && client
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
        ? `Not covered — no endpoint_mobility profile configured for scope "${scope || "default"}".`
        : "Not covered — connect to Splunk with a configured endpoint_mobility profile to investigate.",
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
        ? "Click Investigate to inspect MAC/IP moves, duplicate IPs, ARP spikes, and port flaps."
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
        macs: selectedRow.macs,
        ips: selectedRow.ips,
        switches: selectedRow.switches,
        earliest,
        latest,
      })
    : undefined;

  const matrixMissingStatus: ProtocolStatus = result?.capped
    ? "unknown"
    : "none_observed";

  return (
    <ProtocolLensLayout
      title="Endpoint Mobility & ARP"
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
            title="Switch × VLAN/VNI mobility & conflict concentration"
            rowHeader="Switch / Leaf"
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
            title="Mobility & conflict timeline"
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
          ? selectedRow.endpointLabel
          : missingCell
            ? `${missingCell.row} · ${missingCell.col}`
            : undefined
      }
      drawerTitleNode={
        selectedRow ? (
          isIpLike(selectedRow.endpointLabel) ? (
            <CopyableIp value={selectedRow.endpointLabel} label="endpoint" />
          ) : (
            <span className="pl-mono">{selectedRow.endpointLabel}</span>
          )
        ) : missingCell ? (
          <span className="pl-mono">
            {`${missingCell.row} · ${missingCell.col}`}
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
            <dt>Observed MACs</dt>
            <dd>
              {selectedRow.macs.length ? (
                <ul className="pl-kv-list">
                  {selectedRow.macs.map((mac) => (
                    <li key={mac} className="pl-mono">
                      {mac}
                    </li>
                  ))}
                </ul>
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>
            <dt>Observed IPs</dt>
            <dd>
              {!selectedRow.hasIpCoverage ? (
                <StatusChip status="not_covered" />
              ) : selectedRow.ips.length ? (
                <ul className="pl-kv-list">
                  {selectedRow.ips.map((ip) => (
                    <li key={ip}>
                      <CopyableIp value={ip} label="endpoint IP" />
                    </li>
                  ))}
                </ul>
              ) : (
                <StatusChip status="none_observed" />
              )}
            </dd>
            <dt>VLAN / VNI</dt>
            <dd className="pl-mono">{selectedRow.vlanVnis.join(", ")}</dd>
            <dt>Path transitions</dt>
            <dd>
              {!selectedRow.hasAttachmentCoverage ? (
                <StatusChip status="not_covered" />
              ) : selectedRow.transitions.length ? (
                <ul className="pl-kv-list">
                  {selectedRow.transitions.map((t, idx) => (
                    <li
                      key={`${t.timestamp}-${t.switchName}-${t.port}-${idx}`}
                      className="pl-mono"
                    >
                      {`${formatUtcTimestamp(t.timestamp)} · ${t.switchName} ${t.port}${t.modType ? ` (${t.modType})` : ""}`}
                    </li>
                  ))}
                </ul>
              ) : (
                <StatusChip status="none_observed" />
              )}
            </dd>
            <dt>ARP rate</dt>
            <dd className="pl-mono">
              {selectedRow.hasArpCoverage ? (
                `${formatCount(selectedRow.arpCount)} ${selectedRow.arpCount === 1 ? "packet" : "packets"} in window`
              ) : (
                <StatusChip status="not_covered" />
              )}
            </dd>
            <dt>Port flaps</dt>
            <dd>
              {!selectedRow.hasFlapCoverage ? (
                <StatusChip status="not_covered" />
              ) : selectedRow.portFlapCount > 0 ? (
                <ul className="pl-kv-list">
                  <li className="pl-mono">
                    {`${formatCount(selectedRow.portFlapCount)} ${selectedRow.portFlapCount === 1 ? "flap" : "flaps"}${selectedRow.flappingPorts.length ? ` (${selectedRow.flappingPorts.join(", ")})` : ""}`}
                  </li>
                </ul>
              ) : (
                <StatusChip status="none_observed" />
              )}
            </dd>
            {selectedRow.tenant ||
            selectedRow.displayBd ||
            selectedRow.displayEpg ||
            selectedRow.lcC ||
            selectedRow.maxAnomalyScore !== undefined ? (
              <>
                <dt>Fabric context</dt>
                <dd className="pl-mono">
                  {[
                    selectedRow.tenant
                      ? `tenant=${selectedRow.tenant}`
                      : undefined,
                    selectedRow.displayBd
                      ? `bd=${selectedRow.displayBd}`
                      : undefined,
                    selectedRow.displayEpg
                      ? `epg=${selectedRow.displayEpg}`
                      : undefined,
                    selectedRow.lcC ? `lcC=${selectedRow.lcC}` : undefined,
                    selectedRow.maxAnomalyScore !== undefined
                      ? `anomalyScore=${Math.round(selectedRow.maxAnomalyScore)}`
                      : undefined,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </dd>
              </>
            ) : null}
            <dt>Sources</dt>
            <dd className="pl-mono">{selectedRow.sourcetypes.join(", ")}</dd>
            <dt>Last seen</dt>
            <dd className="pl-mono">
              {formatUtcTimestamp(selectedRow.lastSeen)}
            </dd>
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
              {missingCell.status === "unknown"
                ? "Result hit the search row cap — this switch and VLAN/VNI pair may have unseen mobility events outside the capped rows."
                : `No endpoint mobility or conflict events observed on ${missingCell.row} (${missingCell.col}) in the selected UTC window.`}
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink={rawEventsLink}
      filter={filter}
      filterFields={ENDPOINT_MOBILITY_FILTER_FIELDS}
      filterSuggestions={{
        src: collectFilterSuggestions(
          (result?.rows ?? []).flatMap((r) => [
            r.primaryMac,
            ...r.ips,
            r.endpointLabel,
          ]),
        ),
        device: collectFilterSuggestions(
          (result?.rows ?? []).flatMap((r) => r.switches),
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
                src:
                  selectedRow.primaryMac ??
                  selectedRow.ips[0] ??
                  selectedRow.endpointLabel,
                ...(selectedRow.switches[0]
                  ? { device: selectedRow.switches[0] }
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
      focusFlowLabel="Focus endpoint"
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

export default EndpointMobilityLensPage;
