import { useEffect, useRef, useState, type ReactNode } from "react";
import type {
  ProtocolKpi,
  ProtocolStatus,
  ProtocolViewMode,
} from "../contract";
import { formatUtcWindow } from "../format";
import { KpiStrip } from "./KpiStrip";
import { ProtocolStateBanner, type BannerState } from "./ProtocolStateBanner";
import { StatusChip } from "./StatusChip";

export interface ProtocolTableColumn<RowT> {
  key: string;
  header: string;
  align?: "left" | "right";
  render: (row: RowT) => ReactNode;
}

function isSafeLink(href: string | undefined): href is string {
  if (!href) return false;
  if (href.startsWith("//")) return false;
  return href.startsWith("/") || href.startsWith("https://");
}

const HIDE_BODY_STATES = new Set<BannerState>([
  "empty",
  "blocked",
  "unavailable",
]);
const MUTE_BODY_STATES = new Set<BannerState>([
  "partial",
  "estimate_only",
  "stale_config",
]);

/**
 * Shared single-header + verdict + KPI strip + Overview/Matrix + right-side
 * detail drawer layout for every protocol lens.
 */
export function ProtocolLensLayout<
  RowT extends { id: string; attention?: boolean },
>({
  title,
  scope,
  scopes,
  earliest,
  latest,
  view,
  coverageStatus,
  coverageLabel,
  verdict,
  verdictStatus,
  kpis,
  banner,
  rows,
  columns,
  matrixView,
  extraOverview,
  drawerTitle,
  drawerTitleNode,
  drawerOpen,
  drawerBody,
  rawEventsLink,
  busy,
  onScopeChange,
  onViewChange,
  onInvestigate,
  onCancel,
  onBackToHub,
  onSelectRow,
  onCloseDrawer,
}: {
  title: string;
  scope: string;
  scopes: readonly string[];
  earliest: number;
  latest: number;
  view: ProtocolViewMode;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  verdict: string;
  verdictStatus: ProtocolStatus;
  kpis: readonly ProtocolKpi[];
  banner?: {
    state: BannerState;
    reason?: string;
    onAction?: () => void;
    actionLabel?: string;
  };
  rows: readonly RowT[];
  columns: readonly ProtocolTableColumn<RowT>[];
  matrixView?: ReactNode;
  extraOverview?: ReactNode;
  drawerTitle?: string;
  drawerTitleNode?: ReactNode;
  drawerOpen?: boolean;
  drawerBody?: ReactNode;
  rawEventsLink?: string;
  busy?: boolean;
  onScopeChange: (scope: string) => void;
  onViewChange: (view: ProtocolViewMode) => void;
  onInvestigate: () => void;
  onCancel?: () => void;
  onBackToHub: () => void;
  onSelectRow?: (row: RowT) => void;
  onCloseDrawer?: () => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const drawerHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const prevDrawerOpen = useRef(false);

  useEffect(() => {
    if (drawerOpen && !prevDrawerOpen.current) {
      returnFocusRef.current =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;
      requestAnimationFrame(() => drawerHeadingRef.current?.focus());
    } else if (!drawerOpen && prevDrawerOpen.current) {
      returnFocusRef.current?.focus();
      returnFocusRef.current = null;
    }
    prevDrawerOpen.current = Boolean(drawerOpen);
  }, [drawerOpen]);

  useEffect(() => {
    if (!drawerOpen || !onCloseDrawer) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCloseDrawer();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen, onCloseDrawer]);

  const safeColumns = columns.slice(0, 8);
  const flagged = rows.filter((r) => r.attention);
  const sortedRows = [...flagged, ...rows.filter((r) => !r.attention)];
  const visibleRows =
    !showAll && flagged.length > 0 && flagged.length < sortedRows.length
      ? flagged
      : sortedRows;

  const isLoading = banner?.state === "loading";
  const hideBody = banner ? HIDE_BODY_STATES.has(banner.state) : false;
  const muteBody = banner ? MUTE_BODY_STATES.has(banner.state) : false;

  const effectiveVerdictStatus: ProtocolStatus =
    banner?.state === "loading"
      ? "unknown"
      : banner?.state === "empty"
        ? "none_observed"
        : banner?.state === "unavailable"
          ? verdictStatus === "unknown"
            ? "unknown"
            : "not_covered"
          : banner?.state === "blocked"
            ? "unknown"
            : verdictStatus;

  const effectiveVerdict =
    banner?.state === "loading"
      ? "Searching the selected UTC window…"
      : banner?.state === "empty"
        ? "No exceptions or matching activity observed."
        : banner?.state === "unavailable"
          ? verdictStatus === "unknown" && verdict
            ? verdict
            : "No active source profile covers this scope."
          : banner?.state === "blocked"
            ? "Source evidence could not be read for this role."
            : verdict;

  const showViewSwitch = Boolean(matrixView) && !isLoading && !hideBody;

  return (
    <main
      className="pl-page"
      data-testid="protocol-lens-page"
      aria-busy={isLoading || busy ? "true" : undefined}
    >
      <header className="pl-header" data-testid="protocol-header">
        <div className="pl-header-left">
          <button
            type="button"
            className="pl-back-btn"
            onClick={onBackToHub}
            aria-label="Back to Protocols hub"
          >
            ← Protocols
          </button>
          <h1 className="pl-title">{title}</h1>
        </div>
        <div className="pl-header-controls">
          <label className="pl-scope-field">
            <span className="atlas-visually-hidden">Scope</span>
            <select
              value={scope}
              onChange={(e) => onScopeChange(e.target.value)}
              aria-label="Scope"
            >
              {scopes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <span
            className="pl-window-pill pl-mono"
            title="UTC window"
            data-pl-data="true"
          >
            {formatUtcWindow(earliest, latest)}
          </span>
          {busy && onCancel ? (
            <button
              type="button"
              className="pl-btn-secondary"
              onClick={onCancel}
            >
              Cancel
            </button>
          ) : (
            <button
              type="button"
              className="pl-btn-primary"
              disabled={busy}
              onClick={onInvestigate}
            >
              Investigate
            </button>
          )}
          <StatusChip status={coverageStatus} label={coverageLabel} />
        </div>
      </header>

      <section
        className={`pl-verdict pl-verdict-${effectiveVerdictStatus}`}
        data-testid="protocol-verdict"
        aria-live="polite"
      >
        {isLoading ? (
          <span className="pl-spinner" aria-hidden="true" />
        ) : (
          <StatusChip status={effectiveVerdictStatus} />
        )}
        <p className="pl-verdict-text" data-pl-data="true">
          {effectiveVerdict}
        </p>
        {showViewSwitch ? (
          <div
            className="pl-view-tabs"
            role="group"
            aria-label="Lens display mode"
          >
            <button
              type="button"
              aria-pressed={view === "overview"}
              className={
                view === "overview" ? "pl-tab pl-tab-active" : "pl-tab"
              }
              onClick={() => onViewChange("overview")}
            >
              Overview
            </button>
            <button
              type="button"
              aria-pressed={view === "matrix"}
              className={view === "matrix" ? "pl-tab pl-tab-active" : "pl-tab"}
              onClick={() => onViewChange("matrix")}
            >
              Matrix
            </button>
          </div>
        ) : null}
      </section>

      {banner ? <ProtocolStateBanner {...banner} /> : null}

      {isLoading ? (
        <div
          className="pl-skeleton-grid"
          aria-hidden="true"
          data-testid="protocol-loading-skeleton"
        >
          <div className="pl-skeleton-card" />
          <div className="pl-skeleton-card" />
          <div className="pl-skeleton-card" />
          <div className="pl-skeleton-card" />
        </div>
      ) : hideBody ? null : (
        <>
          <div className={muteBody ? "pl-body-muted" : undefined}>
            <KpiStrip tiles={kpis} />
          </div>

          <div
            className={`pl-body${drawerOpen ? " pl-body-with-drawer" : ""}${muteBody ? " pl-body-muted" : ""}`}
          >
            <div className="pl-main-pane">
              {view === "matrix" && matrixView ? (
                matrixView
              ) : (
                <>
                  <div className="pl-table-wrap">
                    <table
                      className="pl-table"
                      data-testid="protocol-overview-table"
                    >
                      <thead>
                        <tr>
                          {safeColumns.map((col) => (
                            <th
                              key={col.key}
                              scope="col"
                              className={
                                col.align === "right" ? "pl-num" : undefined
                              }
                            >
                              {col.header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {visibleRows.length ? (
                          visibleRows.map((row) => (
                            <tr
                              key={row.id}
                              className={
                                row.attention ? "pl-row-attention" : undefined
                              }
                              tabIndex={onSelectRow ? 0 : undefined}
                              onClick={() => onSelectRow?.(row)}
                              onKeyDown={(e) => {
                                if (
                                  onSelectRow &&
                                  (e.key === "Enter" || e.key === " ")
                                ) {
                                  e.preventDefault();
                                  onSelectRow(row);
                                }
                              }}
                            >
                              {safeColumns.map((col) => (
                                <td
                                  key={col.key}
                                  data-pl-data="true"
                                  className={
                                    col.align === "right" ? "pl-num" : undefined
                                  }
                                >
                                  {col.render(row)}
                                </td>
                              ))}
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td
                              colSpan={safeColumns.length}
                              className="pl-empty-cell"
                            >
                              No rows observed.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {flagged.length > 0 && flagged.length < sortedRows.length ? (
                    <div className="pl-show-all">
                      <button
                        type="button"
                        className="pl-btn-link"
                        onClick={() => setShowAll((v) => !v)}
                      >
                        {showAll
                          ? `Show flagged only (${flagged.length})`
                          : `Show all (${sortedRows.length})`}
                      </button>
                    </div>
                  ) : null}
                  {extraOverview}
                </>
              )}
            </div>

            {drawerOpen ? (
              <aside
                className="pl-drawer"
                role="complementary"
                aria-label={drawerTitle ?? "Detail"}
                data-testid="protocol-detail-drawer"
              >
                <div className="pl-drawer-head">
                  <h2 ref={drawerHeadingRef} tabIndex={-1}>
                    {drawerTitleNode ?? drawerTitle ?? "Detail"}
                  </h2>
                  {onCloseDrawer ? (
                    <button
                      type="button"
                      className="pl-drawer-close"
                      aria-label="Close detail"
                      onClick={onCloseDrawer}
                    >
                      ×
                    </button>
                  ) : null}
                </div>
                <div className="pl-drawer-body" data-pl-data="true">
                  {drawerBody}
                </div>
                {isSafeLink(rawEventsLink) ? (
                  <div className="pl-drawer-foot">
                    <a
                      href={rawEventsLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="pl-btn-link"
                    >
                      Open raw events in Splunk ↗
                    </a>
                  </div>
                ) : null}
              </aside>
            ) : null}
          </div>
        </>
      )}
    </main>
  );
}
