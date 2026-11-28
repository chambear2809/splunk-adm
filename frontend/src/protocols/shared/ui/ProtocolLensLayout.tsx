import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { SlidersHorizontal } from "lucide-react";
import { validateProtocolFilter } from "../../inputs";
import type {
  ProtocolFilter,
  ProtocolFilterFieldKey,
  ProtocolFilterFieldSpec,
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

function extractRowSearchText(value: unknown, depth = 0): string {
  if (value === null || value === undefined || depth > 2) return "";
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => extractRowSearchText(item, depth + 1)).join(" ");
  }
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>)
      .map((item) => extractRowSearchText(item, depth + 1))
      .join(" ");
  }
  return "";
}

function hasActiveFilter(filter?: ProtocolFilter): boolean {
  if (!filter) return false;
  return Boolean(
    filter.src ||
    filter.dst ||
    filter.device ||
    filter.port ||
    filter.vni ||
    filter.iface ||
    filter.bidirectional,
  );
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

const WINDOW_PRESETS_MIN = [15, 30, 60] as const;

/**
 * Shared single-header + verdict + filter bar + KPI strip + Overview/Matrix +
 * right-side detail drawer layout for every protocol lens.
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
  filter,
  filterFields,
  supportsBidirectional,
  filterSuggestions,
  onApplyFilter,
  onWindowChange,
  getRowSearchText,
  onFocusFlow,
  focusFlowLabel,
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
  /** Active server-side SPL filter synced with URL params. */
  filter?: ProtocolFilter;
  /** Lens-specific SPL filter inputs rendered in the compact filter bar. */
  filterFields?: readonly ProtocolFilterFieldSpec[];
  /** Enable bidirectional A <-> B matching toggle for flow-pair lenses. */
  supportsBidirectional?: boolean;
  /** Observed values per filter key used for `<datalist>` autocomplete. */
  filterSuggestions?: Partial<
    Record<ProtocolFilterFieldKey, readonly string[]>
  >;
  /** Called on explicit Apply/Enter/Clear with validated `ProtocolFilter`. */
  onApplyFilter?: (next: ProtocolFilter | undefined) => void;
  /** Called when the operator picks a 15m/30m/60m UTC window preset. */
  onWindowChange?: (nextEarliest: number, nextLatest: number) => void;
  /** Optional extractor for instant client-side table search (defaults to row primitives). */
  getRowSearchText?: (row: RowT) => string;
  /** Optional one-click drawer pivot to scope SPL to the selected row's flow. */
  onFocusFlow?: () => void;
  focusFlowLabel?: string;
  onScopeChange: (scope: string) => void;
  onViewChange: (view: ProtocolViewMode) => void;
  onInvestigate: () => void;
  onCancel?: () => void;
  onBackToHub: () => void;
  onSelectRow?: (row: RowT) => void;
  onCloseDrawer?: () => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const [showMoreFilters, setShowMoreFilters] = useState(false);
  const [tableQuery, setTableQuery] = useState("");
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [filterError, setFilterError] = useState<string>();
  const [draft, setDraft] = useState<Record<ProtocolFilterFieldKey, string>>({
    src: filter?.src ?? "",
    dst: filter?.dst ?? "",
    device: filter?.device ?? "",
    port: filter?.port ?? "",
    vni: filter?.vni ?? "",
    iface: filter?.iface ?? "",
  });
  const [draftBidir, setDraftBidir] = useState(Boolean(filter?.bidirectional));
  const [suggestionsActive, setSuggestionsActive] = useState(false);
  const [capTipOpen, setCapTipOpen] = useState(false);

  const filterListId = useId();
  const capTipId = useId();
  const drawerHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const prevDrawerOpen = useRef(false);

  // Sync draft inputs whenever external URL / pivot filter changes.
  useEffect(() => {
    setDraft({
      src: filter?.src ?? "",
      dst: filter?.dst ?? "",
      device: filter?.device ?? "",
      port: filter?.port ?? "",
      vni: filter?.vni ?? "",
      iface: filter?.iface ?? "",
    });
    setDraftBidir(Boolean(filter?.bidirectional));
    setFilterError(undefined);
  }, [
    filter?.src,
    filter?.dst,
    filter?.device,
    filter?.port,
    filter?.vni,
    filter?.iface,
    filter?.bidirectional,
  ]);

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
    if (!capTipOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setCapTipOpen(false);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [capTipOpen]);

  useEffect(() => {
    if (!drawerOpen || !onCloseDrawer) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (capTipOpen) return;
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;
      onCloseDrawer();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen, onCloseDrawer, capTipOpen]);

  const DEFAULT_HEALTHY_PREVIEW_ROWS = 20;
  const safeColumns = columns.slice(0, 8);
  const flaggedAll = useMemo(() => rows.filter((r) => r.attention), [rows]);
  const hasMixedRows = flaggedAll.length > 0 && flaggedAll.length < rows.length;

  const trimmedTableQuery = tableQuery.trim().toLowerCase();
  const filteredRows = useMemo(() => {
    let base = rows;
    if (flaggedOnly && hasMixedRows) {
      base = base.filter((r) => r.attention);
    }
    if (!trimmedTableQuery) return base;
    const terms = trimmedTableQuery.split(/\s+/).filter(Boolean);
    return base.filter((row) => {
      const haystack = (
        getRowSearchText ? getRowSearchText(row) : extractRowSearchText(row)
      ).toLowerCase();
      return terms.every((term) => haystack.includes(term));
    });
  }, [rows, flaggedOnly, hasMixedRows, trimmedTableQuery, getRowSearchText]);

  const flagged = filteredRows.filter((r) => r.attention);
  const sortedRows = [...flagged, ...filteredRows.filter((r) => !r.attention)];
  const isLocallyFiltered = Boolean(
    trimmedTableQuery || (flaggedOnly && hasMixedRows),
  );
  const canCollapseFlagged =
    !isLocallyFiltered &&
    flagged.length > 0 &&
    flagged.length < sortedRows.length;
  const canCollapseLongList =
    !isLocallyFiltered &&
    ((flagged.length === 0 &&
      sortedRows.length > DEFAULT_HEALTHY_PREVIEW_ROWS) ||
      (flagged.length === sortedRows.length &&
        sortedRows.length > DEFAULT_HEALTHY_PREVIEW_ROWS));
  const visibleRows = showAll
    ? sortedRows
    : canCollapseFlagged
      ? flagged.slice(0, DEFAULT_HEALTHY_PREVIEW_ROWS)
      : canCollapseLongList
        ? sortedRows.slice(0, DEFAULT_HEALTHY_PREVIEW_ROWS)
        : sortedRows;
  const canExpandRows =
    canCollapseFlagged ||
    canCollapseLongList ||
    (!isLocallyFiltered && visibleRows.length < sortedRows.length);

  const isLoading = banner?.state === "loading";
  const isCapOnlyBanner =
    banner?.state === "partial" &&
    rows.length > 0 &&
    Boolean(banner.reason?.startsWith("Sample capped"));
  const hideBody = banner ? HIDE_BODY_STATES.has(banner.state) : false;
  const muteBody =
    banner && !isCapOnlyBanner ? MUTE_BODY_STATES.has(banner.state) : false;

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
        ? verdict || "No exceptions or matching activity observed."
        : banner?.state === "unavailable"
          ? verdictStatus === "unknown" && verdict
            ? verdict
            : "No active source profile covers this scope."
          : banner?.state === "blocked"
            ? "Source evidence could not be read for this role."
            : verdict;

  const showViewSwitch = Boolean(matrixView) && !isLoading && !hideBody;

  const primaryFields = useMemo(
    () => (filterFields ?? []).filter((f, idx) => f.primary ?? idx < 3),
    [filterFields],
  );
  const secondaryFields = useMemo(
    () => (filterFields ?? []).filter((f, idx) => !(f.primary ?? idx < 3)),
    [filterFields],
  );
  const hasSecondaryActive = secondaryFields.some((f) => Boolean(draft[f.key]));
  const visibleFilterFields =
    showMoreFilters || hasSecondaryActive
      ? (filterFields ?? [])
      : primaryFields;

  const draftHasValue =
    Object.values(draft).some((v) => v.trim().length > 0) ||
    draftBidir ||
    hasActiveFilter(filter);

  const handleFilterSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!onApplyFilter) return;
    try {
      const candidate: Record<string, unknown> = {};
      for (const field of filterFields ?? []) {
        const val = draft[field.key].trim();
        if (val) candidate[field.key] = val;
      }
      if (
        supportsBidirectional &&
        draftBidir &&
        (candidate.src || candidate.dst)
      ) {
        candidate.bidirectional = true;
      }
      const validated = validateProtocolFilter(
        Object.keys(candidate).length ? candidate : undefined,
      );
      setFilterError(undefined);
      onApplyFilter(validated);
    } catch (error) {
      setFilterError(
        error instanceof Error ? error.message : "Invalid filter value.",
      );
    }
  };

  const handleClearFilters = () => {
    setDraft({ src: "", dst: "", device: "", port: "", vni: "", iface: "" });
    setDraftBidir(false);
    setFilterError(undefined);
    onApplyFilter?.(undefined);
  };

  const currentWindowMin = Math.max(
    1,
    Math.min(60, Math.round((latest - earliest) / 60)),
  );
  const windowOptions: number[] = WINDOW_PRESETS_MIN.includes(
    currentWindowMin as (typeof WINDOW_PRESETS_MIN)[number],
  )
    ? [...WINDOW_PRESETS_MIN]
    : [...WINDOW_PRESETS_MIN, currentWindowMin].sort((a, b) => a - b);

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
            <select
              value={scope}
              onChange={(e) => onScopeChange(e.target.value)}
              aria-label="Scope"
              data-pl-data="true"
            >
              {scopes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          {onWindowChange ? (
            <label className="pl-scope-field">
              <select
                className="pl-window-select"
                aria-label="Time window"
                data-testid="protocol-window-select"
                data-pl-data="true"
                value={currentWindowMin}
                onChange={(e) => {
                  const mins = Number(e.target.value);
                  if (Number.isFinite(mins) && mins >= 1 && mins <= 60) {
                    onWindowChange(latest - mins * 60, latest);
                  }
                }}
              >
                {windowOptions.map((mins) => (
                  <option key={mins} value={mins}>
                    {mins}m
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          <span
            className="pl-window-pill pl-mono"
            title="UTC window"
            data-pl-data="true"
          >
            {formatUtcWindow(earliest, latest, {
              includeDuration: !onWindowChange,
            })}
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
        {isCapOnlyBanner && banner?.reason ? (
          <span
            className="pl-cap-wrap"
            data-pl-data="true"
            onMouseEnter={() => setCapTipOpen(true)}
            onMouseLeave={() => setCapTipOpen(false)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && capTipOpen) {
                e.stopPropagation();
                setCapTipOpen(false);
              }
            }}
            onBlur={(e) => {
              if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                setCapTipOpen(false);
              }
            }}
          >
            <button
              type="button"
              className="pl-neutral-tag pl-cap-btn"
              aria-describedby={capTipId}
              data-testid="protocol-cap-indicator"
              onFocus={() => setCapTipOpen(true)}
              onClick={() => setCapTipOpen((v) => !v)}
            >
              Capped
            </button>
            <span
              id={capTipId}
              role="tooltip"
              className={
                capTipOpen ? "pl-cap-tip pl-cap-tip-open" : "pl-cap-tip"
              }
            >
              {banner.reason}
            </span>
          </span>
        ) : null}
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

      {filterFields && filterFields.length > 0 && onApplyFilter ? (
        <form
          className="pl-filter-bar"
          data-testid="protocol-filter-bar"
          aria-label="Flow and device filters"
          onSubmit={handleFilterSubmit}
        >
          {visibleFilterFields.map((field) => {
            const suggestions = suggestionsActive
              ? filterSuggestions?.[field.key]
              : undefined;
            const listId =
              suggestions && suggestions.length > 0
                ? `${filterListId}-${field.key}`
                : undefined;
            const isSmall = field.key === "port" || field.key === "vni";
            return (
              <label key={field.key} className="pl-filter-field">
                <input
                  type="text"
                  className={
                    isSmall
                      ? "pl-filter-input pl-filter-input-sm"
                      : "pl-filter-input"
                  }
                  value={draft[field.key]}
                  placeholder={field.placeholder}
                  title={field.label}
                  aria-label={field.label}
                  data-testid={`protocol-filter-${field.key}`}
                  list={listId}
                  onFocus={() => {
                    if (!suggestionsActive) setSuggestionsActive(true);
                  }}
                  onChange={(e) => {
                    const value = e.target.value;
                    setDraft((prev) => ({ ...prev, [field.key]: value }));
                    if (filterError) setFilterError(undefined);
                  }}
                />
                {listId && suggestions ? (
                  <datalist id={listId}>
                    {suggestions.map((val) => (
                      <option key={val} value={val} />
                    ))}
                  </datalist>
                ) : null}
              </label>
            );
          })}
          {supportsBidirectional ? (
            <button
              type="button"
              className="pl-filter-toggle"
              aria-pressed={draftBidir}
              data-testid="protocol-filter-bidir"
              title="Match source and destination in either direction"
              onClick={() => setDraftBidir((v) => !v)}
            >
              A↔B
            </button>
          ) : null}
          {secondaryFields.length > 0 && !hasSecondaryActive ? (
            <button
              type="button"
              className="pl-filter-toggle"
              aria-expanded={showMoreFilters}
              aria-label={showMoreFilters ? "Fewer filters" : "More filters"}
              title={showMoreFilters ? "Fewer filters" : "More filters"}
              data-testid="protocol-filter-more"
              onClick={() => setShowMoreFilters((v) => !v)}
            >
              <SlidersHorizontal size={13} aria-hidden="true" />
            </button>
          ) : null}
          <button
            type="submit"
            className="pl-btn-secondary"
            disabled={busy}
            data-testid="protocol-filter-apply"
          >
            Filter
          </button>
          {draftHasValue ? (
            <button
              type="button"
              className="pl-btn-link"
              disabled={busy}
              data-testid="protocol-filter-clear"
              onClick={handleClearFilters}
            >
              Clear
            </button>
          ) : null}
          {filterError ? (
            <p
              className="pl-filter-error"
              role="alert"
              data-testid="protocol-filter-error"
              data-pl-data="true"
            >
              {filterError}
            </p>
          ) : null}
        </form>
      ) : null}

      {banner && !isCapOnlyBanner ? <ProtocolStateBanner {...banner} /> : null}

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
          <KpiStrip tiles={kpis} />

          <div
            className={`pl-body${drawerOpen ? " pl-body-with-drawer" : ""}${muteBody ? " pl-body-muted" : ""}`}
          >
            <div className="pl-main-pane">
              {view === "matrix" && matrixView ? (
                matrixView
              ) : (
                <>
                  <div className="pl-table-wrap">
                    {rows.length > 0 ? (
                      <div
                        className="pl-table-toolbar"
                        data-testid="protocol-table-toolbar"
                      >
                        <label className="pl-filter-field">
                          <input
                            type="search"
                            className="pl-table-search-input"
                            value={tableQuery}
                            placeholder={`Search ${rows.length} loaded ${rows.length === 1 ? "row" : "rows"}…`}
                            aria-label="Search loaded rows"
                            data-testid="protocol-table-search"
                            onChange={(e) => setTableQuery(e.target.value)}
                          />
                        </label>
                        <div className="pl-table-toolbar-meta">
                          {hasMixedRows &&
                          (showAll || Boolean(trimmedTableQuery)) ? (
                            <button
                              type="button"
                              className="pl-filter-toggle"
                              aria-pressed={flaggedOnly}
                              data-testid="protocol-table-flagged-only"
                              onClick={() => setFlaggedOnly((v) => !v)}
                            >
                              Flagged
                            </button>
                          ) : null}
                          {isLocallyFiltered ? (
                            <>
                              <span data-pl-data="true">
                                {filteredRows.length}/{rows.length}
                              </span>
                              <button
                                type="button"
                                className="pl-btn-link"
                                onClick={() => {
                                  setTableQuery("");
                                  setFlaggedOnly(false);
                                }}
                              >
                                Reset
                              </button>
                            </>
                          ) : null}
                        </div>
                      </div>
                    ) : null}
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
                              {isLocallyFiltered
                                ? "No loaded rows match this search."
                                : "No rows observed."}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {canExpandRows ? (
                    <div className="pl-show-all">
                      <button
                        type="button"
                        className="pl-btn-link"
                        onClick={() => setShowAll((v) => !v)}
                      >
                        {showAll
                          ? canCollapseFlagged
                            ? `Show flagged only (${flagged.length})`
                            : `Show top ${DEFAULT_HEALTHY_PREVIEW_ROWS}`
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
                {onFocusFlow || isSafeLink(rawEventsLink) ? (
                  <div className="pl-drawer-foot pl-drawer-actions">
                    {onFocusFlow ? (
                      <button
                        type="button"
                        className="pl-btn-secondary"
                        data-testid="protocol-focus-flow"
                        onClick={onFocusFlow}
                      >
                        {focusFlowLabel ?? "Focus flow"}
                      </button>
                    ) : null}
                    {isSafeLink(rawEventsLink) ? (
                      <a
                        href={rawEventsLink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="pl-btn-link"
                      >
                        Open raw events in Splunk ↗
                      </a>
                    ) : null}
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
