import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentType,
} from "react";
import { pageURL, URL_STATE_CHANGED } from "../app/urlState";
import type { SearchClient } from "../data/searchClient";
import {
  parseProtocolLink,
  protocolItemId,
  protocolLink,
  protocolScopeName,
  validateProtocolFilter,
  validateProtocolWindow,
  type ParsedProtocolLink,
} from "./inputs";
import {
  lensById,
  PROTOCOL_LENSES,
  registeredProfileValidators,
} from "./registry";
import {
  MAX_WINDOW_SECONDS,
  type ProtocolConfiguration,
  type ProtocolLensComponentProps,
  type ProtocolLensId,
  type ProtocolLensSummary,
  type ProtocolStatus,
} from "./shared/contract";
import { readProtocolConfiguration } from "./shared/runner";
import {
  loadProtocolTrafficMix,
  selectTrafficMixIndex,
  type TrafficMixResult,
} from "./shared/trafficMix";
import { ProtocolStateBanner, StatusChip } from "./shared/ui";
import "./protocols.css";

function defaultWindow() {
  const latest = Math.floor(Date.now() / 1000);
  return { earliest: latest - 900, latest };
}

function writeProtocolParams(parsed: ParsedProtocolLink) {
  if (typeof window === "undefined") return;
  try {
    const current = new URLSearchParams(location.search);
    const next = new URLSearchParams();
    if (current.has("mode")) next.set("mode", current.get("mode")!);
    if (parsed.lens) {
      protocolLink(parsed).forEach((value, key) => next.set(key, value));
    }
    const qs = next.toString();
    history.replaceState(
      null,
      "",
      `${location.pathname}${qs ? `?${qs}` : ""}${location.hash}`,
    );
    window.dispatchEvent(new Event(URL_STATE_CHANGED));
  } catch {
    /* Invalid parameters stay local until fixed. */
  }
}

/**
 * Applies a partial parameter update from an active protocol lens, validating
 * any incoming filter (e.g., from a Focus flow pivot) and clearing filter
 * fields cleanly when `{ filter: undefined }` is passed.
 */
export function applyProtocolParamPatch(
  current: ParsedProtocolLink,
  activeLensId: ProtocolLensId,
  activeScope: string,
  win: { earliest: number; latest: number },
  patch: Parameters<ProtocolLensComponentProps["onChangeParams"]>[0],
  now = Date.now() / 1000,
): ParsedProtocolLink {
  let nextFilter = current.filter;
  if ("filter" in patch) {
    if (!patch.filter) {
      nextFilter = undefined;
    } else {
      const sanitized: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(patch.filter)) {
        if (v === undefined || v === "" || v === false) continue;
        try {
          const single = validateProtocolFilter({ [k]: v });
          if (single && k in single) {
            sanitized[k] = single[k as keyof typeof single];
          }
        } catch {
          // Drop malformed pivot field rather than failing or injecting raw values
        }
      }
      nextFilter = Object.keys(sanitized).length
        ? validateProtocolFilter(sanitized)
        : undefined;
    }
  }
  const scope =
    patch.scope === undefined
      ? activeScope
      : (protocolScopeName(patch.scope) ?? activeScope);
  const nextWindowMode =
    "windowMode" in patch
      ? patch.windowMode === "metrics"
        ? "metrics"
        : undefined
      : current.windowMode;
  let nextWin = win;
  if (
    patch.earliest !== undefined ||
    patch.latest !== undefined ||
    "windowMode" in patch
  ) {
    const candidateLatest = patch.latest ?? win.latest;
    const rawEarliest = patch.earliest ?? win.earliest;
    // Only clamp down to MAX_WINDOW_SECONDS when transitioning OUT of metrics
    // mode; invalid window patches while already in events mode stay rejected.
    const leavingMetrics =
      current.windowMode === "metrics" && nextWindowMode !== "metrics";
    const candidateEarliest = leavingMetrics
      ? Math.max(rawEarliest, candidateLatest - MAX_WINDOW_SECONDS)
      : rawEarliest;
    try {
      nextWin = validateProtocolWindow(
        candidateEarliest,
        candidateLatest,
        now,
        nextWindowMode ?? "events",
      );
    } catch {
      // Keep the last valid window rather than dispatching an unbounded search
    }
  }
  return {
    lens: activeLensId,
    scope,
    earliest: nextWin.earliest,
    latest: nextWin.latest,
    ...(nextWindowMode ? { windowMode: nextWindowMode } : {}),
    view:
      patch.view === "overview" || patch.view === "matrix"
        ? patch.view
        : current.view,
    filter: nextFilter,
    item: protocolItemId(patch.item) ? patch.item : undefined,
  };
}

export function ProtocolsPage({
  client,
  live,
  timezone,
  theme = "light",
}: {
  client?: SearchClient;
  live: boolean;
  timezone?: string;
  theme?: "light" | "dark";
}) {
  const [initialLink] = useState<{
    params: ParsedProtocolLink;
    error?: string;
  }>(() => {
    if (typeof location === "undefined")
      return { params: { view: "overview" } };
    try {
      return {
        params: parseProtocolLink(new URLSearchParams(location.search)),
      };
    } catch (error) {
      return {
        params: { view: "overview" },
        error:
          error instanceof Error ? error.message : "Invalid protocols link.",
      };
    }
  });
  const [linkError, setLinkError] = useState(initialLink.error);
  const [params, setParams] = useState<ParsedProtocolLink>(initialLink.params);
  const [fallbackWin] = useState(() => defaultWindow());
  const [config, setConfig] = useState<ProtocolConfiguration>({
    profiles: [],
    fingerprint: "",
  });
  const [configLoadedOnce, setConfigLoadedOnce] = useState(!live);
  const [configState, setConfigState] = useState<"loading" | "ready" | "error">(
    live ? "loading" : "ready",
  );
  const [configError, setConfigError] = useState<string>();
  const [configRevision, setConfigRevision] = useState(0);

  const [summaries, setSummaries] = useState<
    Partial<Record<ProtocolLensId, ProtocolLensSummary>>
  >({});
  const [trafficMix, setTrafficMix] = useState<TrafficMixResult>();
  const [loadingMix, setLoadingMix] = useState(false);
  const [checkingAll, setCheckingAll] = useState(false);
  const checkAbort = useRef<AbortController | null>(null);
  const mixAbort = useRef<AbortController | null>(null);

  const [lensComponent, setLensComponent] =
    useState<ComponentType<ProtocolLensComponentProps>>();
  const [lensLoadError, setLensLoadError] = useState<string>();

  useEffect(() => {
    return () => {
      checkAbort.current?.abort();
      mixAbort.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!live) {
      setConfig({ profiles: [], fingerprint: "" });
      setConfigState("ready");
      return;
    }
    const controller = new AbortController();
    setConfigState("loading");
    setConfigError(undefined);
    readProtocolConfiguration(registeredProfileValidators(), controller.signal)
      .then((loaded) => {
        if (!controller.signal.aborted) {
          setConfig(loaded);
          setConfigLoadedOnce(true);
          setConfigState("ready");
          setSummaries({});
          setTrafficMix(undefined);
        }
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setConfigError(
            error instanceof Error
              ? error.message
              : "Protocol source configuration could not be read.",
          );
          setConfigState("error");
        }
      });
    return () => controller.abort();
  }, [live, configRevision]);

  const activeLens = params.lens ? lensById(params.lens) : undefined;

  useEffect(() => {
    setLensComponent(undefined);
    setLensLoadError(undefined);
    if (!activeLens) return;
    if (!activeLens.loadComponent) {
      setLensLoadError(
        `${activeLens.title} lens module is staged and not wired yet.`,
      );
      return;
    }
    let cancelled = false;
    activeLens
      .loadComponent()
      .then((comp) => {
        if (!cancelled) setLensComponent(() => comp);
      })
      .catch((error: unknown) => {
        if (!cancelled)
          setLensLoadError(
            error instanceof Error ? error.message : "Lens failed to load.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, [activeLens]);

  const scopes = useMemo(
    () =>
      [...new Set(config.profiles.map((profile) => profile.scope))].sort(
        (a, b) => a.localeCompare(b),
      ),
    [config.profiles],
  );

  const configuredByLens = useMemo(() => {
    const counts = new Map<ProtocolLensId, number>();
    for (const profile of config.profiles) {
      counts.set(profile.lens, (counts.get(profile.lens) ?? 0) + 1);
    }
    return counts;
  }, [config.profiles]);

  const openLens = useCallback(
    (lensId: ProtocolLensId) => {
      checkAbort.current?.abort();
      mixAbort.current?.abort();
      setLinkError(undefined);
      const rawWin =
        params.earliest && params.latest
          ? { earliest: params.earliest, latest: params.latest }
          : defaultWindow();
      // Always reset to bounded 1-hour event window when opening a lens so a
      // 7-day metrics window can never spill into an event-backed lens.
      const clampedEarliest = Math.max(
        rawWin.earliest,
        rawWin.latest - MAX_WINDOW_SECONDS,
      );
      const next: ParsedProtocolLink = {
        lens: lensId,
        scope: params.scope ?? scopes[0],
        earliest: clampedEarliest,
        latest: rawWin.latest,
        view: "overview",
      };
      setParams(next);
      writeProtocolParams(next);
    },
    [params.earliest, params.latest, params.scope, scopes],
  );

  const backToHub = useCallback(() => {
    const next: ParsedProtocolLink = {
      view: "overview",
      ...(params.scope ? { scope: params.scope } : {}),
    };
    setParams(next);
    writeProtocolParams(next);
  }, [params.scope]);

  const handleLoadTrafficMix = useCallback(async () => {
    if (!client || !live || loadingMix) return;
    const scope = params.scope ?? scopes[0];
    if (!scope) return;
    const win = defaultWindow();
    mixAbort.current?.abort();
    const controller = new AbortController();
    mixAbort.current = controller;
    setLoadingMix(true);
    try {
      const mix = await loadProtocolTrafficMix(client, {
        configuration: config,
        scope,
        earliest: win.earliest,
        latest: win.latest,
        signal: controller.signal,
      });
      if (!controller.signal.aborted) setTrafficMix(mix);
    } catch {
      /* Aborted or handled by loadProtocolTrafficMix. */
    } finally {
      if (mixAbort.current === controller) mixAbort.current = null;
      setLoadingMix(false);
    }
  }, [client, config, live, loadingMix, params.scope, scopes]);

  /** Explicit operator action: runs configured lens summaries one at a time. */
  const handleCheckAll = useCallback(async () => {
    if (!client || !live || checkingAll) return;
    const scope = params.scope ?? scopes[0];
    if (!scope) return;
    const win = defaultWindow();
    const controller = new AbortController();
    checkAbort.current = controller;
    setCheckingAll(true);
    try {
      if (selectTrafficMixIndex(config, scope)) {
        try {
          const mix = await loadProtocolTrafficMix(client, {
            configuration: config,
            scope,
            earliest: win.earliest,
            latest: win.latest,
            signal: controller.signal,
          });
          if (!controller.signal.aborted) setTrafficMix(mix);
        } catch {
          if (controller.signal.aborted) return;
        }
      }
      for (const lens of PROTOCOL_LENSES) {
        if (controller.signal.aborted) break;
        if (!lens.summarize || !configuredByLens.get(lens.id)) continue;
        try {
          const rawSummary = await lens.summarize(
            client,
            {
              version: 1,
              lens: lens.id,
              scope,
              earliest: win.earliest,
              latest: win.latest,
            },
            config,
            controller.signal,
          );
          const hasDegraded =
            rawSummary.capped ||
            rawSummary.outcomes.some(
              (o) =>
                o.state === "blocked" ||
                o.state === "unavailable" ||
                o.state === "partial",
            );
          const summary =
            hasDegraded && rawSummary.status === "ok"
              ? { ...rawSummary, status: "attention" as const }
              : hasDegraded && rawSummary.status === "none_observed"
                ? { ...rawSummary, status: "unknown" as const }
                : rawSummary;
          if (!controller.signal.aborted) {
            setSummaries((prev) => ({ ...prev, [lens.id]: summary }));
          }
        } catch {
          if (controller.signal.aborted) break;
          setSummaries((prev) => ({
            ...prev,
            [lens.id]: {
              lens: lens.id,
              status: "unknown",
              verdict: "Summary check failed.",
              checkedAt: Math.floor(Date.now() / 1000),
              capped: false,
              outcomes: [],
            },
          }));
        }
      }
    } finally {
      if (checkAbort.current === controller) checkAbort.current = null;
      setCheckingAll(false);
    }
  }, [
    checkingAll,
    client,
    config,
    configuredByLens,
    live,
    params.scope,
    scopes,
  ]);

  const cancelCheckAll = useCallback(() => {
    checkAbort.current?.abort();
  }, []);

  if (activeLens) {
    const win =
      params.earliest && params.latest
        ? { earliest: params.earliest, latest: params.latest }
        : fallbackWin;
    const activeScope = params.scope ?? scopes[0] ?? "";
    if (configState === "error") {
      return (
        <main className="pl-page" data-testid="protocol-lens-config-error">
          <header className="pl-header">
            <div className="pl-header-left">
              <button type="button" className="pl-back-btn" onClick={backToHub}>
                ← Protocols
              </button>
              <h1 className="pl-title">{activeLens.title}</h1>
            </div>
          </header>
          <ProtocolStateBanner
            state="unavailable"
            reason={
              configError ?? "Protocol source configuration could not be read."
            }
            onAction={() => setConfigRevision((v) => v + 1)}
            actionLabel="Retry"
          />
        </main>
      );
    }
    if (lensComponent && (configState !== "loading" || configLoadedOnce)) {
      const Lens = lensComponent;
      return (
        <Lens
          client={client}
          live={live}
          timezone={timezone}
          theme={theme}
          scope={activeScope}
          scopes={scopes}
          earliest={win.earliest}
          latest={win.latest}
          windowMode={params.windowMode}
          view={params.view}
          filter={params.filter}
          selectedItem={params.item}
          configuration={config}
          profileValidators={registeredProfileValidators()}
          onBackToHub={backToHub}
          onRefreshConfig={() => setConfigRevision((v) => v + 1)}
          onChangeParams={(patch) => {
            const next = applyProtocolParamPatch(
              params,
              activeLens.id,
              activeScope,
              win,
              patch,
            );
            setParams(next);
            writeProtocolParams(next);
          }}
        />
      );
    }
    return (
      <main className="pl-page" data-testid="protocol-lens-loading">
        <header className="pl-header">
          <div className="pl-header-left">
            <button type="button" className="pl-back-btn" onClick={backToHub}>
              ← Protocols
            </button>
            <h1 className="pl-title">{activeLens.title}</h1>
          </div>
        </header>
        <ProtocolStateBanner
          state={lensLoadError ? "unavailable" : "loading"}
          reason={lensLoadError ?? `Loading ${activeLens.title}…`}
          onAction={backToHub}
          actionLabel="Back to hub"
        />
      </main>
    );
  }

  const configuredCount = PROTOCOL_LENSES.filter(
    (lens) => (configuredByLens.get(lens.id) ?? 0) > 0,
  ).length;
  const checkedSummaries = Object.values(summaries).filter(
    (item): item is ProtocolLensSummary => Boolean(item),
  );
  const attentionCount = checkedSummaries.filter(
    (item) => item.status === "attention",
  ).length;

  const hubStatus: ProtocolStatus =
    attentionCount > 0
      ? "attention"
      : checkedSummaries.length > 0 &&
          checkedSummaries.every((item) => item.status === "ok")
        ? "ok"
        : configuredCount > 0
          ? "unknown"
          : "not_covered";

  const hubVerdict =
    attentionCount > 0
      ? `${attentionCount} of ${checkedSummaries.length} checked lenses need attention.`
      : checkedSummaries.length > 0
        ? `${checkedSummaries.length} checked lenses reported no active exceptions.`
        : configuredCount > 0
          ? `Choose a lens below or run Check all.`
          : `No protocol profiles configured yet — open Multicast below or add profiles in Admin → Protocols.`;

  return (
    <main className="pl-page" data-testid="protocols-hub">
      <header className="pl-header" data-testid="protocol-header">
        <div className="pl-header-left">
          <h1 className="pl-title">Protocols</h1>
        </div>
        <div className="pl-header-controls">
          {checkingAll ? (
            <button
              type="button"
              className="pl-btn-secondary"
              onClick={cancelCheckAll}
            >
              Cancel
            </button>
          ) : configuredCount > 0 ? (
            <button
              type="button"
              className="pl-btn-primary"
              disabled={!live || !client}
              title={
                !live
                  ? "Connect to Splunk to run live checks."
                  : "Run configured lens summary checks sequentially."
              }
              onClick={() => void handleCheckAll()}
            >
              Check all
            </button>
          ) : null}
          <span className="pl-neutral-tag" data-pl-data="true">
            {configuredCount}/{PROTOCOL_LENSES.length} configured
          </span>
        </div>
      </header>

      <section
        className={`pl-verdict pl-verdict-${hubStatus}`}
        data-testid="protocol-verdict"
      >
        <StatusChip
          status={hubStatus}
          label={
            hubStatus === "unknown" && configuredCount > 0
              ? "Not checked"
              : undefined
          }
        />
        <p className="pl-verdict-text" data-pl-data="true">
          {hubVerdict}
        </p>
      </section>

      {linkError ? (
        <ProtocolStateBanner state="unavailable" reason={linkError} />
      ) : null}
      {configState === "error" && configError ? (
        <ProtocolStateBanner
          state="blocked"
          reason={configError}
          onAction={() => setConfigRevision((v) => v + 1)}
          actionLabel="Retry"
        />
      ) : null}

      {configuredCount > 0 ? (
        <section
          className="pl-traffic-mix"
          aria-label="Traffic and IPv4/IPv6 mix"
          data-testid="protocol-traffic-mix"
        >
          <div className="pl-traffic-mix-head">
            <span className="pl-traffic-mix-title">Traffic &amp; IP mix</span>
            <div className="pl-header-controls">
              {trafficMix ? (
                <StatusChip
                  status={trafficMix.status}
                  title={trafficMix.statusReason}
                />
              ) : null}
              <button
                type="button"
                className="pl-btn-secondary"
                disabled={!live || !client || loadingMix}
                onClick={() => void handleLoadTrafficMix()}
              >
                {loadingMix
                  ? "Loading…"
                  : trafficMix
                    ? "Refresh"
                    : "Load traffic mix"}
              </button>
            </div>
          </div>
          {trafficMix ? (
            <div className="pl-traffic-mix-body" data-pl-data="true">
              <p className="pl-traffic-mix-summary">{trafficMix.summary}</p>
              {trafficMix.topProtocols.length > 0 ? (
                <div className="pl-traffic-mix-chips">
                  {trafficMix.topProtocols.map((b) => (
                    <span key={b.id} className="pl-neutral-tag pl-mono">
                      {b.label} {b.sharePct}%
                    </span>
                  ))}
                  <span className="pl-neutral-tag pl-mono">
                    IPv4 {trafficMix.ipv4Pct}% · IPv6 {trafficMix.ipv6Pct}%
                  </span>
                </div>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : null}

      <section
        className="pl-hub-grid"
        aria-label="Protocol lenses"
        data-testid="protocols-hub-grid"
      >
        <a
          className="pl-hub-card"
          href={pageURL("multicast")}
          data-testid="protocol-card-multicast"
        >
          <div className="pl-hub-card-head">
            <span className="pl-hub-card-title">Multicast / IGMP</span>
            <span className="pl-neutral-tag">Standalone</span>
          </div>
          <p className="pl-hub-card-summary" data-pl-data="true">
            IGMP membership, forwarding tree, and multicast flow evidence.
          </p>
        </a>

        {PROTOCOL_LENSES.map((lens) => {
          const profiles = configuredByLens.get(lens.id) ?? 0;
          const summary = summaries[lens.id];
          const isConfigured = profiles > 0;
          const cardStatus: ProtocolStatus = summary
            ? summary.status
            : isConfigured
              ? "unknown"
              : "not_covered";
          const chipLabel = summary
            ? undefined
            : isConfigured
              ? "Not checked"
              : "Not covered";
          return (
            <button
              key={lens.id}
              type="button"
              className={`pl-hub-card${isConfigured ? "" : " pl-hub-card-unconfigured"}`}
              data-testid={`protocol-card-${lens.id}`}
              onClick={() => openLens(lens.id)}
            >
              <div className="pl-hub-card-head">
                <span className="pl-hub-card-title">{lens.title}</span>
                <StatusChip status={cardStatus} label={chipLabel} />
              </div>
              <p className="pl-hub-card-summary" data-pl-data="true">
                {lens.summary}
              </p>
              {summary ? (
                <p className="pl-hub-card-verdict" data-pl-data="true">
                  {summary.verdict}
                </p>
              ) : null}
            </button>
          );
        })}
      </section>
    </main>
  );
}
