import ButtonExport from "@splunk/react-ui/Button";
import { toolkitDefault } from "../app/interop";
import { HealthResults, useHealthData } from "../HealthPanel";
import type { SearchClient } from "../data/searchClient";
import { useEffect, useState } from "react";
import {
  loadSummaryHealth,
  summaryHealthText,
  type SummaryHealth,
} from "../data/summaryHealth";
import { formatUtc } from "../time";
import { TimePicker } from "../map/TimePicker";
import { isSafeTime, resolveTime, timeError } from "../data/timeBounds";

/** earliest/latest from the URL; a latest other than now evaluates health at that instant. */
export function healthWindow(
  search: string,
  nowSeconds = Date.now() / 1000,
  timezone?: string,
): { earliest: string; latest: string; asOf?: number } {
  const q = new URLSearchParams(search);
  const e = q.get("earliest") ?? "-7d";
  const l = q.get("latest") ?? "now";
  if (!isSafeTime(e) || !isSafeTime(l) || timeError(e, l, timezone, nowSeconds))
    return { earliest: "-7d", latest: "now" };
  if (l === "now") return { earliest: e, latest: l };
  const end = resolveTime(l, timezone, nowSeconds);
  // An end within a minute of now is the current check.
  return end === undefined || end >= nowSeconds - 60
    ? { earliest: e, latest: l }
    : { earliest: e, latest: l, asOf: Math.floor(end) };
}
const Button = toolkitDefault(ButtonExport);
export function HealthPage({
  client,
  live,
  timezone,
}: {
  client?: SearchClient;
  live: boolean;
  timezone?: string;
}) {
  const [range, setRange] = useState(() =>
    healthWindow(
      typeof location === "undefined" ? "" : location.search,
      undefined,
      timezone,
    ),
  );
  useEffect(() => {
    if (typeof window === "undefined") return;
    const q = new URLSearchParams(location.search);
    q.set("earliest", range.earliest);
    q.set("latest", range.latest);
    const query = `?${q}`;
    if (location.search !== query)
      history.replaceState(
        null,
        "",
        `${location.pathname}${query}${location.hash}`,
      );
  }, [range]);
  const { report, error, busy, checkAgain } = useHealthData(
    client,
    live,
    range.asOf,
  );
  return (
    <section className="atlas-admin-panel" aria-labelledby="health-title">
      <h2 id="health-title">Data health</h2>
      {!live ? (
        <p role="status">Demo data · switch to Splunk to check health.</p>
      ) : (
        <>
          <TimePicker
            earliest={range.earliest}
            latest={range.latest}
            timezone={timezone}
            live={live}
            onChange={(e, l) =>
              setRange(
                healthWindow(`?earliest=${e}&latest=${l}`, undefined, timezone),
              )
            }
          />{" "}
          <Button
            appearance="secondary"
            label={busy ? "Checking…" : "Check again"}
            onClick={checkAgain}
            disabled={busy || !client}
          />
          {busy && (
            <p role="status">
              Checking data sources, flow quality and scheduled searches…
            </p>
          )}
          {error && <p role="alert">{error}</p>}
          {report && <HealthResults report={report} />}
          <SummaryHealthSection
            client={client}
            refresh={report}
            asOf={range.asOf}
          />
        </>
      )}
    </section>
  );
}

/** Qualified graph summary lag/gaps (Admin → Data health). */
function SummaryHealthSection({
  client,
  refresh,
  asOf,
}: {
  client?: SearchClient;
  refresh: unknown;
  asOf?: number;
}) {
  const [state, setState] = useState<
    { health?: SummaryHealth; error?: string } | undefined
  >();
  useEffect(() => {
    if (!client) return;
    const controller = new AbortController();
    loadSummaryHealth(client, controller.signal, asOf)
      .then((health) => !controller.signal.aborted && setState({ health }))
      .catch(
        (e: unknown) =>
          !controller.signal.aborted &&
          setState({
            error: /disabled/i.test(String(e))
              ? "Not enabled"
              : "Unavailable (requires qualified identity and summaries)",
          }),
      );
    return () => controller.abort();
  }, [client, refresh, asOf]);
  if (!state) return null;
  const h = state.health;
  return (
    <section aria-labelledby="summary-health-title">
      <h3 id="summary-health-title">Graph summaries</h3>
      <p
        role="status"
        className={
          h && h.status !== "ok" && h.status !== "disabled" ? "warn" : ""
        }
      >
        {h ? summaryHealthText(h) : state.error}
      </p>
      {h?.newestEnd !== undefined && (
        <p className="muted small">
          Summarized through{" "}
          {formatUtc(new Date(h.newestEnd * 1000).toISOString())} UTC
          {h.oldestMissing !== undefined &&
            ` · oldest missing slice ${formatUtc(new Date(h.oldestMissing * 1000).toISOString())} UTC (backfill it)`}
          {h.supersededRuns > 0 && ` · ${h.supersededRuns} superseded runs`}
          {h.duplicatedRuns > 0 && ` · ${h.duplicatedRuns} duplicated runs`}
        </p>
      )}
    </section>
  );
}
