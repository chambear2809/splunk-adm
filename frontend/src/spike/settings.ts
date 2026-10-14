import { buildGraphSearch } from "../provider";
import { MAX_ROWS, type Row } from "../rows";

/** Only this view is implemented in Phase 0; do not silently mount elsewhere. */
export function spikePage(pathname: string): "map" {
  if (!/\/app\/splunk_adm\/map\/?$/.test(pathname))
    throw new Error("Unsupported Application Atlas page.");
  return "map";
}

const time = (value: string) =>
  /^(?:\d{1,12}|now|-(?:15m|1h|4h|24h))$/.test(value);

export function spikeSearch(params: URLSearchParams) {
  const request = {
    service: params.get("service") ?? "frontend",
    environment: params.get("environment") ?? "demo",
    cluster: params.get("cluster") ?? "demo-cluster",
    namespace: params.get("namespace") ?? "shop",
    earliest: "-1h",
  };
  const search = buildGraphSearch(request);
  const earliest = params.get("earliest") ?? "-1h";
  const latest = params.get("latest") ?? "now";
  if (!time(earliest) || !time(latest))
    throw new Error("Unsupported time window.");
  if (/^\d+$/.test(earliest) && /^\d+$/.test(latest) && +earliest >= +latest)
    throw new Error("Earliest must precede latest.");
  return { search, earliest_time: earliest, latest_time: latest };
}

export function spikeRows(payload: unknown): Row[] {
  const results = (payload as { results?: unknown } | null)?.results;
  if (!Array.isArray(results))
    throw new Error("Search returned invalid results.");
  if (!results.length) throw new Error("Graph search returned no rows.");
  if (results.length > MAX_ROWS)
    throw new Error("Graph exceeds the pilot limit.");
  if (results.some((r) => !r || typeof r !== "object" || Array.isArray(r)))
    throw new Error("Search returned an invalid row.");
  return results as Row[];
}
