import { pageURL } from "../app/urlState";
import { isSafeTime } from "../data/timeBounds";
import { isImpactToken, MAX_IMPACT_ELEMENTS } from "./elements";
import type { ImpactMode } from "./model";

export interface ImpactRequest {
  elements: string[];
  mode: ImpactMode;
  earliest: string;
  latest: string;
}

/** Same default window as the rest of the app (urlState). */
export const DEFAULT_IMPACT_WINDOW = "-15m";

/** True for the Impact view's `mode` values (data mode stays demo/live elsewhere). */
export const isImpactMode = (v: string | null): v is ImpactMode =>
  v === "fails" || v === "depends";

/** `/impact?element=…&element=…&mode=fails|depends&window=-15m` (earliest/latest also accepted; default -15m, the app default). */
export function parseImpactParams(params: URLSearchParams): ImpactRequest {
  const elements = [
    ...new Set(
      params
        .getAll("element")
        .flatMap((v) => v.split(","))
        .map((v) => v.trim())
        .filter(isImpactToken),
    ),
  ].slice(0, MAX_IMPACT_ELEMENTS);
  const mode = params.get("mode");
  const raw =
    params.get("window") ?? params.get("earliest") ?? DEFAULT_IMPACT_WINDOW;
  const latest = params.get("latest") ?? "now";
  return {
    elements,
    mode: mode === "depends" ? "depends" : "fails",
    earliest: isSafeTime(raw) ? raw : DEFAULT_IMPACT_WINDOW,
    latest: isSafeTime(latest) ? latest : "now",
  };
}

const current = () =>
  new URLSearchParams(typeof location === "undefined" ? "" : location.search);

/** Impact link for one or more elements; keeps the time window. */
export function impactURL(
  elements: string[],
  opts: { mode?: ImpactMode; earliest?: string; latest?: string } = {},
  params: URLSearchParams = current(),
): string {
  const next = new URLSearchParams();
  for (const e of elements.filter(isImpactToken).slice(0, MAX_IMPACT_ELEMENTS))
    next.append("element", e);
  next.set("mode", opts.mode ?? "fails");
  const earliest =
    opts.earliest ?? params.get("window") ?? params.get("earliest");
  if (earliest && isSafeTime(earliest)) next.set("window", earliest);
  const latest = opts.latest ?? params.get("latest");
  if (latest && latest !== "now" && isSafeTime(latest))
    next.set("latest", latest);
  return pageURL("impact", next);
}
