import { createStaticURL } from "@splunk/splunk-utils/url";

export interface CatalogCapture {
  search: string;
  earliest: string;
  latest: string;
  provenance: Record<string, unknown>;
  rows: Record<string, unknown>[];
}
export interface FindQueryCapture {
  query: string;
  search: string;
  rows: Record<string, unknown>[];
}
export interface FindCapture {
  earliest: string;
  latest: string;
  provenance: Record<string, unknown>;
  queries: FindQueryCapture[];
}
export interface CatalogDemo {
  catalog: CatalogCapture;
  find: FindCapture;
}
let pending: Promise<CatalogDemo> | undefined;
const production =
  typeof __ADM_SPLUNK_BUILD__ !== "undefined" && __ADM_SPLUNK_BUILD__;
const url = (name: string) =>
  production
    ? createStaticURL(`app/splunk_adm/demo/${name}`)
    : `/fixtures/${name}`;
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const rows = (value: unknown, label: string): Record<string, unknown>[] => {
  if (!Array.isArray(value) || !value.every(object))
    throw new Error(`${label} fixture has invalid rows.`);
  return value;
};
const validWindow = (start: unknown, end: unknown) =>
  typeof start === "string" &&
  typeof end === "string" &&
  /^\d+$/.exec(start)?.[0] === start &&
  /^\d+$/.exec(end)?.[0] === end &&
  Number.isSafeInteger(Number(start)) &&
  Number.isSafeInteger(Number(end)) &&
  Number(start) < Number(end) &&
  Number(end) <= 253402300799;
const catalog = (value: unknown): CatalogCapture => {
  if (
    !object(value) ||
    typeof value.search !== "string" ||
    typeof value.earliest !== "string" ||
    typeof value.latest !== "string" ||
    !validWindow(value.earliest, value.latest) ||
    !object(value.provenance)
  )
    throw new Error("Catalog fixture has invalid shape.");
  return {
    search: value.search,
    earliest: value.earliest,
    latest: value.latest,
    provenance: value.provenance,
    rows: rows(value.rows, "Catalog"),
  };
};
const find = (value: unknown): FindCapture => {
  if (
    !object(value) ||
    typeof value.earliest !== "string" ||
    typeof value.latest !== "string" ||
    !validWindow(value.earliest, value.latest) ||
    !object(value.provenance) ||
    !Array.isArray(value.queries)
  )
    throw new Error("Find fixture has invalid shape.");
  const queries = value.queries.map((query) => {
    if (
      !object(query) ||
      typeof query.query !== "string" ||
      typeof query.search !== "string"
    )
      throw new Error("Find fixture has invalid query.");
    return {
      query: query.query,
      search: query.search,
      rows: rows(query.rows, "Find query"),
    };
  });
  return {
    earliest: value.earliest,
    latest: value.latest,
    provenance: value.provenance,
    queries,
  };
};
async function load(name: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(url(name), { signal });
  if (!response.ok)
    throw new Error(`Catalog fixture request failed (${response.status}).`);
  return response.json();
}
export function loadCatalogDemo(): Promise<CatalogDemo> {
  if (pending) return pending;
  pending = (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const [catalogPayload, findPayload] = await Promise.all([
        load("demo-catalog.json", controller.signal),
        load("demo-find.json", controller.signal),
      ]);
      return { catalog: catalog(catalogPayload), find: find(findPayload) };
    } finally {
      controller.abort();
      clearTimeout(timer);
    }
  })().catch((error) => {
    pending = undefined;
    throw error;
  });
  return pending;
}
export const prepareCatalogDemo = loadCatalogDemo;
