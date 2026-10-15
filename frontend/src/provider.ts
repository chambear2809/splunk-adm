import { type Graph } from "./graph";
import { MAX_ROWS, rowsToGraph, type GraphArgs, type Row } from "./rows";
import { MAX_TOPOLOGY_ROWS, rowsToTopology, type Topology } from "./topology";
import type {
  SearchClient,
  SearchRequest,
  RunResult,
} from "./data/searchClient";
export { timeError } from "./data/searchClient";
export { isIncompleteWindow, resolveTime } from "./data/timeBounds";
export {
  demoArgs,
  demoArgsFor,
  demoGraph,
  demoTopology,
  DEMO_SCENARIOS,
} from "./data/demoClient";
export type { DemoScenario } from "./data/demoClient";
export interface LiveRequest extends GraphArgs {
  earliest: string;
  latest?: string;
  timezone?: string;
}
const MAX_MESSAGE_CHARS = 300;
const MAX_MESSAGES = 20;
export const FINALIZED_SEARCH_WARNING =
  "Splunk finalized this job before all results were available; the graph may be incomplete.";
export const ARG_RULES: Record<keyof GraphArgs, { re: RegExp; hint: string }> =
  {
    service: {
      re: /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/,
      hint: "letters, numbers and . _ : / @ -",
    },
    environment: {
      re: /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/,
      hint: "letters, numbers and . _ -",
    },
    cluster: {
      re: /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/,
      hint: "letters, numbers and . _ -",
    },
    namespace: {
      re: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/,
      hint: "lowercase letters, numbers and -, at most 63 characters",
    },
  };
export function argError(key: keyof GraphArgs, value: string) {
  return ARG_RULES[key].re.test(value)
    ? undefined
    : `${key[0].toUpperCase()}${key.slice(1)} may contain ${ARG_RULES[key].hint}.`;
}
export function buildGraphSearch(request: LiveRequest): string {
  for (const key of Object.keys(ARG_RULES) as (keyof GraphArgs)[]) {
    const error = argError(key, String(request[key] ?? ""));
    if (error) throw new Error(error);
  }
  const { service, environment, cluster, namespace } = request;
  return `\`adm_graph("${service}","${environment}","${cluster}","${namespace}")\``;
}
export function splunkMessage(payload: unknown): string | undefined {
  let text: unknown;
  if (typeof payload === "string") text = payload;
  else if (payload && typeof payload === "object") {
    const p = payload as {
      message?: unknown;
      text?: unknown;
      content?: { messages?: { text?: unknown }[] };
    };
    text =
      typeof p.message === "string"
        ? p.message
        : typeof p.text === "string"
          ? p.text
          : p.content?.messages
              ?.map((m) => m?.text)
              .filter((t) => typeof t === "string" && t.trim())
              .join(" ");
  }
  if (typeof text !== "string") return undefined;
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) return undefined;
  return clean.length > MAX_MESSAGE_CHARS
    ? `${clean.slice(0, MAX_MESSAGE_CHARS - 1)}…`
    : clean;
}
export function splunkWarnings(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") {
    const message = splunkMessage(payload);
    return message ? [message] : [];
  }
  const p = payload as { message?: unknown; content?: { messages?: unknown } };
  const messages = Array.isArray(p.content?.messages)
    ? p.content.messages
    : undefined;
  const values = messages?.length
    ? messages
    : p.message === undefined
      ? []
      : [p.message];
  return values
    .filter((value) => {
      if (!value || typeof value !== "object") return true;
      const type = (value as { type?: unknown }).type;
      return !(
        typeof type === "string" &&
        /^(?:info|information|notice)$/i.test(type.trim())
      );
    })
    .map(splunkMessage)
    .filter((value): value is string => !!value)
    .filter((value, index, all) => all.indexOf(value) === index)
    .slice(0, MAX_MESSAGES);
}
interface Results {
  fields: (string | { name?: string })[];
  rows: unknown[][];
}
export function resultRows(data: Results): Row[] {
  const fields = data.fields.map((f) => (typeof f === "string" ? f : f?.name));
  if (!fields.every((f) => typeof f === "string" && f))
    throw new Error("Splunk returned results without field names.");
  return (data.rows ?? []).map((values) => {
    const row: Row = {};
    fields.forEach((f, i) => {
      if (values[i] !== null && values[i] !== undefined)
        row[f as string] = values[i];
    });
    return row;
  });
}
const request = (
  search: string,
  earliest: string,
  maxRows: number,
  signal: AbortSignal,
  latest?: string,
  timezone?: string,
): SearchRequest => ({
  search,
  earliest,
  latest: latest ?? "now",
  timezone,
  maxRows,
  signal,
});
export function loadLive(
  client: SearchClient,
  input: LiveRequest,
  signal: AbortSignal,
): Promise<Graph> {
  let search: string;
  try {
    search = buildGraphSearch(input);
  } catch (e) {
    return Promise.reject(e);
  }
  return client
    .search(
      request(
        search,
        input.earliest,
        MAX_ROWS,
        signal,
        input.latest,
        input.timezone,
      ),
    )
    .then(({ rows, warnings }) => {
      const graph = rowsToGraph(rows, input);
      graph.coverage.warnings = [
        ...new Set([...graph.coverage.warnings, ...warnings]),
      ];
      return graph;
    });
}
export function loadTopology(
  client: SearchClient,
  earliest: string,
  signal: AbortSignal,
  latest?: string,
  timezone?: string,
): Promise<Topology> {
  return client
    .search(
      request(
        "`adm_topology`",
        earliest,
        MAX_TOPOLOGY_ROWS,
        signal,
        latest,
        timezone,
      ),
    )
    .then(({ rows, warnings }) => {
      const topology = rowsToTopology(rows);
      topology.warnings = [...new Set([...topology.warnings, ...warnings])];
      return topology;
    });
}
export type { RunResult };
export const TOPOLOGY_SEARCH = "`adm_topology`";
