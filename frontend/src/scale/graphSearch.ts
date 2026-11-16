import type { SearchClient, SearchRequest } from "../data/searchClient";
import { MAX_GRAPH_EDGES, SERVER_NODE_CAP } from "./limits";

const GRAPH_READ = "| `adm_application_graph_read(";

/**
 * Bounds the aggregated adm_graph result server-side: the meta row first (it
 * still carries the full node and edge counts), then nodes, then edges ranked
 * by relationship, bytes and connection count, each truncated to a cap. The
 * graph macro already aggregates conversations per entity pair and port, so
 * this only limits how many of those aggregates are transferred.
 */
export const GRAPH_BOUND_SUFFIX =
  ` | eval adm_rank_group=case(row_type=="meta", 0, row_type=="node", 1, row_type=="edge" AND relationship=="communicates_with", 3, row_type=="edge" AND relationship=="traffic_observation", 4, true(), 2),` +
  ` adm_rank_bytes=if(row_type=="edge", coalesce(tonumber(bytes), tonumber(count), 0), 0),` +
  ` adm_rank_count=if(row_type=="edge", coalesce(tonumber(count), 0), 0)` +
  ` | sort 0 adm_rank_group -adm_rank_bytes -adm_rank_count id` +
  ` | streamstats count AS adm_rank by row_type` +
  ` | where row_type=="meta" OR (row_type=="node" AND adm_rank<=${SERVER_NODE_CAP}) OR (row_type=="edge" AND adm_rank<=${MAX_GRAPH_EDGES})` +
  ` | fields - adm_rank adm_rank_group adm_rank_bytes adm_rank_count`;

/** Meta row, every node the server keeps, and the top edges. */
export const GRAPH_BOUND_ROWS = 1 + SERVER_NODE_CAP + MAX_GRAPH_EDGES;

export const isGraphRead = (search: string) =>
  search.startsWith(GRAPH_READ) && !search.includes(GRAPH_BOUND_SUFFIX);

export function boundGraphRequest(request: SearchRequest): SearchRequest {
  if (!isGraphRead(request.search)) return request;
  return {
    ...request,
    search: `${request.search}${GRAPH_BOUND_SUFFIX}`,
    maxRows: Math.max(request.maxRows, GRAPH_BOUND_ROWS),
    overflow: "truncate",
  };
}

/** A client whose graph reads are bounded top-N searches that never overflow. */
export function boundedGraphClient(client: SearchClient): SearchClient {
  return {
    search: (request) => client.search(boundGraphRequest(request)),
  };
}
