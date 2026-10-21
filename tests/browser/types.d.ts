export {};

declare global {
  interface Window {
    __ADM_REQUESTS__?: { spl: string; earliest: string; latest: string }[];
    __ADM_LAST_EARLIEST__?: unknown;
    __ADM_LAST_GRAPH_SEARCH__?: unknown;
    __ADM_DEPLOYMENT_READS__?: number;
  }
}
