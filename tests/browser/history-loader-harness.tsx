import { createRoot } from "react-dom/client";
import { LazyChangeTimelineInspection } from "../../frontend/src/HistoryLazyInspection";
import type { SearchClient } from "../../frontend/src/data/searchClient";

const client = {
  search: async () => ({ results: [], messages: [] }),
} as unknown as SearchClient;

(
  globalThis as typeof globalThis & { __ADM_FORCE_SPLUNK_BUILD__: boolean }
).__ADM_FORCE_SPLUNK_BUILD__ = true;

createRoot(document.getElementById("root")!).render(
  <>
    <main aria-label="Other evidence">Evidence remains available</main>
    <LazyChangeTimelineInspection
      client={client}
      view={{ scope: "prod-east", window: { start: 100, end: 200 } }}
    />
  </>,
);
