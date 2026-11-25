import { createRoot } from "react-dom/client";
import { useState } from "react";
import { LazyChangeTimelineInspection } from "../../frontend/src/HistoryLazyInspection";
import type { SearchClient } from "../../frontend/src/data/searchClient";

const client = {
  search: async () => ({ results: [], messages: [] }),
} as unknown as SearchClient;

(
  globalThis as typeof globalThis & { __ADM_FORCE_SPLUNK_BUILD__: boolean }
).__ADM_FORCE_SPLUNK_BUILD__ = true;

function Harness() {
  const [attempt, setAttempt] = useState(0);
  return (
    <>
      <main aria-label="Other evidence">Evidence remains available</main>
      <button onClick={() => setAttempt((value) => value + 1)}>
        Retry history
      </button>
      <LazyChangeTimelineInspection
        key={attempt}
        client={client}
        view={{ scope: "prod-east", window: { start: 100, end: 200 } }}
      />
    </>
  );
}

createRoot(document.getElementById("root")!).render(<Harness />);
