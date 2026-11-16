import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import "../../frontend/src/incident/incident.css";
import { createRoot } from "react-dom/client";
import { CaseRecords } from "../../frontend/src/investigations/CaseRecords";
import { createCaseClient } from "../../frontend/src/investigations/caseClient";
import "../../frontend/src/styles.css";

const reference = JSON.stringify({
  schema: 1,
  scope: {
    cluster: "synthetic-cluster",
    environment: "test",
    namespace: "synthetic",
    service: "checkout",
  },
  windows: [
    { end: 200, start: 100 },
    { end: 300, start: 200 },
  ],
});
const client = createCaseClient({
  baseUrl: "/test-cases",
  transport: (url, init) => fetch(url, init),
});
const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
const theme =
  new URLSearchParams(location.search).get("theme") === "dark"
    ? "dark"
    : "light";
createRoot(document.getElementById("root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="map">
      <main className="adm atlas-page" data-adm-theme={theme}>
        <h1>Synthetic case replay</h1>
        <CaseRecords
          client={client}
          window={{
            start: "2026-01-01T00:00:00Z",
            end: "2026-01-01T01:00:00Z",
          }}
          comparisonReference={reference}
        />
      </main>
    </Shell>
  </ThemeProvider>,
);
