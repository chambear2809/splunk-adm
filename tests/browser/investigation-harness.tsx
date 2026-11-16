import { createRoot } from "react-dom/client";
import { IncidentWorkspace } from "../../frontend/src/incident/IncidentWorkspace";
import { demoGraph } from "../../frontend/src/provider";
import { BusinessServiceImport } from "../../frontend/src/businessServices/BusinessServiceImport";
import "../../frontend/src/styles.css";
import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";

// Synthetic window adapter exercises UI behavior; it is not real-source qualification.
const incident = demoGraph();
const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
const theme =
  new URLSearchParams(location.search).get("theme") === "dark"
    ? "dark"
    : "light";
createRoot(document.getElementById("root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="map">
      <main className="adm atlas-page" data-adm-theme={theme}>
        <IncidentWorkspace
          incident={incident}
          loadWindow={async (window) => ({
            ...incident,
            snapshot_id: "synthetic-baseline",
            window,
            edges: [],
          })}
        />
        <BusinessServiceImport />
      </main>
    </Shell>
  </ThemeProvider>,
);
