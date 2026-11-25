import { createRoot } from "react-dom/client";
import { IncidentWorkspace } from "../../frontend/src/incident/IncidentWorkspace";
import { demoGraph } from "../../frontend/src/provider";
import { BusinessServiceImport } from "../../frontend/src/businessServices/BusinessServiceImport";
import "../../frontend/src/styles.css";
import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { createCaseClient } from "../../frontend/src/investigations/caseClient";

// Synthetic window adapter exercises UI behavior; it is not real-source qualification.
const incident = demoGraph();
const acl = new URLSearchParams(location.search).get("acl");
const aclEdge = incident.edges.find(
  (edge) => edge.relationship === "communicates_with",
)!;
const policyPoint = "a".repeat(64);
if (acl) {
  incident.edges = [
    {
      ...aclEdge,
      acl_action: "drop",
      acl_drops: 1,
      acl_permits: acl === "mixed" ? 1 : undefined,
      acl_policy_point:
        acl === "same"
          ? policyPoint
          : acl === "cross"
            ? "b".repeat(64)
            : undefined,
    },
  ];
}
const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
const theme =
  new URLSearchParams(location.search).get("theme") === "dark"
    ? "dark"
    : "light";
const caseClient = new URLSearchParams(location.search).has("cases")
  ? createCaseClient({
      baseUrl: "/test-cases",
      transport: (url, init) => {
        if (!new URLSearchParams(location.search).has("casePreview"))
          return fetch(url, init);
        // Design-only synthetic note record; never a deployed persistence claim.
        const sample = {
          schema_version: 1,
          id: "00000000-0000-4000-8000-000000000001",
          revision: 1,
          title: "Synthetic case preview",
          window: incident.window,
          captures: [],
          attachments: [],
          entries: [
            {
              id: "entry-1",
              revision: 1,
              author: "synthetic-investigator",
              created_at: "2026-01-01T01:00:00Z",
              type: "note",
              text: "Synthetic observation for layout review",
            },
          ],
        };
        const data = url.endsWith("/capabilities")
          ? {
              available: true,
              evidenceWrites: false,
              mode: "notes_only",
              qualified: false,
            }
          : url.endsWith("/cases") && init.method === "GET"
            ? { items: [sample], next: null }
            : sample;
        return Promise.resolve(
          new Response(JSON.stringify(data), {
            headers: { "Content-Type": "application/json" },
          }),
        );
      },
    })
  : undefined;
createRoot(document.getElementById("root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="map">
      <main className="adm atlas-page" data-adm-theme={theme}>
        <IncidentWorkspace
          incident={incident}
          caseClient={caseClient}
          loadWindow={async (window) => ({
            ...incident,
            snapshot_id: "synthetic-baseline",
            window,
            edges: acl
              ? [
                  {
                    ...aclEdge,
                    acl_action: "permit",
                    acl_permits: 1,
                    acl_drops: undefined,
                    acl_policy_point: policyPoint,
                  },
                ]
              : [],
          })}
        />
        <BusinessServiceImport />
      </main>
    </Shell>
  </ThemeProvider>,
);
