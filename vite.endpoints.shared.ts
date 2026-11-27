import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/HistoryLazyInspection": "history",
  "frontend/src/JourneyLazyEvidence": "journeys",
  "frontend/src/MapView": "mapView",
  "frontend/src/RoutingScopeSelect": "routingScopeSelect",
  "frontend/src/SuggestCombobox": "suggestCombobox",
  "frontend/src/ThousandEyesLazyInspection": "thousandEyes",
  "frontend/src/app/urlState": "urlState",
  "frontend/src/csv": "csv",
  "frontend/src/data/appdynamicsEvidence": "appdynamicsEvidence",
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/healthStatus": "healthStatus",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/proxyEvidence": "proxyEvidence",
  "frontend/src/data/routingScopes": "routingScopes",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/data/supplementalEvidence": "supplementalEvidence",
  "frontend/src/download": "download",
  "frontend/src/ecosystem/EcosystemLazyEvidence": "ecosystem",
} as const;

const bundledFiles = [
  "frontend/src/pages/EndpointsPage.tsx",
  "frontend/src/pages/endpointPeerLink.ts",
  "frontend/src/EndpointEvidencePanels.tsx",
  "frontend/src/MapDnsInspection.tsx",
  "frontend/src/DnsEvidencePanel.tsx",
  "frontend/src/ProxyEvidencePanel.tsx",
  "frontend/src/CloudFlowEvidencePanel.tsx",
  "frontend/src/InventoryEvidencePanel.tsx",
  "frontend/src/AppDynamicsEvidencePanel.tsx",
  "frontend/src/data/endpointInvestigation.ts",
  "frontend/src/data/dnsAdapters.ts",
  "frontend/src/data/dnsEvidence.ts",
  "frontend/src/data/dnsDrilldown.ts",
  "frontend/src/data/inventoryEvidence.ts",
  "frontend/src/data/cloudFlowEvidence.ts",
  "frontend/src/dnsExport.ts",
  "frontend/src/data/ownership.ts",
];

export function endpointsAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.endpoints.config.ts",
    "vite.endpoints.shared.ts",
    ...bundledFiles,
    ...readdirSync("frontend/src/endpoints")
      .filter((name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."))
      .map((name) => `frontend/src/endpoints/${name}`),
    ...Object.keys(host).map((path) => {
      const file = path.split("/").pop()!;
      const dir = path.slice(0, -file.length);
      return (
        dir +
        readdirSync(dir).find(
          (name) => name === file + ".ts" || name === file + ".tsx",
        )
      );
    }),
  ];
  for (const file of versioned.sort())
    hash.update(file).update(readFileSync(resolve(file)));
  return hash.digest("hex").slice(0, 24);
}

const hostModules = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  ...Object.entries(host).map(([path, name]): [string, string] => [
    resolve(path),
    name,
  ]),
]);

export const endpointsHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
