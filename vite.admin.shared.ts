import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/SimpleTable": "simpleTable",
  "frontend/src/app/interop": "interop",
  "frontend/src/app/urlState": "urlState",
  "frontend/src/JourneyLazyEvidence": "journeys",
  "frontend/src/ecosystem/EcosystemLazyEvidence": "ecosystem",
  "frontend/src/health": "health",
  "frontend/src/data/healthStatus": "healthStatus",
  "frontend/src/data/deploymentClient": "deploymentClient",
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/observerMappingClient": "observerMappingClient",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/data/timeBounds": "timeBounds",
  "frontend/src/map/TimePicker": "timePicker",
  "frontend/src/time": "time",
} as const;

const bundledFiles = [
  "frontend/src/pages/AdminPage.tsx",
  "frontend/src/pages/SetupPage.tsx",
  "frontend/src/pages/HealthPage.tsx",
  "frontend/src/data/setupClient.ts",
  "frontend/src/HealthPanel.tsx",
  "frontend/src/data/vendorTaCheck.ts",
  "frontend/src/data/summaryHealth.ts",
  "frontend/src/components/ModifiedVendorTaCallout.tsx",
];

export function adminAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.admin.config.ts",
    "vite.admin.shared.ts",
    ...bundledFiles,
    ...readdirSync("frontend/src/admin")
      .filter((name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."))
      .map((name) => `frontend/src/admin/${name}`),
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
  ["@splunk/react-ui/Button", "splunkButton"],
  ["@splunk/react-ui/Text", "splunkText"],
  ["@splunk/splunk-utils/fetch", "splunkFetch"],
  ["@splunk/splunk-utils/url", "splunkUrl"],
  ["lucide-react", "lucideIcons"],
  ...Object.entries(host).map(([path, name]): [string, string] => [
    resolve(path),
    name,
  ]),
]);

export const adminHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
