import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/data/supplementalEvidence": "supplementalEvidence",
} as const;

const bundledFiles = [
  "frontend/src/MapServiceHealthInspection.tsx",
  "frontend/src/O11yHealthPanel.tsx",
  "frontend/src/O11yDetectorEventsPanel.tsx",
  "frontend/src/O11yNavigationPanel.tsx",
  "frontend/src/data/o11yHealth.ts",
  "frontend/src/data/o11yDetectorEvents.ts",
  "frontend/src/data/o11yNavigation.ts",
  "frontend/src/data/serviceHealthSelection.ts",
  "frontend/src/data/observabilityRealm.ts",
];

export function o11yAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.o11y.config.ts",
    "vite.o11y.shared.ts",
    ...bundledFiles,
    ...readdirSync("frontend/src/o11y")
      .filter((name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."))
      .map((name) => `frontend/src/o11y/${name}`),
    ...Object.keys(host).map((path) => `${path}.ts`),
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

export const o11yHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
