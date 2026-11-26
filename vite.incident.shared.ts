import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/diff": "diff",
  "frontend/src/time": "time",
  "frontend/src/download": "download",
  "frontend/src/provider": "provider",
  "frontend/src/JourneyLazyEvidence": "journeys",
} as const;

export function incidentAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.incident.config.ts",
    "vite.incident.shared.ts",
    "frontend/src/graph.ts",
    "frontend/src/investigations/caseClient.ts",
    "frontend/src/investigations/InvestigationHandoff.tsx",
    "frontend/src/investigations/portable.ts",
    "frontend/src/investigations/reference.ts",
    ...readdirSync("frontend/src/incident")
      .filter(
        (name) =>
          /\.(tsx?|css)$/.test(name) &&
          !name.includes(".test.") &&
          !name.includes(".browser-"),
      )
      .map((name) => `frontend/src/incident/${name}`),
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
export const incidentHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
