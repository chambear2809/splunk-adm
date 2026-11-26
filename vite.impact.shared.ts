import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/download": "download",
  "frontend/src/glossary": "glossary",
  "frontend/src/map/TimePicker": "timePicker",
  "frontend/src/pages/ExploreTools": "explore",
  "frontend/src/app/urlState": "urlState",
  "frontend/src/scale/VirtualTable": "virtualTable",
  "frontend/src/JourneyLazyEvidence": "journey",
  "frontend/src/topology": "topology",
  "frontend/src/trace/traceModel": "traceModel",
  "frontend/src/trace/pathEvidence": "pathEvidence",
  "frontend/src/data/timeBounds": "timeBounds",
  "frontend/src/csv": "csv",
} as const;

export function impactAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.impact.config.ts",
    "vite.impact.shared.ts",
    ...["impact", "changeVerification"].flatMap((dir) =>
      readdirSync(`frontend/src/${dir}`)
        .filter(
          (name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."),
        )
        .map((name) => `frontend/src/${dir}/${name}`),
    ),
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
export const impactHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
