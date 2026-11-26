import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/data/supplementalEvidence": "supplementalEvidence",
} as const;
export function ecosystemAssetVersion() {
  const hash = createHash("sha256");
  const files = [
    "package-lock.json",
    "vite.ecosystem.config.ts",
    "vite.ecosystem.shared.ts",
    ...readdirSync("frontend/src/ecosystem")
      .filter((name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."))
      .map((name) => `frontend/src/ecosystem/${name}`),
    ...Object.keys(host).map((path) => `${path}.ts`),
  ];
  for (const file of files.sort())
    hash.update(file).update(readFileSync(resolve(file)));
  return hash.digest("hex").slice(0, 24);
}
const modules = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  ...Object.entries(host).map(([path, name]): [string, string] => [
    resolve(path),
    name,
  ]),
]);
export const ecosystemHostModule = (id: string) =>
  modules.get(id.replace(/\.tsx?$/, ""));
