import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/searchClient": "searchClient",
} as const;
export function multicastAssetVersion() {
  const hash = createHash("sha256");
  const files = [
    "package-lock.json",
    "vite.multicast.config.ts",
    "vite.multicast.shared.ts",
    ...readdirSync("frontend/src/multicast")
      .filter((name) => /\.(tsx?|css)$/.test(name) && !name.includes(".test."))
      .map((name) => `frontend/src/multicast/${name}`),
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
export const multicastHostModule = (id: string) =>
  modules.get(id.replace(/\.tsx?$/, ""));
