import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/app/urlState": "urlState",
} as const;

function collectProtocolCoreFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (
        entry.name === "shared" ||
        dir.endsWith("/shared") ||
        dir.includes("/shared/")
      ) {
        out.push(...collectProtocolCoreFiles(full));
      }
      continue;
    }
    if (
      /\.(tsx?|css)$/.test(entry.name) &&
      !entry.name.includes(".test.") &&
      entry.name !== "ProtocolsLazyPage.tsx"
    ) {
      out.push(full);
    }
  }
  return out;
}

export function protocolsCoreAssetVersion() {
  const hash = createHash("sha256");
  const files = [
    "package-lock.json",
    "vite.protocols-core.config.ts",
    "vite.protocols-core.shared.ts",
    ...collectProtocolCoreFiles("frontend/src/protocols"),
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

export const protocolsCoreHostModule = (id: string) =>
  modules.get(id.replace(/\.tsx?$/, ""));
