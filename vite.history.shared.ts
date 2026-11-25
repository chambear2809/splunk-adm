import { createHash } from "node:crypto";
import {
  openSync,
  readSync,
  closeSync,
  readdirSync,
  lstatSync,
  statSync,
  realpathSync,
  readlinkSync,
} from "node:fs";
import { resolve, sep } from "node:path";

const GENERATED_DEPENDENCY_CACHES = new Set([
  ".vite",
  ".vite-temp",
  ".vite-browser",
  ".cache",
]);
let defaultVersion: string | undefined;

/** Bind cached optional code to all runtime sources and installed build dependencies.
 * Only known generated Vite caches are excluded; package contents and symlink
 * identities remain inputs. Explicit roots bypass memoization for regressions.
 */
export function historyAssetVersion(rootDirectory?: string): string {
  if (rootDirectory === undefined && defaultVersion) return defaultVersion;
  const root = resolve(rootDirectory ?? process.cwd());
  const hash = createHash("sha256");
  let fileCount = 0,
    byteCount = 0;
  const files = new Set<string>();
  const visit = (directory: string, dependencyRoot = false) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (dependencyRoot && GENERATED_DEPENDENCY_CACHES.has(entry.name))
        continue;
      const path = resolve(directory, entry.name);
      const info = lstatSync(path);
      if (info.isDirectory()) visit(path);
      else if (info.isFile() || info.isSymbolicLink()) files.add(path);
      else throw new Error("Unsupported optional-build input file type.");
    }
  };
  visit(resolve(root, "frontend/src"));
  visit(resolve(root, "config"));
  files.add(resolve(root, "research/cisco-pipeline-interface.json"));
  visit(resolve(root, "node_modules"), true);
  for (const entry of readdirSync(root)) {
    if (
      /^(?:vite.*\.ts|tsconfig.*\.json|package(?:-lock)?\.json|eslint\.config\.mjs)$/.test(
        entry,
      )
    )
      files.add(resolve(root, entry));
  }
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  for (const file of [...files].sort()) {
    if (++fileCount > 100000)
      throw new Error("Optional-build input file count exceeds its budget.");
    const relative = file.slice(root.length + 1);
    const info = lstatSync(file);
    if (info.isSymbolicLink()) {
      const target = realpathSync(file);
      if (!target.startsWith(root + sep) || !statSync(target).isFile())
        throw new Error("Optional-build symlink escapes regular source files.");
      hash.update(`symlink:${relative}\0${readlinkSync(file)}\0`);
    }
    const size = statSync(file).size;
    byteCount += size;
    if (byteCount > 4 * 1024 ** 3)
      throw new Error("Optional-build inputs exceed their byte budget.");
    hash.update(`${relative}\0${size}\0`);
    const descriptor = openSync(file, "r");
    let total = 0;
    try {
      for (;;) {
        const count = readSync(descriptor, buffer);
        if (count === 0) break;
        total += count;
        hash.update(buffer.subarray(0, count));
      }
    } finally {
      closeSync(descriptor);
    }
    if (total !== size)
      throw new Error("Optional-build input changed while hashing.");
  }
  const version = hash.digest("hex").slice(0, 24);
  if (rootDirectory === undefined) defaultVersion = version;
  return version;
}
const HOST = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  [resolve("frontend/src/HistoryLazyInspection"), "historyLazy"],
  [resolve("frontend/src/data/evidence"), "evidence"],
  [resolve("frontend/src/data/evidenceConfig"), "evidenceConfig"],
  [resolve("frontend/src/data/searchClient"), "searchClient"],
  [resolve("frontend/src/data/deploymentHealth"), "deploymentHealth"],
  [resolve("frontend/src/data/optionalJobs"), "optionalJobs"],
]);
export function historyHostModule(id: string) {
  return HOST.get(id.replace(/\.tsx?$/, ""));
}
