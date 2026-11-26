import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const host = {
  "frontend/src/download": "download",
  "frontend/src/glossary": "glossary",
  "frontend/src/pages/ExploreTools": "explore",
  "frontend/src/csv": "csv",
} as const;

export function segmentationAssetVersion() {
  const hash = createHash("sha256");
  const versioned = [
    "package-lock.json",
    "vite.segmentation.config.ts",
    "vite.segmentation.shared.ts",
    "frontend/src/graph.ts",
    ...readdirSync("frontend/src/segmentation")
      .filter(
        (name) =>
          /\.(tsx?|css)$/.test(name) &&
          !name.includes(".test.") &&
          name !== "testGraph.ts",
      )
      .map((name) => `frontend/src/segmentation/${name}`),
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
export const segmentationHostModule = (id: string) =>
  hostModules.get(id.replace(/\.tsx?$/, ""));
