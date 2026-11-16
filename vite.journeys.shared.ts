import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/** Version binds both bundles and every shared host contract to the same sources. */
export function journeysAssetVersion(): string {
  const hash = createHash("sha256");
  for (const file of [
    "vite.journeys.shared.ts",
    "vite.journeys.config.ts",
    "frontend/src/JourneyLazyEvidence.tsx",
    "frontend/src/journeys-entry.tsx",
    "frontend/src/journeys/FirewallJourneyEvidence.tsx",
    "frontend/src/journeys/JourneyEvidence.tsx",
    "frontend/src/journeys/HubbleJourneyEvidence.tsx",
    "frontend/src/journeys/model.ts",
    "frontend/src/journeys/hubble.ts",
    "frontend/src/journeys/journeys.css",
    "frontend/src/graph.ts",
    "frontend/src/data/evidence.ts",
    "frontend/src/data/proxyEvidence.ts",
    "frontend/src/topology.ts",
    "frontend/src/glossary.ts",
  ]) {
    hash.update(file);
    hash.update(readFileSync(resolve(file)));
  }
  return hash.digest("hex").slice(0, 24);
}
export const JOURNEYS_HOST_MODULES = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  [resolve("frontend/src/graph"), "graph"],
  [resolve("frontend/src/data/evidence"), "evidence"],
  [resolve("frontend/src/data/proxyEvidence"), "proxyEvidence"],
  [resolve("frontend/src/topology"), "topology"],
  [resolve("frontend/src/glossary"), "glossary"],
]);
export function journeysHostModule(id: string): string | undefined {
  return JOURNEYS_HOST_MODULES.get(id.replace(/\.tsx?$/, ""));
}
