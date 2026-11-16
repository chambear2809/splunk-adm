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
    "frontend/src/impact/model.ts",
    "frontend/src/maintenance/model.ts",
    "frontend/src/maintenance/adapter.ts",
    "frontend/src/maintenance/MaintenancePlanner.tsx",
    "frontend/src/maintenance/ImpactMaintenancePlanner.tsx",
    "frontend/src/maintenance/MaintenanceAssessment.tsx",
    "frontend/src/maintenance/maintenance.css",
    "frontend/src/drift/network.ts",
    "frontend/src/drift/LiveDependencyMonitor.tsx",
    "frontend/src/drift/model.ts",
    "frontend/src/drift/client.ts",
    "frontend/src/drift/DependencyMonitor.tsx",
    "frontend/src/drift/BaselineReview.tsx",
    "frontend/src/drift/monitor.css",
    "frontend/src/businessServices/BusinessServiceImport.tsx",
    "frontend/src/businessServices/import.ts",
    "frontend/src/businessServices/ownership.ts",
    "frontend/src/businessServices/bindings.ts",
    "frontend/src/businessServices/OwnershipEvidence.tsx",
    "frontend/src/businessServices/BusinessOwnershipContext.tsx",
    "frontend/src/businessServices/BusinessOwnershipContext.css",
    "frontend/src/data/identityContext.ts",
    "frontend/src/data/strictJson.ts",
    "frontend/src/businessServices/localImport.ts",
    "frontend/src/investigations/CaseRecords.tsx",
    "frontend/src/investigations/CaseEvidence.tsx",
    "frontend/src/investigations/caseHandoff.ts",
    "frontend/src/investigations/caseClient.ts",
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
  [resolve("frontend/src/impact/model"), "impact"],
  [resolve("frontend/src/investigations/caseClient"), "caseClient"],
]);
export function journeysHostModule(id: string): string | undefined {
  return JOURNEYS_HOST_MODULES.get(id.replace(/\.tsx?$/, ""));
}
