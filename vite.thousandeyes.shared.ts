import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/** Both bundles bind to the same source inputs; this is not a configuration fingerprint. */
export function thousandEyesAssetVersion(): string {
  const hash = createHash("sha256");
  for (const file of [
    "vite.thousandeyes.shared.ts",
    "vite.thousandeyes.config.ts",
    "frontend/src/ThousandEyesLazyInspection.tsx",
    "frontend/src/thousandeyes-entry.tsx",
    "frontend/src/ThousandEyesEvidencePanel.tsx",
    "frontend/src/thousandeyes.css",
    "frontend/src/data/thousandEyesTypes.ts",
    "frontend/src/data/thousandEyesConfiguration.ts",
    "frontend/src/data/thousandEyesAdapters.ts",
    "frontend/src/data/thousandEyesEvidence.ts",
    "frontend/src/data/thousandEyesAttribution.ts",
    "frontend/src/data/evidence.ts",
    "frontend/src/data/evidenceConfig.ts",
    "frontend/src/data/deploymentClient.ts",
    "frontend/src/data/supplementalEvidence.ts",
    "frontend/src/data/searchClient.ts",
    "frontend/src/data/deploymentHealth.ts",
    "config/deployment-health.json",
  ]) {
    hash.update(file);
    hash.update(readFileSync(resolve(file)));
  }
  return hash.digest("hex").slice(0, 24);
}

export const THOUSANDEYES_HOST_MODULES = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  [resolve("frontend/src/data/evidence"), "evidence"],
  [resolve("frontend/src/data/evidenceConfig"), "evidenceConfig"],
  [resolve("frontend/src/data/supplementalEvidence"), "supplementalEvidence"],
  [resolve("frontend/src/data/deploymentHealth"), "deploymentHealth"],
  [resolve("frontend/src/data/searchClient"), "searchClient"],
]);

export function thousandEyesHostModule(id: string): string | undefined {
  return THOUSANDEYES_HOST_MODULES.get(id.replace(/\.tsx?$/, ""));
}
