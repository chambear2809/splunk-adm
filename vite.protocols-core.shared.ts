import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import {
  PROTOCOLS_HOST_MODULES,
  protocolLensVersions,
  protocolsCoreHostModule,
} from "./tools/protocol-lenses.mjs";

export { protocolLensVersions, protocolsCoreHostModule };

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
      } else if (entry.name === "lenses") {
        for (const lensDir of readdirSync(full, { withFileTypes: true })) {
          if (!lensDir.isDirectory()) continue;
          const validatePath = `${full}/${lensDir.name}/validate.ts`;
          if (existsSync(resolve(validatePath))) out.push(validatePath);
        }
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
    "tools/protocol-lenses.mjs",
    ...collectProtocolCoreFiles("frontend/src/protocols"),
    ...Object.keys(PROTOCOLS_HOST_MODULES).map((path) => `${path}.ts`),
  ];
  for (const file of files.sort())
    hash.update(file).update(readFileSync(resolve(file)));
  hash.update(JSON.stringify(protocolLensVersions()));
  return hash.digest("hex").slice(0, 24);
}
