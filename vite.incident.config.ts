import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  incidentAssetVersion,
  incidentHostModule,
} from "./vite.incident.shared";
const MAX_GZIP_BYTES = 32 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_INCIDENT_ASSET_VERSION__: JSON.stringify(incidentAssetVersion()),
  },
  plugins: [
    {
      name: "incident-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        let gzipBytes = 0,
          javascript = "";
        for (const entry of Object.values(bundle))
          if (entry.type === "chunk") {
            gzipBytes += gzipSync(entry.code, { level: 9 }).length;
            javascript += entry.code;
          }
        const css = bundle["incident.css"];
        if (!css || css.type !== "asset")
          throw new Error("Incident workspace stylesheet was not generated.");
        this.emitFile({
          type: "asset",
          fileName: "incident-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: incidentAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/incident-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: incidentAssetVersion(),
              gzipBytes,
              ceilingGzipBytes: MAX_GZIP_BYTES,
              loading: "incident-workspace-only",
            },
            null,
            2,
          ) + "\n",
        );
        if (gzipBytes > MAX_GZIP_BYTES)
          throw new Error(
            "Incident workspace optional asset exceeds its 32 KiB gzip budget.",
          );
      },
    },
  ],
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    emptyOutDir: false,
    target: "es2022",
    sourcemap: false,
    lib: {
      entry: resolve("frontend/src/incident/incident-entry.ts"),
      name: "ApplicationAtlasIncident",
      formats: ["iife"],
      fileName: () => "pages/incident.js",
      cssFileName: "incident",
    },
    rolldownOptions: {
      external: (id) => incidentHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasIncidentHost.${incidentHostModule(id)}`,
      },
    },
  },
});
