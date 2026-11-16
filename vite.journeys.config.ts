import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  journeysAssetVersion,
  journeysHostModule,
} from "./vite.journeys.shared";
const MAX_GZIP_BYTES = 32 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_JOURNEYS_ASSET_VERSION__: JSON.stringify(journeysAssetVersion()),
  },
  plugins: [
    {
      name: "journeys-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        let gzipBytes = 0,
          javascript = "";
        for (const entry of Object.values(bundle))
          if (entry.type === "chunk") {
            gzipBytes += gzipSync(entry.code, { level: 9 }).length;
            javascript += entry.code;
          }
        const css = bundle["journeys.css"];
        if (!css || css.type !== "asset")
          throw new Error("Journey stylesheet was not generated.");
        this.emitFile({
          type: "asset",
          fileName: "journeys-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: journeysAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/journeys-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: journeysAssetVersion(),
              gzipBytes,
              ceilingGzipBytes: MAX_GZIP_BYTES,
              loading: "explicit-investigation-only",
            },
            null,
            2,
          ) + "\n",
        );
        if (gzipBytes > MAX_GZIP_BYTES)
          throw new Error(
            "Journey optional asset exceeds its 32 KiB gzip budget.",
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
      entry: resolve("frontend/src/journeys-entry.tsx"),
      name: "ApplicationAtlasJourneys",
      formats: ["iife"],
      fileName: () => "pages/journeys.js",
      cssFileName: "journeys",
    },
    rolldownOptions: {
      external: (id) => journeysHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasJourneysHost.${journeysHostModule(id)}`,
      },
    },
  },
});
