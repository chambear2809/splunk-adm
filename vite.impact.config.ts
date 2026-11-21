import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { impactAssetVersion, impactHostModule } from "./vite.impact.shared";
const MAX_GZIP_BYTES = 64 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_IMPACT_ASSET_VERSION__: JSON.stringify(impactAssetVersion()),
  },
  plugins: [
    {
      name: "impact-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        let gzipBytes = 0,
          javascript = "";
        for (const entry of Object.values(bundle))
          if (entry.type === "chunk") {
            gzipBytes += gzipSync(entry.code, { level: 9 }).length;
            javascript += entry.code;
          }
        const css = bundle["impact.css"];
        if (!css || css.type !== "asset")
          throw new Error("Impact stylesheet was not generated.");
        this.emitFile({
          type: "asset",
          fileName: "impact-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: impactAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/impact-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: impactAssetVersion(),
              gzipBytes,
              ceilingGzipBytes: MAX_GZIP_BYTES,
              loading: "impact-page-only",
            },
            null,
            2,
          ) + "\n",
        );
        if (gzipBytes > MAX_GZIP_BYTES)
          throw new Error(
            "Impact optional asset exceeds its 64 KiB gzip budget.",
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
      entry: resolve("frontend/src/impact/impact-entry.ts"),
      name: "ApplicationAtlasImpact",
      formats: ["iife"],
      fileName: () => "pages/impact.js",
      cssFileName: "impact",
    },
    rolldownOptions: {
      external: (id) => impactHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasImpactHost.${impactHostModule(id)}`,
      },
    },
  },
});
