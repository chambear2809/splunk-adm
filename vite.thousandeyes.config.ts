import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  thousandEyesAssetVersion,
  thousandEyesHostModule,
} from "./vite.thousandeyes.shared";

const MAX_GZIP_BYTES = 48 * 1024;

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_TE_ASSET_VERSION__: JSON.stringify(thousandEyesAssetVersion()),
  },
  plugins: [
    {
      name: "thousandeyes-optional-asset-budget",
      generateBundle(_options, bundle) {
        let gzipBytes = 0;
        let javascript = "";
        for (const entry of Object.values(bundle)) {
          if (entry.type === "chunk") {
            gzipBytes += gzipSync(entry.code, { level: 9 }).length;
            javascript += entry.code;
          }
        }
        this.emitFile({
          type: "asset",
          fileName: "thousandeyes-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: thousandEyesAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/thousandeyes-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: thousandEyesAssetVersion(),
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
            "ThousandEyes optional asset exceeds its 48 KiB gzip budget.",
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
      entry: resolve("frontend/src/thousandeyes-entry.tsx"),
      name: "ApplicationAtlasThousandEyes",
      formats: ["iife"],
      fileName: () => "pages/thousandeyes.js",
      cssFileName: "thousandeyes",
    },
    rolldownOptions: {
      external: (id) => thousandEyesHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) =>
          `__AtlasThousandEyesHost.${thousandEyesHostModule(id)}`,
      },
    },
  },
});
