import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { historyAssetVersion, historyHostModule } from "./vite.history.shared";
const MAX_GZIP_BYTES = 48 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_HISTORY_ASSET_VERSION__: JSON.stringify(historyAssetVersion()),
  },
  plugins: [
    {
      name: "configuration-history-optional-asset-budget",
      generateBundle(_options, bundle) {
        const javascript = Object.values(bundle)
          .filter((entry) => entry.type === "chunk")
          .map((entry) => entry.code)
          .join("");
        const gzipBytes = gzipSync(javascript, { level: 9 }).length;
        this.emitFile({
          type: "asset",
          fileName: "history-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: historyAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/history-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: historyAssetVersion(),
              gzipBytes,
              ceilingGzipBytes: MAX_GZIP_BYTES,
              loading: "explicit-investigation-only",
            },
            null,
            2,
          ) + "\n",
        );
        if (gzipBytes > MAX_GZIP_BYTES)
          throw Error(
            "Configuration history optional asset exceeds its 48 KiB gzip budget.",
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
      entry: resolve("frontend/src/history-entry.tsx"),
      name: "ApplicationAtlasHistory",
      formats: ["iife"],
      fileName: () => "pages/history.js",
      cssFileName: "history",
    },
    rolldownOptions: {
      external: (id) => historyHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasHistoryHost.${historyHostModule(id)}`,
      },
    },
  },
});
