import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  ecosystemAssetVersion,
  ecosystemHostModule,
} from "./vite.ecosystem.shared";

const MAX_GZIP_BYTES = 48 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_ECOSYSTEM_ASSET_VERSION__: JSON.stringify(ecosystemAssetVersion()),
  },
  plugins: [
    {
      name: "ecosystem-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/ecosystem.js"];
        const css = bundle["ecosystem.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Ecosystem evidence assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > MAX_GZIP_BYTES)
          throw new Error(
            "Ecosystem evidence optional asset exceeds its 48 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "ecosystem-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: ecosystemAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(js.code)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
      },
    },
  ],
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    emptyOutDir: false,
    target: "es2022",
    sourcemap: false,
    lib: {
      entry: resolve("frontend/src/ecosystem/ecosystem-entry.tsx"),
      name: "ApplicationAtlasEcosystem",
      formats: ["iife"],
      fileName: () => "pages/ecosystem.js",
      cssFileName: "ecosystem",
    },
    rolldownOptions: {
      external: (id) => ecosystemHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasEcosystemHost.${ecosystemHostModule(id)}`,
      },
    },
  },
});
