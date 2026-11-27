import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { o11yAssetVersion, o11yHostModule } from "./vite.o11y.shared";

const MAX_GZIP_BYTES = 40 * 1024;

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_O11Y_ASSET_VERSION__: JSON.stringify(o11yAssetVersion()),
  },
  plugins: [
    {
      name: "o11y-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/o11y.js"];
        const css = bundle["o11y.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error(
            "Observability inspection assets were not generated.",
          );
        if (gzipSync(js.code, { level: 9 }).length > MAX_GZIP_BYTES)
          throw new Error(
            "Observability inspection optional asset exceeds its 40 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "o11y-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: o11yAssetVersion(),
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
      entry: resolve("frontend/src/o11y/o11y-entry.tsx"),
      name: "ApplicationAtlasO11y",
      formats: ["iife"],
      fileName: () => "pages/o11y.js",
      cssFileName: "o11y",
    },
    rolldownOptions: {
      external: (id) => o11yHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasO11yHost.${o11yHostModule(id)}`,
      },
    },
  },
});
