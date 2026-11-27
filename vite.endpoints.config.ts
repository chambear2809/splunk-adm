import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  endpointsAssetVersion,
  endpointsHostModule,
} from "./vite.endpoints.shared";

const MAX_GZIP_BYTES = 64 * 1024;

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_ENDPOINTS_ASSET_VERSION__: JSON.stringify(endpointsAssetVersion()),
  },
  plugins: [
    {
      name: "endpoints-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/endpoints.js"];
        const css = bundle["endpoints.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Endpoints investigation assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > MAX_GZIP_BYTES)
          throw new Error(
            "Endpoints investigation optional asset exceeds its 64 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "endpoints-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: endpointsAssetVersion(),
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
      entry: resolve("frontend/src/endpoints/endpoints-entry.tsx"),
      name: "ApplicationAtlasEndpoints",
      formats: ["iife"],
      fileName: () => "pages/endpoints.js",
      cssFileName: "endpoints",
    },
    rolldownOptions: {
      external: (id) => endpointsHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasEndpointsHost.${endpointsHostModule(id)}`,
      },
    },
  },
});
