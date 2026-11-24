import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  multicastAssetVersion,
  multicastHostModule,
} from "./vite.multicast.shared";

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_MULTICAST_ASSET_VERSION__: JSON.stringify(multicastAssetVersion()),
  },
  plugins: [
    {
      name: "multicast-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/multicast.js"];
        const css = bundle["multicast.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Multicast assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > 64 * 1024)
          throw new Error(
            "Multicast optional asset exceeds its 64 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "multicast-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: multicastAssetVersion(),
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
      entry: resolve("frontend/src/multicast/multicast-entry.ts"),
      name: "ApplicationAtlasMulticast",
      formats: ["iife"],
      fileName: () => "pages/multicast.js",
      cssFileName: "multicast",
    },
    rolldownOptions: {
      external: (id) => multicastHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasMulticastHost.${multicastHostModule(id)}`,
      },
    },
  },
});
