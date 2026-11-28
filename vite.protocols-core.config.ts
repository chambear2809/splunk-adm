import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  protocolLensVersions,
  protocolsCoreAssetVersion,
  protocolsCoreHostModule,
} from "./vite.protocols-core.shared";

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_PROTOCOLS_CORE_ASSET_VERSION__: JSON.stringify(
      protocolsCoreAssetVersion(),
    ),
    __ADM_PROTOCOL_LENS_VERSIONS__: JSON.stringify(protocolLensVersions()),
  },
  plugins: [
    {
      name: "protocols-core-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/protocols-core.js"];
        const css = bundle["protocols-core.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Protocols core assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > 64 * 1024)
          throw new Error(
            "Protocols core optional asset exceeds its 64 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "protocols-core-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: protocolsCoreAssetVersion(),
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
      entry: resolve("frontend/src/protocols/protocols-core-entry.ts"),
      name: "ApplicationAtlasProtocolsCore",
      formats: ["iife"],
      fileName: () => "pages/protocols-core.js",
      cssFileName: "protocols-core",
    },
    rolldownOptions: {
      external: (id) => protocolsCoreHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasProtocolsHost.${protocolsCoreHostModule(id)}`,
      },
    },
  },
});
