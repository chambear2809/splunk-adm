import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  segmentationAssetVersion,
  segmentationHostModule,
} from "./vite.segmentation.shared";
const MAX_GZIP_BYTES = 40 * 1024;
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_SEGMENTATION_ASSET_VERSION__: JSON.stringify(
      segmentationAssetVersion(),
    ),
  },
  plugins: [
    {
      name: "segmentation-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        let gzipBytes = 0,
          javascript = "";
        for (const entry of Object.values(bundle))
          if (entry.type === "chunk") {
            gzipBytes += gzipSync(entry.code, { level: 9 }).length;
            javascript += entry.code;
          }
        const css = bundle["segmentation.css"];
        if (!css || css.type !== "asset")
          throw new Error("Segmentation stylesheet was not generated.");
        this.emitFile({
          type: "asset",
          fileName: "segmentation-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: segmentationAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(javascript)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
        writeFileSync(
          resolve("dist/segmentation-bundle-report.json"),
          JSON.stringify(
            {
              assetVersion: segmentationAssetVersion(),
              gzipBytes,
              ceilingGzipBytes: MAX_GZIP_BYTES,
              loading: "segmentation-workbench-only",
            },
            null,
            2,
          ) + "\n",
        );
        if (gzipBytes > MAX_GZIP_BYTES)
          throw new Error(
            "Segmentation optional asset exceeds its 40 KiB gzip budget.",
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
      entry: resolve("frontend/src/segmentation/segmentation-entry.ts"),
      name: "ApplicationAtlasSegmentation",
      formats: ["iife"],
      fileName: () => "pages/segmentation.js",
      cssFileName: "segmentation",
    },
    rolldownOptions: {
      external: (id) => segmentationHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) =>
          `__AtlasSegmentationHost.${segmentationHostModule(id)}`,
      },
    },
  },
});
