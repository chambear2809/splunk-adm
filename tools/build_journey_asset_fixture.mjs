import { build, loadConfigFromFile } from "vite";
import { resolve } from "node:path";

// Reuse the production asset's source-derived version and build settings.
const production = await loadConfigFromFile(
  { command: "build", mode: "production" },
  resolve("vite.journeys.config.ts"),
);
if (!production) throw new Error("Journey build configuration is unavailable");
await build({
  configFile: false,
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_JOURNEYS_ASSET_VERSION__:
      production.config.define.__ADM_JOURNEYS_ASSET_VERSION__,
  },
  resolve: {
    alias: [
      { find: /^moment$/, replacement: resolve("frontend/build/moment.cjs") },
    ],
  },
  build: {
    outDir: "dist/journey-loader-test",
    emptyOutDir: true,
    target: "es2022",
    lib: {
      entry: resolve("tests/browser/journey-assets-harness.tsx"),
      name: "JourneyAssetProbe",
      formats: ["iife"],
      fileName: () => "probe.js",
    },
    rolldownOptions: { output: { intro: "var define;" } },
  },
});
