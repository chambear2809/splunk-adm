import { defineConfig } from "vite";
import { resolve } from "node:path";
export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
  },
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    emptyOutDir: true,
    lib: {
      entry: resolve("frontend/src/main.tsx"),
      name: "SplunkADM",
      formats: ["iife"],
      fileName: () => "adm.bundle.js",
      cssFileName: "adm",
    },
    sourcemap: false,
    target: "es2022",
  },
});
