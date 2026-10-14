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
      name: "ApplicationAtlas",
      formats: ["iife"],
      fileName: () => "pages/atlas.js",
      cssFileName: "adm",
    },
    sourcemap: false,
    target: "es2022",
    rolldownOptions: {
      // Simple XML pages expose RequireJS's global define. Shadow it inside the
      // IIFE so UMD dependencies (lodash) take their CommonJS path instead of
      // emitting an anonymous define() and overwriting the page's window._.
      output: { intro: "var define;" },
    },
  },
});
