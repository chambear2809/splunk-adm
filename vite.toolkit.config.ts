import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    // The existing Simple XML bundle is built first and stays available.
    emptyOutDir: false,
    lib: {
      entry: resolve("frontend/src/spike/main.tsx"),
      name: "AtlasToolkitSpike",
      formats: ["iife"],
      fileName: () => "pages/atlas.js",
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
