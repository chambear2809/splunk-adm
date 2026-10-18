import { defineConfig } from "vite";
import { resolve } from "node:path";
const sourceRoot = process.env.ADM_PERF_SOURCE_ROOT ?? process.cwd();
export default defineConfig({
  root: resolve(import.meta.dirname),
  cacheDir: resolve(sourceRoot, "node_modules/.vite-performance"),
  define: { __ADM_SPLUNK_BUILD__: "false" },
  resolve: {
    alias: [
      {
        find: /^react-dom(?:\/client)?$/,
        replacement: resolve(sourceRoot, "node_modules/react-dom/profiling.js"),
      },
      { find: "@atlas", replacement: resolve(sourceRoot, "frontend/src") },
      { find: "@fixtures", replacement: resolve(sourceRoot, "fixtures") },
    ],
    dedupe: ["react", "react-dom", "styled-components"],
  },
  build: {
    outDir: resolve(process.cwd(), "dist/performance-app"),
    emptyOutDir: true,
  },
});
