import { defineConfig } from "vite";
export default defineConfig({
  root: "frontend",
  define: { __ADM_SPLUNK_BUILD__: "false" },
  base: "./",
  build: { outDir: "../dist/preview", emptyOutDir: true },
});
