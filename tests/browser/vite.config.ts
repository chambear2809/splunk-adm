import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  define: { __ADM_SPLUNK_BUILD__: "false" },
  resolve: { preserveSymlinks: true },
});
