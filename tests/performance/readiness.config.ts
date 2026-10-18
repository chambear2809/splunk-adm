import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: import.meta.dirname,
  testMatch: "readiness.spec.ts",
  workers: 1,
  retries: 0,
  timeout: 5000,
  reporter: "list",
  outputDir: "../../dist/performance-readiness-checks",
});
