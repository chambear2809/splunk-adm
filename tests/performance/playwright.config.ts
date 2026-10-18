import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";
const sourceRoot = process.env.ADM_PERF_SOURCE_ROOT ?? process.cwd();
const vite = JSON.stringify(
  resolve(sourceRoot, "node_modules/vite/bin/vite.js"),
);
export default defineConfig({
  testDir: import.meta.dirname,
  testMatch: "browser.perf.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 300000,
  reporter: "list",
  outputDir: "../../dist/performance-artifacts",
  use: {
    actionTimeout: 10000,
    baseURL: "http://127.0.0.1:4187",
    viewport: { width: 1440, height: 1000 },
    browserName: "chromium",
    headless: true,
    deviceScaleFactor: 1,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    trace: "off",
  },
  webServer: {
    cwd: process.cwd(),
    command: `node ${vite} build --config tests/performance/vite.config.ts && node ${vite} preview --config tests/performance/vite.config.ts --host 127.0.0.1 --port 4187 --strictPort`,
    url: "http://127.0.0.1:4187",
    reuseExistingServer: false,
    timeout: 120000,
  },
});
