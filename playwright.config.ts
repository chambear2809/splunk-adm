import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "tests/browser",
  fullyParallel: true,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command:
      "vite --config tests/browser/vite.config.ts --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173/tests/browser/browser.html",
    reuseExistingServer: !process.env.CI,
  },
});
