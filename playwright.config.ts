import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.ADM_BROWSER_PORT ?? 4173);
if (!Number.isInteger(port) || port < 1024 || port > 65535)
  throw new Error(
    "ADM_BROWSER_PORT must be an integer between 1024 and 65535.",
  );
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "tests/browser",
  fullyParallel: true,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: `vite --config tests/browser/vite.config.ts --host 127.0.0.1 --port ${port} --strictPort`,
    url: `${baseURL}/tests/browser/browser.html`,
    reuseExistingServer: !process.env.CI,
  },
});
