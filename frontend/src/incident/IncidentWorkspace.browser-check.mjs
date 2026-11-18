// Run from the repository root: node frontend/src/incident/IncidentWorkspace.browser-check.mjs
import { chromium } from "playwright";
import { createServer } from "vite";

const server = await createServer({
  root: "frontend",
  define: {
    __ADM_SPLUNK_BUILD__: "false",
    __ADM_JOURNEYS_ASSET_VERSION__: JSON.stringify("development"),
  },
  server: { host: "127.0.0.1", port: 0 },
  plugins: [
    {
      name: "incident-test-page",
      configureServer(dev) {
        dev.middlewares.use((request, response, next) => {
          if (request.url !== "/incident-test.html") return next();
          response.setHeader("Content-Type", "text/html");
          response.end(
            '<script>var __ADM_SPLUNK_BUILD__ = false; var __ADM_JOURNEYS_ASSET_VERSION__ = "development";</script><div id="root"></div><script type="module" src="/src/incident/IncidentWorkspace.browser-fixture.tsx"></script>',
          );
        });
      },
    },
  ],
});
let browser;
try {
  await server.listen();
  const address = server.httpServer.address();
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on("pageerror", (error) => globalThis.console.error(error));
  await page.goto(`http://127.0.0.1:${address.port}/incident-test.html`);
  await page.getByRole("button", { name: "Compare windows" }).click();
  await page.getByRole("button", { name: "Timeline" }).click({ timeout: 5000 });
  await page.getByText("Loading audit evidence", { exact: false }).waitFor();
  await page.getByRole("button", { name: "Cancel audit request" }).click();
  await page.getByText("Audit request cancelled", { exact: false }).waitFor();
  await page.evaluate("window.finishSyntheticAudit()");
  await page.getByRole("button", { name: "Connections" }).click();
  await page
    .getByText("Counts and evidence can vary", { exact: false })
    .waitFor();
  await page.getByRole("button", { name: "Timeline" }).click();
  if (
    (await page
      .getByText("Audit request cancelled", { exact: false })
      .count()) !== 1 ||
    (await page.getByText("Audit source coverage").count()) !== 0
  )
    throw new Error("Late audit response changed the cancelled comparison");
  globalThis.console.log(
    "Graph comparison remained available; cancellation suppressed late audit result.",
  );
} finally {
  await browser?.close();
  await server.close();
}
