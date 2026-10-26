// Exercise the installed app's explicit, same-origin ThousandEyes sidecar.
// Credentials arrive only through the environment and never enter evidence.
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const require = createRequire(new URL("../../package.json", import.meta.url));
const { chromium, expect } = require("@playwright/test");

const port = Number(process.env.ADM_LAB_WEB_PORT || 8000);
const BASE = `http://127.0.0.1:${port}`;
const { ADM_VIEWER_USER: user, ADM_VIEWER_PASS: pass } = process.env;
const [mode, scope, startText, endText, screenshotPath] = process.argv.slice(2);
if (!user || !pass) throw new Error("viewer credentials missing from env");
if (!["not-selected", "active"].includes(mode))
  throw new Error("unknown ThousandEyes browser mode");
const start = Number(startText);
const end = Number(endText);
if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end <= start)
  throw new Error("invalid endpoint window");

const searchRequests = [];
const assetRequests = [];
const jsErrors = [];
const badResponses = [];
const browser = await chromium.launch({ headless: true });
let stage = "launch";
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  const rememberAsset = (rawUrl) => {
    try {
      const url = new URL(rawUrl);
      const kind = url.pathname.endsWith(
        "/app/splunk_adm/pages/thousandeyes.js",
      )
        ? "javascript"
        : url.pathname.endsWith("/app/splunk_adm/thousandeyes.css")
          ? "stylesheet"
          : undefined;
      if (!kind) return undefined;
      let item = assetRequests.find((candidate) => candidate.url === rawUrl);
      if (!item) {
        item = {
          url: rawUrl,
          kind,
          sameOrigin: url.origin === BASE,
          version: url.searchParams.get("v"),
        };
        assetRequests.push(item);
      }
      return item;
    } catch {
      return undefined;
    }
  };
  page.on("console", (message) => {
    if (message.type() === "error") jsErrors.push("console-error");
  });
  page.on("pageerror", () => jsErrors.push("page-error"));
  page.on("request", (request) => {
    const url = new URL(request.url());
    rememberAsset(request.url());
    if (
      request.method() !== "POST" ||
      !/\/search\/(?:v2\/)?jobs\/?$/.test(url.pathname)
    )
      return;
    const form = new URLSearchParams(request.postData() || "");
    const search = form.get("search") || "";
    searchRequests.push({
      kind:
        search.includes("index=atlas_te") &&
        search.toLowerCase().includes("thousandeyes")
          ? "thousandeyes"
          : "other",
      search,
      earliest: form.get("earliest_time"),
    });
  });
  page.on("response", (response) => {
    const asset = rememberAsset(response.url());
    if (asset) asset.status = response.status();
    if (response.status() >= 400) {
      const url = new URL(response.url());
      badResponses.push({ status: response.status(), path: url.pathname });
    }
  });

  stage = "login";
  await page.goto(`${BASE}/en-US/account/login`);
  await page.locator('input[name="username"]').fill(user);
  await page.locator('input[name="password"]').fill(pass);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes("/account/login"), {
      timeout: 30000,
    }),
    page.locator('input[type="submit"], button[type="submit"]').first().click(),
  ]);

  stage = "endpoint-selection";
  const endpointURL = `${BASE}/en-US/app/splunk_adm/endpoints?mode=live`;
  const response = await page.goto(endpointURL, {
    waitUntil: "domcontentloaded",
  });
  expect(response?.status()).toBeLessThan(400);
  const localDate = (seconds) => {
    const value = new Date(seconds * 1000);
    return new Date(value.getTime() - value.getTimezoneOffset() * 60000)
      .toISOString()
      .replace(/Z$/, "");
  };
  await page.getByLabel("IP address", { exact: true }).fill("198.51.100.20");
  await page.getByLabel("Verified routing scope", { exact: true }).fill(scope);
  await page.getByLabel("Start time", { exact: true }).fill(localDate(start));
  await page.getByLabel("End time", { exact: true }).fill(localDate(end));
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await page.getByRole("region", { name: "Endpoint results" }).waitFor({
    timeout: 150000,
  });
  const endpointSearches = searchRequests.filter(
    (item) => item.kind === "other",
  );
  expect(endpointSearches.length).toBeGreaterThan(0);
  expect(assetRequests).toHaveLength(0);
  const beforeOpen = searchRequests.filter(
    (item) => item.kind === "thousandeyes",
  ).length;
  expect(beforeOpen).toBe(0);

  stage = "open-investigation";
  await page
    .getByRole("button", { name: "Open ThousandEyes investigation" })
    .click();
  await page
    .getByRole("region", { name: "Optional ThousandEyes evidence inspection" })
    .waitFor({ timeout: 30000 });
  expect(assetRequests).toHaveLength(2);
  expect(assetRequests.map((item) => item.kind).sort()).toEqual([
    "javascript",
    "stylesheet",
  ]);
  expect(assetRequests.every((item) => item.sameOrigin)).toBe(true);
  expect(assetRequests.every((item) => item.status === 200)).toBe(true);
  const versions = [...new Set(assetRequests.map((item) => item.version))];
  expect(versions).toHaveLength(1);
  expect(versions[0]).toMatch(/^[a-f0-9]{24}$/);
  const runtimeVersions = await page.evaluate(() => ({
    host: window.__AtlasThousandEyesHost?.assetVersion,
    optional: window.ApplicationAtlasThousandEyes?.assetVersion,
  }));
  expect(runtimeVersions.host).toBe(versions[0]);
  expect(runtimeVersions.optional).toBe(versions[0]);
  expect(
    searchRequests.filter((item) => item.kind === "thousandeyes"),
  ).toHaveLength(beforeOpen);

  stage = "inspect-source";
  await page
    .getByRole("button", { name: "Inspect ThousandEyes evidence" })
    .click();
  if (mode === "not-selected") {
    await page
      .getByText(/ThousandEyes source not selected/)
      .waitFor({ timeout: 60000 });
    expect(
      searchRequests.filter((item) => item.kind === "thousandeyes"),
    ).toHaveLength(0);
  } else {
    await page
      .getByText("Search complete: 7 returned observations.")
      .waitFor({ timeout: 150000 });
    const teSearches = searchRequests.filter(
      (item) => item.kind === "thousandeyes",
    );
    expect(teSearches).toHaveLength(1);
    for (const sourcetype of [
      "cisco:thousandeyes:metric",
      "cisco:thousandeyes:trace",
      "cisco:thousandeyes:activity",
      "cisco:thousandeyes:event",
      "cisco:thousandeyes:alerts",
      "atlas:thousandeyes:path",
    ])
      expect(teSearches[0].search).toContain(sourcetype);
    await expect(page.getByText("Checkout availability")).toBeVisible();
    const monitorRow = page
      .getByRole("row")
      .filter({ hasText: "Test name not supplied" });
    await expect(monitorRow).toHaveCount(1);
    await monitorRow
      .getByRole("button", { name: "Inspect observation" })
      .click();
    const detail = page.getByRole("region", {
      name: "Selected ThousandEyes observation detail",
    });
    const fields = await detail.locator("dt").evaluateAll((nodes) => {
      const values = {};
      for (const node of nodes) {
        const label = (node.textContent || "").trim();
        values[label] = (node.nextElementSibling?.textContent || "").trim();
      }
      return values;
    });
    expect(fields["Monitor ID"]).toBe("monitor-4");
    expect(fields.Test).toContain("native ID not supplied");
    expect(fields.Agent).toContain("native ID not supplied");
    const attribution = await detail
      .getByRole("region", { name: "ThousandEyes observation attribution" })
      .innerText();
    expect(attribution).toContain("Attribution state: context only");
    expect(attribution).not.toContain("Binding IDs:");
    await mkdir(dirname(resolve(screenshotPath)), { recursive: true });
    await detail.screenshot({ path: resolve(screenshotPath) });
  }

  stage = "browser-health";
  expect(jsErrors).toEqual([]);
  expect(
    badResponses.filter((item) =>
      /\/app\/splunk_adm\/(?:pages\/thousandeyes\.js|thousandeyes\.css)$/.test(
        item.path,
      ),
    ),
  ).toEqual([]);
  process.stdout.write(
    JSON.stringify({
      ok: true,
      mode,
      endpointSelected: true,
      noEagerSidecar: true,
      sidecarAssets: assetRequests.map(({ kind, status, version }) => ({
        kind,
        status,
        version,
      })),
      sourceSearchCount: searchRequests.filter(
        (item) => item.kind === "thousandeyes",
      ).length,
      activeRows: mode === "active" ? 7 : 0,
      bgpContextOnly: mode === "active",
      jsErrors: jsErrors.length,
    }) + "\n",
  );
  await context.close();
} catch {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      mode,
      stage,
      assetCount: assetRequests?.length ?? 0,
      searchCount: searchRequests?.length ?? 0,
      jsErrorCount: jsErrors?.length ?? 0,
    }) + "\n",
  );
  process.exitCode = 1;
} finally {
  await browser.close();
}
