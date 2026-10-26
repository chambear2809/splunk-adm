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

const safePath = (rawUrl) => {
  try {
    const url = new URL(rawUrl, BASE);
    return url.pathname
      .replaceAll(encodeURIComponent(user), "[viewer]")
      .replaceAll(user, "[viewer]")
      .replaceAll(encodeURIComponent(pass), "[redacted]")
      .replaceAll(pass, "[redacted]")
      .replace(/\/search\/(?:v2\/)?jobs\/[^/]+/g, "/search/jobs/[job]")
      .slice(0, 300);
  } catch {
    return "[unknown-path]";
  }
};
const safeMessage = (rawMessage) =>
  String(rawMessage ?? "")
    .replaceAll(encodeURIComponent(user), "[viewer]")
    .replaceAll(user, "[viewer]")
    .replaceAll(encodeURIComponent(pass), "[redacted]")
    .replaceAll(pass, "[redacted]")
    .replace(/\bBasic\s+[A-Za-z0-9+/=]+/gi, "Basic [redacted]")
    .replace(/\bBearer\s+\S+/gi, "Bearer [redacted]")
    .replace(
      /(?:password|token|session|cookie|sid)(\s*[:=]\s*)[^\s,;]+/gi,
      "$1[redacted]",
    )
    .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => safePath(url))
    .slice(0, 300);
const safeSource = (stack) => {
  const frame = String(stack || "")
    .split("\n")
    .find((line) => line.includes(".js"));
  const match = frame?.match(
    /(?:https?:\/\/|\/)[^\s()]+?\.m?js(?:\?[^\s()]*)?/,
  );
  return match ? safePath(match[0]) : "[unknown-source]";
};

const EXPECTED_METADATA_DENIALS = new Map([
  [
    "/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/static/appIcon.png",
    "app_icon",
  ],
  [
    "/en-US/splunkd/__raw/services/configs/conf-web/settings",
    "global_web_settings",
  ],
  [
    "/en-US/splunkd/__raw/services/configs/conf-limits/structured_data_service",
    "structured_data_service_limits",
  ],
  ...[
    "adm_data_contract_version",
    "adm_health_sources",
    "adm_find(1)",
    "adm_graph(4)",
    "adm_catalog_build",
    "adm_health_quality",
    "adm_flow_evidence(4)",
    "adm_topology",
  ].map((name) => [
    `/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/configs/conf-macros/${name}`,
    `legacy_macro_${name.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "")}`,
  ]),
]);
const isExpectedMetadataDenial = (item) =>
  item.method === "GET" &&
  item.status === 403 &&
  EXPECTED_METADATA_DENIALS.has(item.path);
const EXPECTED_NAVIGATION_ABORTS = new Map([
  [
    "/en-US/splunkd/__raw/servicesNS/[viewer]/system/storage/collections/data/RecentlyViewedKO",
    "recently_viewed_cleanup",
  ],
]);
const isExpectedNavigationAbort = (item) =>
  item.method === "DELETE" &&
  item.errorText === "net::ERR_ABORTED" &&
  EXPECTED_NAVIGATION_ABORTS.has(item.path);
const metadataDenialCounts = (responses, consoleList) =>
  [...EXPECTED_METADATA_DENIALS].map(([path, name]) => ({
    name,
    path,
    method: "GET",
    status: 403,
    count: responses.filter(
      (item) => isExpectedMetadataDenial(item) && item.path === path,
    ).length,
    consoleErrors: consoleList.filter((item) => item.source === path).length,
  }));

const searchRequests = [];
const assetRequests = [];
const consoleErrors = [];
const pageErrors = [];
const badResponses = [];
const failedRequests = [];
let consoleErrorCount = 0;
let httpErrorCount = 0;
let failedRequestCount = 0;
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
    if (message.type() === "error") {
      consoleErrorCount++;
      if (consoleErrors.length < 64)
        consoleErrors.push({
          kind: "console",
          message: safeMessage(message.text()),
          source: safePath(message.location().url || ""),
        });
    }
  });
  page.on(
    "pageerror",
    (error) =>
      pageErrors.length < 8 &&
      pageErrors.push({
        name: safeMessage(error.name || "Error"),
        message: safeMessage(error.message),
        source: safeSource(error.stack),
      }),
  );
  page.on("requestfailed", (request) => {
    failedRequestCount++;
    const failure = request.failure();
    if (failedRequests.length < 64)
      failedRequests.push({
        method: request.method(),
        path: safePath(request.url()),
        errorText: safeMessage(failure?.errorText || "request failed"),
      });
  });
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
      httpErrorCount++;
      if (badResponses.length < 64)
        badResponses.push({
          status: response.status(),
          method: response.request().method(),
          path: safePath(response.url()),
        });
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

  stage = "endpoint-route";
  const endpointURL = `${BASE}/en-US/app/splunk_adm/endpoints?mode=live`;
  const response = await page.goto(endpointURL, {
    waitUntil: "domcontentloaded",
  });
  expect(response?.status()).toBeLessThan(400);
  const localDate = (seconds) => {
    const value = new Date(seconds * 1000);
    return new Date(value.getTime() - value.getTimezoneOffset() * 60000)
      .toISOString()
      .replace(/Z$/, "")
      .replace(/\.000$/, "")
      .replace(/:00$/, "");
  };
  stage = "endpoint-ip";
  await page.getByLabel("IP address", { exact: true }).fill("198.51.100.20");
  stage = "endpoint-scope";
  await page.getByLabel("Verified routing scope", { exact: true }).fill(scope);
  stage = "endpoint-start-time";
  await page.getByLabel("Start time", { exact: true }).fill(localDate(start));
  stage = "endpoint-end-time";
  await page.getByLabel("End time", { exact: true }).fill(localDate(end));
  stage = "endpoint-submit";
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  stage = "endpoint-results";
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
    await page.getByLabel("Group by", { exact: true }).selectOption("family");
    const metricGroup = page.getByRole("region", {
      name: "Family: Metric",
      exact: true,
    });
    const monitorRow = metricGroup
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
  const expectedConsoleErrors = [];
  const availableDenials = new Map();
  for (const item of badResponses.filter(isExpectedMetadataDenial))
    availableDenials.set(item.path, (availableDenials.get(item.path) || 0) + 1);
  const unexpectedConsoleErrors = [];
  for (const item of consoleErrors) {
    const remaining = availableDenials.get(item.source) || 0;
    const isExpected =
      item.message ===
        "Failed to load resource: the server responded with a status of 403 (Forbidden)" &&
      EXPECTED_METADATA_DENIALS.has(item.source) &&
      remaining > 0;
    if (isExpected) {
      expectedConsoleErrors.push(item);
      availableDenials.set(item.source, remaining - 1);
    } else {
      unexpectedConsoleErrors.push(item);
    }
  }
  const unexpectedHttpErrors = badResponses.filter(
    (item) => !isExpectedMetadataDenial(item),
  );
  const expectedNavigationAborts = failedRequests.filter(
    isExpectedNavigationAbort,
  );
  const unexpectedFailedRequests = failedRequests.filter(
    (item) => !isExpectedNavigationAbort(item),
  );
  expect(pageErrors).toEqual([]);
  expect(consoleErrorCount).toBe(consoleErrors.length);
  expect(httpErrorCount).toBe(badResponses.length);
  expect(failedRequestCount).toBe(failedRequests.length);
  expect(unexpectedFailedRequests).toEqual([]);
  expect(unexpectedConsoleErrors).toEqual([]);
  expect(unexpectedHttpErrors).toEqual([]);
  const metadataReadDenials = metadataDenialCounts(
    badResponses,
    expectedConsoleErrors,
  );
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
      pageErrors: pageErrors.length,
      metadataReadDenials,
      consoleErrorCount,
      unexpectedConsoleErrors: unexpectedConsoleErrors.length,
      httpErrorCount,
      unexpectedHttpErrors: unexpectedHttpErrors.length,
      failedRequestCount,
      unexpectedFailedRequestCount: unexpectedFailedRequests.length,
      navigationAbortCount: expectedNavigationAborts.length,
      navigationAborts: expectedNavigationAborts,
    }) + "\n",
  );
  await context.close();
} catch (error) {
  const caught = error && typeof error === "object" ? error : {};
  process.stdout.write(
    JSON.stringify({
      ok: false,
      mode,
      stage,
      caughtError: {
        name: safeMessage(caught.name || "Error"),
        message: safeMessage(caught.message || error),
        source: safeSource(caught.stack),
      },
      assetCount: assetRequests?.length ?? 0,
      searchCount: searchRequests?.length ?? 0,
      pageErrors: pageErrors?.slice(0, 8) ?? [],
      consoleErrorCount,
      consoleErrors: consoleErrors?.slice(0, 24) ?? [],
      httpErrorCount,
      httpErrors: badResponses?.slice(0, 32) ?? [],
      failedRequestCount,
      failedRequests: failedRequests?.slice(0, 32) ?? [],
      metadataReadDenials: metadataDenialCounts(badResponses, consoleErrors),
    }) + "\n",
  );
  process.exitCode = 1;
} finally {
  await browser.close();
}
