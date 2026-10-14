// Browser qualification for the search-only viewer. Credentials are supplied
// through the environment and are never written to stdout or evidence.
import { createRequire } from "node:module";
import { createInterface } from "node:readline";

const require = createRequire(new URL("../../package.json", import.meta.url));
const { chromium } = require("@playwright/test");

const BASE = "http://127.0.0.1:8000";
const { ADM_VIEWER_USER: user, ADM_VIEWER_PASS: pass } = process.env;
const [earliest, latest, expectedNodes, timezone] = process.argv.slice(2);
if (!user || !pass) throw new Error("viewer credentials missing from env");

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({
    acceptDownloads: true,
    viewport: { width: 1400, height: 1000 },
  });
  const page = await context.newPage();
  const safePath = (url) =>
    new URL(url).pathname
      .replaceAll(encodeURIComponent(user), "[viewer]")
      .replaceAll(user, "[viewer]");
  const consoleErrors = [];
  const failures = [];
  const searchRequests = [];
  const atlasScripts = [];
  page.on("console", (message) => {
    if (message.type() === "error")
      consoleErrors.push(message.text().slice(0, 300));
  });
  page.on("pageerror", (error) =>
    consoleErrors.push(`pageerror: ${String(error).slice(0, 300)}`),
  );
  page.on("response", (response) => {
    const url = response.url();
    if (response.status() >= 400)
      failures.push({ status: response.status(), path: safePath(url) });
    if (
      /\/search\/(v2\/)?jobs/.test(url) &&
      response.request().method() === "POST"
    ) {
      searchRequests.push({
        status: response.status(),
        path: safePath(url),
      });
    }
    if (
      response.request().resourceType() === "script" &&
      url.includes("splunk_adm")
    ) {
      atlasScripts.push({
        status: response.status(),
        path: safePath(url),
      });
    }
  });

  await page.goto(`${BASE}/en-US/account/login`);
  await page.locator('input[name="username"]').fill(user);
  await page.locator('input[name="password"]').fill(pass);
  if ((await page.locator('input[name="username"]').inputValue()) !== user) {
    throw new Error("username field did not retain its value");
  }
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes("/account/login"), {
      timeout: 30000,
    }),
    page.locator('input[type="submit"], button[type="submit"]').first().click(),
  ]);
  process.stdout.write(
    JSON.stringify({ login: "ok", url: new URL(page.url()).pathname }) + "\n",
  );

  async function routeEvidence(path, heading) {
    const response = await page.goto(`${BASE}${path}`, {
      waitUntil: "domcontentloaded",
    });
    const body = (await page.locator("body").innerText()).slice(0, 1000);
    let headingPresent = null;
    if (heading) {
      try {
        await page
          .getByRole("heading", { name: heading, exact: true })
          .waitFor({ state: "visible", timeout: 60000 });
        headingPresent = true;
      } catch {
        headingPresent = false;
      }
    }
    return {
      path,
      status: response?.status() ?? null,
      finalPath: new URL(page.url()).pathname,
      loginRedirect: new URL(page.url()).pathname.includes("/account/login"),
      notFound: /(?:page|view|app)\s+not found|could not be found/i.test(body),
      headingPresent,
    };
  }

  const rl = createInterface({ input: process.stdin });
  for await (const line of rl) {
    const [command, theme] = line.trim().split(/\s+/);
    if (command === "quit") break;
    if (command !== "theme") continue;
    const evidence = { theme };
    let stage = "live map";
    try {
      consoleErrors.length = 0;
      failures.length = 0;
      searchRequests.length = 0;
      atlasScripts.length = 0;
      let demoRequests = 0;
      await page.route("**/demo/*.json", (route) => {
        demoRequests += 1;
        void route.abort();
      });
      const map = await routeEvidence(
        `/en-US/app/splunk_adm/map?mode=live&earliest=${encodeURIComponent(earliest)}&latest=${encodeURIComponent(latest)}&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop`,
      );
      evidence.mapRoute = map;
      const root = page.locator("#atlas-root");
      await root.waitFor({ timeout: 60000 });
      const adm = root.locator(".adm");
      await adm.waitFor({ timeout: 60000 });
      await root
        .locator('.adm[data-loaded="true"]')
        .waitFor({ timeout: 150000 });
      await adm
        .locator(".scope-service")
        .filter({ hasText: "frontend" })
        .waitFor({ timeout: 150000 });
      const text = await adm.innerText();
      evidence.mounted = await root.getAttribute("data-mounted");
      evidence.theme = await page
        .locator(".atlas")
        .getAttribute("data-atlas-theme");
      evidence.themeOk = evidence.theme === theme;
      evidence.timezone = await adm.getAttribute("data-timezone");
      evidence.timezoneOk = evidence.timezone === timezone;
      evidence.scopeService = await adm.locator(".scope-service").innerText();
      evidence.scopeDims = await adm.locator(".scope-dims").innerText();
      evidence.notLoaded = text.includes("Splunk · not loaded");
      evidence.cards = await adm.locator("[data-hit]").count();
      evidence.expectedNodes = Number(expectedNodes);
      evidence.nodeCount = Number(await adm.getAttribute("data-node-count"));
      evidence.edgeCount = Number(await adm.getAttribute("data-edge-count"));
      evidence.cardsPresent = evidence.cards > 0;
      await root.screenshot({ path: `dist/atlas-live-${theme}.png` });
      evidence.nodesOk = evidence.nodeCount === Number(expectedNodes);
      evidence.demoRequests = demoRequests;

      stage = "live map reload";
      const liveReload = `${BASE}/en-US/app/splunk_adm/map?mode=live&tab=services&earliest=${encodeURIComponent(earliest)}&latest=${encodeURIComponent(latest)}&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop`;
      await page.goto(liveReload, { waitUntil: "domcontentloaded" });
      const reloaded = page.locator(".adm");
      await page
        .locator('.adm[data-loaded="true"]')
        .waitFor({ timeout: 150000 });
      evidence.reload = {
        scopeService: await reloaded.locator(".scope-service").innerText(),
        nodeCount: Number(await reloaded.getAttribute("data-node-count")),
        edgeCount: Number(await reloaded.getAttribute("data-edge-count")),
        cards: await reloaded.locator("[data-hit]").count(),
      };
      stage = "legacy dependency_map redirect";
      const legacy = `${BASE}/en-US/app/splunk_adm/dependency_map?mode=live&earliest=${encodeURIComponent(earliest)}&latest=${encodeURIComponent(latest)}&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop`;
      await page.goto(legacy, { waitUntil: "domcontentloaded" });
      await page.waitForURL(
        (url) => /\/app\/splunk_adm\/map\/?$/.test(url.pathname),
        { timeout: 60000 },
      );
      const legacyMap = page.locator(".adm");
      await page
        .locator('.adm[data-loaded="true"]')
        .waitFor({ timeout: 150000 });
      const legacyUrl = new URL(page.url());
      evidence.legacy = {
        path: legacyUrl.pathname,
        earliest: legacyUrl.searchParams.get("earliest"),
        latest: legacyUrl.searchParams.get("latest"),
        scopeService: await legacyMap.locator(".scope-service").innerText(),
        nodeCount: Number(await legacyMap.getAttribute("data-node-count")),
        edgeCount: Number(await legacyMap.getAttribute("data-edge-count")),
      };
      evidence.legacyRedirectOk =
        evidence.legacy.path.endsWith("/map") &&
        evidence.legacy.earliest === earliest &&
        evidence.legacy.latest === latest &&
        evidence.legacy.scopeService === "frontend" &&
        evidence.legacy.nodeCount === evidence.reload.nodeCount &&
        evidence.legacy.edgeCount === evidence.reload.edgeCount;
      await page.unroute("**/demo/*.json");

      stage = "demo map";
      await page.goto(
        `${BASE}/en-US/app/splunk_adm/map?mode=demo&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop`,
        { waitUntil: "domcontentloaded" },
      );
      const demo = page.locator(".adm");
      await demo
        .getByText("Synthetic demo", { exact: true })
        .waitFor({ timeout: 60000 });
      evidence.demo = {
        synthetic: true,
        cards: await demo.locator("[data-hit]").count(),
      };

      stage = "supporting views";
      evidence.routes = {};
      for (const name of ["applications", "data_health", "help"]) {
        stage = `view ${name}`;
        evidence.routes[name] = await routeEvidence(
          `/en-US/app/splunk_adm/${name}`,
          name === "data_health"
            ? "Data health"
            : name[0].toUpperCase() + name.slice(1),
        );
      }
      stage = "setup view";
      evidence.setup = {
        app: await routeEvidence("/en-US/app/splunk_adm/setup"),
        manager: await routeEvidence("/en-US/manager/splunk_adm/setup"),
      };
      const setupRest = await page.request.get(
        `${BASE}/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/data/ui/views/setup?output_mode=json`,
      );
      evidence.setupRestStatus = setupRest.status();
      evidence.searchRequests = [...searchRequests];
      evidence.atlasScripts = [...atlasScripts];
      evidence.consoleErrorCount = consoleErrors.length;
      evidence.failedResponses = [...failures];
      evidence.requireMismatch = consoleErrors.some((error) =>
        /Mismatched anonymous define/.test(error),
      );
    } catch (error) {
      evidence.error = `browser qualification failed at ${stage}`;
      evidence.consoleErrorCount = consoleErrors.length;
    }
    process.stdout.write(JSON.stringify(evidence) + "\n");
  }
  rl.close();
} catch {
  process.stdout.write(
    JSON.stringify({
      error: "browser qualification failed",
      stage: "initialization",
    }) + "\n",
  );
  process.exitCode = 1;
} finally {
  await browser.close();
}
