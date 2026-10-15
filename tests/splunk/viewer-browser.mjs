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
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const page = await context.newPage();
  const safePath = (url) =>
    new URL(url).pathname
      .replaceAll(encodeURIComponent(user), "[viewer]")
      .replaceAll(user, "[viewer]");
  const consoleErrors = [];
  const failures = [];
  const searchRequests = [];
  const searchPayloads = [];
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
      /\/search\/(v2\/)?jobs\/?$/.test(new URL(url).pathname) &&
      response.request().method() === "POST"
    ) {
      searchRequests.push({
        status: response.status(),
        path: safePath(url),
      });
      const body = response.request().postData() || "";
      const params = new URLSearchParams(body);
      searchPayloads.push({
        earliest: params.get("earliest_time"),
        latest: params.get("latest_time"),
        scopeOptions: body.includes("adm_scope_options"),
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

  async function chooseScope(label, value) {
    const control = page.getByRole("combobox", { name: label }).first();
    await control.waitFor({ state: "visible", timeout: 60000 });
    const tag = await control.evaluate((element) => element.tagName);
    if (tag === "SELECT") {
      await control
        .selectOption({ label: value })
        .catch(() => control.selectOption(value));
      return;
    }
    await control.click();
    await control.fill("");
    const option = page.getByRole("option", { name: value, exact: true }).last();
    if (await option.count()) {
      await option.click();
      return;
    }
    await control.fill(value);
    await control.press("Enter");
  }

  async function waitForSearch(after, timeout = 60000) {
    const deadline = Date.now() + timeout;
    while (searchPayloads.length <= after && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    return searchPayloads.at(-1);
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
      evidence.scopeFieldStyle = await page.getByRole("combobox", { name: "Environment", exact: true }).evaluate((element) => {
        const style = getComputedStyle(element);
        return { background: style.backgroundColor, color: style.color, border: style.borderTopWidth, shadow: style.boxShadow };
      });
      evidence.scopeService = await adm.locator(".scope-service").innerText();
      evidence.scopeDims = await adm.locator(".scope-dims").innerText();
      evidence.notLoaded = text.includes("Splunk · not loaded");
      evidence.incompleteWindow = text.includes("Incomplete window");
      evidence.cards = await adm.locator("[data-hit]").count();
      evidence.expectedNodes = Number(expectedNodes);
      evidence.nodeCount = Number(await adm.getAttribute("data-node-count"));
      evidence.edgeCount = Number(await adm.getAttribute("data-edge-count"));
      evidence.cardsPresent = evidence.cards > 0;
      await root.screenshot({ path: `dist/atlas-live-${theme}.png` });
      evidence.nodesOk = evidence.nodeCount === Number(expectedNodes);
      evidence.demoRequests = demoRequests;

      stage = "scope controls";
      const beforeBuild = searchPayloads.length;
      const previousWindow = (await adm.locator(".scope-time").textContent()) ?? "";
      await chooseScope("Environment", "demo");
      await chooseScope("Cluster", "demo-cluster");
      await chooseScope("Namespace", "shop");
      await chooseScope("Service", "frontend");
      const timeRange = page.getByLabel("Time range").first();
      await timeRange.waitFor({ state: "visible", timeout: 60000 });
      evidence.timezonePicker = {
        name:
          (await timeRange.getAttribute("data-zone-name")) ??
          (await timeRange.getAttribute("data-atlas-timezone-name")),
        offset: Number(
          (await timeRange.getAttribute("data-atlas-timezone-offset")) ??
            "NaN",
        ),
      };
      const timeTag = await timeRange.evaluate((element) => element.tagName);
      if (timeTag === "SELECT") {
        await timeRange.selectOption("-1h");
      } else {
        await timeRange.getByRole("button").click();
        await page.locator('[data-test="time-range-dialog"]').screenshot({ path: `dist/atlas-picker-${theme}.png` });
        await page.getByRole("button", { name: "Presets", exact: true }).click();
        await page.getByText(/Last (60 minutes|hour)/i).last().click();
      }
      await page.getByRole("button", { name: "Build map", exact: true }).click();
      const buildSearch = await waitForSearch(beforeBuild);
      await page.waitForFunction((previous) => {
        const current = document.querySelector(".scope-time")?.textContent?.trim();
        return current && current !== previous.trim();
      }, previousWindow, { timeout: 150000 });
      await page.getByText(/Incomplete window/i).waitFor({ state: "visible", timeout: 60000 });
      evidence.scopeControls = {
        buildEarliest: buildSearch?.earliest,
        buildLatest: buildSearch?.latest,
        incompleteWindow: true,
        optionSearch: searchPayloads.some((request) => request.scopeOptions),
      };

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
      stage = "live evidence search";
      const liveFinding = page
        .getByRole("article")
        .filter({ hasText: "Unknown endpoint identity" })
        .first();
      await liveFinding.waitFor({ state: "visible", timeout: 60000 });
      await liveFinding
        .getByRole("button", { name: "Show path", exact: true })
        .click();
      const liveSearch = page.getByRole("link", {
        name: "Open in Search",
        exact: true,
      });
      const liveHref = await liveSearch.getAttribute("href");
      const popupPromise = page.waitForEvent("popup", { timeout: 30000 });
      const [searchPopup] = await Promise.all([popupPromise, liveSearch.click()]);
      let searchSid;
      let macroRequest = false;
      searchPopup.on("response", async (response) => {
        if (
          response.request().method() !== "POST" ||
          !/\/search\/(?:v2\/)?jobs\/?$/.test(new URL(response.url()).pathname)
        )
          return;
        const body = response.request().postData() || "";
        if (!body.includes("adm_flow_evidence")) return;
        macroRequest = true;
        try {
          const payload = await response.json();
          const sid = payload.sid ?? payload.entry?.[0]?.content?.sid;
          if (typeof sid === "string" && sid.length > 0) searchSid = sid;
        } catch {
          // The UI may return an HTML error; evidence remains false.
        }
      });
      await searchPopup.waitForLoadState("domcontentloaded").catch(() => {});
      const searchDeadline = Date.now() + 120000;
      let completed = false;
      let nonEmpty = false;
      while (Date.now() < searchDeadline && (!searchSid || !completed)) {
        if (searchSid) {
          const state = await searchPopup.request
            .get(
              `${BASE}/en-US/splunkd/__raw/servicesNS/${encodeURIComponent(user)}/splunk_adm/search/jobs/${encodeURIComponent(searchSid)}?output_mode=json`,
            )
            .catch(() => null);
          if (state?.ok()) {
            const payload = await state.json().catch(() => ({}));
            const content = payload.entry?.[0]?.content ?? {};
            const failed = content.dispatchState === "FAILED" || content.isFailed === true || content.isFailed === 1 || content.isFailed === "1";
            if (failed) break;
            completed = content.dispatchState === "DONE" || content.isDone === true || content.isDone === 1 || content.isDone === "1";
            if (completed) {
              const results = await searchPopup.request
                .get(
                  `${BASE}/en-US/splunkd/__raw/servicesNS/${encodeURIComponent(user)}/splunk_adm/search/jobs/${encodeURIComponent(searchSid)}/results?count=1&output_mode=json`,
                )
                .catch(() => null);
              if (results?.ok()) {
                const resultPayload = await results.json().catch(() => ({}));
                nonEmpty = Array.isArray(resultPayload.results) && resultPayload.results.length > 0;
              }
            }
          }
        }
        if (!searchSid || !completed) await new Promise((resolve) => setTimeout(resolve, 500));
      }
      await searchPopup.close().catch(() => {});
      evidence.liveEvidence = {
        selected: (await page.locator("[data-hit].selected").count()) > 0,
        target: await liveSearch.getAttribute("target"),
        rel: await liveSearch.getAttribute("rel"),
        safeHref:
          !!liveHref &&
          liveHref.includes("adm_flow_evidence") &&
          liveHref.includes(earliest) &&
          liveHref.includes(latest),
        searchPopup: {
          opened: true,
          dispatched: Boolean(searchSid),
          macroRequest,
          completed,
          nonEmpty,
        },
      };
      stage = "live applications catalog";
      const catalogEarliest = String(Number(latest) - 3600);
      await page.goto(
        `${BASE}/en-US/app/splunk_adm/applications?mode=live&earliest=${catalogEarliest}&latest=${encodeURIComponent(latest)}`,
        { waitUntil: "domcontentloaded" },
      );
      await page
        .getByRole("heading", { name: "Applications", exact: true })
        .waitFor({ state: "visible", timeout: 60000 });
      const catalogRow = page.getByRole("button", {
        name: "Open map for frontend",
        exact: true,
      });
      await catalogRow.waitFor({ state: "visible", timeout: 60000 });
      await catalogRow.click();
      await page.waitForURL(
        (url) => /\/app\/splunk_adm\/map\/?$/.test(url.pathname),
        { timeout: 60000 },
      );
      const catalogMapUrl = new URL(page.url());
      await page
        .locator('.adm[data-loaded="true"]')
        .waitFor({ timeout: 150000 });
      evidence.catalog = {
        loaded: true,
        mapPath: catalogMapUrl.pathname,
        service: catalogMapUrl.searchParams.get("service"),
        earliest: catalogMapUrl.searchParams.get("earliest"),
        latest: catalogMapUrl.searchParams.get("latest"),
      };
      await page.goto(
        `${BASE}/en-US/app/splunk_adm/applications?mode=live&earliest=${catalogEarliest}&latest=${encodeURIComponent(latest)}`,
        { waitUntil: "domcontentloaded" },
      );
      await page
        .getByRole("heading", { name: "Applications", exact: true })
        .waitFor({ state: "visible", timeout: 60000 });
      stage = "live application Find";
      const findControls = page.locator("#atlas-root .atlas-find");
      const findInput = findControls.getByLabel(/Find an address, EPG, or device/);
      await findInput.fill("10.42.0.20");
      stage = "live Find submit";
      await findControls.getByRole("button", { name: "Find", exact: true }).click();
      stage = "live Find result";
      const findRow = page.locator('#atlas-root [aria-label="Find results"]').first().getByRole("button", {
        name: "Open map for checkout",
        exact: true,
      });
      await findRow.waitFor({ state: "visible", timeout: 60000 });
      stage = "live Find map";
      await findRow.click();
      await page.waitForURL(
        (url) => /\/app\/splunk_adm\/map\/?$/.test(url.pathname),
        { timeout: 60000 },
      );
      const findMapUrl = new URL(page.url());
      await page
        .locator('.adm[data-loaded="true"]')
        .waitFor({ timeout: 150000 });
      evidence.find = {
        loaded: true,
        mapPath: findMapUrl.pathname,
        service: findMapUrl.searchParams.get("service"),
        earliest: findMapUrl.searchParams.get("earliest"),
        latest: findMapUrl.searchParams.get("latest"),
      };
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
      const demoFinding = page
        .getByRole("article")
        .filter({ hasText: "Blocked conversation" })
        .first();
      await demoFinding.waitFor({ state: "visible", timeout: 60000 });
      const demoCopy = demoFinding.getByRole("button", {
        name: "Copy request",
        exact: true,
      });
      await demoCopy.click();
      const copied = await demoFinding
        .getByRole("status")
        .innerText()
        .catch(() => "");
      const clipboard = await page.evaluate(() => navigator.clipboard.readText());
      evidence.demoFindings = {
        copied: /request copied/i.test(copied),
        csv: /,|\n/.test(clipboard),
        openDisabled: await demoFinding
          .getByRole("button", { name: "Open in Search", exact: true })
          .isDisabled(),
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
      const message = error instanceof Error ? error.message : "";
      evidence.errorKind = message.includes("strict mode violation") ? "ambiguous locator" : message.includes("Timeout") ? "timeout" : "browser check";
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
