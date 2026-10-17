// Native-browser qualification for both combined Cisco V2 scopes. Credentials
// are read only from the environment and are never included in evidence.
import { createRequire } from "node:module";
import { createInterface } from "node:readline";

const require = createRequire(new URL("../../package.json", import.meta.url));
const { chromium, expect } = require("@playwright/test");

const BASE = "http://127.0.0.1:8000";
const { ADM_VIEWER_USER: user, ADM_VIEWER_PASS: pass } = process.env;
const scenarios = JSON.parse(process.argv[2] || "[]");
if (!user || !pass) throw new Error("viewer credentials missing from env");
if (scenarios.length !== 2)
  throw new Error("expected the two captured Cisco scopes");

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  const demoRequests = { count: 0 };
  const searchPayloads = [];
  const browserDiagnostics = {
    console: [],
    pageErrors: [],
    failedRequests: [],
    responses: [],
  };
  const safeText = (value) =>
    String(value)
      .replace(/https?:\/\/[^\s"'<>]+/gi, "[url]")
      .replace(/(?:bearer\s+)[a-z0-9._~+/-]+=*/gi, "Bearer [redacted]")
      .replace(
        /(?:password|token|session|cookie)(\s*[:=]\s*)[^\s,;]+/gi,
        "$1[redacted]",
      )
      .slice(0, 500);
  const safePath = (rawUrl) => {
    try {
      return new URL(rawUrl).pathname.slice(0, 300);
    } catch {
      return "[invalid-url]";
    }
  };
  const keepRecent = (items, value) => {
    items.push(value);
    if (items.length > 20) items.shift();
  };
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning")
      keepRecent(browserDiagnostics.console, {
        type: message.type(),
        text: safeText(message.text()),
      });
  });
  page.on("pageerror", (error) =>
    keepRecent(browserDiagnostics.pageErrors, safeText(error.message)),
  );
  page.on("requestfailed", (request) =>
    keepRecent(browserDiagnostics.failedRequests, {
      method: request.method(),
      path: safePath(request.url()),
      error: safeText(request.failure()?.errorText || "request failed"),
    }),
  );
  page.on("response", (response) => {
    if (response.status() >= 400)
      keepRecent(browserDiagnostics.responses, {
        status: response.status(),
        path: safePath(response.url()),
      });
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      !/\/search\/(v2\/)?jobs\/?$/.test(url.pathname) ||
      request.method() !== "POST"
    )
      return;
    const payload = new URLSearchParams(request.postData() || "");
    searchPayloads.push({
      search: payload.get("search") || "",
      earliest: payload.get("earliest_time"),
      latest: payload.get("latest_time"),
    });
  });
  await page.route("**/demo/*.json", (route) => {
    demoRequests.count += 1;
    void route.abort();
  });

  await page.goto(`${BASE}/en-US/account/login`);
  await page.locator('input[name="username"]').fill(user);
  await page.locator('input[name="password"]').fill(pass);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes("/account/login"), {
      timeout: 30000,
    }),
    page.locator('input[type="submit"], button[type="submit"]').first().click(),
  ]);
  process.stdout.write(JSON.stringify({ login: "ok" }) + "\n");

  async function waitForLoadedMap(scenario) {
    await page
      .locator("#atlas-root .adm[data-loaded='true']")
      .waitFor({ timeout: 150000 });
    const adm = page.locator("#atlas-root .adm");
    await expect(adm.locator(".scope-service")).toHaveText("checkout", {
      timeout: 150000,
    });
    await expect(adm.locator(".scope-dims")).toContainText(scenario.cluster, {
      timeout: 150000,
    });
    return adm;
  }

  async function openMap(scenario) {
    const path =
      `/en-US/app/splunk_adm/map?mode=live&earliest=${encodeURIComponent(scenario.earliest)}` +
      `&latest=${encodeURIComponent(scenario.latest)}&service=checkout&environment=demo` +
      `&cluster=${encodeURIComponent(scenario.cluster)}&namespace=shop`;
    const response = await page.goto(`${BASE}${path}`, {
      waitUntil: "domcontentloaded",
    });
    expect(response?.status(), `${scenario.label} map route`).toBeLessThan(400);
    const adm = await waitForLoadedMap(scenario);
    return { adm, path };
  }

  async function graphCounts(adm, scenario) {
    const nodeCount = Number(await adm.getAttribute("data-node-count"));
    const edgeCount = Number(await adm.getAttribute("data-edge-count"));
    expect(nodeCount, `${scenario.label} live node count`).toBe(scenario.nodes);
    expect(edgeCount, `${scenario.label} live edge count`).toBe(scenario.edges);
    return { nodeCount, edgeCount };
  }

  async function failureDiagnostics() {
    const dom = await page
      .evaluate(() => {
        const root = document.querySelector("#atlas-root");
        const adm = root?.querySelector(".adm");
        const alerts = [
          ...document.querySelectorAll(
            '[role="alert"], .error, .error-message',
          ),
        ]
          .map((element) => (element.textContent || "").trim().slice(0, 300))
          .filter(Boolean)
          .slice(0, 8);
        return {
          title: document.title.slice(0, 160),
          path: window.location.pathname,
          rootPresent: Boolean(root),
          appRootPresent: Boolean(adm),
          loaded: adm?.getAttribute("data-loaded") || null,
          nodeCount: adm?.getAttribute("data-node-count") || null,
          edgeCount: adm?.getAttribute("data-edge-count") || null,
          alertCount: alerts.length,
          alerts,
        };
      })
      .catch(() => ({ unavailable: true }));
    return {
      dom,
      console: browserDiagnostics.console,
      pageErrors: browserDiagnostics.pageErrors,
      failedRequests: browserDiagnostics.failedRequests,
      httpErrors: browserDiagnostics.responses,
      searches: searchPayloads.slice(-8).map((entry) => ({
        macro:
          entry.search.match(/adm_[a-z0-9_]+\(/i)?.[0]?.slice(0, -1) ||
          "unknown",
      })),
    };
  }

  const rl = createInterface({ input: process.stdin });
  for await (const line of rl) {
    if (line.trim() === "quit") break;
    if (line.trim() !== "run") continue;
    const result = { scenarios: [], demoRequests: 0 };
    try {
      for (const scenario of scenarios) {
        const item = {
          label: scenario.label,
          cluster: scenario.cluster,
          expectedNodes: scenario.nodes,
          expectedEdges: scenario.edges,
        };
        const beforeMap = searchPayloads.length;
        const { adm, path } = await openMap(scenario);
        Object.assign(item, await graphCounts(adm, scenario));
        const graphSearch = searchPayloads
          .slice(beforeMap)
          .find((entry) => entry.search.includes("adm_graph("));
        expect(
          graphSearch,
          `${scenario.label} live public graph search`,
        ).toBeTruthy();
        expect(graphSearch.search).toContain(scenario.cluster);
        expect(graphSearch.earliest).toBe(scenario.earliest);
        expect(graphSearch.latest).toBe(scenario.latest);

        await adm.getByRole("button", { name: "Devices", exact: true }).click();
        const attachment = page.getByRole("region", {
          name: "Client attachment devices",
        });
        await attachment.waitFor({ state: "visible", timeout: 30000 });
        const attachmentText = await attachment.innerText();
        expect(attachmentText).toContain(scenario.attachmentDeviceId);
        expect(attachmentText).toContain(scenario.attachmentDeviceName);
        item.attachmentDevice = true;
        if (scenario.cluster === "cilium-nxos-west") {
          expect(attachmentText).toContain("meraki_association_flow");
          expect(attachmentText).toContain(`SSID ${scenario.ssidNumber}`);
          item.associationBasis = attachmentText.includes(
            "meraki_association_flow",
          );
          item.ssidNumber = attachmentText.includes(
            `SSID ${scenario.ssidNumber}`,
          );
          item.inventedSsidName = /SSID name/i.test(attachmentText);
          expect(item.inventedSsidName).toBe(false);
        }

        await page.goto(`${BASE}${path}`, { waitUntil: "domcontentloaded" });
        const reloaded = await waitForLoadedMap(scenario);
        Object.assign(item, { reload: await graphCounts(reloaded, scenario) });

        const findPath =
          `/en-US/app/splunk_adm/applications?mode=live&earliest=${encodeURIComponent(scenario.earliest)}` +
          `&latest=${encodeURIComponent(scenario.latest)}&service=checkout&environment=demo` +
          `&cluster=${encodeURIComponent(scenario.cluster)}&namespace=shop`;
        const beforeFind = searchPayloads.length;
        const findResponse = await page.goto(`${BASE}${findPath}`, {
          waitUntil: "domcontentloaded",
        });
        expect(
          findResponse?.status(),
          `${scenario.label} Find route`,
        ).toBeLessThan(400);
        const findInput = page.locator("#atlas-find-value");
        await findInput.waitFor({ state: "visible", timeout: 60000 });
        await findInput.fill(scenario.clientIp);
        await page
          .locator("main.atlas-page")
          .getByRole("button", { name: "Find", exact: true })
          .click();
        const evidenceTable = page.locator(
          '[aria-label="Network client evidence"]',
        );
        await evidenceTable.waitFor({ state: "visible", timeout: 150000 });
        const evidenceText = await evidenceTable.innerText();
        expect(evidenceText).toContain(scenario.clientMac);
        expect(evidenceText).toContain(scenario.sourceLabel);
        expect(evidenceText).toContain(scenario.sourceAuthority);
        expect(evidenceText).toContain(scenario.findAttachmentBasis);
        expect(evidenceText).toContain(scenario.attachmentDeviceId);
        expect(evidenceText).toContain(scenario.scope);
        const findSearches = searchPayloads
          .slice(beforeFind)
          .map((entry) => entry.search);
        expect(
          findSearches.some((search) => search.includes("adm_find(")),
        ).toBe(true);
        expect(
          findSearches.some((search) =>
            search.includes("adm_find_network_client("),
          ),
        ).toBe(true);
        item.liveFind = true;
        result.scenarios.push(item);
      }
      result.demoRequests = demoRequests.count;
      process.stdout.write(JSON.stringify(result) + "\n");
    } catch (error) {
      process.stdout.write(
        JSON.stringify({
          error: safeText(error),
          demoRequests: demoRequests.count,
          diagnostics: await failureDiagnostics(),
        }) + "\n",
      );
    }
  }
  rl.close();
  process.stdin.pause();
  await context.close();
} finally {
  await browser.close();
}
