import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

test.describe("Application Atlas browser regressions", () => {
  test("filters the map and opens endpoint inspection", async ({ page }) => {
    await page.goto("/tests/browser/browser.html");
    await expect(
      page.getByText("Synthetic demo", { exact: true }),
    ).toBeVisible();

    const search = page.getByLabel(
      "Highlight by name, IP, EPG, port or device",
    );
    await search.fill("checkout");
    await expect(page.locator(".match-count")).toContainText("card");
    await search.press("Enter");
    await expect(page.locator("[data-hit].match").first()).toBeVisible();
    await page.locator("[data-hit].match").first().click();
    await expect(
      page.getByRole("complementary", { name: "Details" }),
    ).toContainText("checkout");
    await page.getByRole("button", { name: "Clear selection" }).click();
    await expect(
      page.getByRole("button", { name: "Clear selection" }),
    ).toHaveCount(0);
    await search.fill("");
    await expect(page.getByRole("status")).toHaveCount(0);
  });

  test("submits all live scope filters and the selected time window", async ({
    page,
  }) => {
    await page.goto("/tests/browser/browser.html");
    await page.getByRole("button", { name: "Map settings" }).click();
    await page.getByRole("button", { name: "Splunk" }).click();
    for (const [label, value] of [
      ["Environment", "demo"],
      ["Cluster", "demo-cluster"],
      ["Namespace", "shop"],
      ["Service", "frontend"],
    ]) {
      const control = page.getByRole("combobox", { name: label, exact: true });
      await expect(control).toBeEnabled();
      await control.fill("");
      await control.click();
      await page.getByRole("option", { name: value, exact: true }).click();
    }
    await page
      .getByLabel("Time range", { exact: true })
      .getByRole("button")
      .click();
    await page.getByRole("button", { name: "Presets", exact: true }).click();
    await page.getByText("Last 24 hours", { exact: true }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(
      page.getByText("Synthetic demo", { exact: true }),
    ).toBeHidden();
    await expect
      .poll(() => page.evaluate(() => window.__ADM_LAST_EARLIEST__))
      .toBe("-24h@h");
    await expect
      .poll(() => page.evaluate(() => window.__ADM_LAST_GRAPH_SEARCH__))
      .toBe('`adm_graph("frontend","demo","demo-cluster","shop")`');
    await expect(page.locator(".scope-service")).toHaveText("frontend");
    await expect(page.locator(".scope-dims")).toHaveText(
      "demo · demo-cluster · shop",
    );
  });

  test("shows permission errors from the live search", async ({ page }) => {
    await page.goto("/tests/browser/browser.html?scenario=permission");
    await page.getByRole("button", { name: "Map settings" }).click();
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByRole("alert")).toContainText("search failed");
    await expect(page.getByRole("alert")).toContainText("permission denied");
  });

  test("surfaces an incomplete result warning", async ({ page }) => {
    await page.goto("/tests/browser/browser.html?scenario=incomplete");
    await page.getByRole("button", { name: "Map settings" }).click();
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    const warnings = page.getByRole("button", { name: /warning/ });
    await expect(warnings).toBeVisible();
    await warnings.click();
    await expect(
      page.getByRole("region", { name: "Search warnings" }),
    ).toContainText("incomplete");
  });
});

test("reload reproduces a validated live deep link", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1770000000&latest=1770003600&tab=services&q=checkout",
  );
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByLabel("Highlight by name, IP, EPG, port or device"),
  ).toHaveValue("checkout");
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__ADM_REQUESTS__?.find((r) => r.spl.includes("adm_graph")),
      ),
    )
    .toMatchObject({ earliest: "1770000000", latest: "1770003600" });
  const count = await page.locator(".adm").getAttribute("data-node-count");
  await page.reload();
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  await expect(page.locator(".adm")).toHaveAttribute("data-node-count", count!);
});

test("loads each foundation page", async ({ page }) => {
  for (const [route, title] of [
    ["applications", "Applications"],
    ["data_health", "Data health"],
    ["help", "Help"],
    ["setup", "Setup"],
  ]) {
    await page.goto(`/tests/browser/browser.html?page=${route}`);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
  }
});

test("setup checklist reads live configuration and gates safe actions", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  await expect(
    page.getByRole("heading", { name: "Setup", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Index macros", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Summary reader and writer match.", { exact: true }),
  ).toBeVisible();
  const input = page.getByLabel("Index for adm_index_netflow", { exact: true });
  await input.fill("adm_index_netflow_test");
  await page
    .getByRole("button", { name: "Save adm_index_netflow", exact: true })
    .click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
            .__ADM_SETUP_REQUESTS__ ?? [],
      ),
    )
    .toContain("macro:adm_index_netflow:adm_index_netflow_test");
  const enable = page.getByRole("button", {
    name: "Enable schedule for ADM - Identity builder",
    exact: true,
  });
  await expect(enable).toBeEnabled();
  await enable.click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
            .__ADM_SETUP_REQUESTS__ ?? [],
      ),
    )
    .toContain("builder:ADM - Identity builder");
  expect(
    await page.evaluate(
      () =>
        (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
          .__ADM_SETUP_REQUESTS__,
    ),
  ).toEqual(
    expect.arrayContaining([
      "macro:adm_index_netflow:adm_index_netflow_test",
      "builder:ADM - Identity builder",
    ]),
  );
});

test("setup checklist blocks unknown and uppercase prerequisites", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-unknown",
  );
  await expect(page.getByRole("alert")).toContainText("Administrator access");
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-uppercase",
  );
  await expect(page.getByText(/contain uppercase observer/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
});

test("demo setup never reads or mutates configuration", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=demo");
  await expect(page.getByRole("status")).toContainText("unavailable in Demo");
  expect(
    await page.evaluate(
      () =>
        (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
          .__ADM_SETUP_REQUESTS__,
    ),
  ).toBeUndefined();
});

test("setup verification failure clears the checklist and blank scopes stay gated", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-partial",
  );
  await expect(
    page.getByLabel("Index for adm_index_netflow", { exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Index for adm_index_netflow", { exact: true })
    .fill("adm_index_netflow_test");
  await page
    .getByRole("button", { name: "Save adm_index_netflow", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("verification failed");
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-blank",
  );
  await expect(
    page.getByText("No observer mappings are configured.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
});

test("rejects injected state before dispatching a search", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=bad%22%29%7Cdelete",
  );
  await expect(page.locator("#adm-root")).toContainText("Service may contain");
  expect(await page.evaluate(() => window.__ADM_REQUESTS__)).toBeUndefined();
});

test("built bundle isolates dependencies from the dashboard AMD globals", async ({
  page,
}) => {
  const { readFile, access } = await import("node:fs/promises");
  const bundlePath = "splunk_app/splunk_adm/appserver/static/pages/atlas.js";
  try {
    await access(bundlePath);
  } catch {
    test.skip(true, "Run npm run build before bundle qualification");
    return;
  }
  const bundle = await readFile(bundlePath, "utf8");
  await page.goto("about:blank");
  await page.evaluate(() => {
    const state = window as unknown as {
      define: ((...args: unknown[]) => never) & { amd?: object };
      _: object;
      __atlasSentinel: object;
    };
    state.define = Object.assign(
      () => {
        throw new Error("Anonymous AMD definition escaped the Atlas IIFE");
      },
      { amd: {} },
    );
    state._ = state.__atlasSentinel = {};
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addScriptTag({ content: bundle });
  expect(errors).toEqual([]);
  expect(
    await page.evaluate(() => {
      const state = window as unknown as { _: object; __atlasSentinel: object };
      return state._ === state.__atlasSentinel;
    }),
  ).toBe(true);
});

test("the real demo bootstrap renders with Toolkit fonts and both themes", async ({
  page,
}) => {
  for (const theme of ["dark", "light"]) {
    await page.goto(`/map?mode=demo&theme=${theme}`);
    await expect(page.locator(".atlas")).toHaveAttribute(
      "data-atlas-theme",
      theme,
    );
    await expect(
      page.getByText("Synthetic demo", { exact: true }),
    ).toBeVisible();
    expect(
      await page
        .locator(".atlas")
        .evaluate((element) => getComputedStyle(element).fontFamily),
    ).not.toContain("Times");
  }
  await page.goto("/applications");
  await expect(
    page.getByRole("heading", { name: "Applications", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Open map for frontend", exact: true })
    .click();
  const demoMap = new URL(page.url());
  expect(demoMap.searchParams.get("mode")).toBe("demo");
  expect(demoMap.searchParams.get("scenario")).toBe("aci");
  expect(demoMap.searchParams.get("earliest")).toBe("1791373500");
  expect(demoMap.searchParams.get("latest")).toBe("1791374400");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
});

test("clears dependent scope fields and rejects invalid manual input", async ({
  page,
}) => {
  await page.clock.install();
  await page.goto("/tests/browser/browser.html?mode=live");
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const environment = page.getByRole("combobox", {
    name: "Environment",
    exact: true,
  });
  await expect(environment).toBeEnabled();
  await environment.fill("prod");
  await expect(
    page.getByRole("combobox", { name: "Cluster", exact: true }),
  ).toHaveValue("");
  await expect(
    page.getByRole("combobox", { name: "Namespace", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("combobox", { name: "Service", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Build map", exact: true }),
  ).toBeDisabled();
  const count = await page.evaluate(
    () =>
      window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph"))
        .length,
  );
  await environment.fill('prod"|delete');
  await expect(
    page.getByRole("button", { name: "Build map", exact: true }),
  ).toBeDisabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph"))
          .length,
    ),
  ).toBe(count);
});

test("demo controls retain the captured scope and time", async ({ page }) => {
  await page.goto("/tests/browser/browser.html");
  const service = page.getByRole("combobox", { name: "Service", exact: true });
  await expect(service).toBeEnabled();
  await service.fill("uncaptured");
  await expect(service).toHaveValue("frontend");
  await expect(page.locator(".scope-service")).toHaveText("frontend");
  await expect(
    page.getByLabel("Time range", { exact: true }).getByRole("button"),
  ).toBeDisabled();
  expect(new URL(page.url()).searchParams.get("earliest")).toMatch(/^\d/);
  expect(new URL(page.url()).searchParams.get("latest")).toMatch(/^\d/);
});

test("applications catalog sorts numeric metrics and opens a captured scope", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  await expect(
    page.getByRole("heading", { name: "Applications", exact: true }),
  ).toBeVisible();
  const catalog = page.locator("table").last();
  const rows = catalog.locator("tbody > tr");
  await expect(
    page.getByRole("button", { name: "Open map for frontend", exact: true }),
  ).toBeVisible();
  const metric = page.getByRole("button", { name: /Conversations \(1h\)/ });
  await metric.click();
  const ascending = await rows.evaluateAll((items) =>
    items.map((item) => Number(item.children[6]?.textContent?.trim())),
  );
  expect(ascending.filter(Number.isFinite)).toEqual(
    expect.arrayContaining([1, 2, 4, 6]),
  );
  await metric.click();
  const descending = await rows.evaluateAll((items) =>
    items.map((item) => Number(item.children[6]?.textContent?.trim())),
  );
  expect(descending.filter(Number.isFinite)).toEqual(
    expect.arrayContaining([1, 2, 4, 6]),
  );
  await page
    .getByRole("button", { name: "Open map for frontend", exact: true })
    .click();
  await expect(page).toHaveURL(/\/map\?/);
  expect(new URL(page.url()).searchParams.get("service")).toBe("frontend");
  expect(new URL(page.url()).searchParams.get("earliest")).toBe("1791370800");
  expect(new URL(page.url()).searchParams.get("latest")).toBe("1791374400");
});

test("catalog layout has one header row and contained narrow scrolling", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  const catalog = page.locator("table").last();
  await expect(catalog).toBeVisible();
  await expect(catalog.locator("thead tr")).toHaveCount(1);
  const layout = await catalog
    .locator("tbody > tr")
    .first()
    .evaluate((row) => ({
      rowHeight: row.getBoundingClientRect().height,
      widths: [...row.querySelectorAll("td")].map(
        (cell) => cell.getBoundingClientRect().width,
      ),
    }));
  expect(layout.rowHeight).toBeLessThan(130);
  expect(layout.widths.every((width) => width >= 80)).toBe(true);

  await page.setViewportSize({ width: 600, height: 900 });
  await page.reload();
  await expect(catalog).toBeVisible();
  const narrow = await catalog.evaluate((table) => {
    const parent = table.parentElement;
    return {
      overflow: parent ? getComputedStyle(parent).overflowX : "",
      documentFits: document.documentElement.scrollWidth <= innerWidth + 1,
    };
  });
  expect(narrow.overflow).toMatch(/auto|scroll/);
  expect(narrow.documentFits).toBe(true);
});

test("Find opens the captured application scope and rejects injection", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  await input.fill("10.42.0.15");
  await page.getByRole("button", { name: "Find", exact: true }).click();
  const checkout = page
    .locator('[aria-label="Find results"]')
    .getByRole("button", {
      name: "Open map for checkout",
      exact: true,
    })
    .first();
  await expect(checkout).toBeVisible();
  await checkout.first().click();
  await expect(page).toHaveURL(/\/map\?/);
  expect(new URL(page.url()).searchParams.get("service")).toBe("checkout");
  await page.goBack();
  await expect(input).toBeVisible();
  const before = await page.evaluate(
    () =>
      window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_find"))
        .length ?? 0,
  );
  await input.fill('10.42.0.15"|delete');
  await expect(
    page.getByText("Enter an exact IP, EPG or attached-device value."),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Find", exact: true }),
  ).toBeDisabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_find"))
          .length ?? 0,
    ),
  ).toBe(before);
});

test("stale Find responses cannot replace a newer result", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=find-stale",
  );
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  const find = page.getByRole("button", { name: "Find", exact: true });
  await input.fill("10.42.0.15");
  await find.click();
  await input.fill("db");
  await expect(find).toBeEnabled();
  await find.click();
  const results = page.locator('[aria-label="Find results"]');
  await expect(results).toContainText("checkout");
  await expect(results).not.toContainText("frontend");
});

test("empty catalog falls back to scopes without invented metrics", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=empty-catalog",
  );
  await expect(
    page.getByRole("status").filter({ hasText: /metrics are unavailable/i }),
  ).toBeVisible();
  const batch = page.locator("tbody tr").filter({ hasText: "batch-worker" });
  await expect(batch).toBeVisible();
  await expect(batch).toContainText("—");
});

test("captured demo applications explain unavailable Find evidence", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=applications&mode=demo");
  await expect(
    page.getByRole("heading", { name: "Applications", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Open map for frontend", exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/Captured Find window/i)).toBeVisible();
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  await input.fill("not-captured");
  await expect(
    page.getByRole("button", { name: "Find", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(/captured.*evidence/i)).toBeVisible();
});

test("findings expose safe demo evidence actions", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  const finding = page
    .getByRole("article")
    .filter({ hasText: "Blocked conversation" })
    .first();
  await expect(finding).toBeVisible();

  const copy = finding.getByRole("button", {
    name: "Copy request",
    exact: true,
  });
  await expect(copy).toBeEnabled();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await copy.click();
  await expect(finding.getByRole("status")).toContainText(/request copied/i);
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toMatch(/,|\n/);

  const openDemo = finding.getByRole("button", {
    name: "Open in Search",
    exact: true,
  });
  await expect(openDemo).toBeDisabled();
  await expect(finding).toContainText(
    /Synthetic demo evidence cannot be searched/i,
  );

  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  await expect(page.locator("[data-hit].selected").first()).toBeVisible();

  const edgeActions = page.getByRole("region", { name: "Evidence actions" });
  await expect(edgeActions).toBeVisible();
  await expect(
    edgeActions.getByRole("button", { name: "Copy request", exact: true }),
  ).toBeEnabled();
});

test("live evidence links preserve the graph window safely", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791373500&latest=1791374400",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const liveFinding = page
    .getByRole("article")
    .filter({ hasText: "Blocked conversation" })
    .first();
  await expect(liveFinding).toBeVisible();
  await liveFinding
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const search = page.getByRole("link", {
    name: "Open in Search",
    exact: true,
  });
  await expect(search).toHaveAttribute("target", "_blank");
  await expect(search).toHaveAttribute("rel", /noopener/);
  const href = await search.getAttribute("href");
  expect(href).toContain("adm_flow_evidence");
  expect(href).toContain("1791373500");
  expect(href).toContain("1791374400");
});

test("live health refreshes every five minutes and demo stays quiet", async ({
  page,
}) => {
  await page.clock.install();
  await page.goto("/tests/browser/browser.html?mode=live");
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const before = await page.evaluate(
    () =>
      (window.__ADM_REQUESTS__ ?? []).filter((r) =>
        r.spl.includes("adm_health"),
      ).length,
  );
  await page.clock.fastForward(300001);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window.__ADM_REQUESTS__ ?? []).filter((r) =>
            r.spl.includes("adm_health"),
          ).length,
      ),
    )
    .toBeGreaterThan(before);
  await page.goto("/tests/browser/browser.html");
  expect(
    await page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((r) =>
          r.spl.includes("adm_health"),
        ).length,
    ),
  ).toBe(0);
});

test("scope fields retain dark Toolkit surfaces under classic dashboard CSS", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?theme=dark");
  await page.addStyleTag({
    content:
      'input[type="text"] { background-color: white; border: 1px solid #ccc; box-shadow: inset 0 1px 1px #ddd; margin-bottom: 9px; }',
  });
  const field = page.getByRole("combobox", {
    name: "Environment",
    exact: true,
  });
  await expect(field).toBeEnabled();
  expect(
    await field.evaluate(
      (element) => getComputedStyle(element).backgroundColor,
    ),
  ).toBe("rgba(0, 0, 0, 0)");
  expect(
    await field.evaluate((element) => getComputedStyle(element).borderTopWidth),
  ).toBe("0px");
  expect(
    await field.evaluate((element) => getComputedStyle(element).boxShadow),
  ).toBe("none");
});

test("inferred backend findings open their collected candidate path", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  const finding = page.getByRole("article", {
    name: "Backend inferred",
    exact: true,
  });
  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  const path = page.getByRole("region", { name: /^Candidate path:/ });
  await expect(path).toBeVisible();
  await expect(path).toContainText("catalog");
  await expect(
    page.getByRole("complementary", { name: "Details" }),
  ).toContainText("catalog-api");
  await page.getByRole("button", { name: "Clear selection" }).click();
  await expect(finding).toBeVisible();
});

test("findings remain reachable below the map on narrow screens", async ({
  page,
}) => {
  await page.setViewportSize({ width: 600, height: 900 });
  await page.goto("/tests/browser/browser.html?mode=demo");
  const findings = page.getByRole("region", { name: "Map findings" });
  await expect(findings).toBeVisible();
  const finding = findings.getByRole("article", {
    name: "Blocked conversation",
    exact: true,
  });
  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Clear selection" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Clear selection" }).click();
  await expect(findings).toBeVisible();
});

test("traced call actions open a validated collected trace", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791373500&latest=1791374400&tab=services",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  await page
    .getByRole("button", { name: "Service frontend", exact: true })
    .click();
  await page
    .getByRole("complementary", { name: "Details" })
    .getByRole("button", { name: /checkout.*Traced call/ })
    .click();
  const actions = page.getByRole("region", { name: "Evidence actions" });
  const link = actions.getByRole("link", {
    name: "Open in Search",
    exact: true,
  });
  const url = new URL((await link.getAttribute("href"))!);
  expect(url.pathname).toBe("/app/splunk_adm/search");
  expect(url.searchParams.get("q")).toMatch(
    /^\| `adm_trace_evidence\("[0-9a-f]{16,32}"\)`$/,
  );
  expect(url.searchParams.get("earliest")).toBe("1791373500");
  expect(url.searchParams.get("latest")).toBe("1791374400");
  await expect(
    actions.getByRole("button", { name: "Copy request", exact: true }),
  ).toBeDisabled();
  await expect(actions).toContainText("first collected trace");
});

test("Setup inputs keep Toolkit surfaces under classic dashboard CSS", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&theme=dark",
  );
  await page.addStyleTag({
    content:
      'input[type="text"] { background-color: white; border: 1px solid #ccc; box-shadow: inset 0 1px 1px #ddd; margin-bottom: 9px; }',
  });
  const input = page.getByLabel("Index for adm_index_hubble", { exact: true });
  await expect(input).toBeVisible();
  expect(
    await input.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        background: style.backgroundColor,
        border: style.borderWidth,
        shadow: style.boxShadow,
        margin: style.marginBottom,
      };
    }),
  ).toEqual({
    background: "rgba(0, 0, 0, 0)",
    border: "0px",
    shadow: "none",
    margin: "0px",
  });
});

test("map facets combine, clear, and keep full evidence exports", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByRole("button", { name: "Legend", exact: true }),
  ).toHaveAttribute("aria-expanded", "false");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  const total = await page.locator(".table-view tbody tr").count();
  await page
    .getByLabel("Filter identity", { exact: true })
    .selectOption("external");
  const filtered = await page.locator(".table-view tbody tr").count();
  expect(filtered).toBeGreaterThan(0);
  expect(filtered).toBeLessThan(total);
  await expect(page.locator(".atlas-filter-status")).toContainText(
    "Findings and exports use the full map",
  );
  await page.getByRole("button", { name: "Export", exact: true }).click();
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: /Map data \(JSON\)/ }).click();
  const artifact = await downloaded;
  const exported = JSON.parse(
    await readFile((await artifact.path())!, "utf8"),
  ) as { nodes: unknown[] };
  expect(exported.nodes.length).toBe(
    Number(await page.locator(".adm").getAttribute("data-node-count")),
  );
  await page.getByLabel("Blocked only", { exact: true }).check();
  await expect(page.locator(".atlas-filter-status")).toBeVisible();
  await page
    .getByRole("button", { name: "Clear filters and focus", exact: true })
    .first()
    .click();
  await expect(page.locator(".table-view tbody tr")).toHaveCount(total);
  await page.getByLabel("Hide infrastructure", { exact: true }).check();
  await page.getByLabel("Hide infrastructure", { exact: true }).uncheck();
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("focus limits the neighborhood and clears without a new search", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByLabel("Focus around selected card", { exact: true }),
  ).toBeDisabled();
  const highlight = page.getByLabel(
    "Highlight by name, IP, EPG, port or device",
  );
  await highlight.fill("win-client-01");
  await highlight.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  await highlight.fill("");
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("1");
  await expect(page.locator(".atlas-filter-status")).toContainText(
    "Within 1 hop",
  );
  await page
    .getByRole("button", { name: "Clear filters and focus", exact: true })
    .first()
    .click();
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("persona preference persists but explicit view links take precedence", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await page.getByRole("button", { name: "Map settings", exact: true }).click();
  await page
    .getByLabel("Default view for persona", { exact: true })
    .selectOption("application");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.goto("/tests/browser/browser.html?tab=network");
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("Services clears network facets and only lists traced-call legend", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await page
    .getByLabel("Filter identity", { exact: true })
    .selectOption("external");
  await page.getByRole("button", { name: "Services", exact: true }).click();
  await expect(page.getByLabel("Filter identity", { exact: true })).toHaveCount(
    0,
  );
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
  await page.getByRole("button", { name: "Legend", exact: true }).click();
  await expect(page.getByLabel("Legend", { exact: true })).toContainText(
    "Traced call",
  );
  await expect(page.getByLabel("Legend", { exact: true })).not.toContainText(
    "Node tunnel",
  );
  await page.getByRole("button", { name: "1 external", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Map settings", exact: true }).click();
  await page
    .getByLabel("Default view for persona", { exact: true })
    .selectOption("application");
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("shrinking focus clears a selected connection outside the new neighborhood", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const highlight = page.getByLabel(
    "Highlight by name, IP, EPG, port or device",
  );
  await highlight.fill("frontend");
  await highlight.press("Enter");
  await page
    .getByRole("button", { name: "Service frontend", exact: true })
    .click();
  await highlight.fill("");
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("2");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page
    .locator(".table-view table")
    .first()
    .locator("tbody button")
    .first()
    .click();
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("1");
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
});

test("candidate paths stay on map tabs and remain available from Table inspection", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await page
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  await expect(page.locator(".path-strip")).toBeVisible();
  await page.getByRole("button", { name: "Services", exact: true }).click();
  await expect(page.locator(".path-strip")).toBeVisible();
  await page.getByRole("button", { name: "Devices", exact: true }).click();
  await expect(page.locator(".path-strip")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Show candidate path", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.locator(".path-strip")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".path-strip")).toBeVisible();
});

test("inspector full names are readable and copy exact collected text", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/tests/browser/browser.html");
  await page
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const title = page.locator(".atlas-inspector-title h2");
  const full = await title.textContent();
  await expect(title).toHaveCSS("text-overflow", "ellipsis");
  await page.locator(".atlas-inspector-title summary").click();
  await expect(page.locator(".atlas-full-name")).toHaveText(full!);
  await page
    .getByRole("button", { name: "Copy full name", exact: true })
    .click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe(full);
  await expect(page.getByText("Name copied.", { exact: true })).toBeVisible();
});

test("map emphasis explains dimming and clears both highlight and selection", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const search = page.getByLabel("Highlight by name, IP, EPG, port or device");
  await search.fill("checkout");
  await expect(page.locator(".atlas-emphasis-banner")).toContainText(
    "checkout",
  );
  await page.mouse.move(0, 0);
  const cards = await page.locator(".item").count();
  const emphasizedCards = await page.locator(".item:not(.dim)").count();
  const connections = await page.locator(".edge").count();
  const emphasizedConnections = await page.locator(".edge:not(.dim)").count();
  await expect(page.locator(".atlas-emphasis-banner")).toContainText(
    `${emphasizedCards} of ${cards} cards and ${emphasizedConnections} of ${connections} connections`,
  );
  await search.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  await page.locator(".atlas-emphasis-banner").getByRole("button").click();
  await expect(search).toHaveValue("");
  await expect(page.locator(".atlas-emphasis-banner")).toHaveCount(0);
  await expect(page.locator(".item.dim, .edge.dim")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
  await search.fill("no-such-endpoint-zzzz");
  await expect(page.locator(".atlas-emphasis-banner")).toContainText("0");
});

test("glossary explanations are available from the keyboard", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await page
    .getByRole("article", { name: "Backend inferred", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const info = page
    .getByRole("button", { name: "Explain Determined", exact: true })
    .first();
  await info.focus();
  await expect(page.getByRole("tooltip")).toContainText(
    "linked the frontend to a backend pod",
  );
  await expect(info).toBeFocused();
  await info.press("Tab");
  await expect(page.getByRole("tooltip")).toHaveCount(0);
});

test("copy-name feedback handles denied access and prevents overlapping attempts", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await page
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  await page.locator(".atlas-inspector-title summary").click();
  await page.evaluate(() =>
    Object.defineProperty(navigator.clipboard, "writeText", {
      configurable: true,
      value: () =>
        new Promise((_, reject) =>
          window.addEventListener(
            "reject-copy",
            () => reject(new Error("denied")),
            { once: true },
          ),
        ),
    }),
  );
  const copy = page.getByRole("button", {
    name: "Copy full name",
    exact: true,
  });
  await copy.click();
  await expect(copy).toBeDisabled();
  await page.evaluate(() => window.dispatchEvent(new Event("reject-copy")));
  await expect(
    page.locator(".atlas-inspector-title [role=alert]"),
  ).toContainText("Could not copy");
  await expect(copy).toBeEnabled();
  await page.evaluate(() =>
    Object.defineProperty(navigator.clipboard, "writeText", {
      configurable: true,
      value: () => Promise.resolve(),
    }),
  );
  await copy.click();
  await expect(page.locator(".atlas-inspector-title [role=alert]")).toHaveCount(
    0,
  );
  await expect(page.locator(".atlas-inspector-title [role=status]")).toHaveText(
    "Name copied.",
  );
});

test("long collected names truncate without losing their full text", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const search = page.getByLabel("Highlight by name, IP, EPG, port or device");
  await search.fill("cilium-ingress-shop-www");
  await search.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  const heading = page.locator(".atlas-inspector-title h2");
  await expect
    .poll(() => heading.evaluate((el) => el.scrollWidth > el.clientWidth))
    .toBe(true);
  await page.locator(".atlas-inspector-title summary").click();
  await expect(page.locator(".atlas-full-name")).toHaveText(
    (await heading.textContent())!,
  );
});

test("copy link preserves validated scope, time, tab, and highlight state", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=demo&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791370800&latest=1791374400&tab=services&q=checkout",
  );
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: (value: string) => {
          (
            window as Window & { __ADM_CLIPBOARD__?: string }
          ).__ADM_CLIPBOARD__ = value;
          return Promise.resolve();
        },
      },
    });
  });
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("button", { name: "Copy link", exact: true }).click();
  const copied = await page.evaluate(() => {
    const value = (window as Window & { __ADM_CLIPBOARD__?: string })
      .__ADM_CLIPBOARD__;
    return value ?? "";
  });
  expect(copied).toContain("service=frontend");
  expect(copied).toContain("earliest=1791373500");
  expect(copied).toContain("tab=services");
  expect(copied).toContain("q=checkout");
  await page.goto(new URL(copied).pathname + new URL(copied).search);
  await expect(page.locator(".scope-service")).toHaveText("frontend");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByLabel("Highlight by name, IP, EPG, port or device"),
  ).toHaveValue("checkout");
});

test("saved views persist per user and can be reopened or deleted", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByLabel("View name", { exact: true }).fill("Checkout demo");
  await page.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Checkout demo", exact: true }).click();
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toHaveCount(0);
});

test("saved views report denied storage and do not render a false save", async ({
  page,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(Storage.prototype, "setItem", {
      configurable: true,
      value: () => {
        throw new Error("denied");
      },
    });
  });
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page.getByRole("button", { name: "Saved views", exact: true }).click();
  await page.getByLabel("View name", { exact: true }).fill("Denied");
  await page.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("stored");
});

test("export downloads a nonempty PNG and print invokes the browser print API", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page.evaluate(() => {
    window.print = () => {
      (window as Window & { __ADM_PRINT__?: boolean }).__ADM_PRINT__ = true;
    };
  });
  await page.getByRole("button", { name: "Export", exact: true }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /Map image \(PNG\)/ }).click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).toBeTruthy();
  const bytes = await readFile(path!);
  const signature = Array.from(bytes.subarray(0, 8));
  expect(signature).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
  await page.getByRole("button", { name: /Print \/ PDF/ }).click();
  expect(
    await page.evaluate(
      () => (window as Window & { __ADM_PRINT__?: boolean }).__ADM_PRINT__,
    ),
  ).toBe(true);
});

test("ACI compare previous window identifies added connections", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page.getByRole("button", { name: "Changes", exact: true }).click();
  await page
    .getByRole("button", { name: "Compare previous window", exact: true })
    .click();
  await expect(page.getByText(/^Previous:/)).toBeVisible();
  await expect(page.getByText(/^Current:/)).toBeVisible();
  await expect(page.getByText(/^[1-9]\d* connections added/)).toBeVisible();
});

test("image and print exports are unavailable for an empty filtered map", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page
    .getByLabel("Filter identity", { exact: true })
    .selectOption("unknown");
  await page.getByLabel("Blocked only", { exact: true }).check();
  await expect(page.locator(".map-canvas > svg")).toHaveCount(0);
  await page.getByRole("button", { name: "Export", exact: true }).click();
  await expect(
    page.getByRole("button", { name: /Map image \(PNG\)/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /Print \/ PDF/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /Required flows \(CSV\)/ }),
  ).toBeEnabled();
});
