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
    await expect(page.getByRole("status")).toContainText("card");
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
