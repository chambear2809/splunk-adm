import { expect, test } from "@playwright/test";

test.describe("Application Atlas browser regressions", () => {
  test("filters the map and opens endpoint inspection", async ({ page }) => {
    await page.goto("/tests/browser/browser.html");
    await expect(page.getByText("Synthetic demo")).toBeVisible();

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
    await page.getByRole("button", { name: "Splunk" }).click();
    const settings = page.getByRole("region", { name: "Map settings" });
    const inputs = settings.locator("input");
    await inputs.nth(0).fill("payments");
    await inputs.nth(1).fill("prod");
    await inputs.nth(2).fill("cluster-a");
    await inputs.nth(3).fill("payments");
    const range = page.getByLabel("Time range");
    await expect(range).toBeEnabled();
    await range.selectOption("-24h");
    await expect(range).toHaveValue("-24h");
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByText("Synthetic demo")).toBeHidden();
    await expect
      .poll(() => page.evaluate(() => window.__ADM_LAST_EARLIEST__))
      .toBe("-24h");
    await expect
      .poll(() => page.evaluate(() => window.__ADM_LAST_GRAPH_SEARCH__))
      .toBe('`adm_graph("payments","prod","cluster-a","payments")`');
    await expect(page.locator(".scope-service")).toHaveText("payments");
    await expect(page.locator(".scope-dims")).toHaveText(
      "prod · cluster-a · payments",
    );
  });

  test("shows permission errors from the live search", async ({ page }) => {
    await page.goto("/tests/browser/browser.html?scenario=permission");
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByRole("alert")).toContainText("search failed");
    await expect(page.getByRole("alert")).toContainText("permission denied");
  });

  test("surfaces an incomplete result warning", async ({ page }) => {
    await page.goto("/tests/browser/browser.html?scenario=incomplete");
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
  await page.getByRole("button", { name: "Open map", exact: true }).click();
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
});
