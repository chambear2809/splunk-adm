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
    await expect(page.getByText("Synthetic demo")).toBeHidden();
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

test("clears dependent scope fields and rejects invalid manual input", async ({
  page,
}) => {
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
