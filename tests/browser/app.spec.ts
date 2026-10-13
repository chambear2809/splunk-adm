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
