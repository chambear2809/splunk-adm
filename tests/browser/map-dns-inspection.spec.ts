import { expect, test } from "@playwright/test";
test("cancelled DNS investigation ignores a late failure", async ({ page }) => {
  await page.goto("/tests/browser/map-dns-inspection.html");
  await page.getByRole("button", { name: "Choose evidence context" }).click();
  await expect(
    page.getByRole("combobox", { name: "Observed address" }),
  ).toBeVisible();
  await page
    .getByRole("combobox", { name: "Observed address" })
    .selectOption("192.0.2.10");
  await page
    .getByRole("combobox", { name: "Verified routing scope" })
    .selectOption("prod");
  await page
    .getByRole("button", { name: "Resolve observed evidence context" })
    .click();
  await expect
    .poll(() => page.evaluate(() => !!window.__MAP_DNS_TEST__))
    .toBe(true);
  await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(
    page.getByRole("button", { name: "Resolve observed evidence context" }),
  ).toBeEnabled();
  await page.evaluate(() => window.__MAP_DNS_TEST__?.control.reject());
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByRole("status")).toHaveCount(0);
});
