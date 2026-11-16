import { expect, test } from "@playwright/test";

const MAX_ROWS = 50;
const RAW_TUPLE = /Source [\d.]+(:\d+)? → Destination/;

for (const scenario of ["aci", "catalyst-aci"]) {
  test(`Devices tab shows compact rows, not raw tuples (${scenario})`, async ({
    page,
  }) => {
    await page.goto(`/tests/browser/browser.html?scenario=${scenario}`);
    await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
    await page.getByRole("button", { name: "Devices", exact: true }).click();
    const view = page.locator(".devices-view");
    const rows = view.locator(".device-row");
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeLessThanOrEqual(MAX_ROWS);
    await expect(view).not.toContainText(RAW_TUPLE);
    await expect(view).not.toContainText("Reply true");
    await expect(view).not.toContainText("Domain present");
    // Conversation tables open on demand.
    await expect(view.getByRole("table")).toHaveCount(0);

    await rows.first().locator(".devices-row-toggle").click();
    const table = rows.first().getByRole("table");
    await expect(table).toBeVisible();
    const bodyRows = table.locator("tbody tr[aria-rowindex]");
    expect(await bodyRows.count()).toBeLessThanOrEqual(MAX_ROWS);
    for (const header of [
      "Source",
      "Destination",
      "Service",
      "Flows",
      "Replies",
      "Bytes",
      "Last seen",
    ])
      await expect(
        table.getByRole("columnheader", { name: header, exact: true }),
      ).toBeVisible();
    await expect(view).not.toContainText(RAW_TUPLE);

    const filter = page.getByRole("searchbox", { name: "Filter devices" });
    await filter.fill("zzz-no-such-device");
    await expect(rows).toHaveCount(0);
    await expect(view.getByText("No devices match.")).toBeVisible();
    await filter.fill("");
    await expect(rows.first()).toBeVisible();
  });
}

test("Devices tab groups collapse and expand", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?scenario=catalyst-aci");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  await page.getByRole("button", { name: "Devices", exact: true }).click();
  const leaf = page
    .locator(".devices-group button")
    .filter({ hasText: "Leaf" });
  await expect(leaf).toHaveAttribute("aria-expanded", "true");
  const before = await page.locator(".device-row").count();
  await leaf.click();
  await expect(leaf).toHaveAttribute("aria-expanded", "false");
  expect(await page.locator(".device-row").count()).toBeLessThan(before);
  const first = page.locator(".device-row").first();
  await expect(first.getByRole("link", { name: "Impact" })).toHaveAttribute(
    "href",
    /impact\?(.*&)?element=/,
  );
});
