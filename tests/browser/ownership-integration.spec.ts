import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
const base = "/tests/browser/ownership-integration.html";
test("catalog resolves explicit business binding and exports native references only", async ({
  page,
}) => {
  await page.goto(`${base}?view=catalog`);
  await page
    .getByRole("button", { name: "Business ownership for checkout" })
    .click();
  await page
    .getByRole("button", { name: "Open business ownership evidence" })
    .click();
  const ownership = page.getByRole("region", {
    name: "Business ownership context",
  });
  await ownership
    .getByRole("button", { name: "Load local assertions" })
    .click();
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toContainText("Commerce");
  await ownership.getByText("Assertion and technical binding details").click();
  await expect(ownership).toContainText("mapping-ticket-123");
  await ownership.getByText("Export technical identity references").click();
  const button = ownership.getByRole("button", { name: "Download references" });
  await expect(button).toBeDisabled();
  await ownership
    .getByLabel("I intend to include these identifiers in a local file.")
    .check();
  const download = page.waitForEvent("download");
  await button.click();
  const text = await readFile((await (await download).path())!, "utf8");
  expect(text).toContain("qualified_v2");
  expect(text).not.toContain("mapping-ticket-123");
  expect(text).not.toContain("cmdb-east");
});
test("map withholds native ownership during refresh, denial and client replacement", async ({
  page,
}) => {
  await page.goto(`${base}?view=map`);
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  await page.getByRole("button", { name: "More actions", exact: true }).click();
  await page
    .getByRole("button", { name: "Business ownership", exact: true })
    .click();
  const ownership = page.getByRole("region", {
    name: "Business ownership context",
  });
  await ownership
    .getByRole("button", { name: "Load local assertions" })
    .click();
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toContainText("Commerce");
  await page
    .getByRole("button", { name: "Hold synthetic graph refresh" })
    .click();
  await page.getByRole("button", { name: "Build map", exact: true }).click();
  await expect(ownership).toContainText("Map source evidence is loading");
  await expect(
    ownership.getByRole("button", { name: "Download references" }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Deny held graph refresh" }).click();
  await expect(ownership).toContainText(
    "The map source could not be rechecked",
  );
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toHaveCount(0);
  await expect(
    ownership.getByRole("button", { name: "Download references" }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Replace synthetic source client" })
    .click();
  await expect(
    ownership.getByRole("button", { name: "Download references" }),
  ).toHaveCount(0);
});
test("impact without a qualified native graph does not join imported names", async ({
  page,
}) => {
  await page.goto(`${base}?view=impact&element=checkout&scope=synthetic`);
  await page
    .getByRole("button", { name: "Open business ownership evidence" })
    .click();
  const ownership = page.getByRole("region", {
    name: "Business ownership context",
  });
  await ownership
    .getByRole("button", { name: "Load local assertions" })
    .click();
  await expect(ownership).toContainText(
    "Impact source evidence is unavailable",
  );
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toHaveCount(0);
  await expect(
    ownership.getByRole("button", { name: "Download references" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Open maintenance planning evidence" }),
  ).toBeVisible();
});

test("client replacement suppresses previously authorized map identity", async ({
  page,
}) => {
  await page.goto(`${base}?view=map`);
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  await page.getByRole("button", { name: "More actions", exact: true }).click();
  await page
    .getByRole("button", { name: "Business ownership", exact: true })
    .click();
  const ownership = page.getByRole("region", {
    name: "Business ownership context",
  });
  await ownership
    .getByRole("button", { name: "Load local assertions" })
    .click();
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Hold synthetic graph refresh" })
    .click();
  await page
    .getByRole("button", { name: "Replace synthetic source client" })
    .click();
  await expect(ownership).toContainText(/previous source connection|loading/);
  await expect(
    ownership.getByRole("region", { name: "Business service Payments" }),
  ).toHaveCount(0);
  await expect(
    ownership.getByRole("button", { name: "Download references" }),
  ).toHaveCount(0);
});
for (const theme of ["light", "dark"])
  for (const width of [320, 1440]) {
    test(`ownership pages fit ${width}px ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(`${base}?view=catalog&theme=${theme}`);
      await page
        .getByRole("button", { name: "Business ownership for checkout" })
        .click();
      await page
        .getByRole("button", { name: "Open business ownership evidence" })
        .click();
      await page.getByRole("button", { name: "Load local assertions" }).click();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
      await page.goto(`${base}?view=map&theme=${theme}`);
      await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
      await page
        .getByRole("button", { name: "More actions", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Business ownership", exact: true })
        .click();
      await page.getByRole("button", { name: "Load local assertions" }).click();
      // Map width assertion follows after checking the impact view.
      const mapWidth = await page.evaluate(
        () => document.documentElement.scrollWidth,
      );
      await page.goto(
        `${base}?view=impact&element=checkout&scope=synthetic&theme=${theme}`,
      );
      await page
        .getByRole("button", { name: "Open business ownership evidence" })
        .click();
      await page.getByRole("button", { name: "Load local assertions" }).click();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
      expect(mapWidth).toBeLessThanOrEqual(width);
    });
  }

test("ownership closes back to the map action without displacing the compact map", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}?view=map`);
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const before = (await page.locator(".map-area").boundingBox())!.y;
  await page.getByRole("button", { name: "More actions", exact: true }).click();
  await page
    .getByRole("button", { name: "Business ownership", exact: true })
    .click();
  const region = page.getByRole("region", {
    name: "Business ownership",
    exact: true,
  });
  await expect(region).toBeFocused();
  await page
    .getByRole("button", { name: "Close business ownership", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "More actions", exact: true }),
  ).toBeFocused();
  await expect(region).toHaveCount(0);
  expect((await page.locator(".map-area").boundingBox())!.y).toBe(before);
});
