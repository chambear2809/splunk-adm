import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("investigation notes survive section changes and export fixed evidence only by explicit choice", async ({
  page,
}) => {
  await page.goto("/tests/browser/investigation.html");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await page
    .getByLabel("Notes", { exact: true })
    .fill("Observed deny; ask network owner");
  await page
    .getByLabel("Hypotheses", { exact: true })
    .fill("Policy change remains unconfirmed");
  await page.getByRole("button", { name: "Record revision" }).click();
  await page.getByRole("button", { name: "Timeline", exact: true }).click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await expect(page.getByLabel("Notes", { exact: true })).toHaveValue(
    "Observed deny; ask network owner",
  );
  const textDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download readable handoff" }).click();
  const text = await readFile((await (await textDownload).path())!, "utf8");
  expect(text).toContain("Observed deny; ask network owner");
  expect(text).toContain("no shared case save");
  await page
    .getByRole("checkbox", { name: /Include full captured graph/ })
    .check();
  const jsonDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download evidence package" }).click();
  const exported = JSON.parse(
    await readFile((await (await jsonDownload).path())!, "utf8"),
  );
  expect(exported.version).toBe(1);
  expect(exported.captures).toHaveLength(2);
  expect(exported.revisions[0].hypotheses).toContain("unconfirmed");
});

test("handoff remains usable on narrow screens", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/tests/browser/investigation.html");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await expect(page.getByLabel("Unresolved questions")).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
});
