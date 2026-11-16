import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("maintenance preserves before/after evidence and requires opt-in for source payloads", async ({
  page,
}) => {
  await page.goto("/tests/browser/planning.html");
  const planner = page.getByRole("region", {
    name: "Maintenance planning",
    exact: true,
  });
  await expect(
    planner.getByRole("heading", { name: "Identified blockers" }),
  ).toBeVisible();
  await planner.getByRole("button", { name: "Capture before" }).click();
  await page
    .getByRole("button", { name: "Use later synthetic maintenance evidence" })
    .click();
  await planner.getByRole("button", { name: "Capture after" }).click();
  await expect(
    planner.getByRole("region", { name: "Capture comparison" }),
  ).toContainText("health blocked → confirmed");
  const download = page.waitForEvent("download");
  await planner
    .getByRole("button", { name: "Download evidence", exact: true })
    .click();
  const data = JSON.parse(
    await readFile((await (await download).path())!, "utf8"),
  );
  expect(JSON.stringify(data)).not.toContain("synthetic qualified replay");
  await planner.getByRole("checkbox").check();
  const full = page.waitForEvent("download");
  await planner
    .getByRole("button", { name: "Download evidence", exact: true })
    .click();
  expect(await readFile((await (await full).path())!, "utf8")).toContain(
    "synthetic qualified replay",
  );
});

test("dependency evidence rejects ranked captures and clears revoked evidence", async ({
  page,
}) => {
  await page.goto("/tests/browser/planning.html?mode=incomplete");
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  await page.getByLabel("Baseline name").fill("Cannot save ranked result");
  await expect(
    page.getByRole("button", { name: "Save new baseline" }),
  ).toBeDisabled();
  await page.goto("/tests/browser/planning.html");
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  await page
    .getByRole("button", { name: "List baselines", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Saved service dependencies · version 1" })
    .click();
  await page
    .getByText("Saved service dependencies · version 1", { exact: true })
    .last()
    .click();
  await expect(page.getByText(/newly observed/)).toBeVisible();
  await page
    .getByRole("button", { name: "Revoke synthetic source access" })
    .click();
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  await expect(page.getByRole("alert")).toContainText("denied");
  await expect(page.getByText(/newly observed/)).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Save new baseline" }),
  ).toBeDisabled();
});

test("baseline lost-response retry uses one stored record and watch definitions stay passive", async ({
  page,
}) => {
  await page.goto("/tests/browser/planning.html?mode=lost");
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  await page.getByLabel("Baseline name").fill("New source baseline");
  await page.getByRole("button", { name: "Save new baseline" }).click();
  await expect(
    page.getByRole("button", { name: "Retry same baseline request" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Retry same baseline request" })
    .click();
  await page
    .getByRole("button", { name: "List baselines", exact: true })
    .click();
  const record = page.getByRole("button", {
    name: "New source baseline · version 1",
  });
  await expect(record).toHaveCount(1);
  await record.click();
  await page.getByText("Passive watch", { exact: true }).click();
  await page
    .getByRole("button", { name: "Save passive watch", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("saved");
});

test("planning controls fit narrow dark screens", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/tests/browser/planning.html?theme=dark");
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
});

test("impact maintenance retains captures during refresh and clears them on denial", async ({
  page,
}) => {
  await page.goto("/tests/browser/planning.html?mode=impact");
  const planner = page.getByRole("region", {
    name: "Maintenance planning",
    exact: true,
  });
  await expect(planner).toContainText(
    "Demo data with synthetic topology context",
  );
  await expect(planner).toContainText("Readiness cannot be confirmed");
  const currentAssessment = planner.locator(".atlas-maintenance").first();
  await expect(currentAssessment).toContainText(
    new Date(1791373400 * 1000).toISOString(),
  );
  await expect(planner).toContainText("synthetic-leaf-b: Unknown");
  await planner.getByRole("button", { name: "Capture before" }).click();
  await expect(
    planner.getByText("Before capture", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Begin synthetic refresh" }).click();
  await expect(planner).toContainText("Previous planning evidence is retained");
  await expect(
    planner.getByText("Before capture", { exact: true }),
  ).toBeVisible();
  await expect(
    planner.getByRole("button", { name: "Capture before" }),
  ).toBeDisabled();
  await expect(
    planner.getByRole("button", { name: "Capture after" }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Complete synthetic refresh" })
    .click();
  await expect(
    planner.getByRole("button", { name: "Capture after" }),
  ).toBeEnabled();
  await expect(currentAssessment).toContainText(
    new Date(1791373700 * 1000).toISOString(),
  );
  await planner.getByRole("button", { name: "Capture after" }).click();
  await expect(
    planner.getByText("After capture", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Deny synthetic impact access" })
    .click();
  await expect(planner).toContainText("unavailable");
  await expect(
    planner.getByText("Before capture", { exact: true }),
  ).toHaveCount(0);
  await expect(
    planner.getByRole("button", { name: "Download evidence" }),
  ).toHaveCount(0);
});
