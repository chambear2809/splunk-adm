import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

// Demo data: ACI demo fabric with esx-01 re-cabled through a UCS FI pair to a
// vPC on leaf-101/leaf-102 (fixtures/demo-impact-aci.json).
const headline = (page: import("@playwright/test").Page) =>
  page.locator(".atlas-impact-headline");

test("deep link: a vPC leaf failure is degraded, single-homed pods are out", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/impact?element=leaf-101&mode=fails&window=-1h");
  await expect(headline(page)).toHaveText(
    /^leaf-101 down: 2 outage · 4 apps degraded · 1 unverified · \d+ peers · [\d.]+ KB\/h shifts to leaf-102$/,
  );
  const kpis = page.getByLabel("Impact by severity");
  await expect(kpis.getByLabel(/^Apps: 2 outage, 4 degraded/)).toBeVisible();
  const table = page.getByRole("table");
  const db = table
    .getByRole("row")
    .filter({ hasText: "checkout-5f8b9c7d6-m4n7q" })
    .filter({ hasText: "orders-db-01" });
  await expect(db).toContainText("Degraded");
  await expect(db).toContainText("leaf-102");
  await expect(db).toContainText("vPC peer");
  await expect(
    table.getByRole("row").filter({ hasText: "payment-np" }),
  ).toContainText("single-homed");
  const blast = page.getByRole("figure", { name: "Blast map" });
  await expect(blast.locator(".blast-node.down text")).toHaveText("leaf-101");
  await expect(blast.locator(".blast-node.alternate text")).toContainText([
    "leaf-102",
  ]);
});

test("what-if: one FI degrades, adding the other FI is an outage", async ({
  page,
}) => {
  await page.goto("/impact?element=ucs-fi-b&mode=fails");
  await expect(headline(page)).toHaveText(
    /^ucs-fi-b down: 0 outage · 1 app degraded .* shifts to ucs-fi-a$/,
  );
  const picker = page.getByRole("form", { name: "Elements" });
  await picker.getByLabel("Add element").fill("ucs-fi-a");
  await picker.getByRole("button", { name: "Add" }).click();
  await expect(headline(page)).toHaveText(
    /^ucs-fi-b \+ ucs-fi-a down: 1 outage · 0 apps degraded/,
  );
  await expect(page).toHaveURL(/element=ucs-fi-b&element=ucs-fi-a&mode=fails/);
  const row = page.getByRole("row").filter({ hasText: "orders-db-01" }).first();
  await expect(row).toContainText("Outage");
  await expect(row).toContainText("all redundant members down");
  await picker.getByRole("button", { name: "Remove ucs-fi-a" }).click();
  await expect(headline(page)).toHaveText(/^ucs-fi-b down: 0 outage/);
});

test("depends on: single points and redundant members, linked to their impact", async ({
  page,
}) => {
  await page.goto("/impact?element=orders-db-01&mode=fails");
  await page.getByRole("radio", { name: "Depends on" }).click();
  await expect(page).toHaveURL(/mode=depends/);
  await expect(headline(page)).toHaveText(
    /^orders-db-01 depends on \d+ · 2 single points \(vmm-shop, esx-01\) · \d+ redundant$/,
  );
  const esx = page.getByRole("row").filter({ hasText: "esx-01" });
  await expect(esx).toContainText("Single point");
  const leaf = page.getByRole("row").filter({
    has: page.getByRole("link", { name: "leaf-101", exact: true }),
  });
  await expect(leaf).toContainText("Redundant");
  await leaf.getByRole("link", { name: "leaf-101" }).click();
  await expect(page).toHaveURL(/\/impact\?element=192\.0\.2\.101&mode=fails/);
  await expect(headline(page)).toHaveText(/^leaf-101 down:/);
});

test("CSV export carries the headline and one row per affected conversation", async ({
  page,
}) => {
  await page.goto("/impact?element=spine-201&mode=fails");
  await expect(headline(page)).toHaveText(/^spine-201 down: 0 outage/);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "CSV" }).click(),
  ]);
  const text = await readFile((await download.path())!, "utf8");
  const lines = text.split("\r\n");
  expect(lines[0]).toContain("spine-201 down: 0 outage");
  expect(lines[2]).toMatch(/^severity,app,src_ip,/);
  expect(lines.slice(3).every((l) => l.startsWith("degraded,"))).toBe(true);
  expect(text).toContain("spine-202");
});

test("Impact is the map's blast-radius action and overlays the map", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const toolbarImpact = page.locator(".atlas-impact-btn.compact").first();
  await expect(toolbarImpact).toHaveAttribute("aria-disabled", "true");
  const db = page.getByRole("button", { name: /^VM orders-db-01/ });
  await db.focus();
  await db.press("Enter");
  const action = page.getByRole("link", {
    name: "Impact if orders-db-01 fails",
  });
  await expect(action.first()).toBeVisible();
  await action.first().click();
  await expect(page).toHaveURL(/\/impact\?element=vm%3Aprod%2F10\.20\.30\.40/);
  await expect(headline(page)).toHaveText(/^orders-db-01 down: /);
  // The map overlay: affected cards keep focus, the rest dim.
  await page.goto(
    "/map?mode=demo&scenario=aci&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&impact=leaf-103",
  );
  await expect(page.locator(".item.impact-outage").first()).toBeVisible();
  await expect(page.locator(".atlas-emphasis-banner")).toContainText(
    "leaf-103 down: ",
  );
});

test("device page and trace hops open Impact for the device and its interfaces", async ({
  page,
}) => {
  await page.goto("/device?mode=demo&id=pod-1/node-103");
  const link = page.getByRole("link", { name: "Impact if leaf-103 fails" });
  await expect(link).toHaveAttribute(
    "href",
    /\/impact\?element=192\.0\.2\.103/,
  );
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=demo&trace_src=10.30.40.25&trace_dst=orders-db-01",
  );
  const view = page.getByRole("region", {
    name: "Trace 10.30.40.25 to orders-db-01",
  });
  await view.getByRole("button", { name: /^Leaf leaf-103/ }).click();
  await expect(
    view.getByRole("link", { name: /^Impact if leaf-103 fails/ }),
  ).toHaveAttribute("href", /element=/);
});

test("a vPC fails by name: one vPC degrades, both FI vPCs are an outage", async ({
  page,
}) => {
  await page.goto("/impact?element=vpc-1-22-UCS-FI&mode=fails");
  await expect(headline(page)).toHaveText(/^vpc-1-22-UCS-FI down: 0 outage/);
  const row = page.getByRole("row").filter({ hasText: "orders-db-01" }).first();
  await expect(row).toContainText("Degraded");
  await page.goto(
    "/impact?element=vpc-1-22-UCS-FI&element=vpc-1-21-UCS-FI&mode=fails",
  );
  await expect(headline(page)).toHaveText(
    /^vpc-1-22-UCS-FI \+ vpc-1-21-UCS-FI down: 1 outage/,
  );
});
