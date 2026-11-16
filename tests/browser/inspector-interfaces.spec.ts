import { expect, test, type Locator } from "@playwright/test";

const cells = async (table: Locator) =>
  table
    .locator("tbody tr")
    .evaluateAll((trs) =>
      trs.map((tr) =>
        [...tr.querySelectorAll("th, td")].map((c) =>
          (c as HTMLElement).innerText.replace(/\s+/g, " ").trim(),
        ),
      ),
    );

test("a selected line lists each observer's named in and out interfaces", async ({
  page,
}) => {
  await page.goto("/tests/browser/inspector-interfaces.html");
  await page.getByRole("tab", { name: "Flows" }).click();
  const table = page.getByRole("table", { name: "Seen by" });
  await expect(table).toBeVisible();
  await expect(table.locator("thead th")).toHaveText([
    "Device",
    "In",
    "Out",
    "Records",
    "Evidence",
  ]);
  const rows = await cells(table);
  // Device cells span their interface rows (one group per observer device).
  expect(rows).toContainEqual([
    "fab1-leaf101",
    "port-channel2",
    "vpc-1-22-FI (inferred)",
    "—",
    "Stream NetFlow out inferred",
  ]);
  expect(rows).toContainEqual([
    "vmm-dc1 on 203.0.113.11",
    "vmnic7 (vmm-dc1 uplink)",
    "k8s-vm-01 vNIC (port 9)",
    "—",
    "Stream NetFlow",
  ]);
  expect(rows).toContainEqual([
    "k8s-vm-01 vNIC (port 9)",
    "—",
    "—",
    "Stream NetFlow",
  ]);
  expect(JSON.stringify(rows)).not.toMatch(/ifIndex/);
  await expect(table.locator("tbody th[rowspan='2']")).toHaveCount(2);
});

test("a bundled pair lists every grouped link with its interfaces", async ({
  page,
}) => {
  await page.goto("/tests/browser/inspector-interfaces.html?select=bundle");
  const table = page.getByRole("table", { name: "Interfaces by link" });
  await expect(table).toBeVisible();
  await expect(table.locator("tr.atlas-ifs-link")).toHaveText([
    "k8s-vm-01 → app-vm-02",
    "k8s-vm-01 → app-vm-02",
  ]);
  const rows = await cells(table);
  expect(rows.filter((r) => r[0] === "fab1-leaf102")).toHaveLength(2);
  expect(rows).toContainEqual([
    "fab1-leaf102",
    "port-channel1",
    "vpc-1-22-FI (inferred)",
    "—",
    "Stream NetFlow out inferred",
  ]);
});

test("a selected card aggregates its conversations per observer device", async ({
  page,
}) => {
  await page.goto("/tests/browser/inspector-interfaces.html?select=node");
  await page.getByRole("tab", { name: "Flows" }).click();
  const table = page.getByRole("table", { name: "Seen by" });
  await expect(table).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Seen by" }).locator("h3 .count"),
  ).toHaveText("4");
  const rows = await cells(table);
  expect(rows.filter((r) => r[0] === "fab1-leaf101")).toHaveLength(1);
});
