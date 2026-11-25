import { expect, test } from "@playwright/test";

test("capped Device results keep drop evidence and qualify the summary", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=live&id=test-vds&fault=device-capped",
  );
  const summary = page.getByLabel("Summary", { exact: true });
  await expect(summary).toContainText("11 flow records");
  await expect(summary).toContainText("2 peers shown");
  await expect(summary).toContainText("1 blocked shown");
  const table = page.getByRole("region", {
    name: "Showing 1 of at least 4 conversations",
  });
  await expect(table.getByLabel("Blocked", { exact: true })).toBeVisible();
});

test("a device conversation carries its historical window into a trace", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=demo&id=192.0.2.73&earliest=1791370800&latest=1791374400",
  );
  const link = page
    .getByRole("region", { name: "Conversations" })
    .getByRole("link", { name: "win-client-01" });
  await expect(link).toBeVisible();
  const trace = new URL((await link.getAttribute("href"))!, page.url());
  expect(trace.searchParams.get("earliest")).toBe("1791370800");
  expect(trace.searchParams.get("latest")).toBe("1791374400");
});

test("device navigation keeps its selected window and restores browser history", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=live&id=192.0.2.73&earliest=1791370800&latest=1791374400&service=frontend",
  );
  await expect(
    page.getByRole("heading", { name: /192\.0\.2\.73|esx-03/ }),
  ).toBeVisible();
  const before = new URL(page.url());
  expect(before.searchParams.get("earliest")).toBe("1791370800");
  expect(before.searchParams.get("service")).toBe("frontend");

  await page
    .getByLabel("Time range", { exact: true })
    .getByRole("button")
    .click();
  await page.getByRole("button", { name: "Presets", exact: true }).click();
  await page.getByText("Last 24 hours", { exact: true }).click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("earliest"))
    .not.toBe("1791370800");
  const current = new URL(page.url());
  const start = current.searchParams.get("earliest");
  const end = current.searchParams.get("latest");
  expect(start).toMatch(/^\d/);
  expect(end).toMatch(/^\d/);
  const impact = new URL(
    (await page
      .getByRole("link", { name: /Impact if/ })
      .getAttribute("href")) ?? "",
    page.url(),
  );
  expect(impact.searchParams.get("window")).toBe(start);
  expect(impact.searchParams.get("latest")).toBe(end);

  await page.goBack();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("earliest"))
    .toBe("1791370800");
  await expect
    .poll(async () =>
      new URL(
        (await page
          .getByRole("link", { name: /Impact if/ })
          .getAttribute("href")) ?? "",
        page.url(),
      ).searchParams.get("window"),
    )
    .toBe("1791370800");
  await page.goForward();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("earliest"))
    .toBe(start);
});

test("device rejects a partial historical window", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=live&id=192.0.2.73&earliest=1791370800",
  );
  await expect(page.getByRole("alert")).toContainText(
    "Both time window bounds are required",
  );
  await expect(page.getByRole("link", { name: /Impact if/ })).toHaveCount(0);
});
