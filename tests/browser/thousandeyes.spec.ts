import { expect, test } from "@playwright/test";

interface SearchLog {
  search: string;
  earliest: string;
  aborted: boolean;
  released: boolean;
  settled: boolean;
}

interface ThousandEyesTestState {
  searches: SearchLog[];
  comparisons: {
    before: { start: number; end: number };
    after: { start: number; end: number };
  }[];
  lateResults: number;
}

type ThousandEyesTestWindow = Window & {
  __THOUSANDEYES_TEST__?: ThousandEyesTestState;
};

const state = (page: import("@playwright/test").Page) =>
  page.evaluate(
    () => (window as ThousandEyesTestWindow).__THOUSANDEYES_TEST__ ?? null,
  );

test.describe("optional ThousandEyes evidence inspection", () => {
  test("does not search without a selected application or endpoint", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=no-selection");
    await expect(
      page.getByText("No application or endpoint selection is active."),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Inspect ThousandEyes evidence" }),
    ).toHaveCount(0);
    expect((await state(page))?.searches).toEqual([]);
  });

  test("renders failed synthetic measurements with native units and injected comparisons", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByRole("region", { name: "Optional ThousandEyes evidence" }),
    ).toBeVisible();
    await expect(
      page.getByText("Search complete: 1 visible observation."),
    ).toBeVisible();
    await expect(
      page.getByRole("table", {
        name: "Reported measurements, with native units and basis",
      }),
    ).toContainText("network.latency");
    await expect(page.getByText("0.125")).toBeVisible();
    await expect(page.getByText("seconds (seconds)")).toBeVisible();
    await expect(page.getByText("Reported outcome: failure")).toBeVisible();
    await expect(
      page.getByText(
        "do not create passive traffic, service calls, dependency edges",
      ),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Open configured ThousandEyes origin" }),
    ).toHaveAttribute("href", "https://app.thousandeyes.example.test");
    await expect(page.locator('a[href*="event.example.test"]')).toHaveCount(0);

    await page
      .getByRole("button", { name: "Compare loaded measurements" })
      .click();
    await expect(
      page.getByRole("table", {
        name: "Scrollable before and after comparison table",
      }),
    ).toContainText("0.025");
    expect((await state(page))?.comparisons).toHaveLength(1);
    expect((await state(page))?.searches).toMatchObject([
      { aborted: false, released: true, settled: true },
    ]);
  });

  test("keeps event-only results distinct from missing metrics and empty evidence", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=no-metric");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByRole("region", {
        name: "ThousandEyes event and alert lifecycle",
      }),
    ).toBeVisible();
    await expect(page.getByText("Detected event lifecycle")).toBeVisible();
    await expect(
      page.getByText("Source history is incomplete or unverified"),
    ).toBeVisible();
    await expect(
      page.getByRole("table", {
        name: "Reported measurements, with native units and basis",
      }),
    ).toHaveCount(0);
    await expect(page.getByText(/0\s*(ms|seconds|percent)/i)).toHaveCount(0);

    await page.goto("/tests/browser/thousandeyes.html?fault=empty");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText(/No visible ThousandEyes observations were returned/),
    ).toBeVisible();
    await expect(
      page.getByText(/does not prove that no tests ran/),
    ).toBeVisible();
    await expect(page.getByText(/healthy|health is good/i)).toHaveCount(0);
  });

  test("does not dispatch for an unselected source", async ({ page }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=off");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText(/ThousandEyes source not selected/),
    ).toBeVisible();
    expect((await state(page))?.searches).toEqual([]);
  });

  test("reports caller denial without replacing other investigation evidence", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=denied");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page
        .getByRole("alert")
        .getByText(
          /Access to the selected ThousandEyes evidence search was denied/,
        ),
    ).toBeVisible();
    expect((await state(page))?.searches).toMatchObject([
      { aborted: false, released: true, settled: true },
    ]);
  });

  test("cancellation releases its caller-owned search and allows retry", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=slow");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText("Loading optional ThousandEyes evidence…"),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Cancel ThousandEyes search" })
      .click();
    await expect(
      page.getByText(
        "Search cancelled. Optional search cleanup may still be pending.",
      ),
    ).toBeVisible();
    await expect
      .poll(async () => (await state(page))?.searches[0])
      .toMatchObject({
        aborted: true,
        released: true,
        settled: true,
      });
    await expect(
      page.getByRole("table", {
        name: "Reported measurements, with native units and basis",
      }),
    ).toHaveCount(0);

    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByRole("table", {
        name: "Reported measurements, with native units and basis",
      }),
    ).toContainText("network.latency");
    expect((await state(page))?.searches).toMatchObject([
      { aborted: true, released: true },
      { aborted: false, released: true },
    ]);
  });

  test("rejects a late response after the user changes the scoped selection", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=late");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText("Loading optional ThousandEyes evidence…"),
    ).toBeVisible();
    await page.getByRole("button", { name: "Use another selection" }).click();
    await expect(
      page.getByRole("region", {
        name: "Optional ThousandEyes evidence inspection",
      }),
    ).toBeVisible();
    await expect.poll(async () => (await state(page))?.lateResults).toBe(1);
    await expect(page.getByText("Search complete:")).toHaveCount(0);
    await expect(page.getByText("Checkout API synthetic test")).toHaveCount(0);
    await expect(
      page.getByText(/No ThousandEyes search has run/),
    ).toBeVisible();
    expect((await state(page))?.searches[0].aborted).toBe(true);
  });

  test("surfaces a configuration change and stale index receipt without invalidating historical data", async ({
    page,
  }) => {
    await page.goto("/tests/browser/thousandeyes.html?fault=config-changed");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText(/configuration changed during the search/i),
    ).toBeVisible();
    await expect(
      page.getByText("No visible ThousandEyes observations were returned."),
    ).toHaveCount(0);

    await page.goto("/tests/browser/thousandeyes.html?fault=receipt-stale");
    await page
      .getByRole("button", { name: "Inspect ThousandEyes evidence" })
      .click();
    await expect(
      page.getByText(/selected evidence-index receipt is stale/i),
    ).toBeVisible();
    await expect(
      page.getByText(/does not invalidate historical measurements/i),
    ).toBeVisible();
    await expect(page.getByText("0.125")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Compare loaded measurements" }),
    ).toBeEnabled();
  });
});
