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

test("network baseline versions and watch evaluation use authorized references and retry withheld receipts", async ({
  page,
}) => {
  let lost = false;
  const writes: { key: string; body: unknown }[] = [];
  const start = 1791373400;
  const capture = (windowStart: number) => ({
    id: `synthetic-${windowStart}`,
    coverage: {
      requested: { start: windowStart, end: windowStart + 300 },
      returned: { start: windowStart, end: windowStart + 300 },
      authority: "synthetic",
      scope: "synthetic",
      sourceRevision: "v1",
      configRevision: "c1",
      normalizationRevision: "n1",
      signatureVersion: 1,
      permission: "allowed",
      complete: true,
      capped: false,
      progressive: false,
      sampled: false,
      stale: false,
      knowledgeHorizon: windowStart + 360,
      requiredLatenessSeconds: 60,
    },
    dependencies: [
      {
        authority: "synthetic",
        scope: "synthetic",
        source: "service:a",
        destination: "service:b",
        protocol: "tcp",
        port: 443,
        relation: "calls",
        direction: "forward",
        blocked: false,
      },
    ],
  });
  await page.route("**/test-monitor/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          sourceAvailable: true,
          qualificationReasons: [],
        },
      });
    if (path.endsWith("/capture"))
      return route.fulfill({
        json: { reference: "synthetic-reference", capture: capture(start) },
      });
    if (path.endsWith("/baselines"))
      return route.fulfill({
        json: {
          items: [
            {
              id: "baseline-1",
              name: "Synthetic baseline",
              revision: 3,
              version: 2,
            },
          ],
          next: null,
        },
      });
    if (path.endsWith("/versions"))
      return route.fulfill({
        json: { items: [{ version: 1 }, { version: 2 }], next: null },
      });
    if (path.endsWith("/watches"))
      return route.fulfill({
        json: {
          items: [
            {
              id: "watch-1",
              baselineVersion: 1,
              threshold: 2,
              cooldownSeconds: 60,
              expectedWindows: [],
            },
          ],
          next: null,
        },
      });
    if (path.endsWith("/occurrences"))
      return route.fulfill({
        json: {
          items: [
            {
              seq: url.searchParams.has("after") ? 2 : 1,
              signature: JSON.stringify([
                1,
                "synthetic",
                "synthetic",
                "service:a",
                "service:b",
                "tcp",
                443,
                "calls",
                "forward",
              ]),
              window: url.searchParams.has("after")
                ? { start, end: start + 300 }
                : { start: start - 300, end: start },
              observedAt: url.searchParams.has("after")
                ? start + 310
                : start + 10,
              baselineVersion: 1,
              changeKinds: url.searchParams.has("after")
                ? ["not_observed"]
                : ["newly_blocked", "lost_redundancy"],
            },
          ],
          next: url.searchParams.has("after") ? null : 1,
        },
      });
    if (path.endsWith("/evaluate") && request.method() === "GET")
      return route.fulfill({
        json: {
          count: 2,
          thresholdMet: true,
          expected: false,
          coolingDown: true,
        },
      });
    if (path.endsWith("/evaluate")) {
      writes.push({
        key: request.headers()["idempotency-key"],
        body: request.postDataJSON(),
      });
      if (!lost) {
        lost = true;
        return route.abort("failed");
      }
      return route.fulfill({
        json: { id: "baseline-1", revision: 4, resultWithheld: true },
      });
    }
    return route.fulfill({
      json: {
        id: "baseline-1",
        name: "Synthetic baseline",
        revision: 3,
        version: path.endsWith("/versions/1") ? 1 : 2,
        capture: capture(start - 300),
      },
    });
  });
  const reviewWidth = Number(process.env.ADM_REVIEW_WIDTH || 1440);
  const reviewTheme = process.env.ADM_REVIEW_THEME || "light";
  if (process.env.ADM_FINAL_REVIEW_SCREENSHOTS)
    await page.setViewportSize({ width: reviewWidth, height: 900 });
  await page.goto(
    `/tests/browser/planning.html?mode=network&theme=${reviewTheme}`,
  );
  await page
    .getByRole("button", { name: "Read complete dependency evidence" })
    .click();
  await page
    .getByRole("button", { name: "List baselines", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Synthetic baseline · version 2" })
    .click();
  await page.getByRole("button", { name: "Open version 1" }).click();
  await expect(
    page.getByText(/baseline version 1 · threshold 2/),
  ).toBeVisible();
  await page.getByRole("button", { name: "Read watch occurrences" }).click();
  const observations = page.getByRole("region", { name: "Watch occurrences" });
  await expect(observations).toContainText(
    "1 loaded observations; more are available.",
  );
  await expect(observations).toContainText("service:a → service:b · tcp/443");
  await expect(observations).toContainText("Newly reported blocked");
  await expect(observations).toContainText("Fewer observed failure domains");
  await expect(observations).toContainText("Compared with baseline version 1");
  const details = observations.getByText("Source and relationship details");
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(observations).toContainText("Authority: synthetic");
  await expect(observations).not.toContainText("[1,");
  await page.getByRole("button", { name: "Read status", exact: true }).click();
  await expect(
    page.getByRole("region", { name: "Authorized watch status" }),
  ).toContainText("2 distinct observation windows; threshold met");
  await expect(
    page.getByRole("region", { name: "Authorized watch status" }),
  ).toContainText("expected window inactive; cooldown active");
  await expect(observations).toContainText(
    "Counts distinct recorded windows with any qualifying change for this dependency, across change types.",
  );
  await page.getByRole("button", { name: "Load more occurrences" }).click();
  await expect(observations).toContainText("2 loaded observations.");
  await expect(observations).toContainText("Not observed in this window");
  await expect(observations).not.toContainText("removed");
  await expect(
    page.getByRole("button", { name: "Load more occurrences" }),
  ).toHaveCount(0);
  if (process.env.ADM_FINAL_REVIEW_SCREENSHOTS) {
    await observations
      .getByRole("button", { name: "Read status", exact: true })
      .first()
      .click();
    await observations.screenshot({
      path: `${process.env.ADM_REVIEW_SCREENSHOT_DIR || "/tmp/atlas-feature-final-review"}/watch-${reviewWidth}-${reviewTheme}.png`,
    });
  }
  await page
    .getByRole("button", { name: "Open version 2", exact: true })
    .click();
  await expect(
    page.getByRole("region", { name: "Watch occurrences", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("region", { name: "Authorized watch status" }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Read watch occurrences", exact: true })
    .click();
  await page.getByRole("button", { name: "Read status", exact: true }).click();
  await expect(
    page.getByRole("region", { name: "Authorized watch status" }),
  ).toBeVisible();
  await page
    .getByRole("button", {
      name: "Synthetic baseline · version 2",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("region", { name: "Watch occurrences", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("region", { name: "Authorized watch status" }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Open version 1", exact: true })
    .click();
  await page.getByRole("button", { name: "Evaluate current evidence" }).click();
  await expect(
    page.getByRole("button", { name: "Retry same baseline request" }),
  ).toBeEnabled();
  await page
    .getByRole("button", { name: "Retry same baseline request" })
    .click();
  await expect(page.getByRole("status")).toContainText("result is withheld");
  expect(writes).toHaveLength(2);
  expect(writes[0]).toEqual(writes[1]);
  expect(writes[0].body).toEqual({
    expected_revision: 3,
    baseline_version: 1,
    reference: "synthetic-reference",
  });
});

test("network source denial leaves only metadata and never fabricates capture", async ({
  page,
}) => {
  const paths: string[] = [];
  await page.route("**/test-monitor/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    paths.push(path);
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          sourceAvailable: false,
          qualificationReasons: ["No loss or lateness proof"],
        },
      });
    if (path.endsWith("/baselines"))
      return route.fulfill({
        json: {
          items: [
            { id: "b", name: "Metadata baseline", revision: 1, version: 1 },
          ],
          next: null,
        },
      });
    if (path.endsWith("/versions"))
      return route.fulfill({ json: { items: [{ version: 1 }], next: null } });
    if (path.endsWith("/watches"))
      return route.fulfill({
        json: {
          items: [
            {
              id: "watch",
              baselineVersion: 1,
              threshold: 2,
              cooldownSeconds: 60,
              expectedWindows: [],
            },
          ],
          next: null,
        },
      });
    return route.fulfill({ status: 403, json: {} });
  });
  await page.goto("/tests/browser/planning.html?mode=network");
  await expect(
    page.getByText(
      "A qualified complete dependency source is unavailable for this selection.",
    ),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "List baselines", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Metadata baseline · version 1" })
    .click();
  await expect(
    page.getByRole("button", { name: "Open version 1" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Evaluate current evidence" }),
  ).toBeDisabled();
  await expect(
    page.getByText(/baseline version 1 · threshold 2/),
  ).toBeVisible();
  expect(paths).toEqual([
    "/test-monitor/capabilities",
    "/test-monitor/baselines",
    "/test-monitor/baselines/b/versions",
    "/test-monitor/baselines/b/watches",
  ]);
});
