import { expect, test, type Page } from "@playwright/test";

// Health polling starts its deployment read synchronously inside a passive
// effect; after a frame and a task every effect from the last commit has run.
const settleEffects = (page: Page) =>
  page.evaluate(
    () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => setTimeout(resolve, 0)),
      ),
  );

test.describe("health polling lifecycle", () => {
  test("starts hidden, pauses on hide, resumes on show, and skips Help", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      let visible = false;
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        get: () => (visible ? "visible" : "hidden"),
      });
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility = (next) => {
        visible = next;
        document.dispatchEvent(new Event("visibilitychange"));
      };
    });
    await page.goto("/tests/browser/browser.html?mode=live");
    // Scope options load from a mount effect and resolve asynchronously, so
    // health polling would already have read deployment settings if it had started.
    await expect
      .poll(() =>
        page.evaluate(() =>
          (window.__ADM_REQUESTS__ ?? []).some(
            (request) => request.spl === "| `adm_scope_options`",
          ),
        ),
      )
      .toBe(true);
    await expect(
      page.getByRole("combobox", { name: "Environment", exact: true }),
    ).toBeEnabled();
    await settleEffects(page);
    const hidden = await page.evaluate(() => ({
      health: (window.__ADM_REQUESTS__ ?? []).filter((request) =>
        request.spl.includes("adm_health"),
      ).length,
      deploymentReads: window.__ADM_DEPLOYMENT_READS__ ?? 0,
    }));
    expect(hidden).toEqual({ health: 0, deploymentReads: 0 });
    await page.clock.install();
    await page.evaluate(() =>
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility?.(true),
    );
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            (window.__ADM_REQUESTS__ ?? []).filter((request) =>
              request.spl.includes("adm_health"),
            ).length,
        ),
      )
      .toBe(4);
    await page.evaluate(() =>
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility?.(false),
    );
    const before = await page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((request) =>
          request.spl.includes("adm_health"),
        ).length,
    );
    await page.clock.fastForward(300001);
    await page.waitForTimeout(0);
    expect(
      await page.evaluate(
        () =>
          (window.__ADM_REQUESTS__ ?? []).filter((request) =>
            request.spl.includes("adm_health"),
          ).length,
      ),
    ).toBe(before);
    for (const target of ["help"]) {
      await page.goto(`/tests/browser/browser.html?page=${target}&mode=live`);
      await page.evaluate(() =>
        (
          window as Window & { __setVisibility?: (next: boolean) => void }
        ).__setVisibility?.(true),
      );
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await settleEffects(page);
      expect(
        await page.evaluate(() => ({
          health: (window.__ADM_REQUESTS__ ?? []).filter((request) =>
            request.spl.includes("adm_health"),
          ).length,
          deploymentReads: window.__ADM_DEPLOYMENT_READS__ ?? 0,
        })),
      ).toEqual({ health: 0, deploymentReads: 0 });
    }
  });
});

test("a background health refresh keeps the last assessment until new evidence arrives", async ({
  page,
}) => {
  await page.addInitScript(() => {
    let visible = true;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => (visible ? "visible" : "hidden"),
    });
    (
      window as Window & { __setVisibility?: (next: boolean) => void }
    ).__setVisibility = (next) => {
      visible = next;
      document.dispatchEvent(new Event("visibilitychange"));
    };
  });
  await page.goto("/tests/browser/browser.html?mode=live&fault=health-hold");
  const indicator = page.locator("a.health-status");
  const healthRequests = () =>
    page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((request) =>
          request.spl.includes("adm_health"),
        ).length,
    );
  await expect.poll(healthRequests).toBe(4);
  await expect(indicator).not.toHaveClass(/health-loading/);
  const settled = await indicator.getAttribute("class");
  await page.evaluate(() => {
    (window as Window & { __ADM_HOLD_HEALTH__?: boolean }).__ADM_HOLD_HEALTH__ =
      true;
  });
  for (const next of [false, true])
    await page.evaluate(
      (value) =>
        (
          window as Window & { __setVisibility?: (next: boolean) => void }
        ).__setVisibility?.(value),
      next,
    );
  await expect.poll(healthRequests).toBeGreaterThan(4);
  await expect(indicator).toHaveAttribute("class", settled!);
  await page.evaluate(() => {
    const target = window as Window & {
      __ADM_HOLD_HEALTH__?: boolean;
      __ADM_HELD__?: (() => void)[];
    };
    target.__ADM_HOLD_HEALTH__ = false;
    for (const release of target.__ADM_HELD__ ?? []) release();
  });
  await expect.poll(healthRequests).toBe(8);
  await expect(indicator).toHaveAttribute("class", settled!);
});

test("Setup fetches scheduler evidence once, refreshes manually, and does not poll source health", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  await expect(
    page.getByRole("heading", { name: "Builder schedules", exact: true }),
  ).toBeVisible();
  const requests = () =>
    page.evaluate(() =>
      (window.__ADM_REQUESTS__ ?? [])
        .filter((request) => request.spl.includes("adm_health"))
        .map((request) => request.spl),
    );
  await expect.poll(requests).toEqual(["| `adm_health_jobs`"]);
  const row = page.getByRole("row").filter({
    has: page.getByRole("cell", {
      name: "ADM - Identity builder",
      exact: true,
    }),
  });
  await expect(row).toContainText("2023-11-14T22:13:20.000Z");
  await page.clock.install();
  await page.clock.fastForward(300001);
  expect(await requests()).toEqual(["| `adm_health_jobs`"]);
  await page
    .getByRole("button", { name: "Refresh checklist", exact: true })
    .click();
  await expect.poll(requests).toHaveLength(2);
  expect(await requests()).toEqual([
    "| `adm_health_jobs`",
    "| `adm_health_jobs`",
  ]);
});

test("Setup validates administrator source cadence before saving expectations", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  const save = page.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });
  // A clean configured draft must not spend a bounded-history slot.
  await expect(save).toBeDisabled();
  await page.getByLabel("Cadence for NetFlow", { exact: true }).fill("0");
  await expect(save).toBeDisabled();
  await page.getByLabel("Cadence for NetFlow", { exact: true }).fill("300");
  await page
    .getByLabel("Expectation for NetFlow", { exact: true })
    .selectOption("staged");
  await expect(save).toBeEnabled();
  await save.click();
  await expect(
    page.getByText("Deployment expectations saved and verified.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toHaveValue("staged");
});

test("Setup keeps unavailable expectations and scheduler evidence explicit", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=deployment-unavailable",
  );
  await expect(
    page.getByText("Deployment settings permission denied.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Save deployment expectations",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", {
      name: "Enable schedule for ADM - Identity builder",
      exact: true,
    }),
  ).toBeDisabled();
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=health-permission",
  );
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Scheduler evidence permission denied." }),
  ).toBeVisible();
  const row = page.getByRole("row").filter({
    has: page.getByRole("cell", {
      name: "ADM - Identity builder",
      exact: true,
    }),
  });
  await expect(row).toContainText("Unknown");
});

test("Setup refreshes only scheduler evidence after verified builder writes", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  const requests = () =>
    page.evaluate(() =>
      (window.__ADM_REQUESTS__ ?? [])
        .filter((request) => request.spl.includes("adm_health"))
        .map((request) => request.spl),
    );
  await expect.poll(requests).toEqual(["| `adm_health_jobs`"]);
  await page
    .getByRole("button", {
      name: "Enable schedule for ADM - Identity builder",
      exact: true,
    })
    .click();
  await expect
    .poll(requests)
    .toEqual(["| `adm_health_jobs`", "| `adm_health_jobs`"]);
});

for (const [fault, observation] of [
  ["health-failed", "Last run: failed"],
  ["health-skipped", "Last run: skipped"],
  ["health-overdue", "Successful run is overdue"],
]) {
  test(`Setup displays ${fault} run evidence beside its schedule`, async ({
    page,
  }) => {
    await page.goto(
      `/tests/browser/browser.html?page=setup&mode=live&fault=${fault}`,
    );
    const row = page.getByRole("row").filter({
      has: page.getByRole("cell", {
        name: "ADM - Identity builder",
        exact: true,
      }),
    });
    await expect(row).toContainText(observation);
    await expect(
      page.getByRole("columnheader", {
        name: "Last run / success (UTC)",
        exact: true,
      }),
    ).toBeVisible();
  });
}

async function draftSetup(page: import("@playwright/test").Page, fault = "") {
  await page.addInitScript(() => {
    let visible = true;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => (visible ? "visible" : "hidden"),
    });
    (
      window as Window & { __setVisibility?: (value: boolean) => void }
    ).__setVisibility = (value) => {
      visible = value;
      document.dispatchEvent(new Event("visibilitychange"));
    };
  });
  await page.goto(
    `/tests/browser/browser.html?page=setup&mode=live${fault ? `&fault=${fault}` : ""}`,
  );
  const save = page.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toBeEnabled();
  await expect(save).toBeDisabled();
  await page
    .getByLabel("Expectation for NetFlow", { exact: true })
    .selectOption("active");
  await page.getByLabel("Cadence for NetFlow", { exact: true }).fill("600");
  await expect(save).toBeEnabled();
  await page.evaluate(() =>
    (
      window as Window & { __setVisibility?: (value: boolean) => void }
    ).__setVisibility?.(false),
  );
  await page.evaluate(() =>
    (
      window as Window & { __setVisibility?: (value: boolean) => void }
    ).__setVisibility?.(true),
  );
}
test("Setup preserves an unsaved expectation draft when another tab causes a passive refresh", async ({
  page,
}) => {
  await draftSetup(page);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window.__ADM_REQUESTS__ ?? []).filter((request) =>
            request.spl.includes("adm_health_jobs"),
          ).length,
      ),
    )
    .toBe(2);
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toHaveValue("active");
  await expect(
    page.getByLabel("Cadence for NetFlow", { exact: true }),
  ).toHaveValue("600");
  await expect(
    page.getByText(
      "Unsaved deployment changes are preserved across background checks.",
      { exact: true },
    ),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Discard draft and reload", exact: true })
    .click();
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toHaveValue("not_selected");
});
test("Setup keeps a dirty draft and blocks save when a passive read finds a newer revision", async ({
  page,
}) => {
  await draftSetup(page, "deployment-revision-change");
  await expect(
    page.getByRole("alert").filter({
      hasText: "Deployment settings changed since this draft began.",
    }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toHaveValue("active");
  await expect(
    page.getByRole("button", {
      name: "Save deployment expectations",
      exact: true,
    }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Discard draft and reload", exact: true })
    .click();
  await expect(
    page.getByLabel("Expectation for NetFlow", { exact: true }),
  ).toHaveValue("staged");
  const save = page.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });
  await expect(save).toBeDisabled();
  await page
    .getByLabel("Expectation for NetFlow", { exact: true })
    .selectOption("active");
  await expect(save).toBeEnabled();
});
