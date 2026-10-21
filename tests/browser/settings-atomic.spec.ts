import { expect, test } from "@playwright/test";

test("server conflict preserves the draft, refreshes the saved revision, and requires explicit reload", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=deployment-server-conflict",
  );
  const source = page.getByLabel("Expectation for NetFlow", { exact: true });
  await expect(source).toBeEnabled();
  await source.selectOption("active");
  await page.getByLabel("Cadence for NetFlow", { exact: true }).fill("600");
  const save = page.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });
  await save.click();
  await expect(
    page.getByRole("alert").filter({
      hasText: "Deployment settings changed since this draft began.",
    }),
  ).toBeVisible();
  await expect(source).toHaveValue("active");
  await expect(
    page.getByLabel("Cadence for NetFlow", { exact: true }),
  ).toHaveValue("600");
  await expect(save).toBeDisabled();
  await page
    .getByRole("button", { name: "Discard draft and reload", exact: true })
    .click();
  await expect(source).toHaveValue("staged");
  await expect(save).toBeDisabled();
  await source.selectOption("active");
  await expect(save).toBeEnabled();
});

test("unqualified deployment keeps saved settings visible and explains disabled writes", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=deployment-write-disabled",
  );
  await expect(
    page.getByText("Saved expectations; active data contract: 1.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText(/Settings writes are disabled\. An operator must qualify/),
  ).toBeVisible();
  await expect(
    page.getByLabel("Expectation for ACI", { exact: true }),
  ).toHaveValue("active");
  await expect(
    page.getByRole("button", {
      name: "Save deployment expectations",
      exact: true,
    }),
  ).toBeDisabled();
});

const saveButton = (page: import("@playwright/test").Page) =>
  page.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });

test("save is withheld for a clean configured draft and offered for absent settings or edits", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  const source = page.getByLabel("Expectation for NetFlow", { exact: true });
  await expect(source).toBeEnabled();
  await expect(saveButton(page)).toBeDisabled();
  await source.selectOption("staged");
  await expect(saveButton(page)).toBeEnabled();

  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=deployment-absent",
  );
  await expect(
    page.getByText("No deployment expectations have been saved.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(saveButton(page)).toBeEnabled();
  await saveButton(page).click();
  await expect(
    page.getByText("Deployment expectations saved and verified.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(saveButton(page)).toBeDisabled();
});

async function uncertainSetup(page: import("@playwright/test").Page) {
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
    "/tests/browser/browser.html?page=setup&mode=live&fault=deployment-write-uncertain",
  );
  const source = page.getByLabel("Expectation for NetFlow", { exact: true });
  await expect(source).toBeEnabled();
  await source.selectOption("active");
  await saveButton(page).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "Save outcome is uncertain." }),
  ).toBeVisible();
  for (const value of [false, true])
    await page.evaluate(
      (next) =>
        (
          window as Window & { __setVisibility?: (value: boolean) => void }
        ).__setVisibility?.(next),
      value,
    );
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
  return source;
}

test("an uncertain save stays retryable after a passive read observes its revision", async ({
  page,
}) => {
  const source = await uncertainSetup(page);
  await expect(
    page.getByRole("alert").filter({
      hasText: "Deployment settings changed since this draft began.",
    }),
  ).toHaveCount(0);
  await expect(source).toHaveValue("active");
  await expect(saveButton(page)).toBeEnabled();
  await saveButton(page).click();
  await expect(
    page.getByText("Deployment expectations saved and verified.", {
      exact: true,
    }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () =>
        (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
          .__ADM_SETUP_REQUESTS__,
    ),
  ).toContain("deployment:recovered");
  await expect(source).toHaveValue("active");
});

test("editing a draft after an uncertain save requires a reload when a newer revision was observed", async ({
  page,
}) => {
  const source = await uncertainSetup(page);
  await page.getByLabel("Cadence for NetFlow", { exact: true }).fill("600");
  await expect(
    page.getByRole("alert").filter({
      hasText: "Deployment settings changed since this draft began.",
    }),
  ).toBeVisible();
  await expect(saveButton(page)).toBeDisabled();
  await expect(source).toHaveValue("active");
});

test("verifying a setup change keeps the checklist mounted and moves focus to the outcome", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-stale",
  );
  const sources = page.locator('[aria-label="Deployment sources"]');
  await expect(sources).toBeVisible();
  await page
    .getByRole("textbox", { name: "Index for adm_index_hubble", exact: true })
    .fill("adm_alt");
  await page
    .getByRole("button", { name: "Save adm_index_hubble", exact: true })
    .click();
  await expect(
    page.getByText("Change saved. Checking the current configuration…", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(sources).toBeVisible();
  const outcome = page.getByText("Change saved and configuration refreshed.", {
    exact: true,
  });
  await expect(outcome).toBeVisible();
  await expect(outcome).toBeFocused();
  await expect(sources).toBeVisible();
});
