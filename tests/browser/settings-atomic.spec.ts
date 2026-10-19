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
