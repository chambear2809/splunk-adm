import { expect, test } from "@playwright/test";

for (const acl of ["cross", "same", "mixed"]) {
  test(`qualifies the ${acl} ACL comparison in the incident workspace`, async ({
    page,
  }) => {
    await page.goto(`/tests/browser/investigation.html?acl=${acl}`);
    await page
      .getByRole("button", { name: "Compare windows", exact: true })
      .click();
    const lead = page.locator("details.atlas-incident-finding");
    await expect(lead.locator("summary")).toHaveText(
      acl === "same"
        ? "Policy blocking may have changed · Supported"
        : "Policy blocking may be relevant · Needs evidence",
    );
    await lead.locator("summary").click();
    await expect(lead).toContainText(
      acl === "same"
        ? "baseline permit and incident drop reported"
        : "incident drop reported; baseline permit reported; a shared policy point is unverified",
    );
  });
}

test("incident leads disclose ranked evidence and uncertainty", async ({
  page,
}) => {
  const reviewWidth = Number(process.env.ADM_REVIEW_WIDTH || 1440);
  const reviewTheme = process.env.ADM_REVIEW_THEME || "light";
  if (process.env.ADM_FINAL_REVIEW_SCREENSHOTS)
    await page.setViewportSize({ width: reviewWidth, height: 900 });
  await page.goto(`/tests/browser/investigation.html?theme=${reviewTheme}`);
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  const investigation = page.getByRole("region", {
    name: "Incident investigation",
  });
  await expect(
    investigation.getByRole("heading", {
      name: "Prioritized investigation leads",
    }),
  ).toBeVisible();
  await expect(investigation).toContainText("not likelihood or cause");
  const leads = investigation.locator("details.atlas-incident-finding");
  await expect(leads).toHaveCount(2);
  await expect(leads.nth(0)).toContainText(
    "Newly observed connections may need review",
  );
  await expect(leads.nth(1)).toContainText("Policy blocking may be relevant");
  await leads.first().locator(":scope > summary").click();
  await expect(leads.first()).toContainText("Supports");
  await expect(leads.first().getByText(/Showing 3 of/)).toBeVisible();
  await expect(leads.first().getByText(/Show remaining/)).toBeVisible();
  await expect(leads.first().getByText(/Next read-only check:/)).toBeVisible();
  await expect(leads.first()).toContainText("Counterevidence");
  await expect(leads.first()).toContainText(
    "No direct counterevidence available in these snapshots.",
  );
  await expect(leads.first()).toContainText("Missing evidence");
  await expect(
    investigation.getByText("Partial or uncertain evidence"),
  ).toBeVisible();
  if (process.env.ADM_FINAL_REVIEW_SCREENSHOTS) {
    await investigation.screenshot({
      path: `/tmp/atlas-feature-final-review/incident-${reviewWidth}-${reviewTheme}.png`,
    });
  }
});
