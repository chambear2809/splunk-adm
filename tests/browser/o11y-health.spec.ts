import { expect, test } from "@playwright/test";

interface SearchState {
  search: string;
  aborted: boolean;
  released: boolean;
  abortSettled: boolean;
}

type HealthTestWindow = Window & {
  __O11Y_HEALTH_TEST__?: { searches: SearchState[] };
};

const searches = (page: import("@playwright/test").Page) =>
  page.evaluate(
    () => (window as HealthTestWindow).__O11Y_HEALTH_TEST__?.searches ?? [],
  );

test("cancelling an Observability health search leaves the panel retryable", async ({
  page,
}) => {
  await page.goto("/tests/browser/o11y-health.html");
  const inspect = page.getByRole("button", {
    name: "Inspect service health",
    exact: true,
  });
  await expect(inspect).toBeEnabled();
  await inspect.click();

  await expect(
    page.getByText("Loading an indexed, completed Observability Cloud export…"),
  ).toBeVisible();
  await expect.poll(async () => (await searches(page)).length).toBe(1);
  await expect(
    page.getByRole("button", { name: "Cancel health search", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Cancel health search", exact: true })
    .click();

  await expect(
    page.getByText(
      "Health search cancelled. You can inspect this service again.",
    ),
  ).toBeVisible();
  await expect(inspect).toBeEnabled();
  await expect
    .poll(async () => (await searches(page))[0])
    .toMatchObject({ aborted: true, released: true, abortSettled: true });
  await expect(
    page.getByRole("table", {
      name: "Measured Observability Cloud service health",
    }),
  ).toHaveCount(0);

  await inspect.click();
  await expect.poll(async () => (await searches(page)).length).toBe(2);
  await expect(
    page.getByRole("table", {
      name: "Measured Observability Cloud service health",
    }),
  ).toContainText("Service requests");
  await expect(page.getByText("Health source: complete")).toBeVisible();
  expect(await searches(page)).toMatchObject([
    { aborted: true, released: true },
    { aborted: false, released: true },
  ]);
});
