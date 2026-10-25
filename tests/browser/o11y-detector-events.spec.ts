import { expect, test } from "@playwright/test";

interface SearchState {
  search: string;
  aborted: boolean;
  released: boolean;
  abortSettled: boolean;
}

type DetectorTestWindow = Window & {
  __O11Y_DETECTOR_TEST__?: { searches: SearchState[] };
};

const searches = (page: import("@playwright/test").Page) =>
  page.evaluate(
    () => (window as DetectorTestWindow).__O11Y_DETECTOR_TEST__?.searches ?? [],
  );

test("cancelling an detector event search leaves the panel retryable", async ({
  page,
}) => {
  await page.goto("/tests/browser/o11y-detector-events.html");
  const inspect = page.getByRole("button", {
    name: "Inspect detector events",
    exact: true,
  });
  await expect(inspect).toBeEnabled();
  await inspect.click();

  await expect(
    page.getByText("Loading a completed indexed detector capture…"),
  ).toBeVisible();
  await expect.poll(async () => (await searches(page)).length).toBe(1);
  await expect(
    page.getByRole("button", { name: "Cancel detector search", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Cancel detector search", exact: true })
    .click();

  await expect(
    page.getByText("Detector search cancelled. You can inspect events again."),
  ).toBeVisible();
  await expect(inspect).toBeEnabled();
  await expect
    .poll(async () => (await searches(page))[0])
    .toMatchObject({ aborted: true, released: true, abortSettled: true });
  await expect(
    page.getByRole("table", {
      name: "Observed detector events",
    }),
  ).toHaveCount(0);

  await inspect.click();
  await expect.poll(async () => (await searches(page)).length).toBe(2);
  await expect(
    page.getByRole("table", {
      name: "Observed detector events",
    }),
  ).toContainText("event-trigger-001");
  await expect(page.getByText("Detector source: complete")).toBeVisible();
  expect(await searches(page)).toMatchObject([
    { aborted: true, released: true },
    { aborted: false, released: true },
  ]);
});
