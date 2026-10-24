import { expect, test } from "@playwright/test";

interface ScopeReadState {
  aborted: boolean;
  settled: boolean;
}

type MapServiceHealthTestWindow = Window & {
  __MAP_SERVICE_HEALTH_TEST__?: { reads: ScopeReadState[] };
};

const reads = (page: import("@playwright/test").Page) =>
  page.evaluate(
    () =>
      (window as MapServiceHealthTestWindow).__MAP_SERVICE_HEALTH_TEST__
        ?.reads ?? [],
  );

test("cancelling a map health scope read leaves refresh enabled", async ({
  page,
}) => {
  await page.goto("/tests/browser/map-service-health.html");
  const refresh = page.getByRole("button", {
    name: "Refresh health scope",
    exact: true,
  });
  await expect(refresh).toBeEnabled();
  await refresh.click();
  await expect(
    page.getByRole("button", { name: "Cancel scope read", exact: true }),
  ).toBeVisible();
  await expect.poll(async () => (await reads(page)).length).toBe(1);

  await page
    .getByRole("button", { name: "Cancel scope read", exact: true })
    .click();
  await expect(
    page.getByText(
      "Scope read cancelled. You can refresh the health scope again.",
    ),
  ).toBeVisible();
  await expect(refresh).toBeEnabled();
  await expect
    .poll(async () => (await reads(page))[0])
    .toMatchObject({ aborted: true, settled: true });

  await refresh.click();
  await expect.poll(async () => (await reads(page)).length).toBe(2);
  await expect(
    page.getByRole("combobox", { name: "Service health routing scope" }),
  ).toHaveValue("prod-east");
  await expect(
    page.getByRole("button", { name: "Inspect service health", exact: true }),
  ).toBeEnabled();
  expect(await reads(page)).toMatchObject([
    { aborted: true, settled: true },
    { aborted: false, settled: true },
  ]);
});
