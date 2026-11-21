import { expect, test, type Page } from "@playwright/test";

async function expectScopedGap(page: Page, scenario: "acl" | "pod") {
  await page.goto(`/tests/browser/trace-gaps.html?case=${scenario}`);
  const pair =
    scenario === "acl"
      ? "192.0.2.3 to 198.51.100.2"
      : "10.244.1.10 to 10.244.2.20";
  const trace = page.getByRole("region", { name: `Trace ${pair}` });
  await expect(trace).toContainText("Source coverage incomplete");
  await expect(trace).toContainText(
    "A complete scoped packet route is unavailable for this window.",
  );
  await expect(trace).toContainText(
    "missing observations do not prove absence",
  );
  await expect(trace).not.toContainText("Blocked tcp/");
  await expect(
    trace.getByRole("list", { name: "Hops" }).getByRole("button"),
  ).toHaveCount(1);
}

test("an ACI pair remains partial without a time-qualified topology path", async ({
  page,
}) => {
  await expectScopedGap(page, "acl");
});

test("a pod pair remains partial without a time-qualified topology path", async ({
  page,
}) => {
  await expectScopedGap(page, "pod");
});
