import { expect, test } from "@playwright/test";

test.describe("optional DNS and scoped endpoint investigations", () => {
  test("keeps traffic visible after optional permission failure", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=denied");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await expect(
      page.getByRole("table", { name: "Observed one-hop conversations" }),
    ).toContainText("198.51.100.20");
    await page
      .getByRole("button", { name: "Inspect DNS evidence", exact: true })
      .click();
    await expect(
      page.getByText("dns_stream: unavailable", { exact: false }),
    ).toBeVisible();
    await expect(
      page.getByRole("table", { name: "Observed one-hop conversations" }),
    ).toContainText("198.51.100.20");
  });
  test("shows DNS-only root evidence and explicit protected downloads", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=dns-only");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Inspect DNS evidence", exact: true })
      .click();
    await expect(
      page.getByRole("table", { name: "DNS resolution observations" }),
    ).toContainText("api.example.test.");
    const downloadPromise = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Export loaded DNS JSON", exact: true })
      .click();
    expect((await downloadPromise).suggestedFilename()).toBe(
      "atlas-dns-evidence.json",
    );
    await expect(page.locator(".endpoint-diagram")).toBeVisible();
  });
  test("unselected DNS dispatches no optional jobs and input edits clear stale evidence", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=off");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Inspect DNS evidence", exact: true })
      .click();
    await expect(
      page.getByText("dns_stream: not_selected", { exact: false }),
    ).toBeVisible();
    expect(
      await page.evaluate(() =>
        (
          (window as Window & { __DNS_SEARCHES__?: string[] })
            .__DNS_SEARCHES__ ?? []
        ).some((s) => s.includes("dns_completion")),
      ),
    ).toBe(false);
    await page.getByLabel("IP address", { exact: true }).fill("192.0.2.11");
    await expect(
      page.getByRole("table", { name: "DNS resolution observations" }),
    ).toHaveCount(0);
  });
  test("announces display subsets, supports keyboard actions and cancellation", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=cap&theme=dark");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .focus();
    await page.keyboard.press("Enter");
    await page
      .getByRole("button", { name: "Inspect DNS evidence", exact: true })
      .click();
    await expect(
      page.getByText("This is a capped subset.", { exact: false }),
    ).toBeVisible();
    await expect(
      page
        .getByRole("table", { name: "DNS resolution observations" })
        .locator("tbody tr"),
    ).toHaveCount(64);
    await page.goto("/tests/browser/dns-evidence.html?fault=slow");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Inspect DNS evidence", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Cancel DNS search", exact: true })
      .click();
    await expect(
      page.getByText("Cancelled. Native cleanup may remain pending.", {
        exact: true,
      }),
    ).toBeVisible();
  });
});

test("keeps wide conversation columns in a labelled keyboard-scroll region", async ({
  page,
}) => {
  await page.setViewportSize({ width: 420, height: 900 });
  await page.goto("/tests/browser/dns-evidence.html?theme=dark");
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  const region = page.getByRole("region", { name: /conversation.*table/i });
  await expect(region).toBeVisible();
  await region.focus();
  await expect(region).toBeFocused();
  expect(await region.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(
    true,
  );
  await expect(
    page.getByRole("link", { name: "Investigate peer 198.51.100.20" }),
  ).toHaveAttribute(
    "href",
    /\/en-US\/app\/splunk_adm\/endpoints\?endpoint_ip=198.51.100.20/,
  );
});
