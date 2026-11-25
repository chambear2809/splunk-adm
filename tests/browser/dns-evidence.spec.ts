import { expect, test } from "@playwright/test";

test.describe("optional DNS and scoped endpoint investigations", () => {
  test("a capped Flow Logs status search leaves matching endpoint flows visible", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=cloud-cap");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Inspect Flow Logs evidence" })
      .click();
    const panel = page.getByRole("region", {
      name: "Optional AWS VPC Flow Logs evidence",
    });
    await expect(panel.getByRole("status")).toHaveText(
      "1 visible endpoint flow records; 1 flow inputs.",
    );
    await expect(
      panel.getByText(/Capture-wide status: 65 inputs.*display cap reached/),
    ).toBeVisible();
    await expect(
      panel.getByRole("row").filter({ hasText: "Selected address matched" }),
    ).toHaveCount(1);
    await expect(
      panel.getByRole("row").filter({ hasText: "SKIPDATA" }),
    ).toHaveCount(64);
  });

  test("keeps optional sources together and isolates an unselected source from traffic", async ({
    page,
  }) => {
    await page.goto("/tests/browser/dns-evidence.html?fault=off");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await expect(page.getByLabel("Scoped endpoint evidence")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Inspect proxy evidence" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Inspect Flow Logs evidence" }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Inspect asset history" }),
    ).toBeVisible();
    const before = await page.evaluate(
      () =>
        (
          (window as Window & { __DNS_SEARCHES__?: string[] })
            .__DNS_SEARCHES__ ?? []
        ).length,
    );
    await page.getByRole("button", { name: "Inspect proxy evidence" }).click();
    await expect(
      page.getByText(
        "Proxy evidence is off. An administrator must select and qualify an Envoy source before a search can run.",
      ),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Inspect Flow Logs evidence" })
      .click();
    await expect(page.getByText("Source state: not_selected.")).toBeVisible();
    await page.getByRole("button", { name: "Inspect asset history" }).click();
    await expect(
      page
        .locator('section[aria-labelledby="inventory-evidence-title"]')
        .getByText("state: not_selected", { exact: false }),
    ).toBeVisible();
    const after = await page.evaluate(
      () =>
        (
          (window as Window & { __DNS_SEARCHES__?: string[] })
            .__DNS_SEARCHES__ ?? []
        ).length,
    );
    expect(after).toBe(before);
    await expect(
      page.getByRole("table", { name: "Observed one-hop conversations" }),
    ).toContainText("198.51.100.20");
  });
  for (const finish of ["resolve", "reject"]) {
    test(`does not publish a cancelled asset-history recheck that will ${finish} after retry`, async ({
      page,
    }) => {
      await page.goto(
        "/tests/browser/dns-evidence.html?fault=asset-race" +
          (finish === "reject" ? "&reject=1" : ""),
      );
      await page
        .getByRole("button", { name: "Investigate", exact: true })
        .click();
      const panel = page.locator(
        'section[aria-labelledby="inventory-evidence-title"]',
      );
      await panel
        .getByRole("button", { name: "Inspect asset history" })
        .click();
      await expect(page.locator("body")).toHaveAttribute(
        "data-asset-recheck",
        "pending",
      );
      await panel.getByRole("button", { name: "Cancel", exact: true }).click();
      await panel
        .getByRole("button", { name: "Inspect asset history" })
        .click();
      await expect(panel.getByRole("row", { name: /asset-new/ })).toBeVisible();
      await page.evaluate(() =>
        (
          window as Window & { __RELEASE_ASSET__?: () => void }
        ).__RELEASE_ASSET__?.(),
      );
      await expect(page.locator("body")).toHaveAttribute(
        "data-asset-recheck",
        "settled",
      );
      await expect(panel.getByRole("row", { name: /asset-old/ })).toHaveCount(
        0,
      );
      await expect(panel.getByRole("row", { name: /asset-new/ })).toBeVisible();
      await expect(panel).not.toContainText("Source configuration changed");
    });
  }
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
