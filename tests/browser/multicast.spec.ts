import { expect, test, type Page } from "@playwright/test";
import configuration from "../../fixtures/multicast/profiles.json" with { type: "json" };

const earliest = 1795283857;
const latest = earliest + 300;
const sharedPath = "**/storage/collections/data/adm_multicast_profiles?*";
const link = (fault = "") =>
  `/tests/browser/browser.html?page=multicast&mode=live&mc_v=1&mc_scope=lab%3Amedia&mc_group=239.1.2.3&mc_sender=192.0.2.20&mc_earliest=${earliest}&mc_latest=${latest}${fault ? `&fault=${fault}` : ""}`;

const scopeLink = (fault = "") =>
  `/tests/browser/browser.html?page=multicast&mode=live&mc_v=1&mc_scope=lab%3Amedia&mc_earliest=${earliest}&mc_latest=${latest}${fault ? `&fault=${fault}` : ""}`;
const requests = (page: Page) =>
  page.evaluate(() => window.__ADM_REQUESTS__?.length ?? 0);

async function profiles(page: Page, active: ReadonlyArray<object>) {
  await page.route(sharedPath, (route) =>
    route.fulfill({
      json: active.length
        ? [
            {
              _key: "active",
              configuration: JSON.stringify({
                ...configuration,
                profiles: active,
              }),
            },
          ]
        : [],
    }),
  );
}

test("opens the top-level Multicast route directly", async ({ page }) => {
  await page.goto("/multicast?service=bad%22&tab=invalid");
  await expect(
    page.getByRole("heading", { name: "Multicast", exact: true }),
  ).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Application Atlas" });
  await expect(
    nav.getByRole("link", { name: "Multicast", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    nav.getByRole("link", { name: "Map", exact: true }),
  ).toHaveAttribute("href", "/map");
  await expect(page.getByText("Some link parameters were invalid")).toHaveCount(
    0,
  );
});

test("shows multicast setup with no active source and dispatches no search", async ({
  page,
}) => {
  await profiles(page, []);
  await page.goto(link());
  await expect(page.getByText(/Setup required/)).toBeVisible();
  await expect(page.getByText(/Stream IGMP|NetFlow/)).toBeVisible();
  expect(await page.evaluate(() => window.__ADM_REQUESTS__ ?? [])).toEqual([]);
});

for (const [source, heading, address, absent] of [
  ["multicast_igmp", "Receiver interest", "192.0.2.10", "192.0.2.20"],
  ["multicast_netflow", "Senders", "192.0.2.20", "192.0.2.10"],
] as const) {
  test(`restores a deep link and renders ${source} evidence alone`, async ({
    page,
  }) => {
    await profiles(
      page,
      configuration.profiles.filter((profile) => profile.source === source),
    );
    await page.goto(link());
    await expect(
      page.getByRole("combobox", { name: "Scope", exact: true }),
    ).toHaveValue("lab:media");
    await expect(page.getByLabel("Multicast group")).toHaveValue("239.1.2.3");
    await expect(page.getByLabel("Sender (optional)")).toHaveValue(
      "192.0.2.20",
    );
    await page.getByRole("button", { name: "Investigate group" }).click();
    const map = page.getByRole("group", { name: "Observed evidence map" });
    await expect(map).toHaveCSS("display", "grid");
    await expect(
      map.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    await expect(
      map.getByRole("button", { name: new RegExp(address) }),
    ).toBeVisible();
    await expect(
      map.getByRole("button", { name: new RegExp(absent) }),
    ).toHaveCount(0);
    await expect(page.getByRole("table")).toContainText(address);
    const dispatched = await page.evaluate(() => window.__ADM_REQUESTS__ ?? []);
    expect(dispatched).toHaveLength(1);
    expect(dispatched[0]).toMatchObject({
      earliest: String(earliest),
      latest: String(latest),
    });
    expect(new URL(page.url()).searchParams.get("mc_sender")).toBe(
      "192.0.2.20",
    );
  });
}

test("keeps the shared Multicast navigation link in sync after edits", async ({
  page,
}) => {
  await profiles(page, configuration.profiles);
  await page.goto(link());
  await page.getByLabel("Sender (optional)").fill("192.0.2.21");
  await page.getByRole("button", { name: "Investigate group" }).click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("mc_sender"))
    .toBe("192.0.2.21");
  await expect(
    page
      .getByRole("navigation", { name: "Application Atlas" })
      .getByRole("link", { name: "Multicast", exact: true }),
  ).toHaveAttribute("href", /mc_sender=192\.0\.2\.21/);
});

test("cancels a running investigation and discards late evidence", async ({
  page,
}) => {
  await profiles(page, configuration.profiles);
  await page.goto(link("multicast-slow"));
  await page.getByRole("button", { name: "Investigate group" }).click();
  await expect
    .poll(() => page.evaluate(() => window.__ADM_REQUESTS__?.length))
    .toBeGreaterThan(0);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("status")).toContainText(
    "Investigation cancelled",
  );
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("reports blocked caller access", async ({ page }) => {
  await profiles(page, configuration.profiles);
  await page.goto(link("multicast-blocked"));
  await page.getByRole("button", { name: "Investigate group" }).click();
  await expect(page.getByText(/Stream IGMP.*blocked/)).toBeVisible();
  await expect(page.getByText(/Stream NetFlow.*blocked/)).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("reports blocked caller access on the scope-wide Overview", async ({
  page,
}) => {
  await profiles(page, configuration.profiles);
  await page.goto(scopeLink("multicast-blocked"));
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await expect(page.getByText(/Stream IGMP.*blocked/)).toBeVisible();
  await expect(page.getByText(/Stream NetFlow.*blocked/)).toBeVisible();
  await expect(
    page.getByText("No source in this scope completed its search"),
  ).toBeVisible();
  await expect(
    page.getByText("No caller-visible multicast groups"),
  ).toHaveCount(0);
  await expect(page.getByRole("table")).toHaveCount(0);

  await page.getByRole("tab", { name: "Matrix" }).click();
  await expect(page.getByText(/Stream IGMP.*blocked/)).toBeVisible();
  await expect(page.getByText(/Stream NetFlow.*blocked/)).toBeVisible();
  await expect(
    page.getByText("No source in this scope completed its search"),
  ).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
});

test("discards evidence when the active source verification changes", async ({
  page,
}) => {
  let reads = 0;
  await page.route(sharedPath, (route) =>
    route.fulfill({
      json:
        ++reads < 3
          ? [{ _key: "active", configuration: JSON.stringify(configuration) }]
          : [],
    }),
  );
  await page.goto(link());
  await page.getByRole("button", { name: "Investigate group" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Source verification changed",
  );
  await expect(page.getByRole("table")).toHaveCount(0);
  await page.getByRole("button", { name: "Refresh sources" }).click();
  await expect(page.getByText(/Setup required/)).toBeVisible();
});

test("loads the indexed NX-OS cohort and drills down to each branch", async ({
  page,
}) => {
  await profiles(page, [
    {
      ...configuration.profiles[0],
      source: "multicast_nxos",
      id: "nxos-underlay",
      observer: "atlas-nxos-snapshot",
    },
  ]);
  await page.goto(link());
  await page.getByRole("button", { name: "Investigate group" }).click();
  const map = page.getByRole("group", { name: "Observed evidence map" });
  await expect(map.getByText("Supported link", { exact: true })).toHaveCount(4);
  await expect(
    map.getByText("Next hop unresolved", { exact: true }),
  ).toHaveCount(2);
  await map.getByRole("button", { name: /spine-b \/ eth1\/4/ }).click();
  await expect(page.locator(".multicast-selected")).toContainText(
    "observer: spine-b",
  );
  const [search] = await page.evaluate(() => window.__ADM_REQUESTS__ ?? []);
  expect(search).toMatchObject({ latest: String(latest + 1) });
  expect(search.spl).toContain('sourcetype="atlas:nxos:multicast:v1"');
});

test("an old group link opens the group detail", async ({ page }) => {
  await profiles(page, configuration.profiles);
  await page.goto(link());
  await expect(
    page.getByRole("button", { name: "Back to Overview" }),
  ).toBeVisible();
  await expect(page.getByLabel("Multicast group")).toHaveValue("239.1.2.3");
  await expect(page.getByLabel("Sender (optional)")).toHaveValue("192.0.2.20");
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(await requests(page)).toBe(0);
});

test("defaults to the overview tab and drills into a group from the matrix", async ({
  page,
}) => {
  await profiles(page, configuration.profiles);
  await page.goto(scopeLink());
  await expect(page.getByLabel("Multicast group")).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const topology = page.getByRole("tab", { name: /Topology/ });
  await expect(topology).toHaveAttribute("aria-disabled", "true");
  await expect(topology).toHaveAttribute("title", "Not yet available");
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "239.1.2.3", exact: true }),
  ).toBeVisible();
  const scopeRequests = await requests(page);
  expect(scopeRequests).toBe(2);
  let params = new URL(page.url()).searchParams;
  expect(params.get("mc_view")).toBe("overview");
  expect(params.get("mode")).toBe("live");
  expect(params.has("mc_group")).toBe(false);

  const compare = page.getByRole("button", {
    name: "Compare with previous window",
  });
  await compare.click();
  await expect.poll(() => requests(page)).toBeGreaterThan(scopeRequests);
  await expect(compare).toBeEnabled();
  await expect(page.getByText("Comparison unavailable")).toHaveCount(0);
  const comparedRequests = await requests(page);

  await topology.click({ force: true });
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await page.getByRole("tab", { name: "Matrix" }).click();
  await expect(page.getByRole("tab", { name: "Matrix" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(new URL(page.url()).searchParams.get("mc_view")).toBe("matrix");
  expect(await requests(page)).toBe(comparedRequests);

  await page.getByRole("button", { name: /^239\.1\.2\.3 at vlan 110/ }).click();
  await expect(
    page.getByRole("button", { name: "Back to Matrix" }),
  ).toBeVisible();
  await expect(page.getByLabel("Multicast group")).toHaveValue("239.1.2.3");
  await expect(
    page.getByRole("group", { name: "Observed evidence map" }),
  ).toBeVisible();
  params = new URL(page.url()).searchParams;
  expect(params.get("mc_group")).toBe("239.1.2.3");
  expect(params.get("mc_view")).toBe("matrix");
  expect(params.get("mode")).toBe("live");
  const detailRequests = await requests(page);
  expect(detailRequests).toBeGreaterThan(comparedRequests);

  await page.getByRole("button", { name: "Back to Matrix" }).click();
  await expect(
    page.getByRole("button", { name: /^239\.1\.2\.3 at vlan 110/ }),
  ).toBeVisible();
  expect(await requests(page)).toBe(detailRequests);
  params = new URL(page.url()).searchParams;
  expect(params.has("mc_group")).toBe(false);
  expect(params.get("mc_view")).toBe("matrix");
});

test("opens a flagged overview row with its IGMP timeline and returns", async ({
  page,
}) => {
  await profiles(page, configuration.profiles);
  await page.goto(scopeLink());
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  const flagged = page.getByRole("row", { name: /^239\.1\.2\.4/ });
  await expect(flagged).toContainText("Interest, no sender seen");
  await expect(
    page.getByRole("row", { name: /^239\.1\.2\.3/ }),
  ).not.toContainText("Interest, no sender seen");
  await expect(page.getByRole("row", { name: /^0\.0\.0\.0/ })).toHaveCount(0);
  const scopeRequests = await requests(page);

  await flagged.getByRole("button", { name: "239.1.2.4", exact: true }).click();
  await expect(page.getByLabel("Multicast group")).toHaveValue("239.1.2.4");
  await expect(
    page.getByRole("heading", { name: "IGMP timeline" }),
  ).toBeVisible();
  await expect(
    page.getByRole("img", { name: /^IGMP evidence for vlan 110/ }),
  ).toBeVisible();
  expect(new URL(page.url()).searchParams.get("mc_group")).toBe("239.1.2.4");
  const detailRequests = await requests(page);
  expect(detailRequests).toBeGreaterThan(scopeRequests);

  await page.getByRole("button", { name: "Back to Overview" }).click();
  await expect(flagged).toContainText("Interest, no sender seen");
  expect(await requests(page)).toBe(detailRequests);
  expect(new URL(page.url()).searchParams.has("mc_group")).toBe(false);
});

test("editing inputs cancels the overview search", async ({ page }) => {
  await profiles(page, configuration.profiles);
  await page.goto(scopeLink("multicast-slow"));
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await expect.poll(() => requests(page)).toBeGreaterThan(0);
  await page
    .getByLabel("From (UTC)")
    .fill(new Date((earliest - 60) * 1000).toISOString().slice(0, 19));
  await expect
    .poll(() => page.evaluate(() => window.__ADM_ABORTED__ ?? 0))
    .toBeGreaterThan(0);
  await expect(page.getByRole("status")).toContainText(
    "Investigation cancelled",
  );
  await page.waitForTimeout(5500);
  await expect(page.getByRole("table")).toHaveCount(0);
});
