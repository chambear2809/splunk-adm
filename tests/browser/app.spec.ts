import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";

/** Map overflow menu: Changes, Saved views, Legend, Export, settings, help. */
async function more(page: Page, item: string) {
  const menu = page.getByRole("region", { name: "More actions", exact: true });
  if (!(await menu.count()))
    await page
      .getByRole("button", { name: "More actions", exact: true })
      .click();
  await menu.getByRole("button", { name: item, exact: true }).click();
}
async function filters(page: Page) {
  const panel = page.getByRole("region", { name: "Filters", exact: true });
  if (!(await panel.count()))
    await page.getByRole("button", { name: /^Filters/ }).click();
  return panel;
}
async function openFindings(page: Page) {
  const toggle = page.getByRole("button", { name: /^Findings/ });
  if ((await toggle.getAttribute("aria-expanded")) !== "true")
    await toggle.click();
  return page.getByRole("region", { name: "Map findings" });
}
/** Map scope popover, or the Explore "Open by scope" disclosure. */
async function scope(page: Page) {
  const button = page.getByRole("button", { name: "Scope", exact: true });
  const disclosure = page
    .locator("details.atlas-disclosure")
    .filter({ hasText: "Open by scope" });
  await expect(button.or(disclosure).first()).toBeVisible();
  if (await button.count()) {
    if ((await button.getAttribute("aria-expanded")) !== "true")
      await button.click();
  } else if (
    !(await disclosure.evaluate((d) => (d as HTMLDetailsElement).open))
  )
    await disclosure.locator("summary").click();
  return page;
}
async function detailsTab(page: Page, name: "Overview" | "Flows" | "Evidence") {
  await page
    .getByRole("complementary", { name: "Details" })
    .getByRole("tab", { name, exact: true })
    .first()
    .click();
}

test.describe("Application Atlas browser regressions", () => {
  test("selects the captured Catalyst and Meraki demo flows on the map", async ({
    page,
  }) => {
    for (const [scenario, cluster, attachmentDevice] of [
      ["catalyst-aci", "cilium-aci-east", "CAMPUS-SW-01"],
      ["meraki-nxos", "cilium-nxos-west", "MR-NXOS-01"],
    ]) {
      await page.goto(`/tests/browser/browser.html?scenario=${scenario}`);
      await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
      await expect(page.locator(".scope-service")).toHaveText("checkout");
      await expect(page.locator(".scope-dims")).toContainText(cluster);
      await more(page, "Map settings");
      await expect(page.getByLabel("Demo scenario")).toHaveValue(scenario);
      await page.getByRole("button", { name: "Close settings" }).click();
      await expect(page.locator(".adm")).toHaveAttribute(
        "data-edge-count",
        /[1-9]/,
      );
      await page.getByRole("button", { name: "Devices", exact: true }).click();
      await expect(
        page.getByRole("heading", { name: "Client attachment devices" }),
      ).toBeVisible();
      await expect(
        page
          .getByRole("region", { name: "Client attachment devices" })
          .getByText(attachmentDevice, { exact: false }),
      ).toBeVisible();
      await more(page, "Export");
      const download = page.waitForEvent("download");
      await page
        .getByRole("button", { name: /Context evidence \(CSV\)/ })
        .click();
      const artifact = await download;
      const csv = await readFile((await artifact.path())!, "utf8");
      expect(csv).toContain("attachment_evidence");
      expect(csv).toContain("traffic_observation");
      expect(csv).toContain("evidence_json");
      expect(csv).toContain("scope");
    }
  });

  test("runs captured Meraki client Find and labels unresolved association evidence", async ({
    page,
  }) => {
    await page.goto(
      "/tests/browser/browser.html?page=applications&scenario=meraki-nxos",
    );
    await expect(page.getByLabel("Demo scenario")).toHaveValue("meraki-nxos");
    await page.getByLabel("Find an address, EPG, or device").fill("10.71.0.20");
    await page.getByRole("button", { name: "Find", exact: true }).click();
    await expect(
      page
        .locator("table")
        .first()
        .getByRole("button", { name: "Open map for checkout" }),
    ).toBeEnabled();
    const clients = page.locator("table").nth(1);
    await expect(clients).toBeVisible();
    await expect(clients).toContainText("MR-NXOS-01");
    await expect(clients).toContainText("MR-NXOS-02");
    await expect(clients).toContainText("meraki_association_event");
    await expect(clients).toContainText("unresolved");
  });

  test("reports a failed network-client Find without claiming there are no matches", async ({
    page,
  }) => {
    await page.goto(
      "/tests/browser/browser.html?page=applications&mode=live&fault=find-client-fails",
    );
    await page.getByLabel("Find an address, EPG, or device").fill("10.71.0.20");
    await page.getByRole("button", { name: "Find", exact: true }).click();

    await expect(page.getByRole("alert")).toContainText(
      "Network-client Find unavailable: network-client search was truncated",
    );
    await expect(page.getByText("No matching applications found.")).toHaveCount(
      0,
    );
  });

  test("preserves application matches when network-client Find fails", async ({
    page,
  }) => {
    await page.goto(
      "/tests/browser/browser.html?page=applications&mode=live&fault=find-client-fails",
    );
    await page.getByLabel("Find an address, EPG, or device").fill("10.42.0.15");
    await page.getByRole("button", { name: "Find", exact: true }).click();

    await expect(page.locator('[aria-label="Find results"]')).toContainText(
      "checkout",
    );
    await expect(page.getByRole("alert")).toContainText(
      "Network-client Find unavailable",
    );
  });

  test("preserves client matches and warnings when application Find fails", async ({
    page,
  }) => {
    await page.goto(
      "/tests/browser/browser.html?page=applications&mode=live&fault=find-app-fails",
    );
    await page.getByLabel("Find an address, EPG, or device").fill("10.71.0.20");
    await page.getByRole("button", { name: "Find", exact: true }).click();

    await expect(
      page.locator('[aria-label="Network client evidence"]'),
    ).toContainText("00:11:22:33:44:55");
    await expect(page.getByRole("alert")).toContainText(
      "Application Find unavailable: application search permission denied",
    );
  });

  test("shows warnings returned by the network-client Find source", async ({
    page,
  }) => {
    await page.goto(
      "/tests/browser/browser.html?page=applications&mode=live&fault=find-client-warning",
    );
    await page.getByLabel("Find an address, EPG, or device").fill("10.42.0.15");
    await page.getByRole("button", { name: "Find", exact: true }).click();

    await expect(
      page
        .locator('p[role="status"]')
        .filter({ hasText: "Network-client evidence may be incomplete." }),
    ).toContainText("Network-client evidence may be incomplete.");
    await expect(page.locator('[aria-label="Find results"]')).toContainText(
      "checkout",
    );
  });

  test("filters the map and opens endpoint inspection", async ({ page }) => {
    await page.goto("/tests/browser/browser.html");
    await expect(page.getByText("Demo data", { exact: true })).toBeVisible();

    const search = page.getByLabel(
      "Highlight by name, IP, EPG, port or device",
    );
    await search.fill("checkout");
    await expect(page.locator(".match-count")).toContainText("card");
    await search.press("Enter");
    await expect(page.locator("[data-hit].match").first()).toBeVisible();
    await page.locator("[data-hit].match").first().click();
    await expect(
      page.getByRole("complementary", { name: "Details" }),
    ).toContainText("checkout");
    await page.getByRole("button", { name: "Clear selection" }).click();
    await expect(
      page.getByRole("button", { name: "Clear selection" }),
    ).toHaveCount(0);
    await search.fill("");
    await expect(page.getByRole("status")).toHaveCount(0);
  });

  test("submits all live scope filters and the selected time window", async ({
    page,
  }) => {
    await page.goto("/tests/browser/browser.html");
    await more(page, "Map settings");
    await page.getByRole("button", { name: "Splunk" }).click();
    for (const [label, value] of [
      ["Environment", "demo"],
      ["Cluster", "demo-cluster"],
      ["Namespace", "shop"],
      ["Service", "frontend"],
    ]) {
      const control = page.getByRole("combobox", { name: label, exact: true });
      await expect(control).toBeEnabled();
      await control.fill("");
      await control.click();
      await page.getByRole("option", { name: value, exact: true }).click();
    }
    await page
      .getByLabel("Time range", { exact: true })
      .getByRole("button")
      .click();
    await page.getByRole("button", { name: "Presets", exact: true }).click();
    await page.getByText("Last 24 hours", { exact: true }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByText("Demo data", { exact: true })).toBeHidden();
    // The map pins relative bounds once (here -24h@h) so every read of the
    // build shares one exact window.
    await expect
      .poll(() =>
        page.evaluate(() => {
          const sent = Number(window.__ADM_LAST_EARLIEST__);
          const hour = Math.floor(Date.now() / 3600000) * 3600 - 86400;
          return Math.abs(sent - hour) <= 3600;
        }),
      )
      .toBe(true);
    // The client may append the bounded top-N suffix after the read macro.
    await expect
      .poll(() =>
        page.evaluate(() =>
          String(window.__ADM_LAST_GRAPH_SEARCH__ ?? "").startsWith(
            // Progressive read: summaries first ("deferred" newest minutes).
            '| `adm_application_graph_read("frontend","demo","demo-cluster","shop","deferred")`',
          ),
        ),
      )
      .toBe(true);
    await expect(page.locator(".scope-service")).toHaveText("frontend");
    await expect(page.locator(".scope-dims")).toHaveText(
      "demo · demo-cluster · shop",
    );
  });

  test("shows permission errors from the live search", async ({ page }) => {
    await page.goto("/tests/browser/browser.html?scenario=permission");
    await more(page, "Map settings");
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByRole("alert")).toContainText("search failed");
    await expect(page.getByRole("alert")).toContainText("permission denied");
  });

  test("shows WARN job messages as search warnings without failing the map", async ({
    page,
  }) => {
    await page.goto("/tests/browser/browser.html?scenario=graph-warning");
    await more(page, "Map settings");
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
    await page.getByRole("button", { name: /1 warning/ }).click();
    await expect(
      page.getByRole("region", { name: "Search warnings" }),
    ).toContainText("Peer indexer-3 was unreachable.");
  });

  test("fails closed when a live graph result is incomplete", async ({
    page,
  }) => {
    await page.goto("/tests/browser/browser.html?scenario=incomplete");
    await more(page, "Map settings");
    await page.getByRole("button", { name: "Splunk" }).click();
    await page.getByRole("button", { name: "Build map" }).click();
    await expect(page.getByRole("alert")).toContainText(
      "finalized this job before all results were available",
    );
    await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "false");
    await expect(page.locator(".adm")).toHaveAttribute("data-node-count", "0");
    await expect(
      page.locator('svg[aria-label="frontend dependency map"]'),
    ).toHaveCount(0);
  });
});

test("reload reproduces a validated live deep link", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1770000000&latest=1770003600&tab=services&q=checkout",
  );
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByLabel("Highlight by name, IP, EPG, port or device"),
  ).toHaveValue("checkout");
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__ADM_REQUESTS__?.find((r) =>
          r.spl.includes("adm_application_graph_read"),
        ),
      ),
    )
    .toMatchObject({ earliest: "1770000000", latest: "1770003600" });
  const count = await page.locator(".adm").getAttribute("data-node-count");
  await page.reload();
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  await expect(page.locator(".adm")).toHaveAttribute("data-node-count", count!);
});

test("loads each foundation page", async ({ page }) => {
  for (const [route, title] of [
    ["applications", "Explore"],
    ["endpoints", "Explore"],
    ["data_health", "Data health"],
    ["device", "Device"],
    ["help", "Help"],
    ["setup", "Setup"],
  ]) {
    await page.goto(`/tests/browser/browser.html?page=${route}`);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
  }
});

test("Find shows source-qualified network client evidence without implying attachment", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=applications&mode=live");
  await page.getByLabel("Find an address, EPG, or device").fill("10.71.0.20");
  await page.getByRole("button", { name: "Find", exact: true }).click();
  await expect
    .poll(() => page.evaluate(() => window.__ADM_REQUESTS__ ?? []))
    .toContainEqual(
      expect.objectContaining({
        spl: expect.stringContaining("adm_find_network_client"),
      }),
    );
  const results = page.locator("table").first();
  await expect(results).toBeVisible();
  await expect(results).toContainText("00:11:22:33:44:55");
  await expect(results).toContainText("Meraki · org-a/network-a");
  await expect(results).toContainText("unmapped");
  await expect(results).toContainText("No exact routing scope mapping");
  const requests = await page.evaluate(() => window.__ADM_REQUESTS__ ?? []);
  expect(
    requests.some((request) =>
      request.spl.includes('adm_find_network_client("10.71.0.20")'),
    ),
  ).toBe(true);
});

test("setup checklist reads live configuration and gates safe actions", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=live");
  await expect(
    page.getByRole("heading", { name: "Setup", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Index macros", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Summary reader and writer match.", { exact: true }),
  ).toBeVisible();
  const input = page.getByLabel("Index for adm_index_netflow", { exact: true });
  await input.fill("adm_index_netflow_test");
  await page
    .getByRole("button", { name: "Save adm_index_netflow", exact: true })
    .click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
            .__ADM_SETUP_REQUESTS__ ?? [],
      ),
    )
    .toContain("macro:adm_index_netflow:adm_index_netflow_test");
  const enable = page.getByRole("button", {
    name: "Enable schedule for ADM - Identity builder",
    exact: true,
  });
  await expect(enable).toBeEnabled();
  await enable.click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
            .__ADM_SETUP_REQUESTS__ ?? [],
      ),
    )
    .toContain("builder:ADM - Identity builder");
  expect(
    await page.evaluate(
      () =>
        (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
          .__ADM_SETUP_REQUESTS__,
    ),
  ).toEqual(
    expect.arrayContaining([
      "macro:adm_index_netflow:adm_index_netflow_test",
      "builder:ADM - Identity builder",
    ]),
  );
});

test("setup checklist blocks unknown and uppercase prerequisites", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-unknown",
  );
  await expect(
    page.getByRole("alert").filter({ hasText: "Administrator access" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-uppercase",
  );
  await expect(page.getByText(/contain uppercase observer/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
});

test("demo setup never reads or mutates configuration", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?page=setup&mode=demo");
  await expect(page.getByRole("status")).toContainText("unavailable in Demo");
  expect(
    await page.evaluate(
      () =>
        (window as Window & { __ADM_SETUP_REQUESTS__?: string[] })
          .__ADM_SETUP_REQUESTS__,
    ),
  ).toBeUndefined();
});

test("setup verification failure clears the checklist and blank scopes stay gated", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-partial",
  );
  await expect(
    page.getByLabel("Index for adm_index_netflow", { exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Index for adm_index_netflow", { exact: true })
    .fill("adm_index_netflow_test");
  await page
    .getByRole("button", { name: "Save adm_index_netflow", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("verification failed");
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&fault=setup-blank",
  );
  await expect(
    page.getByText("No observer mappings are configured.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Enable schedule/ }).first(),
  ).toBeDisabled();
});

test("rejects injected state before dispatching a search", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=bad%22%29%7Cdelete",
  );
  await expect(page.locator("#adm-root")).toContainText("Service may contain");
  expect(
    await page.evaluate(() =>
      (window.__ADM_REQUESTS__ ?? []).filter((r) =>
        /adm_(graph|topology|find|app_catalog)/.test(r.spl),
      ),
    ),
  ).toEqual([]);
});

test("built bundle isolates dependencies from the dashboard AMD globals", async ({
  page,
}) => {
  const { readFile, access } = await import("node:fs/promises");
  const bundlePath = "splunk_app/splunk_adm/appserver/static/pages/atlas.js";
  try {
    await access(bundlePath);
  } catch {
    test.skip(true, "Run npm run build before bundle qualification");
    return;
  }
  const bundle = await readFile(bundlePath, "utf8");
  await page.goto("about:blank");
  await page.evaluate(() => {
    const state = window as unknown as {
      define: ((...args: unknown[]) => never) & { amd?: object };
      _: object;
      __atlasSentinel: object;
    };
    state.define = Object.assign(
      () => {
        throw new Error("Anonymous AMD definition escaped the Atlas IIFE");
      },
      { amd: {} },
    );
    state._ = state.__atlasSentinel = {};
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addScriptTag({ content: bundle });
  expect(errors).toEqual([]);
  expect(
    await page.evaluate(() => {
      const state = window as unknown as { _: object; __atlasSentinel: object };
      return state._ === state.__atlasSentinel;
    }),
  ).toBe(true);
});

test("the real demo bootstrap renders with Toolkit fonts and both themes", async ({
  page,
}) => {
  for (const theme of ["dark", "light"]) {
    await page.goto(`/map?mode=demo&theme=${theme}`);
    await expect(page.locator(".atlas")).toHaveAttribute(
      "data-atlas-theme",
      theme,
    );
    await expect(page.getByText("Demo data", { exact: true })).toBeVisible();
    expect(
      await page
        .locator(".atlas")
        .evaluate((element) => getComputedStyle(element).fontFamily),
    ).not.toContain("Times");
  }
  await page.goto("/applications");
  await expect(
    page.getByRole("heading", { name: "Explore", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Open map for frontend", exact: true })
    .click();
  const demoMap = new URL(page.url());
  expect(demoMap.searchParams.get("mode")).toBe("demo");
  expect(demoMap.searchParams.get("scenario")).toBe("aci");
  expect(demoMap.searchParams.get("earliest")).toBe("1791373500");
  expect(demoMap.searchParams.get("latest")).toBe("1791374400");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
});

test("inspector remains usable at narrow width in light and dark themes", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const theme of ["light", "dark"]) {
    await page.goto(
      `/tests/browser/browser.html?fault=vlan-ui&mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&theme=${theme}`,
    );
    await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
    await page
      .getByRole("button", { name: /node-a/ })
      .first()
      .dispatchEvent("click");
    await expect(
      page.getByRole("complementary", { name: "Details" }),
    ).toBeVisible();
    await expect(page.getByText("EPG-ui", { exact: true })).toBeVisible();
    await expect(
      page.getByText("VLAN 1030 · ingress", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("1030", { exact: true })).toBeVisible();
    await expect(page.getByText("bd-clients", { exact: true })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Observed VLANs — NetFlow/ }),
    ).toBeVisible();
    await expect(page.getByText(/Network history is capped/)).toBeVisible();
    expect(
      await page
        .getByRole("complementary", { name: "Details" })
        .evaluate((element) => element.getBoundingClientRect().width),
    ).toBeLessThanOrEqual(390);
    await page
      .getByRole("button", { name: /node-b/ })
      .first()
      .dispatchEvent("click");
    await expect(page.locator(".facts dt", { hasText: "VLAN" })).toHaveCount(0);
    await expect(
      page.locator(".facts dt", { hasText: "Bridge Domain" }),
    ).toHaveCount(0);
    await expect(page.getByText("shop", { exact: true })).toBeVisible();
    await expect(
      page.getByText("EPG-incomplete", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("02:00:00:00:00:02", { exact: true }),
    ).toBeVisible();
  }
});

test("clears dependent scope fields and rejects invalid manual input", async ({
  page,
}) => {
  await page.clock.install();
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const environment = (await scope(page)).getByRole("combobox", {
    name: "Environment",
    exact: true,
  });
  await expect(environment).toBeEnabled();
  await environment.fill("prod");
  await expect(
    (await scope(page)).getByRole("combobox", { name: "Cluster", exact: true }),
  ).toHaveValue("");
  await expect(
    (await scope(page)).getByRole("combobox", {
      name: "Namespace",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    (await scope(page)).getByRole("combobox", { name: "Service", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Build map", exact: true }),
  ).toBeDisabled();
  const count = await page.evaluate(
    () =>
      window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph"))
        .length,
  );
  await environment.fill('prod"|delete');
  await expect(
    page.getByRole("button", { name: "Build map", exact: true }),
  ).toBeDisabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph"))
          .length,
    ),
  ).toBe(count);
});

test("demo controls retain the captured scope and time", async ({ page }) => {
  await page.goto("/tests/browser/browser.html");
  const service = (await scope(page)).getByRole("combobox", {
    name: "Service",
    exact: true,
  });
  await expect(service).toBeEnabled();
  await service.fill("uncaptured");
  await expect(service).toHaveValue("frontend");
  await expect(page.locator(".scope-service")).toHaveText("frontend");
  await expect(
    page.getByLabel("Time range", { exact: true }).getByRole("button"),
  ).toBeDisabled();
  expect(new URL(page.url()).searchParams.get("earliest")).toMatch(/^\d/);
  expect(new URL(page.url()).searchParams.get("latest")).toMatch(/^\d/);
});

test("applications catalog sorts numeric metrics and opens a captured scope", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  await expect(
    page.getByRole("heading", { name: "Explore", exact: true }),
  ).toBeVisible();
  const catalog = page.locator("table").last();
  const rows = catalog.locator("tbody > tr");
  await expect(
    page.getByRole("button", { name: "Open map for frontend", exact: true }),
  ).toBeVisible();
  const metric = page.getByRole("button", { name: /Conversations \(1h\)/ });
  await metric.click();
  const ascending = await rows.evaluateAll((items) =>
    items.map((item) => Number(item.children[4]?.textContent?.trim())),
  );
  expect(ascending.filter(Number.isFinite)).toEqual(
    expect.arrayContaining([1, 2, 4, 6]),
  );
  await metric.click();
  const descending = await rows.evaluateAll((items) =>
    items.map((item) => Number(item.children[4]?.textContent?.trim())),
  );
  expect(descending.filter(Number.isFinite)).toEqual(
    expect.arrayContaining([1, 2, 4, 6]),
  );
  await page
    .getByRole("button", { name: "Open map for frontend", exact: true })
    .click();
  await expect(page).toHaveURL(/\/map\?/);
  expect(new URL(page.url()).searchParams.get("service")).toBe("frontend");
  expect(new URL(page.url()).searchParams.get("earliest")).toBe("1791370800");
  expect(new URL(page.url()).searchParams.get("latest")).toBe("1791374400");
});

test("catalog layout has one header row and contained narrow scrolling", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  const catalog = page.locator("table").last();
  await expect(catalog).toBeVisible();
  await expect(catalog.locator("thead tr")).toHaveCount(1);
  const layout = await catalog
    .locator("tbody > tr")
    .first()
    .evaluate((row) => ({
      rowHeight: row.getBoundingClientRect().height,
      widths: [...row.querySelectorAll("td")].map(
        (cell) => cell.getBoundingClientRect().width,
      ),
    }));
  expect(layout.rowHeight).toBeLessThan(130);
  expect(layout.widths.every((width) => width >= 80)).toBe(true);

  await page.setViewportSize({ width: 600, height: 900 });
  await page.reload();
  await expect(catalog).toBeVisible();
  const narrow = await catalog.evaluate((table) => {
    const parent = table.parentElement;
    return {
      overflow: parent ? getComputedStyle(parent).overflowX : "",
      documentFits: document.documentElement.scrollWidth <= innerWidth + 1,
    };
  });
  expect(narrow.overflow).toMatch(/auto|scroll/);
  expect(narrow.documentFits).toBe(true);
});

test("Find opens the captured application scope and rejects injection", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  await input.fill("10.42.0.15");
  await page.getByRole("button", { name: "Find", exact: true }).click();
  const checkout = page
    .locator('[aria-label="Find results"]')
    .getByRole("button", {
      name: "Open map for checkout",
      exact: true,
    })
    .first();
  await expect(checkout).toBeVisible();
  await checkout.first().click();
  await expect(page).toHaveURL(/\/map\?/);
  expect(new URL(page.url()).searchParams.get("service")).toBe("checkout");
  await page.goBack();
  await expect(input).toBeVisible();
  const before = await page.evaluate(
    () =>
      window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_find"))
        .length ?? 0,
  );
  await input.fill('10.42.0.15"|delete');
  await expect(
    page.getByText("Enter an exact IP, EPG or attached-device value."),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Find", exact: true }),
  ).toBeDisabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_find"))
          .length ?? 0,
    ),
  ).toBe(before);
});

test("stale Find responses cannot replace a newer result", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=find-stale",
  );
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  const find = page.getByRole("button", { name: "Find", exact: true });
  await input.fill("10.42.0.15");
  await find.click();
  await input.fill("db");
  await expect(find).toBeEnabled();
  await find.click();
  const results = page.locator('[aria-label="Find results"]');
  await expect(results).toContainText("checkout");
  await expect(results).not.toContainText("frontend");
});

test("empty catalog falls back to scopes without invented metrics", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=empty-catalog",
  );
  await expect(
    page.getByRole("status").filter({ hasText: /metrics are unavailable/i }),
  ).toBeVisible();
  const batch = page.locator("tbody tr").filter({ hasText: "batch-worker" });
  await expect(batch).toBeVisible();
  await expect(batch).toContainText("—");
});

test("catalog bookkeeping marker falls back without rendering the marker", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=marker-only-catalog",
  );
  await expect(
    page.getByRole("status").filter({ hasText: /metrics are unavailable/i }),
  ).toBeVisible();
  await expect(page.locator("tbody")).not.toContainText("adm-catalog-empty");
  await expect(page.locator("tbody")).toContainText("batch-worker");
});

test("catalog over-limit is actionable and does not fall back to scopes", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&fault=catalog-overlimit",
  );
  await expect(page.getByRole("alert")).toContainText(/more than 5,000 rows/i);
  const requests = await page.evaluate(() => window.__ADM_REQUESTS__ ?? []);
  expect(
    requests.filter((request) => request.spl === "| `adm_scope_options`")
      .length,
  ).toBe(1);
  expect(
    requests.some((request) =>
      request.spl.includes(
        '| `adm_application_catalog_read` | search service="',
      ),
    ),
  ).toBe(true);
});

test("a fresh install without service bindings shows guidance, not a search error", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=live&fault=empty-scopes");
  await expect(
    page.getByText(/No service bindings found\. Enter a valid scope/),
  ).toBeVisible();
  await expect(
    page.getByRole("alert").filter({ hasText: "Scope options:" }),
  ).toHaveCount(0);
});

test("editing the scope keeps Find results and does not restart the catalog", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop",
  );
  const catalogRequests = () =>
    page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((request) =>
          request.spl.startsWith("| `adm_application_catalog_read`"),
        ).length,
    );
  await expect(page.locator("tbody").first()).toContainText("checkout");
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  await input.fill("db");
  await page.getByRole("button", { name: "Find", exact: true }).click();
  const results = page.locator('[aria-label="Find results"]');
  await expect(results).toBeVisible();
  const before = await catalogRequests();
  const service = (await scope(page)).getByRole("combobox", {
    name: "Service",
    exact: true,
  });
  await service.fill("front");
  await service.fill("frontend-x");
  await (
    await scope(page)
  )
    .getByRole("combobox", { name: "Environment", exact: true })
    .fill("prod");
  await expect(results).toBeVisible();
  expect(await catalogRequests()).toBe(before);
});

test("an over-limit catalog narrows again when the service changes", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&fault=catalog-overlimit-narrowed",
  );
  await expect(
    page.getByRole("status").filter({ hasText: "narrowed warning" }),
  ).toBeVisible();
  await (
    await scope(page)
  )
    .getByRole("combobox", { name: "Service", exact: true })
    .fill("checkout");
  await expect
    .poll(() =>
      page.evaluate(() =>
        (window.__ADM_REQUESTS__ ?? []).some(
          (request) =>
            request.spl ===
            '| `adm_application_catalog_read` | search service="checkout"',
        ),
      ),
    )
    .toBe(true);
});

test("catalog preserves warnings from a narrowed service search", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&fault=catalog-overlimit-narrowed",
  );
  await expect(
    page.getByRole("status").filter({ hasText: "narrowed warning" }),
  ).toBeVisible();
});

test("catalog uses its captured metric window when the Find/map picker changes", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&earliest=1791370800&latest=1791374400",
  );
  await expect(page.locator("table").last()).toBeVisible();
  const catalogRequests = () =>
    page.evaluate(() =>
      (window.__ADM_REQUESTS__ ?? []).filter((request) =>
        request.spl.startsWith("| `adm_application_catalog_read`"),
      ),
    );
  const before = await catalogRequests();
  expect(before[0]?.earliest).toBe("0");
  expect(before[0]?.latest).toBe("now");
  await page
    .getByLabel("Time range", { exact: true })
    .getByRole("button")
    .click();
  await page.getByRole("button", { name: "Presets", exact: true }).click();
  await page.getByText("Last 24 hours", { exact: true }).click();
  await expect(
    page.getByLabel("Time range", { exact: true }).getByRole("button"),
  ).toContainText("Last 24 hours");
  // Effects scheduled by the committed time change have run after a frame and a task.
  await page.evaluate(
    () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => setTimeout(resolve, 0)),
      ),
  );
  expect(await catalogRequests()).toHaveLength(before.length);
});

test("captured demo applications explain unavailable Find evidence", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=applications&mode=demo");
  await expect(
    page.getByRole("heading", { name: "Explore", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Open map for frontend", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Demo data", { exact: true })).toHaveAttribute(
    "title",
    /Captured Find window/,
  );
  const input = page.getByLabel(/Find an address, EPG, or device/).first();
  await input.fill("not-captured");
  await expect(
    page.getByRole("button", { name: "Find", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(/captured.*evidence/i)).toBeVisible();
});

test("findings expose safe demo evidence actions", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  const finding = (await openFindings(page))
    .getByRole("article")
    .filter({ hasText: "Blocked conversation" })
    .first();
  await expect(finding).toBeVisible();

  const copy = finding.getByRole("button", {
    name: "Copy request",
    exact: true,
  });
  await expect(copy).toBeEnabled();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await copy.click();
  await expect(finding.getByRole("status")).toContainText(/request copied/i);
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toMatch(/,|\n/);

  const openDemo = finding.getByRole("button", {
    name: "Open in Search",
    exact: true,
  });
  await expect(openDemo).toBeDisabled();
  await expect(
    page.getByRole("region", { name: "Map findings" }),
  ).toContainText("Demo evidence · not searchable");

  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  await expect(page.locator("[data-hit].selected").first()).toBeVisible();

  const edgeActions = page.getByRole("region", { name: "Evidence actions" });
  await expect(edgeActions).toBeVisible();
  await expect(
    edgeActions.getByRole("button", { name: "Copy request", exact: true }),
  ).toBeEnabled();
});

test("live evidence links preserve the graph window safely", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791373500&latest=1791374400",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const liveFinding = (await openFindings(page))
    .getByRole("article")
    .filter({ hasText: "Blocked conversation" })
    .first();
  await expect(liveFinding).toBeVisible();
  await liveFinding
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const search = page.getByRole("link", {
    name: "Open in Search",
    exact: true,
  });
  await expect(search).toHaveAttribute("target", "_blank");
  await expect(search).toHaveAttribute("rel", /noopener/);
  const href = await search.getAttribute("href");
  expect(href).toContain("adm_flow_evidence");
  expect(href).toContain("1791373500");
  expect(href).toContain("1791374400");
});

test("live health refreshes every five minutes and demo stays quiet", async ({
  page,
}) => {
  await page.clock.install();
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const before = await page.evaluate(
    () =>
      (window.__ADM_REQUESTS__ ?? []).filter((r) =>
        r.spl.includes("adm_health"),
      ).length,
  );
  await page.clock.fastForward(300001);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window.__ADM_REQUESTS__ ?? []).filter((r) =>
            r.spl.includes("adm_health"),
          ).length,
      ),
    )
    .toBeGreaterThan(before);
  await page.goto("/tests/browser/browser.html");
  expect(
    await page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((r) =>
          r.spl.includes("adm_health"),
        ).length,
    ),
  ).toBe(0);
});

test("scope fields retain dark Toolkit surfaces under classic dashboard CSS", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?theme=dark");
  await page.addStyleTag({
    content:
      'input[type="text"] { background-color: white; border: 1px solid #ccc; box-shadow: inset 0 1px 1px #ddd; margin-bottom: 9px; }',
  });
  const field = (await scope(page)).getByRole("combobox", {
    name: "Environment",
    exact: true,
  });
  await expect(field).toBeEnabled();
  expect(
    await field.evaluate(
      (element) => getComputedStyle(element).backgroundColor,
    ),
  ).toBe("rgba(0, 0, 0, 0)");
  expect(
    await field.evaluate((element) => getComputedStyle(element).borderTopWidth),
  ).toBe("0px");
  expect(
    await field.evaluate((element) => getComputedStyle(element).boxShadow),
  ).toBe("none");
});

test("inferred backend findings open their collected candidate path", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  const finding = (await openFindings(page)).getByRole("article", {
    name: "Backend inferred",
    exact: true,
  });
  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  const path = page.getByRole("region", { name: /^Candidate path:/ });
  await expect(path).toBeVisible();
  await expect(path).toContainText("catalog");
  await expect(
    page.getByRole("complementary", { name: "Details" }),
  ).toContainText("catalog-api");
  await page.getByRole("button", { name: "Clear selection" }).click();
  await expect(finding).toBeVisible();
});

test("partial client handoff keeps its selected path unresolved and labels aggregate backend", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&fault=partial-shared-handoff",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();

  await page.getByRole("button", { name: "Table", exact: true }).click();
  const conversations = page.locator(".table-view table").first();
  const selectedClient = conversations
    .locator("tbody button")
    .filter({ hasText: "win-client-01" })
    .filter({ hasText: "checkout-api" });
  await expect(selectedClient).toHaveCount(1);
  await selectedClient.click();

  const details = page.getByRole("complementary", { name: "Details" });
  await expect(details).toContainText(
    "Client handoff coverage is partial (1 of 2 connections determined; 1 unresolved).",
  );
  await expect(details).not.toContainText("checkout-5f8b9c7d6-m4n7q");
  await expect(details.getByText("Received on", { exact: true })).toHaveCount(
    0,
  );

  await details
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  const path = page.getByRole("region", { name: /^Candidate path:/ });
  await expect(path).toContainText("Client handoff coverage is partial");
  await expect(path).toContainText("Not determined");
  await expect(path).not.toContainText("checkout-5f8b9c7d6-m4n7q");
  await expect(path).not.toContainText(
    "Kubernetes node · received the traffic",
  );
  await path.getByRole("button", { name: "Close path", exact: true }).click();

  await page.getByRole("button", { name: "Network", exact: true }).click();
  const checkoutFrontend = page.getByRole("button", {
    name: /Kubernetes Service.*checkout-api/,
  });
  await expect(checkoutFrontend).toBeVisible();
  await checkoutFrontend.click();
  await expect(details).toContainText(
    "1 aggregate backends for determined connections",
  );
});

test("complete aggregate handoff cannot replace missing selected-client metadata", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&fault=missing-client-handoff",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();

  await page.getByRole("button", { name: "Table", exact: true }).click();
  const selectedClient = page
    .locator(".table-view table")
    .first()
    .locator("tbody button")
    .filter({ hasText: "win-client-01" })
    .filter({ hasText: "checkout-api" });
  await expect(selectedClient).toHaveCount(1);
  await selectedClient.click();

  const details = page.getByRole("complementary", { name: "Details" });
  await expect(details).toContainText(
    "Client-specific handoff evidence is unavailable or invalid.",
  );
  await expect(details).not.toContainText("checkout-5f8b9c7d6-m4n7q");
  await expect(details.getByText("Received on", { exact: true })).toHaveCount(
    0,
  );
  await details
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  const path = page.getByRole("region", { name: /^Candidate path:/ });
  await expect(path).toContainText(
    "Client-specific handoff evidence is unavailable or invalid.",
  );
  await expect(path).not.toContainText("checkout-5f8b9c7d6-m4n7q");
  await expect(path).not.toContainText(
    "Kubernetes node · received the traffic",
  );
  await path.getByRole("button", { name: "Close path", exact: true }).click();

  await page.getByRole("button", { name: "Network", exact: true }).click();
  const checkoutFrontend = page.getByRole("button", {
    name: /Kubernetes Service.*checkout-api/,
  });
  await expect(checkoutFrontend).toBeVisible();
  await checkoutFrontend.click();
  await expect(details).toContainText("1 identified");
  await expect(details).not.toContainText(
    "Client-specific handoff evidence is unavailable or invalid.",
  );
});

test("findings remain reachable below the map on narrow screens", async ({
  page,
}) => {
  await page.setViewportSize({ width: 600, height: 900 });
  await page.goto("/tests/browser/browser.html?mode=demo");
  const findings = await openFindings(page);
  await expect(findings).toBeVisible();
  const finding = findings.getByRole("article", {
    name: "Blocked conversation",
    exact: true,
  });
  await finding.getByRole("button", { name: "Show path", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Clear selection" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Clear selection" }).click();
  await expect(findings).toBeVisible();
});

test("traced call actions open a validated collected trace", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791373500&latest=1791374400&tab=services",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  await page
    .getByRole("button", { name: "Service frontend", exact: true })
    .click();
  await detailsTab(page, "Flows");
  await page
    .getByRole("complementary", { name: "Details" })
    .getByRole("button", { name: /checkout.*Traced call/ })
    .click();
  const actions = page.getByRole("region", { name: "Evidence actions" });
  const link = actions.getByRole("link", {
    name: "Open in Search",
    exact: true,
  });
  const url = new URL((await link.getAttribute("href"))!);
  expect(url.pathname).toBe("/app/splunk_adm/search");
  expect(url.searchParams.get("q")).toMatch(
    /^\| `adm_trace_evidence\("[0-9a-f]{16,32}"\)`$/,
  );
  expect(url.searchParams.get("earliest")).toBe("1791373500");
  expect(url.searchParams.get("latest")).toBe("1791374400");
  await expect(
    actions.getByRole("button", { name: "Copy request", exact: true }),
  ).toBeDisabled();
  await expect(actions).toContainText("first collected trace");
});

test("Setup inputs keep Toolkit surfaces under classic dashboard CSS", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=setup&mode=live&theme=dark",
  );
  await page.addStyleTag({
    content:
      'input[type="text"] { background-color: white; border: 1px solid #ccc; box-shadow: inset 0 1px 1px #ddd; margin-bottom: 9px; }',
  });
  const input = page.getByLabel("Index for adm_index_hubble", { exact: true });
  await expect(input).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Cisco integration status" }),
  ).toBeVisible();
  await expect(page.getByText(/Cisco v2 remains staged/)).toBeVisible();
  await expect(page.getByText("catalyst_sdwan_ipfix")).toBeVisible();
  await expect(page.getByRole("button", { name: /v2|Cisco/i })).toHaveCount(0);
  expect(
    await input.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        background: style.backgroundColor,
        border: style.borderWidth,
        shadow: style.boxShadow,
        margin: style.marginBottom,
      };
    }),
  ).toEqual({
    background: "rgba(0, 0, 0, 0)",
    border: "0px",
    shadow: "none",
    margin: "0px",
  });
});

test("map facets combine, clear, and keep full evidence exports", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByRole("button", { name: "More actions", exact: true }),
  ).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("region", { name: "Map legend" })).toHaveCount(0);
  await page.getByRole("button", { name: "Table", exact: true }).click();
  const total = await page.locator(".table-view tbody tr").count();
  await (
    await filters(page)
  )
    .getByLabel("Filter identity", { exact: true })
    .selectOption("external");
  const filtered = await page.locator(".table-view tbody tr").count();
  expect(filtered).toBeGreaterThan(0);
  expect(filtered).toBeLessThan(total);
  await expect(page.locator(".atlas-filter-status")).toContainText(
    "Findings and exports use the full map",
  );
  await more(page, "Export");
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: /Map data \(JSON\)/ }).click();
  const artifact = await downloaded;
  const exported = JSON.parse(
    await readFile((await artifact.path())!, "utf8"),
  ) as { nodes: unknown[] };
  expect(exported.nodes.length).toBe(
    Number(await page.locator(".adm").getAttribute("data-node-count")),
  );
  await (
    await filters(page)
  )
    .getByLabel("Blocked only", { exact: true })
    .check();
  await expect(page.locator(".atlas-filter-status")).toBeVisible();
  await page
    .getByRole("button", { name: "Close filters", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Clear filters and focus", exact: true })
    .first()
    .click();
  await expect(page.locator(".table-view tbody tr")).toHaveCount(total);
  await (
    await filters(page)
  )
    .getByLabel("Hide infrastructure", { exact: true })
    .check();
  await (
    await filters(page)
  )
    .getByLabel("Hide infrastructure", { exact: true })
    .uncheck();
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("focus limits the neighborhood and clears without a new search", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByLabel("Focus around selected card", { exact: true }),
  ).toBeDisabled();
  const highlight = page.getByLabel(
    "Highlight by name, IP, EPG, port or device",
  );
  await highlight.fill("win-client-01");
  await highlight.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  await highlight.fill("");
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("1");
  await expect(page.locator(".atlas-filter-status")).toContainText(
    "Within 1 hop",
  );
  await page
    .getByRole("button", { name: "Clear filters and focus", exact: true })
    .first()
    .click();
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("persona preference persists but explicit view links take precedence", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await more(page, "Map settings");
  await page
    .getByLabel("Default view for persona", { exact: true })
    .selectOption("application");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.goto("/tests/browser/browser.html");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.goto("/tests/browser/browser.html?tab=network");
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("Services clears network facets and only lists traced-call legend", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await (
    await filters(page)
  )
    .getByLabel("Filter identity", { exact: true })
    .selectOption("external");
  await page.getByRole("button", { name: "Services", exact: true }).click();
  await expect(
    (await filters(page)).getByLabel("Filter identity", { exact: true }),
  ).toHaveCount(0);
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
  await more(page, "Legend");
  await expect(page.getByLabel("Legend", { exact: true })).toContainText(
    "Traced call",
  );
  await expect(page.getByLabel("Legend", { exact: true })).not.toContainText(
    "Node tunnel",
  );
  await page.getByRole("button", { name: "1 external", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await more(page, "Map settings");
  await page
    .getByLabel("Default view for persona", { exact: true })
    .selectOption("application");
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
});

test("shrinking focus clears a selected connection outside the new neighborhood", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const highlight = page.getByLabel(
    "Highlight by name, IP, EPG, port or device",
  );
  await highlight.fill("frontend");
  await highlight.press("Enter");
  await page
    .getByRole("button", { name: "Service frontend", exact: true })
    .click();
  await highlight.fill("");
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("2");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page
    .locator(".table-view table")
    .first()
    .locator("tbody tr")
    .filter({ hasText: "orders-db-01" })
    .first()
    .locator("button")
    .first()
    .click();
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("1");
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
});

test("candidate paths stay on map tabs and remain available from Table inspection", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await (
    await openFindings(page)
  )
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  await expect(page.locator(".path-strip")).toBeVisible();
  await page.getByRole("button", { name: "Services", exact: true }).click();
  await expect(page.locator(".path-strip")).toBeVisible();
  await page.getByRole("button", { name: "Devices", exact: true }).click();
  await expect(page.locator(".path-strip")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Show candidate path", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.locator(".path-strip")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Network", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".path-strip")).toBeVisible();
});

test("inspector full names are readable and copy exact collected text", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/tests/browser/browser.html");
  await (
    await openFindings(page)
  )
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const title = page.locator(".atlas-inspector-title h2");
  const full = await title.textContent();
  await expect(title).toHaveCSS("text-overflow", "ellipsis");
  await page.locator(".atlas-inspector-title summary").click();
  await expect(page.locator(".atlas-full-name")).toHaveText(full!);
  await page
    .getByRole("button", { name: "Copy full name", exact: true })
    .click();
  await expect
    .poll(() => page.evaluate(() => navigator.clipboard.readText()))
    .toBe(full);
  await expect(page.getByText("Name copied.", { exact: true })).toBeVisible();
});

test("map emphasis explains dimming and clears both highlight and selection", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const search = page.getByLabel("Highlight by name, IP, EPG, port or device");
  await search.fill("checkout");
  await expect(page.locator(".atlas-emphasis-banner")).toContainText(
    "checkout",
  );
  await page.mouse.move(0, 0);
  const cards = await page.locator(".item").count();
  const emphasizedCards = await page.locator(".item:not(.dim)").count();
  const connections = await page.locator(".edge").count();
  const emphasizedConnections = await page.locator(".edge:not(.dim)").count();
  await expect(page.locator(".atlas-emphasis-banner")).toContainText(
    `${emphasizedCards} of ${cards} cards and ${emphasizedConnections} of ${connections} connections`,
  );
  await search.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  await page.locator(".atlas-emphasis-banner").getByRole("button").click();
  await expect(search).toHaveValue("");
  await expect(page.locator(".atlas-emphasis-banner")).toHaveCount(0);
  await expect(page.locator(".item.dim, .edge.dim")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
  await search.fill("no-such-endpoint-zzzz");
  await expect(page.locator(".atlas-emphasis-banner")).toContainText("0");
});

test("glossary explanations are available from the keyboard", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await (
    await openFindings(page)
  )
    .getByRole("article", { name: "Backend inferred", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  const info = page
    .getByRole("button", { name: "Explain Determined", exact: true })
    .first();
  await info.focus();
  await expect(page.getByRole("tooltip")).toContainText(
    "linked the frontend to a backend pod",
  );
  await expect(info).toBeFocused();
  await info.press("Tab");
  await expect(page.getByRole("tooltip")).toHaveCount(0);
});

test("copy-name feedback handles denied access and prevents overlapping attempts", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await (
    await openFindings(page)
  )
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  await page.locator(".atlas-inspector-title summary").click();
  await page.evaluate(() =>
    Object.defineProperty(navigator.clipboard, "writeText", {
      configurable: true,
      value: () =>
        new Promise((_, reject) =>
          window.addEventListener(
            "reject-copy",
            () => reject(new Error("denied")),
            { once: true },
          ),
        ),
    }),
  );
  const copy = page.getByRole("button", {
    name: "Copy full name",
    exact: true,
  });
  await copy.click();
  await expect(copy).toBeDisabled();
  await page.evaluate(() => window.dispatchEvent(new Event("reject-copy")));
  await expect(
    page.locator(".atlas-inspector-title [role=alert]"),
  ).toContainText("Could not copy");
  await expect(copy).toBeEnabled();
  await page.evaluate(() =>
    Object.defineProperty(navigator.clipboard, "writeText", {
      configurable: true,
      value: () => Promise.resolve(),
    }),
  );
  await copy.click();
  await expect(page.locator(".atlas-inspector-title [role=alert]")).toHaveCount(
    0,
  );
  await expect(page.locator(".atlas-inspector-title [role=status]")).toHaveText(
    "Name copied.",
  );
});

test("long collected names truncate without losing their full text", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  const search = page.getByLabel("Highlight by name, IP, EPG, port or device");
  await search.fill("cilium-ingress-shop-www");
  await search.press("Enter");
  await page.locator(".item[data-hit].match").first().click();
  const heading = page.locator(".atlas-inspector-title h2");
  await expect
    .poll(() => heading.evaluate((el) => el.scrollWidth > el.clientWidth))
    .toBe(true);
  await page.locator(".atlas-inspector-title summary").click();
  await expect(page.locator(".atlas-full-name")).toHaveText(
    (await heading.textContent())!,
  );
});

test("copy link preserves validated scope, time, tab, and highlight state", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=demo&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791370800&latest=1791374400&tab=services&q=checkout",
  );
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: (value: string) => {
          (
            window as Window & { __ADM_CLIPBOARD__?: string }
          ).__ADM_CLIPBOARD__ = value;
          return Promise.resolve();
        },
      },
    });
  });
  await more(page, "Saved views");
  await page.getByRole("button", { name: "Copy link", exact: true }).click();
  const copied = await page.evaluate(() => {
    const value = (window as Window & { __ADM_CLIPBOARD__?: string })
      .__ADM_CLIPBOARD__;
    return value ?? "";
  });
  expect(copied).toContain("service=frontend");
  expect(copied).toContain("earliest=1791373500");
  expect(copied).toContain("tab=services");
  expect(copied).toContain("q=checkout");
  await page.goto(new URL(copied).pathname + new URL(copied).search);
  await expect(page.locator(".scope-service")).toHaveText("frontend");
  await expect(
    page.getByRole("button", { name: "Services", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByLabel("Highlight by name, IP, EPG, port or device"),
  ).toHaveValue("checkout");
});

test("saved views persist per user and can be reopened or deleted", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await more(page, "Saved views");
  await page.getByLabel("View name", { exact: true }).fill("Checkout demo");
  await page.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toBeVisible();
  await page.reload();
  await more(page, "Saved views");
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Checkout demo", exact: true }).click();
  await more(page, "Saved views");
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Checkout demo", exact: true }),
  ).toHaveCount(0);
});

test("saved views report denied storage and do not render a false save", async ({
  page,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(Storage.prototype, "setItem", {
      configurable: true,
      value: () => {
        throw new Error("denied");
      },
    });
  });
  await page.goto("/tests/browser/browser.html?mode=demo");
  await more(page, "Saved views");
  await page.getByLabel("View name", { exact: true }).fill("Denied");
  await page.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("stored");
});

test("export downloads a nonempty PNG and print invokes the browser print API", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await page.evaluate(() => {
    window.print = () => {
      (window as Window & { __ADM_PRINT__?: boolean }).__ADM_PRINT__ = true;
    };
  });
  await more(page, "Export");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /Map image \(PNG\)/ }).click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).toBeTruthy();
  const bytes = await readFile(path!);
  const signature = Array.from(bytes.subarray(0, 8));
  expect(signature).toEqual([137, 80, 78, 71, 13, 10, 26, 10]);
  await page.getByRole("button", { name: /Print \/ PDF/ }).click();
  expect(
    await page.evaluate(
      () => (window as Window & { __ADM_PRINT__?: boolean }).__ADM_PRINT__,
    ),
  ).toBe(true);
});

test("ACI compare previous window identifies added connections", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await more(page, "Changes");
  await page
    .getByRole("button", { name: "Compare previous window", exact: true })
    .click();
  await expect(page.getByText(/^Previous:/)).toBeVisible();
  await expect(page.getByText(/^Current:/)).toBeVisible();
  await expect(page.getByText(/^[1-9]\d* connections added/)).toBeVisible();
});

test("image and print exports are unavailable for an empty filtered map", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=demo");
  await (
    await filters(page)
  )
    .getByLabel("Filter identity", { exact: true })
    .selectOption("unknown");
  await (
    await filters(page)
  )
    .getByLabel("Blocked only", { exact: true })
    .check();
  await expect(page.locator(".map-canvas > svg")).toHaveCount(0);
  await more(page, "Export");
  await expect(
    page.getByRole("button", { name: /Map image \(PNG\)/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /Print \/ PDF/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /Required flows \(CSV\)/ }),
  ).toBeEnabled();
});

for (const fault of [
  "empty-catalog-fallback-fails",
  "catalog-and-fallback-fail",
]) {
  test(`catalog fallback failure is reported without a duplicate search: ${fault}`, async ({
    page,
  }) => {
    await page.goto(
      `/tests/browser/browser.html?page=applications&mode=live&fault=${fault}`,
    );
    await expect(
      page.getByRole("alert").filter({ hasText: "Retry" }),
    ).toContainText("Configured scopes unavailable.");
    expect(
      await page.evaluate(
        () =>
          window.__ADM_REQUESTS__?.filter(
            (r) => r.spl === "| `adm_scope_options`",
          ).length,
      ),
    ).toBe(2); // ScopeBar bootstrap plus exactly one catalog fallback.
    expect(
      await page.evaluate(
        () =>
          window.__ADM_REQUESTS__?.filter((r) =>
            r.spl.startsWith("| `adm_application_catalog_read`"),
          ).length,
      ),
    ).toBe(1);
  });
}

test("unscoped live map waits for a scope instead of querying the demo", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=live");
  await expect(
    (await scope(page)).getByRole("combobox", {
      name: "Environment",
      exact: true,
    }),
  ).toBeEnabled();
  await expect(
    page.getByRole("heading", { name: "Choose an application to map" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Build map" })).toBeDisabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph("))
          .length ?? 0,
    ),
  ).toBe(0);
});

test("a sole live scope is preselected without building automatically", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=live&fault=single-scope");
  await expect(
    (await scope(page)).getByRole("combobox", { name: "Service", exact: true }),
  ).toHaveValue("frontend");
  await expect(
    page.getByRole("heading", { name: "Choose an application to map" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Build map" })).toBeEnabled();
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph("))
          .length ?? 0,
    ),
  ).toBe(0);
});

test("navigation follows map scope edits and browser history", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  const namespace = (await scope(page)).getByRole("combobox", {
    name: "Namespace",
    exact: true,
  });
  await namespace.fill("payments");
  for (const name of ["Explore", "Admin"]) {
    await expect(page.getByRole("link", { name, exact: true })).toHaveAttribute(
      "href",
      /namespace=payments/,
    );
  }
  await page.evaluate(() => {
    const url = new URL(location.href);
    url.searchParams.set("namespace", "history-scope");
    history.replaceState(null, "", url);
    dispatchEvent(new PopStateEvent("popstate"));
  });
  await expect(
    page.getByRole("link", { name: "Explore", exact: true }),
  ).toHaveAttribute("href", /namespace=history-scope/);
});

test("copy and saved views use the built scope after unbuilt edits", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop&earliest=1791373500&latest=1791374400",
  );
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
  await page.evaluate(() =>
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: (value: string) => {
          (window as Window & { copied?: string }).copied = value;
          return Promise.resolve();
        },
      },
    }),
  );
  await (
    await scope(page)
  )
    .getByRole("combobox", { name: "Namespace", exact: true })
    .fill("unbuilt");
  await more(page, "Saved views");
  await page.getByRole("button", { name: "Copy link", exact: true }).click();
  expect(
    await page.evaluate(() => (window as Window & { copied?: string }).copied),
  ).toContain("namespace=shop");
  await page.getByLabel("View name", { exact: true }).fill("Built snapshot");
  await page.getByRole("button", { name: "Save view", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "Built snapshot", exact: true }),
  ).toHaveAttribute("href", /namespace=shop/);
});

test("copy and save require a loaded snapshot but existing views remain accessible", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?mode=live");
  await more(page, "Saved views");
  await expect(
    page.getByRole("button", { name: "Copy link", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Save view", exact: true }),
  ).toBeDisabled();
});

test("invalid deep links recover safely with a dismissible notice", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?mode=live&namespace=bad%7Cdelete&earliest=bad&tab=unknown&q=%00",
  );
  await expect(
    page.getByRole("heading", { name: "Choose an application to map" }),
  ).toBeVisible();
  const notice = page.getByRole("alert").filter({ hasText: "link parameters" });
  await expect(notice).toBeVisible();
  await expect(
    (await scope(page)).getByRole("combobox", {
      name: "Namespace",
      exact: true,
    }),
  ).toHaveValue("");
  expect(
    await page.evaluate(
      () =>
        window.__ADM_REQUESTS__?.filter((r) => r.spl.includes("adm_graph("))
          .length ?? 0,
    ),
  ).toBe(0);
  await page.getByRole("button", { name: "Dismiss link notice" }).click();
  await expect(notice).toHaveCount(0);
});

test("focus follows caller and dependency direction for blast radius", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const focus = page.getByLabel("Focus around selected card", { exact: true });
  await expect(focus).toBeDisabled();
  const checkout = page.getByRole("button", { name: /^Service checkout/ });
  await checkout.focus();
  await checkout.press("Enter");
  const status = page.locator(".atlas-filter-status");

  await focus.selectOption("callers:1");
  await expect(status).toContainText(
    "Observed callers within 1 hop of checkout",
  );
  await expect(
    page.getByRole("button", { name: /^Service frontend/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /^Service payment/ }),
  ).toHaveCount(0);

  await focus.selectOption("dependencies:1");
  await expect(status).toContainText(
    "Observed dependencies within 1 hop of checkout",
  );
  await expect(
    page.getByRole("button", { name: /^Service frontend/ }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /^VM orders-db-01/ }),
  ).toBeVisible();

  await expect(status).toContainText(
    "Limited to conversations and traced calls observed in this window",
  );

  await focus.selectOption("0");
  await expect(status).toHaveCount(0);
});

test("applications catalog lists blocked and unknown-peer scopes first", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&scenario=meraki-nxos",
  );
  const catalog = page.locator("table").last();
  const first = catalog.locator("tbody > tr").first();
  // Exceptions are colored in their own column instead of a prose badge.
  await expect(first.locator("td.atlas-exception")).toHaveText(["3"]);
  await expect(first).toContainText("2026-10-18 03:55");
  await expect(first).not.toContainText("Review first");
  await expect(first).toContainText("checkout");
  const find = page.getByLabel("Find an address, EPG, or device");
  const findBox = await find.boundingBox();
  const catalogBox = await catalog.boundingBox();
  expect(findBox!.y).toBeLessThan(300);
  expect(findBox!.y).toBeLessThan(catalogBox!.y);
});

test("narrow maps keep findings below the controls instead of overlapping them", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const filters = await page.locator(".toolbar").boundingBox();
  const findings = await (await openFindings(page)).boundingBox();
  const mapArea = await page.locator(".map-area").boundingBox();
  expect(mapArea!.height).toBeGreaterThanOrEqual(400);
  expect(findings!.y).toBeGreaterThanOrEqual(filters!.y + filters!.height);
  expect(findings!.y).toBeGreaterThanOrEqual(mapArea!.y + mapArea!.height);
});

const cardsInsideMap = async (page: Page, names?: RegExp[]) => {
  const area = (await page.locator(".map-area").boundingBox())!;
  let cards = page.locator(".map-canvas .item[role=button]");
  if (names)
    cards = cards.filter({
      hasText: new RegExp(names.map((name) => name.source).join("|")),
    });
  const boxes = await cards.evaluateAll((items) =>
    items.map((item) => {
      const r = item.getBoundingClientRect();
      return { left: r.left, right: r.right };
    }),
  );
  expect(boxes.length).toBeGreaterThan(0);
  for (const box of boxes) {
    expect(box.left).toBeGreaterThanOrEqual(area.x - 1);
    expect(box.right).toBeLessThanOrEqual(area.x + area.width + 1);
  }
};

test("a wider focus refits so no retained card is clipped", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const db = page.getByRole("button", { name: /^VM orders-db-01/ });
  await db.focus();
  await db.press("Enter");
  const focus = page.getByLabel("Focus around selected card", { exact: true });
  await focus.selectOption("callers:2");
  await expect(page.locator(".atlas-filter-status")).toContainText(
    "within 2 hops of orders-db-01",
  );
  await cardsInsideMap(page);
});

test("showing a candidate path keeps the map usable and fits both ends", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const before = (await page.locator(".map-area").boundingBox())!.height;
  await (
    await openFindings(page)
  )
    .getByRole("article", { name: "Blocked conversation", exact: true })
    .getByRole("button", { name: "Show path", exact: true })
    .click();
  await expect(page.locator(".path-strip")).toBeVisible();
  await expect(page.locator(".path-strip")).toBeInViewport();
  const after = (await page.locator(".map-area").boundingBox())!.height;
  expect(after).toBeGreaterThanOrEqual(Math.min(before, 360));
  await cardsInsideMap(page, [/win-client-01/, /orders-db-01/]);
});

test("applications tables use the page width and every column stays reachable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(
    "/tests/browser/browser.html?page=applications&scenario=meraki-nxos",
  );
  await page.getByLabel("Find an address, EPG, or device").fill("10.71.0.20");
  await page.getByRole("button", { name: "Find", exact: true }).click();
  const tables = page.locator("table");
  await expect(tables).toHaveCount(3);
  for (const index of [0, 1, 2]) {
    const state = await tables.nth(index).evaluate((table) => {
      const wrapper = table.parentElement!;
      const heads = [...table.querySelectorAll("th")];
      const visible = wrapper.getBoundingClientRect();
      wrapper.scrollLeft = wrapper.scrollWidth;
      const last = heads[heads.length - 1].getBoundingClientRect();
      return {
        overflow: getComputedStyle(wrapper).overflowX,
        lastReachable: last.right <= visible.right + 1,
        wrapperWithinViewport: visible.right <= innerWidth,
        scrollbarHeight: getComputedStyle(wrapper, "::-webkit-scrollbar")
          .height,
      };
    });
    expect(state.overflow).toMatch(/auto|scroll/);
    expect(state.lastReachable).toBe(true);
    expect(state.wrapperWithinViewport).toBe(true);
    expect(state.scrollbarHeight).toBe("12px");
  }
  const catalog = tables.last();
  await catalog.evaluate((table) => {
    table.parentElement!.scrollLeft = 0;
  });
  const unknown = catalog.getByRole("columnheader", { name: /Unknown \(1h\)/ });
  const box = (await unknown.boundingBox())!;
  const wrapper = (await catalog.locator("xpath=..").boundingBox())!;
  expect(box.x + box.width).toBeLessThanOrEqual(wrapper.x + wrapper.width + 1);
});

test("directed focus discloses empty, inferred and blocked evidence", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const db = page.getByRole("button", { name: /^VM orders-db-01/ });
  await db.focus();
  await db.press("Enter");
  const focus = page.getByLabel("Focus around selected card", { exact: true });
  const status = page.locator(".atlas-filter-status");
  await focus.selectOption("dependencies:1");
  await expect(status).toContainText(
    "No dependencies were observed here; that does not show that none exist.",
  );
  await focus.selectOption("callers:2");
  await expect(status).toContainText(
    "1 blocked conversation between shown cards, not followed.",
  );
});

test("Explore hosts trace and device placeholders that deep link", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=applications&mode=demo");
  await expect(
    page.getByRole("link", { name: "Explore", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  const trace = page.getByRole("form", { name: "Trace path" });
  await expect(trace.getByRole("button", { name: "Trace" })).toBeDisabled();
  await trace.getByLabel("Trace source").fill("10.30.40.25");
  await trace.getByLabel("Trace destination").fill("orders-db-01");
  await trace.getByRole("button", { name: "Trace" }).click();
  // The trace draws inline on Explore and keeps the pair in the URL.
  const view = page.getByRole("region", {
    name: "Trace 10.30.40.25 to orders-db-01",
  });
  await expect(view).toContainText("win-client-01 → orders-db-01");
  await expect(view.getByRole("list", { name: "Hops" })).toBeVisible();
  await expect(page).toHaveURL(
    /trace_src=10\.30\.40\.25&trace_dst=orders-db-01/,
  );
  await view.getByRole("link", { name: "Open on map" }).click();
  await expect(page).toHaveURL(/\/map\?/);
  const url = new URL(page.url());
  expect(url.searchParams.get("trace_src")).toBe("10.30.40.25");
  expect(url.searchParams.get("trace_dst")).toBe("orders-db-01");
  await expect(page.locator(".atlas-map-header")).toBeVisible();

  await page.goto("/tests/browser/browser.html?page=applications&mode=demo");
  const device = page.getByRole("form", { name: "Device lookup" });
  await device.getByLabel("Device name or ID").fill("pod-1/node-103");
  await device.getByRole("button", { name: "Open" }).click();
  await expect(page).toHaveURL(/\/device\?mode=demo&id=pod-1%2Fnode-103$/);
  await expect(
    page.getByRole("heading", { name: "leaf-103", exact: true }),
  ).toBeVisible();
});

test("trace deep link draws the demo hop strip and highlights the map", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=map&mode=demo&scenario=aci&trace_src=10.30.40.25&trace_dst=10.20.30.40",
  );
  const trace = page.getByRole("region", {
    name: "Trace 10.30.40.25 to 10.20.30.40",
  });
  await expect(trace).toContainText("win-client-01 → orders-db-01");
  await expect(trace).toContainText("tcp/5432");
  await expect(trace).toContainText("2 records");
  await expect(trace).toContainText("Traced");
  await expect(trace.getByText("Blocked").first()).toBeVisible();
  const hops = trace.getByRole("list", { name: "Hops" }).getByRole("button");
  await expect(hops).toHaveCount(7);
  // IS-IS and COOP evidence narrow the ECMP choice to one spine (still inferred).
  await expect(hops.nth(3)).toContainText("spine-201");
  await expect(hops.nth(3)).toContainText("Inferred");
  await expect(hops.nth(1)).not.toContainText("Inferred");
  await expect(page.locator(".map-canvas .item.match").first()).toBeVisible();
  await hops.nth(1).click();
  const detail = trace.getByRole("complementary", { name: "Hop vmm-shop" });
  await expect(detail).toContainText("Stream NetFlow");
  await expect(detail).toContainText("vmnic2");
  await expect(detail.getByRole("link", { name: "Open device" })).toBeVisible();
  // Closing the trace drops it from the shared URL.
  await trace.getByRole("button", { name: "Close trace" }).click();
  await expect(trace).toHaveCount(0);
  await expect(page).not.toHaveURL(/trace_src/);
});

test("map trace form runs a trace by name and keeps it in the URL", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=map&mode=demo");
  const form = page.getByRole("form", { name: "Trace path" });
  await form.getByLabel("Trace source").fill("win-client-01");
  await form.getByLabel("Trace destination").fill("orders-db-01");
  await form.getByRole("button", { name: "Trace" }).click();
  await expect(page).toHaveURL(
    /trace_src=win-client-01&trace_dst=orders-db-01/,
  );
  await expect(
    page.getByRole("region", { name: "Trace win-client-01 to orders-db-01" }),
  ).toContainText("Traced");
  await form.getByLabel("Trace source").fill("10.0.0.250");
  await form.getByRole("button", { name: "Trace" }).click();
  await expect(
    page.getByRole("region", { name: "Trace 10.0.0.250 to orders-db-01" }),
  ).toContainText("not a known endpoint");
});

test("device page lists conversations and a row traces the pair", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=demo&id=192.0.2.73",
  );
  await expect(
    page.getByRole("heading", { name: "esx-03", exact: true }),
  ).toBeVisible();
  const kpis = page.getByLabel("Summary");
  await expect(kpis).toContainText("1 flow");
  await expect(kpis).toContainText("2 peers");
  await expect(kpis).toContainText("60 B");
  await expect(kpis).toContainText("0 blocked");
  await expect(kpis).toContainText("Stream NetFlow · 192.0.2.73");
  const table = page.getByRole("region", { name: "Conversations" });
  await expect(table).toContainText("win-client-01");
  await expect(table).toContainText("tcp/5432");
  // Separate In and Out columns.
  await expect(table.getByRole("cell", { name: "ifIndex 18" })).toBeVisible();
  await expect(table.getByRole("cell", { name: "ifIndex 14" })).toBeVisible();
  await table.getByRole("cell", { name: "60 B" }).click();
  await expect(page).toHaveURL(/\/map\?.*trace_src=10\.30\.40\.25/);
  await expect(
    page.getByRole("region", { name: "Trace 10.30.40.25 to 10.20.30.40" }),
  ).toContainText("Traced");
});

test("device page resolves a DN and shows blocked conversations", async ({
  page,
}) => {
  await page.goto(
    "/tests/browser/browser.html?page=device&mode=demo&id=topology/pod-1/node-103",
  );
  await expect(
    page.getByRole("heading", { name: "leaf-103", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Summary")).toContainText("1 blocked");
  await page.goto("/tests/browser/browser.html?page=device&mode=demo&id=nope");
  await expect(page.getByText("Not in inventory")).toBeVisible();
});

test("double-clicking a device card opens its page", async ({ page }) => {
  await page.goto("/tests/browser/browser.html?page=map&mode=demo&tab=devices");
  const card = page.locator(".device-card header").first();
  await card.dblclick();
  await expect(page).toHaveURL(/\/device\?mode=demo&id=/);
  await expect(
    page.getByLabel("Summary").or(page.getByText("Not in inventory")),
  ).toBeVisible();
});

test("Admin groups Setup and Data health; Help is a header link", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=data_health&mode=demo");
  const tabs = page.getByRole("navigation", { name: "Admin" });
  await expect(
    tabs.getByRole("link", { name: "Data health", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    page.getByRole("link", { name: "Admin", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    page.getByRole("link", { name: "Help", exact: true }),
  ).toHaveAttribute("href", /\/help$/);
});

test("map chrome stays within one header row at 1440x900", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  // The real bootstrap, not the harness page, carries the production chrome.
  await page.goto("/map?mode=demo");
  await expect(page.locator(".adm")).toHaveAttribute("data-loaded", "true");
  const area = (await page.locator(".map-area").boundingBox())!;
  expect(area.y).toBeLessThanOrEqual(120);
  await expect(page.getByRole("button", { name: /^Findings/ })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
  await expect(page.getByRole("region", { name: "Map findings" })).toHaveCount(
    0,
  );
});

test("live Explore traces names without a built map", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=path-trace",
  );
  const form = page.getByRole("form", { name: "Trace path" });
  await form.getByLabel("Trace source").fill("win-client-01");
  await form.getByLabel("Trace destination").fill("10.20.30.40");
  await form.getByRole("button", { name: "Trace" }).click();
  const view = page.getByRole("region", {
    name: "Trace win-client-01 to 10.20.30.40",
  });
  await expect(view).toContainText("tcp/5432");
  await expect(view).toContainText("Traced");
  await expect(
    view.getByRole("list", { name: "Hops" }).getByRole("button"),
  ).toHaveCount(7);
  const searches = await page.evaluate(() =>
    (window.__ADM_REQUESTS__ ?? []).map((r) => r.spl),
  );
  expect(searches).toContain("| `adm_path_trace_resolve(win-client-01)`");
  expect(searches).toContain("| `adm_path_trace(10.30.40.25,10.20.30.40)`");
  await form.getByLabel("Trace source").fill("ghost");
  await form.getByRole("button", { name: "Trace" }).click();
  await expect(
    page.getByRole("region", { name: "Trace ghost to 10.20.30.40" }),
  ).toContainText('Source "ghost" not found.');
});

test("live trace search errors offer a retry", async ({ page }) => {
  await page.goto(
    "/tests/browser/browser.html?page=applications&mode=live&fault=trace-error",
  );
  const form = page.getByRole("form", { name: "Trace path" });
  await form.getByLabel("Trace source").fill("10.30.40.25");
  await form.getByLabel("Trace destination").fill("10.20.30.40");
  await form.getByRole("button", { name: "Trace" }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "timeout" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
});
