import { expect, test } from "@playwright/test";

function controllerRows(
  snapshot: string,
  index: string,
  snapshotAt: number,
  label: string,
) {
  return [
    {
      record_type: "snapshot",
      record_counts: {
        total_records: 4,
        applications: 1,
        tiers: 1,
        nodes: 1,
        backends: 0,
      },
    },
    {
      record_type: "application",
      application_id: 101,
      application_name: label,
    },
    { record_type: "tier", application_id: 101, tier_id: 8, tier_name: "API" },
    {
      record_type: "node",
      application_id: 101,
      tier_id: 8,
      node_id: 5,
      node_name: "checkout-api-1",
      ip_addresses: [],
    },
  ].map((record, position) => ({
    index,
    _indextime: String(snapshotAt + 1),
    _raw: JSON.stringify({
      ...record,
      schema: "application_atlas.appdynamics_inventory.v1",
      schema_version: 1,
      source: "appdynamics_inventory",
      controller_authority: "controller-test",
      scope: "lab",
      identity_basis: "controller_application_model_ids",
      snapshot_id: snapshot,
      snapshot_at: snapshotAt,
      collection_started_at: snapshotAt - 1,
      collection_completed_at: snapshotAt,
      collection_skew_seconds: 1,
      observed_at: snapshotAt,
      snapshot_complete: true,
      record_id: String(position),
      record_fingerprint: String(position + 1).padStart(64, "0"),
    }),
  }));
}

test("Controller catalog and map admit replay across approved indexes and reject conflicts", async ({
  page,
}) => {
  const now = Math.floor(Date.now() / 1000);
  const rows = controllerRows("approved", "atlas_asset", now - 20, "Checkout");
  rows[3].index = "atlas_asset_previous";
  const replay = { ...rows[1], index: "atlas_asset_previous" };
  const decoy = controllerRows(
    "decoy",
    "outside_selector",
    now - 10,
    "Wrong Checkout",
  );
  const conflict = {
    ...replay,
    _raw: JSON.stringify({
      ...JSON.parse(replay._raw),
      application_name: "Conflicting Checkout",
    }),
  };
  await page.addInitScript(
    ({ clean, conflicting }) => {
      window.__ADM_APPD_ROWS__ = new URLSearchParams(location.search).has(
        "conflict",
      )
        ? [...clean, conflicting]
        : clean;
    },
    { clean: [...rows, replay, ...decoy], conflicting: conflict },
  );
  await page.route(/\/configs\/v1\/conftypes\/macros\/stanzas:get/, (route) =>
    route.fulfill({
      json: {
        settings: [
          {
            setting: "definition",
            value:
              route.request().postDataJSON()?.stanza ===
              "adm_appdynamics_inventory_schema_qualified"
                ? "1"
                : "(index=atlas_asset OR index=atlas_asset_previous)",
          },
        ],
      },
    }),
  );
  await page.route(/\/adm\/deployment-settings\?/, (route) =>
    route.fulfill({
      json: {
        state: "configured",
        observedRevisions: ["fixture"],
        settings: {
          schemaVersion: 1,
          revision: "fixture",
          sources: {
            appdynamics_inventory: {
              state: "active",
              cadenceSeconds: 60,
              staleAfterSeconds: 3600,
            },
          },
        },
      },
    }),
  );
  await page.route(
    /\/storage\/collections\/data\/adm_observer_scope\?/,
    (route) =>
      route.fulfill({
        json: new URL(route.request().url()).searchParams.has("skip")
          ? []
          : [
              {
                _key: "appd-fixture",
                observer_kind: "appd_controller",
                observer: "controller-test",
                scope: "lab",
                mapping_status: "verified",
              },
            ],
      }),
  );
  await page.route(/\/map\?/, async (route) => {
    const harness = new URL(
      "/tests/browser/browser.html",
      route.request().url(),
    );
    await route.fulfill({ response: await route.fetch({ url: harness.href }) });
  });

  const applications =
    "/tests/browser/browser.html?page=applications&mode=live";
  await page.goto(applications);
  await page.getByText("AppDynamics applications", { exact: true }).click();
  const catalog = page.getByRole("region", {
    name: "AppDynamics Controller catalog",
  });
  const checkout = catalog.getByRole("link", { name: "Checkout", exact: true });
  await expect(checkout).toHaveCount(1);
  await expect(catalog.getByText("Wrong Checkout")).toHaveCount(0);
  const searches = await page.evaluate(() =>
    window.__ADM_REQUESTS__?.filter(({ spl }) =>
      spl.includes("adm:appdynamics_inventory"),
    ),
  );
  expect(searches).toHaveLength(1);
  expect(searches?.[0].spl).toContain(
    "(index=atlas_asset OR index=atlas_asset_previous)",
  );
  expect(searches?.[0].spl).not.toContain("outside_selector");
  await checkout.click();
  await expect(page).toHaveURL(/appd_snapshot=approved/);
  await expect(
    page.getByRole("heading", {
      name: "Checkout · Controller application ID 101",
    }),
  ).toBeVisible();
  await expect(page.getByText("checkout-api-1", { exact: true })).toHaveCount(
    1,
  );

  await page.goto(applications + "&conflict=1");
  await page.getByText("AppDynamics applications", { exact: true }).click();
  await expect(catalog.getByRole("status")).toContainText(
    "conflicting replayed records",
  );
  await expect(checkout).toHaveCount(0);
});
