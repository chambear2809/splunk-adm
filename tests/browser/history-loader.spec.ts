import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const staticRoot = "splunk_app/splunk_adm/appserver/static";

async function setup(
  page: import("@playwright/test").Page,
  failure?: "js" | "css" | "version",
) {
  const javascript = await readFile(`${staticRoot}/pages/history.js`, "utf8");
  const css = await readFile(`${staticRoot}/history.css`, "utf8");
  const manifest = JSON.parse(
    await readFile(`${staticRoot}/history-manifest.json`, "utf8"),
  ) as { assetVersion: string };
  const requests: string[] = [];
  await page.route("**/app/splunk_adm/**", async (route) => {
    const url = new URL(route.request().url());
    requests.push(url.pathname);
    if (url.pathname.endsWith("/pages/history.js")) {
      if (failure === "js") return route.fulfill({ status: 404 });
      return route.fulfill({
        contentType: "text/javascript",
        body:
          failure === "version"
            ? javascript.replaceAll(manifest.assetVersion, "0".repeat(24))
            : javascript,
      });
    }
    if (url.pathname.endsWith("/history.css")) {
      if (failure === "css") return route.fulfill({ status: 404 });
      return route.fulfill({ contentType: "text/css", body: css });
    }
    return route.continue();
  });
  await page.goto("/tests/browser/history-loader.html");
  return { manifest, requests };
}

test("production history loader requests versioned JS/CSS and preserves other evidence", async ({
  page,
}) => {
  const { manifest, requests } = await setup(page);
  await expect(
    page.getByRole("main", { name: "Other evidence" }),
  ).toContainText("Evidence remains available");
  await expect(
    page.getByRole("button", { name: "Inspect configuration history" }),
  ).toBeVisible();
  expect(
    requests.filter((path) => path.endsWith("/pages/history.js")),
  ).toHaveLength(1);
  expect(requests.filter((path) => path.endsWith("/history.css"))).toHaveLength(
    1,
  );
  expect(requests).toEqual(
    expect.arrayContaining([
      expect.stringContaining("/pages/history.js"),
      expect.stringContaining("/history.css"),
    ]),
  );
  expect(manifest.assetVersion).toMatch(/^[a-f0-9]{24}$/);
});

for (const failure of ["js", "css", "version"] as const) {
  test(`production history ${failure} failure preserves other evidence`, async ({
    page,
  }) => {
    await setup(page, failure);
    await expect(
      page.getByRole("main", { name: "Other evidence" }),
    ).toContainText("Evidence remains available");
    await expect(page.getByRole("alert")).toContainText(
      "Configuration history assets are unavailable",
    );
    await expect(
      page.getByRole("button", { name: "Inspect configuration history" }),
    ).toHaveCount(0);
  });
}
