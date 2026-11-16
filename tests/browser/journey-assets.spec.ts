import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";

const staticRoot = "splunk_app/splunk_adm/appserver/static";
async function setupAssets(page: Page, failure?: "js" | "css" | "version") {
  const javascript = await readFile(`${staticRoot}/pages/journeys.js`, "utf8");
  const css = await readFile(`${staticRoot}/journeys.css`);
  const manifest = JSON.parse(
    await readFile(`${staticRoot}/journeys-manifest.json`, "utf8"),
  );
  let broken = Boolean(failure);
  const requests: string[] = [];
  await page.route("**/app/splunk_adm/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    requests.push(pathname);
    if (pathname.endsWith("/pages/journeys.js")) {
      if (broken && failure === "js") return route.fulfill({ status: 404 });
      return route.fulfill({
        contentType: "text/javascript",
        body:
          broken && failure === "version"
            ? javascript.replaceAll(manifest.assetVersion, "0".repeat(24))
            : javascript,
      });
    }
    if (pathname.endsWith("/journeys.css")) {
      if (broken && failure === "css") return route.fulfill({ status: 404 });
      return route.fulfill({ contentType: "text/css", body: css });
    }
    return route.continue();
  });
  return {
    requests,
    repair: () => {
      broken = false;
    },
  };
}

test("production asset loads on demand with AMD and protects export", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const { requests } = await setupAssets(page);
  await page.goto("/tests/browser/journey-assets.html");
  await expect(
    page.getByRole("button", { name: "Open proxy request evidence" }),
  ).toBeVisible();
  expect(requests).toEqual([]);
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(
    page.getByRole("heading", { name: /Proxy request · Same request event/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Journey investigation", exact: true }),
  ).toBeFocused();
  expect(
    requests.filter((path) => path.endsWith("/pages/journeys.js")),
  ).toHaveLength(1);
  expect(
    requests.filter((path) => path.endsWith("/journeys.css")),
  ).toHaveLength(1);
  expect(
    await page.evaluate(
      () => (window as unknown as { amdCalls: number }).amdCalls,
    ),
  ).toBe(0);
  expect(errors).toEqual([]);
  await page
    .getByText("Download journey evidence", { exact: true })
    .first()
    .click();
  const download = page.getByRole("button", {
    name: "Download journey evidence",
    exact: true,
  });
  await expect(download).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(download).toBeEnabled();
  const pending = page.waitForEvent("download");
  await download.click();
  const payload = JSON.parse(
    await readFile((await (await pending).path())!, "utf8"),
  );
  expect(payload.journeys[0].relation).toBe("request_reported");
});

for (const failure of ["js", "css", "version"] as const) {
  test(`unavailable or mismatched ${failure} can be retried`, async ({
    page,
  }) => {
    const { repair } = await setupAssets(page, failure);
    await page.goto("/tests/browser/journey-assets.html");
    await page
      .getByRole("button", { name: "Open proxy request evidence" })
      .click();
    await expect(page.getByRole("alert")).toContainText(
      "unavailable or from a different app version",
    );
    await expect(
      page.getByRole("button", { name: "Open proxy request evidence" }),
    ).toBeFocused();
    repair();
    await page
      .getByRole("button", { name: "Open proxy request evidence" })
      .click();
    await expect(
      page.getByRole("heading", { name: /Proxy request · Same request event/ }),
    ).toBeVisible();
  });
}

for (const [kind, label, heading] of [
  ["cases", "shared cases", "Shared cases"],
  ["ownershipImport", "business-service import", "Import business services"],
  ["maintenance", "maintenance planning", "Maintenance planning"],
  ["baseline", "dependency baseline", "Dependency baselines"],
] as const) {
  test(`production optional ${kind} opens without an eager request`, async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const { requests } = await setupAssets(page);
    await page.goto(`/tests/browser/journey-assets.html?kind=${kind}`);
    expect(requests).toEqual([]);
    await page
      .getByRole("button", {
        name: kind === "cases" ? "Open shared cases" : `Open ${label} evidence`,
      })
      .click();
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    if (kind === "ownershipImport") {
      await page.getByLabel("JSON import").fill("{}");
      await page.getByRole("button", { name: "Preview import" }).click();
      await expect(
        page.getByText("Import has errors. No rows are ready to apply."),
      ).toBeVisible();
    }
    if (kind === "cases") {
      await page.getByLabel("New case title").fill("Synthetic uncertain write");
      await page.getByRole("button", { name: "Create shared case" }).click();
      await expect(
        page.getByRole("button", { name: "Retry same request" }),
      ).toBeVisible();
      await expect(
        page.getByRole("button", { name: "Create shared case" }),
      ).toBeDisabled();
    }
    expect(errors).toEqual([]);
  });
}
