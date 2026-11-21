import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";

const assets = "splunk_app/splunk_adm/appserver/static";

async function openAtlas(page: Page, entry: "impact" | "help", fail = false) {
  const atlas = await readFile(`${assets}/pages/atlas.js`, "utf8");
  const impact = await readFile(`${assets}/pages/impact.js`, "utf8");
  const css = await readFile(`${assets}/impact.css`, "utf8");
  const manifest = JSON.parse(
    await readFile(`${assets}/impact-manifest.json`, "utf8"),
  );
  let broken = fail;
  const requested: URL[] = [];
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (route.request().isNavigationRequest()) {
      return route.fulfill({
        contentType: "text/html",
        body: '<!doctype html><div id="atlas-root"></div>',
      });
    }
    if (url.pathname.endsWith("/pages/impact.js")) {
      requested.push(url);
      return route.fulfill({
        contentType: "text/javascript",
        body: broken
          ? impact.replaceAll(manifest.assetVersion, "0".repeat(24))
          : impact,
      });
    }
    if (url.pathname.endsWith("/impact.css")) {
      requested.push(url);
      return route.fulfill({ contentType: "text/css", body: css });
    }
    if (route.request().resourceType() === "script")
      return route.fulfill({ contentType: "text/javascript", body: "" });
    return route.fulfill({
      contentType: "application/json",
      body: '{"entry":[]}',
    });
  });
  await page.addInitScript(() => {
    const global = window as typeof window & { define?: unknown };
    global.define = Object.assign(
      () => {
        throw new Error("Impact leaked an AMD definition");
      },
      { amd: {} },
    );
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`/en-US/app/splunk_adm/${entry}`);
  await page.addScriptTag({ content: atlas });
  return {
    requested,
    errors,
    version: manifest.assetVersion,
    repair: () => {
      broken = false;
    },
  };
}

test("the Impact asset is loaded only for the Impact page", async ({
  page,
}) => {
  const help = await openAtlas(page, "help");
  await expect(
    page.getByRole("heading", { name: /Help/i }).first(),
  ).toBeVisible();
  expect(help.requested).toHaveLength(0);
});

test("the packaged Impact page loads version-matched JS and CSS under AMD", async ({
  page,
}) => {
  const result = await openAtlas(page, "impact");
  await expect(
    page.getByText("If this fails", { exact: true }).first(),
  ).toBeVisible();
  expect(
    result.requested.map((url) => url.pathname.split("/").at(-1)).sort(),
  ).toEqual(["impact.css", "impact.js"]);
  expect(
    result.requested.every(
      (url) => url.searchParams.get("v") === result.version,
    ),
  ).toBe(true);
  expect(result.errors).toEqual([]);
});

test("a mismatched version fails closed and refreshes on Retry", async ({
  page,
}) => {
  const result = await openAtlas(page, "impact", true);
  await expect(page.getByRole("alert")).toContainText("different app version");
  await expect(page.getByText("If this fails", { exact: true })).toHaveCount(0);
  result.repair();
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(
    page.getByText("If this fails", { exact: true }).first(),
  ).toBeVisible();
  expect(result.errors).toEqual([]);
});
