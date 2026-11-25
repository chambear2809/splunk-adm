import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";

const staticRoot = "splunk_app/splunk_adm/appserver/static";

async function loadHistoryAsset(page: Page, failure?: "missing" | "version") {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const javascript = await readFile(`${staticRoot}/pages/history.js`, "utf8");
  const style = await readFile(`${staticRoot}/history.css`, "utf8");
  const manifest = JSON.parse(
    await readFile(`${staticRoot}/history-manifest.json`, "utf8"),
  ) as { assetVersion: string };
  await page.addInitScript(() => {
    const global = window as typeof window & {
      __AtlasHistoryHost?: Record<string, unknown>;
    };
    global.__AtlasHistoryHost = {
      assetVersion: "test",
      react: {},
      jsxRuntime: {},
      evidence: {},
      evidenceConfig: {},
      searchClient: {},
      deploymentHealth: {},
      optionalJobs: {},
      canonicalJson: {},
    };
  });
  await page.setContent(
    '<main aria-label="Other evidence">Evidence remains available</main>',
  );
  if (failure === "missing") {
    return { manifest, requested: false, loadedVersion: undefined, errors };
  }
  const script =
    failure === "version"
      ? javascript.replaceAll(manifest.assetVersion, "0".repeat(24))
      : javascript;
  await page.addStyleTag({ content: style });
  await page.addScriptTag({
    content: `var __AtlasHistoryHost = { react: {}, jsxRuntime: {}, evidence: {}, evidenceConfig: {}, searchClient: {}, deploymentHealth: {}, optionalJobs: {}, canonicalJson: {} };\n${script}\nwindow.__historyLoaded = true;`,
  });
  return {
    manifest,
    requested: true,
    loadedVersion:
      failure === "version" ? "0".repeat(24) : manifest.assetVersion,
    errors,
  };
}

test("packaged history asset loads with its manifest version", async ({
  page,
}) => {
  const result = await loadHistoryAsset(page);
  await expect(
    page.getByRole("main", { name: "Other evidence" }),
  ).toContainText("Evidence remains available");
  expect(result.requested).toBe(true);
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __historyLoaded?: boolean }).__historyLoaded,
    ),
  ).toBe(true);
  expect(result.errors).toEqual([]);
  expect(result.loadedVersion).toBe(result.manifest.assetVersion);
});

test("missing history asset leaves other evidence usable", async ({ page }) => {
  const result = await loadHistoryAsset(page, "missing");
  await expect(
    page.getByRole("main", { name: "Other evidence" }),
  ).toContainText("Evidence remains available");
  expect(result.requested).toBe(false);
});

test("version-mismatched history asset is observable and does not clear other evidence", async ({
  page,
}) => {
  const result = await loadHistoryAsset(page, "version");
  await expect(
    page.getByRole("main", { name: "Other evidence" }),
  ).toContainText("Evidence remains available");
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __historyLoaded?: boolean }).__historyLoaded,
    ),
  ).toBe(true);
  expect(result.errors).toEqual([]);
  expect(result.loadedVersion).not.toBe(result.manifest.assetVersion);
});
