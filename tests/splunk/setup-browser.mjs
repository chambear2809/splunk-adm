// Native administrator Setup qualification. Credentials stay in the child environment.
import { createRequire } from "node:module";
const require = createRequire(new URL("../../package.json", import.meta.url));
const { chromium, expect } = require("@playwright/test");
const browser = await chromium.launch({ headless: true });
let stage = "login";
try {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1100 },
  });
  await page.goto("http://127.0.0.1:8000/en-US/account/login");
  await page.locator('input[name="username"]').fill("admin");
  await page.locator('input[name="password"]').fill(process.env.ADM_SETUP_PASS);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes("/account/login")),
    page.locator('input[type="submit"], button[type="submit"]').first().click(),
  ]);
  const writes = [];
  const deploymentWrites = [];
  page.on("response", (response) => {
    const request = response.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== "POST") return;
    const evidence = {
      status: response.status(),
      csrf: !!request.headers()["x-splunk-form-key"],
      namespace: path.includes("/servicesNS/nobody/splunk_adm/"),
    };
    if (/\/(configs\/conf-macros|saved\/searches)\//.test(path))
      writes.push(evidence);
    if (/\/adm\/deployment-settings\/?$/.test(path))
      deploymentWrites.push(evidence);
  });
  stage = "live checklist";
  await page.goto("http://127.0.0.1:8000/en-US/app/splunk_adm/setup?mode=live");
  const root = page.locator("#atlas-root");
  await expect(root.getByText("Summary reader and writer match.")).toBeVisible({
    timeout: 90000,
  });
  await expect(
    root.getByText("Available: adm_summary", { exact: true }),
  ).toBeVisible();
  await expect(
    root.getByText(/stored mappings checked; 0 contain uppercase/),
  ).toBeVisible();
  const macro = root.getByRole("textbox", {
    name: "Index for adm_index_hubble",
    exact: true,
  });
  stage = "native input styling";
  await expect(macro).toBeVisible();
  const fieldStyle = await macro.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      background: style.backgroundColor,
      border: style.borderWidth,
      shadow: style.boxShadow,
    };
  });
  if (
    fieldStyle.background !== "rgba(0, 0, 0, 0)" ||
    fieldStyle.border !== "0px" ||
    fieldStyle.shadow !== "none"
  )
    throw new Error("Native dashboard field styling leaked");
  stage = "save deployment expectations";
  const saveExpectations = root.getByRole("button", {
    name: "Save deployment expectations",
    exact: true,
  });
  const traces = root.getByLabel("Expectation for Traces", { exact: true });
  await expect(traces).toBeEnabled({ timeout: 90000 });
  const sourceExpectations = root.getByLabel(/^Expectation for /);
  if ((await sourceExpectations.count()) === 0)
    throw new Error("Deployment source controls are unavailable");
  for (const source of await sourceExpectations.all())
    await source.selectOption("not_selected");
  // Pass through another state so the draft is dirty even when a previous
  // run already saved this exact selection (clean drafts cannot be saved).
  await traces.selectOption("staged");
  await traces.selectOption("active");
  await expect(saveExpectations).toBeEnabled({ timeout: 90000 });
  await saveExpectations.click();
  await expect(
    root.getByText("Deployment expectations saved and verified.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90000 });
  stage = "deployment expectations readback";
  await page.reload();
  await expect(
    root.getByText("Saved expectations; active data contract: 1.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90000 });
  await expect(
    root.getByLabel("Expectation for Traces", { exact: true }),
  ).toHaveValue("active");
  for (const source of await sourceExpectations.all()) {
    const label = await source.getAttribute("aria-label");
    await expect(source).toHaveValue(
      label === "Expectation for Traces" ? "active" : "not_selected",
    );
  }
  stage = "save macro";
  await macro.fill("adm_alt_nf");
  await root
    .getByRole("button", { name: "Save adm_index_hubble", exact: true })
    .click();
  await expect(
    root.getByText("Change saved and configuration refreshed.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90000 });
  await expect(macro).toHaveValue("adm_alt_nf");
  stage = "restore macro through UI";
  await macro.fill(process.env.ADM_SETUP_ORIGINAL_INDEX);
  await root
    .getByRole("button", { name: "Save adm_index_hubble", exact: true })
    .click();
  await expect(
    root.getByText("Change saved and configuration refreshed.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90000 });
  await expect(macro).toHaveValue(process.env.ADM_SETUP_ORIGINAL_INDEX);
  stage = "enable approved schedule";
  const enable = root.getByRole("button", {
    name: "Enable schedule for ADM - Application catalog",
    exact: true,
  });
  await expect(enable).toBeEnabled();
  await enable.click();
  await expect(
    root.getByText("Change saved and configuration refreshed.", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90000 });
  await expect(enable).toBeDisabled();
  await expect(
    root
      .getByRole("row")
      .filter({
        has: page.getByRole("cell", {
          name: "ADM - Application catalog",
          exact: true,
        }),
      })
      .getByText("Enabled", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "dist/atlas-phase5-setup-native.png",
    fullPage: true,
  });
  stage = "demo setup";
  const before = writes.length;
  const deploymentBefore = deploymentWrites.length;
  await page.goto("http://127.0.0.1:8000/en-US/app/splunk_adm/setup?mode=demo");
  await expect(root.getByText(/Setup is unavailable in Demo/)).toBeVisible({
    timeout: 60000,
  });
  await expect(root.getByRole("textbox")).toHaveCount(0);
  if (
    writes.length !== before ||
    writes.length !== 3 ||
    deploymentWrites.length !== deploymentBefore ||
    deploymentWrites.length !== 1 ||
    [...writes, ...deploymentWrites].some(
      (write) => write.status >= 400 || !write.csrf || !write.namespace,
    )
  )
    throw new Error("Native write qualification failed");
  process.stdout.write(
    JSON.stringify({
      ok: true,
      verifiedWrites: writes.length,
      verifiedDeploymentWrites: deploymentWrites.length,
      deploymentReadback: true,
      csrf: true,
      demoWrites: 0,
    }) + "\n",
  );
} catch (error) {
  process.stdout.write(
    JSON.stringify({ ok: false, stage, errorKind: error.name }) + "\n",
  );
  process.exitCode = 1;
} finally {
  await browser.close();
}
