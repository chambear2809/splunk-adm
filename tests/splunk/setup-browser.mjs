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
  page.on("response", (response) => {
    const request = response.request();
    const path = new URL(request.url()).pathname;
    if (
      request.method() === "POST" &&
      /\/(configs\/conf-macros|saved\/searches)\//.test(path)
    ) {
      writes.push({
        status: response.status(),
        csrf: !!request.headers()["x-splunk-form-key"],
        namespace: path.includes("/servicesNS/nobody/splunk_adm/"),
      });
    }
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
      .filter({ hasText: "ADM - Application catalog" })
      .getByText("Enabled", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "dist/atlas-phase5-setup-native.png",
    fullPage: true,
  });
  stage = "demo setup";
  const before = writes.length;
  await page.goto("http://127.0.0.1:8000/en-US/app/splunk_adm/setup?mode=demo");
  await expect(root.getByText(/Setup is unavailable in Demo/)).toBeVisible({
    timeout: 60000,
  });
  await expect(root.getByRole("textbox")).toHaveCount(0);
  if (
    writes.length !== before ||
    writes.length !== 3 ||
    writes.some(
      (write) => write.status >= 400 || !write.csrf || !write.namespace,
    )
  )
    throw new Error("Native write qualification failed");
  process.stdout.write(
    JSON.stringify({
      ok: true,
      verifiedWrites: writes.length,
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
