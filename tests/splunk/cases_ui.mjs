// Actual installed Web UI. Only the deliberately dropped post-commit response
// is injected; all case data and ACL decisions come from the installed backend.
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import {
  writeFileSync,
  openSync,
  fsyncSync,
  closeSync,
  renameSync,
} from "node:fs";
import { readFile, mkdir, writeFile, rename, open } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";

const input = JSON.parse(await readFile("/dev/stdin", "utf8"));
const origin = new URL(input.url);
if (origin.hostname !== "127.0.0.1" || origin.protocol !== "https:")
  throw new Error("exact local HTTPS only");
const out = input.output;
const receipt = {
  status: "running",
  phase: "setup",
  checks: [],
  mutations: [],
  screenshots: [],
  layouts: [],
};
const processReceipt = { launches: [] };
const processPath = path.join(out, "browser-processes.json");
function persistProcesses() {
  const temp = processPath + ".tmp";
  writeFileSync(temp, JSON.stringify(processReceipt, null, 2) + "\n", {
    mode: 0o600,
  });
  const fd = openSync(temp, "r");
  fsyncSync(fd);
  closeSync(fd);
  renameSync(temp, processPath);
  const dir = openSync(out, "r");
  fsyncSync(dir);
  closeSync(dir);
}
const originalSpawn = childProcess.spawn;
childProcess.spawn = function (command, args, options) {
  if (command !== input.browserExecutable)
    return originalSpawn.call(this, command, args, options);
  const profile = args[args.indexOf("-profile") + 1];
  if (
    !options.detached ||
    !["owner", "member"].some(
      (name) => profile === path.join(input.runtime, "firefox-" + name),
    )
  )
    throw new Error("unowned Firefox launch refused");
  const launch = {
    executable: command,
    profile,
    state: "prepared",
    argv: args,
  };
  processReceipt.launches.push(launch);
  persistProcesses();
  const child = originalSpawn.call(this, command, args, options);
  launch.pid = child.pid;
  launch.pgid = child.pid;
  launch.identity = execFileSync(
    "ps",
    ["-p", String(child.pid), "-o", "pid=,pgid=,lstart=,command="],
    { encoding: "utf8" },
  ).trim();
  launch.state = "spawned";
  persistProcesses();
  return child;
};
syncBuiltinESMExports();
const { firefox, expect } = await import("@playwright/test");
if (firefox.executablePath() !== input.browserExecutable)
  throw new Error("browser executable changed");

const contexts = [];
let drop = false;
let dropped = false;
let searches = 0;
let caseRequests = 0;
let caseId;
let persistence = Promise.resolve();
function persist() {
  persistence = persistence.then(async () => {
    receipt.observed_search_jobs = searches;
    receipt.observed_case_requests = caseRequests;
    const target = path.join(out, "ui-receipt.json");
    const temp = target + ".tmp";
    await writeFile(temp, JSON.stringify(receipt, null, 2) + "\n", {
      mode: 0o600,
    });
    const fd = await open(temp, "r");
    await fd.sync();
    await fd.close();
    await rename(temp, target);
    const directory = await open(out, "r");
    await directory.sync();
    await directory.close();
  });
  return persistence;
}
async function phase(name, fn) {
  receipt.phase = name;
  await persist();
  await fn();
  receipt.checks.push(name);
  await persist();
}
async function shot(page, name) {
  await page.screenshot({
    path: path.join(out, name + ".png"),
    fullPage: true,
  });
  receipt.screenshots.push(name + ".png");
  await persist();
}
async function browser(name) {
  const profile = path.join(input.runtime, "firefox-" + name);
  await mkdir(profile, { mode: 0o700 });
  execFileSync("certutil", ["-N", "--empty-password", "-d", "sql:" + profile], {
    stdio: "ignore",
  });
  execFileSync(
    "certutil",
    [
      "-A",
      "-d",
      "sql:" + profile,
      "-n",
      "Atlas task CA",
      "-t",
      "C,,",
      "-i",
      input.ca,
    ],
    { stdio: "ignore" },
  );
  const context = await firefox.launchPersistentContext(profile, {
    headless: true,
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 1000 },
    acceptDownloads: true,
    firefoxUserPrefs: {
      "security.enterprise_roots.enabled": false,
      "network.proxy.type": 0,
    },
  });
  contexts.push(context);
  receipt.browser = context.browser().version();
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  page.on("request", (r) => {
    if (/\/search\/(?:v\d+\/)?jobs(?:\?|\/|$)/.test(r.url())) searches++;
  });
  await page.route("**/adm/investigations/**", async (route) => {
    caseRequests++;
    const request = route.request();
    if (request.method() !== "POST") return route.continue();
    const entry = {
      method: request.method(),
      path: new URL(request.url()).pathname,
      key: request.headers()["idempotency-key"],
      body: request.postData(),
      state: "prepared",
      browser: name,
    };
    receipt.mutations.push(entry);
    await persist();
    try {
      // NODE_EXTRA_CA_CERTS supplies the same public task CA to Node's HTTPS
      // transport. No TLS exceptions or automatic POST retries are allowed.
      entry.state = "sent_outcome_unknown";
      await persist();
      const response = await route.fetch({
        maxRedirects: 0,
        maxRetries: 0,
        timeout: 30000,
      });
      entry.status = response.status();
      const responseText = await response.text();
      try {
        entry.response = JSON.parse(responseText);
      } catch {
        entry.response_summary = {
          sha256: createHash("sha256").update(responseText).digest("hex"),
          identifies_csrf: /csrf/i.test(responseText),
        };
      }
      entry.state = "response_received";
      await persist();
      if (drop && !dropped && entry.path.endsWith("/entries")) {
        if (response.status() !== 200)
          throw new Error("cannot drop unsuccessful write");
        dropped = true;
        entry.browser_response_dropped = true;
        await persist();
        return route.abort("failed");
      }
      await route.fulfill({ response });
    } catch (error) {
      entry.transport_error = true;
      entry.transport_reason = String(error).split("\n")[0];
      await persist();
      await route.abort("failed");
    }
  });
  return page;
}
async function login(page, index) {
  await page.goto(input.url + "/en-US/account/login", {
    waitUntil: "domcontentloaded",
  });
  await page.locator('input[name="username"]').fill(input.users[index][0]);
  await page.locator('input[name="password"]').fill(input.users[index][1]);
  await page
    .locator('input[type="submit"], button[type="submit"]')
    .first()
    .click();
  await page.waitForURL((url) => !url.pathname.includes("/account/login"));
  await page.goto(input.url + "/en-US/app/splunk_adm/cases", {
    waitUntil: "domcontentloaded",
  });
  await expect(
    page.getByRole("heading", { name: "Shared cases", level: 1 }),
  ).toBeVisible();
  const context = await page.evaluate(async () => {
    const r = await fetch(
      "/en-US/splunkd/__raw/services/authentication/current-context?output_mode=json",
    );
    return (await r.json()).entry[0].content;
  });
  expect(context.username).toBe(input.users[index][0]);
  expect(context.roles).toEqual([input.role]);
  expect(context.capabilities).toEqual(["adm_investigate"]);
}
async function windowForm(page) {
  await page.getByLabel("Case window start (UTC)").fill("2026-01-01T00:00:00Z");
  await page.getByLabel("Case window end (UTC)").fill("2026-01-01T01:00:00Z");
  await page
    .getByRole("button", { name: "Open shared cases", exact: true })
    .click();
  await expect(page.getByLabel("New case title")).toBeVisible();
}
async function saved(page, revision) {
  await expect(
    page.getByText(new RegExp(`^Revision ${revision} ·`)),
  ).toBeVisible();
}
async function download(page, button, name) {
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  const pending = page.waitForEvent("download");
  await page.getByRole("button", { name: button, exact: true }).click();
  const file = await pending;
  expect(await file.failure()).toBeNull();
  await file.saveAs(path.join(out, name));
  return readFile(path.join(out, name), "utf8");
}
try {
  await persist();
  const owner = await browser("owner");
  const member = await browser("member");
  await phase("restricted_login_and_direct_cases_entry", async () => {
    await login(owner, 0);
    await login(member, 1);
  });
  await phase("invalid_window_and_keyboard", async () => {
    await owner
      .getByLabel("Case window start (UTC)")
      .fill("2026-02-30T00:00:00Z");
    await owner
      .getByLabel("Case window end (UTC)")
      .fill("2026-03-01T01:00:00Z");
    await owner.getByLabel("Case window end (UTC)").press("Tab");
    await expect(
      owner.getByRole("button", { name: "Open shared cases", exact: true }),
    ).toBeFocused();
    await owner.keyboard.press("Enter");
    await expect(owner.getByRole("alert")).toContainText(
      "Enter an absolute UTC window",
    );
    await expect(owner.getByLabel("New case title")).toHaveCount(0);
    await windowForm(owner);
    await windowForm(member);
  });
  await phase("native_csrf_rejection_without_case_mutation", async () => {
    for (const invalid of [false, true]) {
      const result = await owner.evaluate(async (invalid) => {
        const headers = {
          "Content-Type": "application/json",
          "Idempotency-Key": "ui-csrf-" + String(invalid),
        };
        if (invalid) headers["X-Splunk-Form-Key"] = "invalid-synthetic-token";
        const response = await fetch(
          "/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/adm/investigations/cases",
          {
            method: "POST",
            headers,
            body: JSON.stringify({
              schema_version: 1,
              title: "Rejected CSRF synthetic case",
              window: {
                start: "2026-01-01T00:00:00Z",
                end: "2026-01-01T01:00:00Z",
              },
            }),
          },
        );
        return {
          status: response.status,
          csrf: /csrf/i.test(await response.text()),
        };
      }, invalid);
      expect([401, 403]).toContain(result.status);
      expect(result.csrf).toBe(true);
      await owner
        .getByRole("button", { name: "List shared cases", exact: true })
        .click();
      await expect(owner.getByText("No shared cases found.")).toBeVisible();
    }
  });
  await phase("create_and_draft_preservation", async () => {
    await owner.getByLabel("New case title").fill("Synthetic UI case");
    await owner
      .getByRole("button", { name: "Create shared case", exact: true })
      .click();
    await saved(owner, 1);
    await expect(
      owner.getByRole("heading", { name: "Synthetic UI case", level: 4 }),
    ).toBeFocused();
    caseId = receipt.mutations.find((m) => m.status === 201).response.id;
    await owner
      .getByLabel("Add note", { exact: true })
      .fill("Preserved UI draft <script>synthetic</script>");
    await owner.getByLabel("New case title").fill("Second synthetic case");
    await owner
      .getByRole("button", { name: "Create shared case", exact: true })
      .click();
    await expect(owner.getByLabel("Add note", { exact: true })).toHaveValue(
      "Preserved UI draft <script>synthetic</script>",
    );
    await owner
      .getByRole("button", { name: "Synthetic UI case", exact: true })
      .click();
    await expect(owner.getByLabel("Case window start (UTC)")).toBeDisabled();
  });
  await phase("post_commit_response_loss_and_same_request_retry", async () => {
    drop = true;
    await owner.getByRole("button", { name: "Save note", exact: true }).click();
    const retry = owner.getByRole("button", {
      name: "Retry same request",
      exact: true,
    });
    await expect(retry).toBeFocused();
    await expect(owner.getByLabel("Add note", { exact: true })).toBeDisabled();
    await shot(owner, "uncertain-write");
    await retry.press("Enter");
    await saved(owner, 2);
    const writes = receipt.mutations.filter((m) => m.path.endsWith("/entries"));
    expect(writes).toHaveLength(2);
    expect(writes[0].key).toBe(writes[1].key);
    expect(writes[0].body).toBe(writes[1].body);
    expect(writes[1].response.entries).toHaveLength(1);
    await expect(owner.getByLabel("Add note", { exact: true })).toHaveValue("");
  });
  await phase("immutable_note_revision", async () => {
    await owner.getByRole("button", { name: "Edit note", exact: true }).click();
    await expect(owner.getByLabel("Edit note", { exact: true })).toBeFocused();
    await owner
      .getByLabel("Edit note", { exact: true })
      .fill("Revised synthetic UI note");
    await owner
      .getByRole("button", { name: "Save revision", exact: true })
      .click();
    await saved(owner, 3);
    await owner.getByText("History (2 versions)", { exact: true }).click();
    await expect(owner.getByText(/Version 1 ·/)).toContainText(
      "Preserved UI draft",
    );
    await shot(owner, "owner-revision-desktop");
  });
  await phase("private_access_and_sharing", async () => {
    await member
      .getByRole("button", { name: "List shared cases", exact: true })
      .click();
    await expect(member.getByText("No shared cases found.")).toBeVisible();
    const privateStatus = await member.evaluate(
      async (id) =>
        (
          await fetch(
            `/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/adm/investigations/cases/${id}`,
          )
        ).status,
      caseId,
    );
    expect(privateStatus).toBe(403);
    await owner.getByLabel("Member username").fill(input.users[1][0]);
    await owner
      .getByRole("button", { name: "Share case", exact: true })
      .click();
    await saved(owner, 4);
    await member
      .getByRole("button", { name: "List shared cases", exact: true })
      .click();
    await member
      .getByRole("button", { name: "Synthetic UI case", exact: true })
      .click();
    await saved(member, 4);
    await member.getByLabel("Entry type").selectOption("question");
    await member
      .getByLabel("Add question", { exact: true })
      .fill("Shared UI question");
    await member
      .getByRole("button", { name: "Save question", exact: true })
      .click();
    await saved(member, 5);
  });
  await phase("json_and_readable_downloads", async () => {
    await expect(
      member.getByRole("button", { name: "Export shared case", exact: true }),
    ).toBeDisabled();
    const text = await download(
      member,
      "Export shared case",
      "member-case.json",
    );
    const data = JSON.parse(text);
    expect(data.id).toBe(caseId);
    expect(data.entries).toHaveLength(3);
    expect(data.captures).toEqual([]);
    expect(data.attachments).toEqual([]);
    const html = await download(
      member,
      "Download readable handoff",
      "member-handoff.md",
    );
    expect(html).toContain("Revised synthetic UI note");
    expect(html).not.toContain("<script>synthetic</script>");
    receipt.exports = {
      json_sha256: createHash("sha256").update(text).digest("hex"),
      markdown_sha256: createHash("sha256").update(html).digest("hex"),
    };
  });
  await phase("narrow_layout_and_keyboard_draft", async () => {
    await member
      .getByLabel("Add question", { exact: true })
      .fill("Narrow retained draft");
    const beforeResize = caseRequests;
    for (const width of [768, 560, 516, 390, 320]) {
      await member.setViewportSize({ width: 1440, height: 1000 });
      const note = member.getByLabel("Add question", { exact: true });
      await expect(note).toBeVisible();
      await note.focus();
      await member.setViewportSize({ width, height: 900 });
      const app = member.locator(".atlas");
      await expect(note).toHaveValue("Narrow retained draft");
      const layout = await app.evaluate((el) => ({
        width: el.clientWidth,
        scroll: el.scrollWidth,
        viewport: innerWidth,
        document: document.documentElement.scrollWidth,
        right: el.getBoundingClientRect().right,
      }));
      receipt.layouts.push(layout);
      expect(layout.scroll).toBeLessThanOrEqual(layout.width + 1);
      if (layout.width >= 320) {
        await expect(note).toBeVisible();
        layout.mode = "supported_application_width";
      } else {
        const notice = member.locator(".atlas-width-notice");
        await expect(notice).toBeVisible();
        await expect(notice).toBeFocused();
        await expect(note).toBeHidden();
        layout.mode = "below_minimum_guard_preserves_draft";
      }
      expect(caseRequests).toBe(beforeResize);
      await shot(member, "member-" + width);
    }
    expect(
      receipt.layouts.some(
        (l) => l.width === 320 && l.mode === "supported_application_width",
      ),
    ).toBe(true);
    await member.setViewportSize({ width: 1440, height: 1000 });
    await member.getByLabel("Add question", { exact: true }).focus();
    await member.keyboard.press("Tab");
    await expect(
      member.getByRole("button", { name: "Save question", exact: true }),
    ).toBeFocused();
    await member.setViewportSize({ width: 1440, height: 1000 });
  });
  await phase("stale_revision_preserves_draft", async () => {
    await owner
      .getByLabel("Add note", { exact: true })
      .fill("Stale conflict draft");
    await owner.getByRole("button", { name: "Save note", exact: true }).click();
    await expect(owner.getByRole("alert")).toContainText("This case changed");
    await expect(owner.getByLabel("Add note", { exact: true })).toHaveValue(
      "Stale conflict draft",
    );
    expect(receipt.mutations.at(-1).status).toBe(409);
  });
  await phase("revocation_rechecks_and_clears_ui", async () => {
    await owner
      .getByRole("button", { name: "List shared cases", exact: true })
      .click();
    await owner
      .getByRole("button", { name: "Synthetic UI case", exact: true })
      .click();
    await saved(owner, 5);
    await owner
      .getByRole("button", { name: "Revoke access", exact: true })
      .click();
    await saved(owner, 6);
    await member
      .getByLabel(
        "I understand this export can contain sensitive case evidence.",
      )
      .check();
    await member
      .getByRole("button", { name: "Export shared case", exact: true })
      .click();
    await expect(member.getByRole("alert")).toContainText("permission");
    await expect(
      member.getByRole("heading", { name: "Synthetic UI case", level: 4 }),
    ).toHaveCount(0);
    await expect(
      member.getByLabel("Add question", { exact: true }),
    ).toHaveCount(0);
    await expect(
      member.getByRole("button", {
        name: "Download readable handoff",
        exact: true,
      }),
    ).toHaveCount(0);
    await expect(
      member.getByText("Case export requested.", { exact: true }),
    ).toHaveCount(0);
    const revoked = await member.evaluate(async (id) => {
      const current = await fetch(
        "/en-US/splunkd/__raw/services/authentication/current-context?output_mode=json",
      );
      const context = (await current.json()).entry[0].content;
      const base = `/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/adm/investigations/cases/${id}`;
      return {
        context,
        read: (await fetch(base)).status,
        export: (await fetch(base + "/export")).status,
      };
    }, caseId);
    expect(revoked.context.username).toBe(input.users[1][0]);
    expect(revoked.context.roles).toEqual([input.role]);
    expect(revoked.context.capabilities).toEqual(["adm_investigate"]);
    expect(revoked.read).toBe(403);
    expect(revoked.export).toBe(403);
    receipt.revocation = {
      authenticated_principal_unchanged: true,
      read_status: revoked.read,
      export_status: revoked.export,
    };
    await shot(member, "revoked-member");
  });
  await phase("unauthenticated_cases_page_requires_login", async () => {
    await member.context().clearCookies();
    await member.goto(input.url + "/en-US/app/splunk_adm/cases", {
      waitUntil: "domcontentloaded",
    });
    await expect(member.locator('input[name="username"]')).toBeVisible();
  });
  receipt.mobile_viewport_fit = receipt.layouts.every(
    (l) => l.document <= l.viewport + 1 && l.right <= l.viewport + 1,
  );
  receipt.no_search_jobs = searches === 0;
  expect(searches).toBe(0);
  expect(receipt.mutations.every((m) => m.state === "response_received")).toBe(
    true,
  );
  receipt.status = "passed";
} catch (error) {
  receipt.status = "failed";
  if (receipt.checks.includes("restricted_login_and_direct_cases_entry")) {
    receipt.failure_focus = [];
    for (const [index, context] of contexts.entries()) {
      const page = context.pages().at(-1);
      receipt.failure_focus.push(
        await page.evaluate(() => ({
          tag: document.activeElement?.tagName,
          text: document.activeElement?.textContent?.slice(0, 150),
          hasFocus: document.hasFocus(),
        })),
      );
      // Never screenshot a login/password form, including an autofill state.
      if ((await page.locator('input[type="password"]').count()) === 0)
        await shot(page, "failure-browser-" + index);
    }
  }
  // Preserve assertions/locator diagnostics privately; redact synthetic passwords.
  let message = String(error);
  for (const [, password] of input.users)
    message = message.split(password).join("[redacted]");
  receipt.error = message.slice(0, 4000);
} finally {
  for (const context of contexts.reverse()) await context.close();
  await persist();
}
process.exitCode = receipt.status === "passed" ? 0 : 1;
