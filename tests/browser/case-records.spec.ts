import { expect, test } from "@playwright/test";

test("case pages follow the server cursor when a byte bound returns a short page", async ({
  page,
}) => {
  const record = (suffix: string, title: string) => ({
    schema_version: 1,
    id: `00000000-0000-4000-8000-${suffix}`,
    revision: 1,
    title,
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [],
    captures: [],
    attachments: [],
  });
  const first = record("000000000001", "First bounded page");
  const second = record("000000000002", "Second bounded page");
  const cursors: (string | null)[] = [];
  await page.route("**/test-cases/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites: false,
          mode: "notes_only",
          qualified: false,
        },
      });
    expect(url.pathname.endsWith("/cases")).toBeTruthy();
    const cursor = url.searchParams.get("after");
    cursors.push(cursor);
    return route.fulfill({
      json:
        cursor === null
          ? { items: [first], next: first.id }
          : { items: [second], next: null },
    });
  });
  await page.goto("/tests/browser/investigation.html?cases");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await page.getByRole("button", { name: "Open shared cases" }).click();
  const list = page.getByRole("button", {
    name: "List shared cases",
    exact: true,
  });
  await list.click();
  await expect(
    page.getByRole("button", { name: first.title, exact: true }),
  ).toBeVisible();
  const more = page.getByRole("button", {
    name: "Load more cases",
    exact: true,
  });
  await more.focus();
  await more.press("Enter");
  await expect(
    page.getByRole("button", { name: first.title, exact: true }),
  ).toHaveCount(1);
  await expect(
    page.getByRole("button", { name: second.title, exact: true }),
  ).toHaveCount(1);
  await expect(more).toHaveCount(0);
  await expect(list).toBeFocused();
  expect(cursors).toEqual([null, first.id]);
});

test("shared notes preserve a draft across case creation and retry lost responses with one request identity", async ({
  page,
}) => {
  // HTTP replay validates browser behavior; Python tests exercise the actual store/host.
  const records = new Map<string, Record<string, unknown>>();
  const keys: string[] = [];
  let lost = false;
  let revoked = false;
  let denyExport = false;
  let requestCount = 0;
  await page.route("**/test-cases/**", async (route) => {
    requestCount++;
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/capabilities")) {
      await route.fulfill({
        json: {
          available: true,
          evidenceWrites: false,
          mode: "notes_only",
          qualified: false,
        },
      });
    } else if (request.method() === "POST" && path.endsWith("/cases")) {
      const body = request.postDataJSON();
      const id = `00000000-0000-4000-8000-${String(records.size + 1).padStart(12, "0")}`;
      const record = {
        ...body,
        id,
        revision: 1,
        entries: [],
        captures: [],
        attachments: [],
      };
      records.set(id, record);
      await route.fulfill({ json: record, status: 201 });
    } else if (path.endsWith("/entries")) {
      const id = path.split("/").at(-2)!;
      keys.push(request.headers()["idempotency-key"]);
      const record = records.get(id)!;
      if (!lost) {
        const body = request.postDataJSON();
        record.revision = 2;
        record.entries = [
          {
            ...body.item,
            id: "entry-1",
            revision: 2,
            author: "alice",
            created_at: "2026-01-01T02:00:00Z",
          },
        ];
        lost = true;
        await route.abort("failed");
      } else await route.fulfill({ json: record });
    } else if (path.endsWith("/share")) {
      const id = path.split("/").at(-2)!;
      const body = request.postDataJSON();
      const record = records.get(id)!;
      expect(body.expected_revision).toBe(record.revision);
      record.revision = (record.revision as number) + 1;
      if (body.grant) await route.fulfill({ json: record });
      else {
        revoked = true;
        await route.fulfill({
          json: { id, revision: record.revision, revoked: true },
        });
      }
    } else if (path.endsWith("/export")) {
      if (denyExport)
        await route.fulfill({ status: 403, json: { error: "forbidden" } });
      else await route.fulfill({ json: records.get(path.split("/").at(-2)!) });
    } else if (request.method() === "GET" && path.includes("/cases/")) {
      if (revoked)
        await route.fulfill({ status: 403, json: { error: "forbidden" } });
      else await route.fulfill({ json: records.get(path.split("/").at(-1)!) });
    } else if (revoked) {
      await route.fulfill({ status: 403, json: { error: "forbidden" } });
    } else
      await route.fulfill({
        json: { items: [...records.values()], next: null },
      });
  });
  await page.goto("/tests/browser/investigation.html?cases");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await page.getByRole("button", { name: "Open shared cases" }).click();
  await page.getByLabel("New case title").fill("First investigation");
  await page.getByRole("button", { name: "Create shared case" }).click();
  await expect(
    page.getByRole("heading", { name: "First investigation", level: 4 }),
  ).toBeFocused();
  await page.getByLabel("Add note").fill("Preserve this draft");
  const beforeResize = requestCount;
  await page.locator(".atlas").evaluate((el) => {
    (el as HTMLElement).style.width = "319.5px";
  });
  await expect(page.locator(".atlas-width-notice")).toBeVisible();
  await expect(page.locator(".atlas-width-notice")).toBeFocused();
  await page.locator(".atlas").evaluate((el) => {
    (el as HTMLElement).style.width = "";
  });
  await expect(page.getByLabel("Add note")).toHaveValue("Preserve this draft");
  expect(requestCount).toBe(beforeResize);
  await page.getByLabel("New case title").fill("Second investigation");
  await page.getByRole("button", { name: "Create shared case" }).click();
  await expect(page.getByLabel("Add note")).toHaveValue("Preserve this draft");
  await page.getByRole("button", { name: "Save note", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Retry same request" }),
  ).toBeVisible();
  await expect(page.getByLabel("Add note")).toBeDisabled();
  await page.getByRole("button", { name: "Retry same request" }).click();
  await expect(
    page
      .getByRole("region", { name: "Shared investigation cases", exact: true })
      .getByRole("listitem")
      .filter({ hasText: "Preserve this draft" }),
  ).toBeVisible();
  await expect(page.getByLabel("Add note")).toBeFocused();
  await expect(page.getByLabel("Add note")).toHaveValue("");
  expect(keys).toHaveLength(2);
  expect(keys[0]).toBe(keys[1]);
  expect([...records.values()][1].entries).toHaveLength(1);
  await page.getByLabel("Member username").fill("bob");
  await page.getByRole("button", { name: "Share case", exact: true }).click();
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  const exported = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export shared case", exact: true })
    .click();
  expect((await exported).suggestedFilename()).toContain("atlas-case-");
  denyExport = true;
  await page
    .getByRole("button", { name: "Export shared case", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("permission");
  await expect(
    page.getByText("Case export requested.", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page
    .getByRole("button", { name: "Second investigation", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Revoke access", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("permission");
  await expect(
    page.getByText("Case export requested.", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Retry same request" }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Add note")).toHaveCount(0);
});

test("attaches an authorized saved comparison only after explicit consent", async ({
  page,
}) => {
  const captureId = "00000000-0000-4000-8000-000000000001";
  const entry = {
    id: "entry-1",
    revision: 1,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    type: "note",
    text: "Review this evidence",
  };
  const capture = {
    id: captureId,
    revision: 2,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    captured_at: "2026-01-01T00:00:00Z",
    label: "Baseline comparison",
    data: {},
  };
  const attachment = {
    id: "attachment-1",
    revision: 3,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    kind: "capture_reference",
    entry_id: entry.id,
    capture_id: captureId,
  };
  const record = {
    schema_version: 1,
    id: "case-1",
    revision: 2,
    title: "Evidence case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [entry],
    captures: [capture],
    capture_ids: [captureId],
    attachments: [] as (typeof attachment)[],
    redactions: { captures: 0, attachments: 0 },
  };
  let denied = false;
  let attachBody: unknown;
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites: true,
          mode: "notes_and_reproducible_evidence",
          qualified: false,
        },
      });
    if (path.endsWith("/attachments")) {
      attachBody = request.postDataJSON();
      expect(attachBody).toEqual({
        expected_revision: 2,
        entry_id: entry.id,
        capture_id: captureId,
      });
      record.revision = 3;
      record.attachments = [attachment];
      return route.fulfill({ json: record });
    }
    if (path.endsWith("/cases"))
      return route.fulfill({ json: { items: [record], next: null } });
    return route.fulfill({
      json: denied
        ? {
            ...record,
            captures: [],
            attachments: [],
            redactions: { captures: 1, attachments: 1 },
          }
        : record,
    });
  });
  await page.route(
    "**/tests/browser/investigation.html?attachmentReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?attachmentReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page
    .getByRole("button", { name: "Evidence case", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Evidence case", level: 4 }),
  ).toBeFocused();
  const attach = page.getByRole("button", {
    name: "Attach saved comparison evidence",
  });
  const consent = page.getByRole("checkbox", {
    name: /links the selected saved capture/,
  });
  await expect(consent).not.toBeChecked();
  await expect(attach).toBeDisabled();
  await page.getByLabel("Entry", { exact: true }).selectOption(entry.id);
  await expect(attach).toBeDisabled();
  await consent.check();
  await attach.click();
  await expect(
    page.getByRole("button", { name: "View attached evidence" }),
  ).toBeVisible();
  expect(attachBody).toBeDefined();
  denied = true;
  await page.getByRole("button", { name: "Recheck capture 1 of 1" }).click();
  await expect(
    page.getByRole("button", { name: "View attached evidence" }),
  ).toHaveCount(0);
  await expect(page.getByText(/1 attachments withheld/)).toBeVisible();
});

test("a retained edit from a revoked case can be discarded before editing another case", async ({
  page,
}) => {
  const window = { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" };
  const entry = (id: string, text: string) => ({
    id,
    revision: 1,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    type: "note",
    text,
  });
  const base = {
    schema_version: 1,
    revision: 1,
    window,
    captures: [],
    attachments: [],
  };
  const a = {
    ...base,
    id: "case-a",
    title: "Case A",
    entries: [entry("entry-a", "A original")],
  };
  const b = {
    ...base,
    id: "case-b",
    title: "Case B",
    entries: [entry("entry-b", "B original")],
  };
  let revoked = false;
  await page.route("**/test-cases/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites: false,
          mode: "notes_only",
          qualified: false,
        },
      });
    if (path.endsWith("/cases"))
      return route.fulfill({
        json: { items: revoked ? [b] : [a, b], next: null },
      });
    if (path.endsWith("/case-a"))
      return revoked
        ? route.fulfill({ status: 403, json: { error: "forbidden" } })
        : route.fulfill({ json: a });
    return route.fulfill({ json: b });
  });
  await page.route(
    "**/tests/browser/investigation.html?revokedEditReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?revokedEditReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Case A", exact: true }).click();
  await page.getByRole("button", { name: "Edit note", exact: true }).click();
  await page.getByLabel("Edit note").fill("A unsaved edit");
  revoked = true;
  await page.getByRole("button", { name: "Case A", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("permission");
  await expect(
    page.getByRole("button", { name: "Discard retained edit" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Case B", exact: true }).click();
  await expect(page.getByText("A unsaved edit", { exact: true })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "Edit note", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Discard retained edit" }).click();
  await page.getByRole("button", { name: "Edit note", exact: true }).click();
  await expect(page.getByLabel("Edit note")).toHaveValue("B original");
});
