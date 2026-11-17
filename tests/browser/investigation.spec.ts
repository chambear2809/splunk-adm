import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("investigation notes survive section changes and export fixed evidence only by explicit choice", async ({
  page,
}) => {
  await page.goto("/tests/browser/investigation.html");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await page
    .getByLabel("Notes", { exact: true })
    .fill("Observed deny; ask network owner");
  await page
    .getByLabel("Hypotheses", { exact: true })
    .fill("Policy change remains unconfirmed");
  await page.getByRole("button", { name: "Record revision" }).click();
  await page.getByRole("button", { name: "Timeline", exact: true }).click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await expect(page.getByLabel("Notes", { exact: true })).toHaveValue(
    "Observed deny; ask network owner",
  );
  const textDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download readable handoff" }).click();
  const text = await readFile((await (await textDownload).path())!, "utf8");
  expect(text).toContain("Observed deny; ask network owner");
  expect(text).toContain("no shared case save");
  await page
    .getByRole("checkbox", { name: /Include full captured graph/ })
    .check();
  const jsonDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download evidence package" }).click();
  const exported = JSON.parse(
    await readFile((await (await jsonDownload).path())!, "utf8"),
  );
  expect(exported.version).toBe(1);
  expect(exported.captures).toHaveLength(2);
  expect(exported.revisions[0].hypotheses).toContain("unconfirmed");
});

test("handoff remains usable on narrow screens", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/tests/browser/investigation.html");
  await page
    .getByRole("button", { name: "Compare windows", exact: true })
    .click();
  await page.getByRole("button", { name: "Notes", exact: true }).click();
  await expect(page.getByLabel("Unresolved questions")).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
});

test("shared entry revisions preserve a draft across a lost response and show history", async ({
  page,
}) => {
  const original = {
    id: "entry-1",
    revision: 1,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    type: "note",
    text: "Original note",
  };
  const revised = {
    ...original,
    id: "entry-2",
    revision: 2,
    author: "bob",
    text: "Revised note",
    supersedes_entry_id: "entry-1",
  };
  const record = {
    schema_version: 1,
    id: "case-1",
    revision: 1,
    title: "Revision case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [original],
    captures: [],
    attachments: [],
  };
  const attempts: Array<{ key?: string; body: unknown }> = [];
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites: false,
          mode: "notes_only",
          qualified: false,
        },
      });
    if (path.endsWith("/entries")) {
      attempts.push({
        key: request.headers()["idempotency-key"],
        body: request.postDataJSON(),
      });
      if (attempts.length === 1) return route.abort("failed");
      return route.fulfill({
        json: { ...record, revision: 2, entries: [original, revised] },
      });
    }
    return route.fulfill({
      json: path.endsWith("/cases") ? { items: [record], next: null } : record,
    });
  });
  await page.route(
    "**/tests/browser/investigation.html?revisionReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?revisionReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page
    .getByRole("button", { name: "Revision case", exact: true })
    .click();
  await page.getByLabel("Add note").fill("Unsent new note");
  await page.getByRole("button", { name: "Edit note", exact: true }).click();
  await expect(page.getByLabel("Edit note")).toHaveValue("Original note");
  await page.getByLabel("Edit note").fill("Revised note");
  await page.getByRole("button", { name: "Save revision" }).click();
  await expect(page.getByLabel("Edit note")).toHaveValue("Revised note");
  await page.getByRole("button", { name: "Retry same request" }).click();
  await expect(page.getByText("Revised note", { exact: false })).toBeVisible();
  await expect(page.getByText(/Edited · version 2/)).toBeVisible();
  await expect(page.getByLabel("Add note")).toHaveValue("Unsent new note");
  await page.getByText("History (2 versions)").click();
  await expect(page.getByText(/Version 1 · alice/)).toBeVisible();
  await expect(page.getByText(/Version 2 · bob/)).toBeVisible();
  expect(attempts).toHaveLength(2);
  expect(attempts[0]).toEqual(attempts[1]);
  expect(attempts[0].body).toEqual({
    expected_revision: 1,
    item: {
      type: "note",
      text: "Revised note",
      supersedes_entry_id: "entry-1",
    },
  });
});

test("a conflicting edit retains its draft until the latest entry is chosen", async ({
  page,
}) => {
  const original = {
    id: "entry-1",
    revision: 1,
    author: "alice",
    created_at: "2026-01-01T00:00:00Z",
    type: "note",
    text: "Original note",
  };
  const other = {
    ...original,
    id: "entry-2",
    revision: 2,
    author: "bob",
    text: "Other edit",
    supersedes_entry_id: "entry-1",
  };
  const final = {
    ...original,
    id: "entry-3",
    revision: 3,
    text: "My draft",
    supersedes_entry_id: "entry-2",
  };
  let revision = 1;
  const base = {
    schema_version: 1,
    id: "case-1",
    title: "Conflict case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    captures: [],
    attachments: [],
  };
  const current = () => ({
    ...base,
    revision,
    entries:
      revision === 1
        ? [original]
        : revision === 2
          ? [original, other]
          : [original, other, final],
  });
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/capabilities"))
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites: false,
          mode: "notes_only",
          qualified: false,
        },
      });
    if (path.endsWith("/entries")) {
      const body = request.postDataJSON();
      if (revision === 1) {
        revision = 2;
        return route.fulfill({ status: 409, json: { error: "conflict" } });
      }
      expect(body).toEqual({
        expected_revision: 2,
        item: {
          type: "note",
          text: "My draft",
          supersedes_entry_id: "entry-2",
        },
      });
      revision = 3;
      return route.fulfill({ json: current() });
    }
    return route.fulfill({
      json: path.endsWith("/cases")
        ? { items: [current()], next: null }
        : current(),
    });
  });
  await page.route(
    "**/tests/browser/investigation.html?conflictReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?conflictReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page
    .getByRole("button", { name: "Conflict case", exact: true })
    .click();
  await page.getByRole("button", { name: "Edit note", exact: true }).click();
  await page.getByLabel("Edit note").fill("My draft");
  await page.getByRole("button", { name: "Save revision" }).click();
  await expect(page.getByRole("alert")).toContainText("changed");
  await expect(page.getByLabel("Edit note")).toHaveValue("My draft");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page
    .getByRole("button", { name: "Conflict case", exact: true })
    .click();
  await expect(page.getByLabel("Edit note")).toHaveValue("My draft");
  await expect(
    page.getByRole("button", { name: "Save revision" }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Apply draft to latest version" })
    .click();
  await page.getByRole("button", { name: "Save revision" }).click();
  await expect(page.getByText(/Edited · version 3/)).toBeVisible();
});
