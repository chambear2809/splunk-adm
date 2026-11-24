import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import type { CaseRecord } from "../../frontend/src/investigations/caseClient";

test("an uncertain write survives denied retry until the same request can be confirmed", async ({
  page,
}) => {
  const attempts: Array<{ key?: string; body: unknown }> = [];
  const record = {
    schema_version: 1,
    id: "case-1",
    revision: 1,
    title: "Retry case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [] as Record<string, unknown>[],
    attachments: [],
    captures: [
      {
        id: "capture-1",
        revision: 1,
        author: "alice",
        created_at: "2026-01-01T01:00:00Z",
        captured_at: "2026-01-01T01:00:00Z",
        label: "Private source capture",
        data: {},
      },
    ],
  };
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
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
      if (attempts.length === 1) {
        record.revision = 2;
        record.entries = [
          {
            id: "entry-1",
            revision: 2,
            author: "alice",
            created_at: "2026-01-01T01:01:00Z",
            type: "note",
            text: "Keep one note",
          },
        ];
        return route.abort("failed");
      }
      if (attempts.length === 2)
        return route.fulfill({ status: 403, json: { error: "forbidden" } });
      return route.fulfill({ json: record });
    }
    return route.fulfill({
      json: path.endsWith("/cases") ? { items: [record], next: null } : record,
    });
  });
  await page.route(
    "**/tests/browser/investigation.html?caseEvidenceReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?caseEvidenceReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Retry case", exact: true }).click();
  await expect(
    page.getByText(/Private source capture · captured/),
  ).toBeVisible();
  await page.getByLabel("Add note").fill("Keep one note");
  await page.getByRole("button", { name: "Save note", exact: true }).click();
  const retry = page.getByRole("button", {
    name: "Retry same request",
    exact: true,
  });
  await expect(retry).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Refresh availability" }),
  ).toBeDisabled();
  await retry.click();
  await expect(page.getByRole("alert")).toContainText("unconfirmed");
  await expect(page.getByText(/Private source capture · captured/)).toHaveCount(
    0,
  );
  await expect(retry).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Create shared case" }),
  ).toBeDisabled();
  await retry.click();
  await expect(retry).toHaveCount(0);
  await expect(page.getByLabel("Add note")).toHaveValue("");
  await expect(
    page.getByRole("listitem").filter({ hasText: "Keep one note" }),
  ).toBeVisible();
  expect(attempts).toHaveLength(3);
  expect(attempts[0]).toEqual(attempts[1]);
  expect(attempts[1]).toEqual(attempts[2]);
  expect(record.entries).toHaveLength(1);
});
test("case evidence is saved only by consent and hidden after source access is revoked", async ({
  page,
}) => {
  let denied = false;
  let expired = false;
  let requestBody: Record<string, unknown> | undefined;
  const record: CaseRecord = {
    schema_version: 1,
    id: "case-1",
    revision: 1,
    title: "Synthetic case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [],
    captures: [],
    attachments: [],
    redactions: { captures: 0, attachments: 0 },
  };
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/capabilities")) {
      await route.fulfill({
        json: {
          available: true,
          evidenceWrites: true,
          mode: "notes_and_reproducible_evidence",
          qualified: false,
        },
      });
    } else if (expired) {
      await route.fulfill({ status: 401, json: { error: "expired" } });
    } else if (path.endsWith("/captures")) {
      requestBody = request.postDataJSON();
      record.revision++;
      record.captures = [
        {
          id: "00000000-0000-4000-8000-000000000001",
          revision: 2,
          author: "synthetic",
          created_at: "2026-01-01T01:00:00Z",
          label: "Synthetic comparison",
          captured_at: "2026-01-01T01:00:00Z",
          data: {
            schema: 1,
            scope: {
              service: "checkout",
              environment: "test",
              cluster: "synthetic-cluster",
              namespace: "synthetic",
            },
            windows: [
              { start: 100, end: 200, rows: [{ source: "synthetic-row" }] },
              { start: 200, end: 300, rows: [] },
            ],
          },
        },
      ];
      record.capture_ids = ["00000000-0000-4000-8000-000000000001"];
      await route.fulfill({ json: record });
    } else if (path.endsWith("/entries")) {
      const body = request.postDataJSON();
      record.revision++;
      record.entries = [
        {
          ...body.item,
          id: "entry-1",
          revision: record.revision,
          author: "synthetic",
          created_at: "2026-01-01T01:01:00Z",
        },
      ];
      await route.fulfill({ json: record });
    } else if (path.endsWith("/cases")) {
      await route.fulfill({
        json: {
          items: [
            {
              ...record,
              captures: [],
              redactions: { captures: record.captures.length, attachments: 0 },
            },
          ],
          next: null,
        },
      });
    } else if (denied) {
      await route.fulfill({
        json: {
          ...record,
          captures: [],
          redactions: { captures: 1, attachments: 0 },
        },
      });
    } else await route.fulfill({ json: record });
  });
  await page.route(
    "**/tests/browser/investigation.html?caseEvidenceReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?caseEvidenceReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Synthetic case" }).click();
  const save = page.getByRole("button", {
    name: "Save comparison to shared case",
  });
  await expect(save).toBeDisabled();
  await expect(page.getByText(/Service: checkout/)).toBeVisible();
  await expect(page.getByText(/Baseline:/)).toBeVisible();
  await page
    .getByLabel("Comparison label (optional)")
    .fill("Synthetic comparison");
  await page
    .getByLabel("I understand this saves source evidence to the shared case.")
    .check();
  await save.click();
  expect(Object.keys(requestBody!).sort()).toEqual([
    "expected_revision",
    "label",
    "reference",
  ]);
  expect(JSON.stringify(requestBody)).not.toContain("synthetic-row");
  await page
    .getByText("Synthetic comparison · captured", { exact: false })
    .click();
  await page.getByText("Show source rows and metadata").click();
  await expect(page.getByText(/synthetic-row/)).toBeVisible();
  await page.getByRole("button", { name: "Recheck capture 1 of 1" }).click();
  await expect(page.getByText("Selected capture: 1 of 1")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Export shared case" }),
  ).toBeDisabled();
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  const handoff = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download readable handoff" }).click();
  const text = await readFile((await (await handoff).path())!, "utf8");
  expect(text).toContain("Synthetic comparison");
  expect(text).toContain("Baseline:");
  expect(text).not.toContain("synthetic-row");
  const jsonDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export shared case" }).click();
  const jsonText = await readFile((await (await jsonDownload).path())!, "utf8");
  expect(jsonText).toContain("synthetic-row");
  expect(jsonText).toContain("Synthetic comparison");
  await page.getByLabel("Add note").fill("Preserve this note");
  await page.getByRole("button", { name: "Save note", exact: true }).click();
  await expect(page.getByText("Preserve this note")).toBeVisible();
  await page.getByRole("button", { name: "Recheck capture 1 of 1" }).click();
  await expect(page.getByText("Selected capture: 1 of 1")).toBeVisible();
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  denied = true;
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export shared case" }).click();
  const redactedJson = await readFile(
    (await (await downloaded).path())!,
    "utf8",
  );
  expect(redactedJson).toContain("Preserve this note");
  expect(redactedJson).not.toContain("synthetic-row");
  expect(redactedJson).not.toContain("Synthetic comparison");
  await expect(page.getByText(/synthetic-row/)).toHaveCount(0);
  await expect(
    page.getByText(/1 captures and 0 attachments withheld/),
  ).toBeVisible();
  denied = false;
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Synthetic case" }).click();
  await page
    .getByText("Synthetic comparison · captured", { exact: false })
    .click();
  await page.getByText("Show source rows and metadata").click();
  await expect(page.getByText(/synthetic-row/)).toBeVisible();
  denied = true;
  await page.getByRole("button", { name: "List shared cases" }).click();
  await expect(page.getByText(/synthetic-row/)).toHaveCount(0);
  await page.getByRole("button", { name: "Synthetic case" }).click();
  await expect(
    page.getByText(/1 captures and 0 attachments withheld/),
  ).toBeVisible();
  await expect(page.getByText(/synthetic-row/)).toHaveCount(0);
  denied = false;
  await page.getByRole("button", { name: "Synthetic case" }).click();
  await page
    .getByText("Synthetic comparison · captured", { exact: false })
    .click();
  await page.getByText("Show source rows and metadata").click();
  await expect(page.getByText(/synthetic-row/)).toBeVisible();
  await page.getByLabel("Add note").fill("Preserve my draft");
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  expired = true;
  await page.getByRole("button", { name: "Export shared case" }).click();
  await expect(page.getByRole("alert")).toContainText("permission");
  await expect(page.getByText(/synthetic-row/)).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Export shared case" }),
  ).toHaveCount(0);
  expired = false;
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Synthetic case" }).click();
  await expect(page.getByLabel("Add note")).toHaveValue("Preserve my draft");
  await expect(
    page.getByLabel(
      "I understand this export can contain sensitive case evidence.",
    ),
  ).not.toBeChecked();
});

test("rechecks and exports a selected capture without reading the others", async ({
  page,
}) => {
  const ids = [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
  ];
  const requests: string[] = [];
  const capture = (index: number) => ({
    id: ids[index],
    revision: index + 2,
    author: "synthetic",
    created_at: "2026-01-01T01:00:00Z",
    label: `Capture ${index + 1}`,
    captured_at: "2026-01-01T01:00:00Z",
    data: {
      scope: {
        service: "checkout",
        environment: "test",
        cluster: "cluster",
        namespace: "ns",
      },
      windows: [
        { start: 100, end: 200, rows: [] },
        { start: 200, end: 300, rows: [] },
      ],
    },
  });
  const record = {
    schema_version: 1,
    id: "case-1",
    revision: 3,
    title: "Two synthetic captures",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [],
    attachments: [],
    capture_ids: ids,
    redactions: { captures: 1, attachments: 0 },
    captures: [capture(0)],
  };
  await page.route("**/test-cases/**", async (route) => {
    const url = new URL(route.request().url());
    requests.push(url.pathname + url.search);
    if (url.pathname.endsWith("/capabilities"))
      await route.fulfill({
        json: {
          available: true,
          evidenceWrites: true,
          mode: "notes_and_reproducible_evidence",
          qualified: false,
        },
      });
    else if (url.pathname.endsWith("/cases"))
      await route.fulfill({
        json: {
          items: [
            {
              ...record,
              captures: [],
              redactions: { captures: 2, attachments: 0 },
            },
          ],
          next: null,
        },
      });
    else
      await route.fulfill({
        json: {
          ...record,
          captures: [
            capture(url.searchParams.get("capture_id") === ids[1] ? 1 : 0),
          ],
        },
      });
  });
  await page.route(
    "**/tests/browser/investigation.html?caseEvidenceReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?caseEvidenceReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Two synthetic captures" }).click();
  await expect(
    page.getByText("Capture 1 · captured", { exact: false }),
  ).toBeVisible();
  expect(requests).toEqual([
    "/test-cases/capabilities",
    "/test-cases/cases",
    "/test-cases/cases/case-1",
  ]);
  await page.getByRole("button", { name: "Recheck capture 2 of 2" }).click();
  await expect(
    page.getByText("Capture 2 · captured", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByText("Capture 1 · captured", { exact: false }),
  ).toHaveCount(0);
  await page
    .getByLabel("I understand this export can contain sensitive case evidence.")
    .check();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download readable handoff" }).click();
  await download;
  expect(requests.slice(3)).toEqual([
    `/test-cases/cases/case-1?capture_id=${ids[1]}`,
    `/test-cases/cases/case-1/export?capture_id=${ids[1]}`,
  ]);
  await expect(
    page.getByText(/1 captures and 0 attachments withheld/),
  ).toBeVisible();
  await expect(page.getByText("Selected capture: 2 of 2")).toBeVisible();
  await page.getByLabel("Add note").fill("Review the evidence");
  await page.getByRole("button", { name: "Save note", exact: true }).click();
  await expect(
    page.getByText("Capture 1 · captured", { exact: false }),
  ).toBeVisible();
  await expect(page.getByText("No capture selected.")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Export shared case", exact: true }),
  ).toBeDisabled();
});

test("keeps an unsaved note with its case while switching cases", async ({
  page,
}) => {
  const record = (id: string, title: string): CaseRecord => ({
    schema_version: 1,
    id,
    revision: 1,
    title,
    window: {
      start: "2026-01-01T00:00:00Z",
      end: "2026-01-01T01:00:00Z",
    },
    entries: [],
    captures: [],
    capture_ids: [],
    attachments: [],
    redactions: { captures: 0, attachments: 0 },
  });
  const records = [
    record("00000000-0000-4000-8000-000000000011", "Case A"),
    record("00000000-0000-4000-8000-000000000012", "Case B"),
  ];
  const entryTypes: string[] = [];
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
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
    if (url.pathname.endsWith("/cases"))
      return route.fulfill({ json: { items: records, next: null } });
    if (url.pathname.endsWith("/entries")) {
      const body = request.postDataJSON();
      entryTypes.push(body.item.type);
      const id = url.pathname.split("/").at(-2);
      const found = records.find((item) => item.id === id)!;
      found.revision++;
      found.entries = [
        {
          ...body.item,
          id: "entry-1",
          revision: found.revision,
          author: "synthetic",
          created_at: "2026-01-01T01:01:00Z",
        },
      ];
      return route.fulfill({ json: found });
    }
    const found = records.find((item) =>
      url.pathname.endsWith(`/cases/${item.id}`),
    );
    return route.fulfill({ json: found });
  });
  await page.route(
    "**/tests/browser/investigation.html?caseEvidenceReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?caseEvidenceReplay");
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Case A", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Case A", level: 4 }),
  ).toBeVisible();
  await page.getByLabel("Entry type").selectOption("hypothesis");
  await page.getByLabel("Add hypothesis").fill("Draft for A");
  await page.getByRole("button", { name: "Case B", exact: true }).click();
  await expect(page.getByLabel("Add note")).toHaveValue("");
  await expect(page.getByLabel("Entry type")).toHaveValue("note");
  await expect(
    page.getByRole("button", { name: "Save note", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Case A", exact: true }).click();
  await expect(page.getByLabel("Add hypothesis")).toHaveValue("Draft for A");
  await expect(page.getByLabel("Entry type")).toHaveValue("hypothesis");
  await page
    .getByRole("button", { name: "Save hypothesis", exact: true })
    .click();
  await expect(page.getByText("Shared case saved.")).toBeVisible();
  expect(entryTypes).toEqual(["hypothesis"]);
});

test("availability gates writes, supports retry, and preserves drafts through refresh", async ({
  page,
}) => {
  let capabilityRead = 0;
  let writes = 0;
  let releaseRefresh: (() => void) | undefined;
  const holdRefresh = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });
  const record = {
    schema_version: 1,
    id: "case-1",
    revision: 1,
    title: "Capability case",
    window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    entries: [],
    captures: [],
    attachments: [],
  };
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url());
    if (url.pathname.endsWith("/capabilities")) {
      capabilityRead++;
      if (capabilityRead === 1)
        return route.fulfill({
          json: {
            available: false,
            evidenceWrites: false,
            mode: "notes_only",
            qualified: false,
          },
        });
      if (capabilityRead === 2) return route.fulfill({ status: 503, json: {} });
      if (capabilityRead === 4) await holdRefresh;
      const evidenceWrites = capabilityRead >= 4;
      return route.fulfill({
        json: {
          available: true,
          evidenceWrites,
          mode: evidenceWrites
            ? "notes_and_reproducible_evidence"
            : "notes_only",
          qualified: false,
        },
      });
    }
    if (request.method() !== "GET") writes++;
    if (url.pathname.endsWith("/cases") && request.method() === "GET")
      return route.fulfill({ json: { items: [record], next: null } });
    return route.fulfill({ json: record });
  });
  await page.route(
    "**/tests/browser/investigation.html?caseEvidenceReplay",
    (route) =>
      route.fulfill({
        contentType: "text/html",
        body: '<meta name="viewport" content="width=device-width, initial-scale=1"><script type="module" src="/@vite/client"></script><div id="root"></div><script type="module" src="/tests/browser/cases-harness.tsx"></script>',
      }),
  );
  await page.goto("/tests/browser/investigation.html?caseEvidenceReplay");
  await expect(page.getByRole("status")).toContainText("unavailable");
  await expect(
    page.getByRole("button", { name: "Create shared case" }),
  ).toHaveCount(0);
  expect(writes).toBe(0);
  await page.getByRole("button", { name: "Retry availability check" }).click();
  await expect(page.getByRole("status")).toContainText("unavailable");
  expect(writes).toBe(0);
  await page.getByRole("button", { name: "Retry availability check" }).click();
  await expect(
    page.getByText(
      "Comparison evidence saving is unavailable. Shared notes remain available.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Capability case" }).click();
  await page.getByLabel("Add note").fill("Retained draft");
  await expect(
    page.getByRole("button", { name: "Save note", exact: true }),
  ).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Save comparison to shared case" }),
  ).toBeDisabled();
  await expect(
    page.getByLabel(
      "I understand this saves source evidence to the shared case.",
    ),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Refresh availability" }).click();
  await expect(page.getByRole("status")).toContainText("Checking");
  await expect(
    page.getByRole("button", { name: "Create shared case" }),
  ).toHaveCount(0);
  expect(writes).toBe(0);
  releaseRefresh!();
  await expect(
    page.getByRole("button", { name: "List shared cases" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "List shared cases" }).click();
  await page.getByRole("button", { name: "Capability case" }).click();
  await expect(page.getByLabel("Add note")).toHaveValue("Retained draft");
  await expect(
    page.getByLabel(
      "I understand this saves source evidence to the shared case.",
    ),
  ).toBeEnabled();
});
