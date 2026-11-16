import { expect, test } from "@playwright/test";

test("shared notes preserve a draft across case creation and retry lost responses with one request identity", async ({
  page,
}) => {
  // HTTP replay validates browser behavior; Python tests exercise the actual store/host.
  const records = new Map<string, Record<string, unknown>>();
  const keys: string[] = [];
  let lost = false;
  let revoked = false;
  await page.route("**/test-cases/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "POST" && path.endsWith("/cases")) {
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
      await route.fulfill({ json: records.get(path.split("/").at(-2)!) });
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
  await page.getByLabel("Add note").fill("Preserve this draft");
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
    page.getByText("Preserve this draft", { exact: false }).last(),
  ).toBeVisible();
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
  await page
    .getByRole("button", { name: "Revoke access", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("permission");
  await expect(
    page.getByRole("button", { name: "Retry same request" }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Add note")).toHaveCount(0);
});
