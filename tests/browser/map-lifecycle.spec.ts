import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import type { Graph } from "../../frontend/src/graph";
import {
  OLD_CLIENT,
  NEW_CLIENT,
  OLD_ATTACHMENT,
  NEW_ATTACHMENT,
  NEW_OBSERVATION,
  OLD_CLIENT_LABEL,
  NEW_CLIENT_LABEL,
  NEW_ATTACHMENT_LABEL,
  CONFLICT_ATTACHMENT_LABEL,
  CLIENT_EDGE,
  CLIENT_BACKEND,
  lifecycleWindow,
} from "./map-lifecycle-fixtures";
import type { LifecycleControl } from "./map-lifecycle-harness";

const url = "/tests/browser/map-lifecycle.html";
const requests = (page: Page) =>
  page.evaluate(() => window.mapLifecycle.requests());
const count = async (page: Page, expected: number) => {
  await expect.poll(async () => (await requests(page)).length).toBe(expected);
};
const action = (
  page: Page,
  name: Exclude<keyof LifecycleControl, "requests" | "resolve" | "reject">,
) => page.evaluate((method) => window.mapLifecycle[method](), name);
const resolve = (page: Page, index: number, version = 1) =>
  page.evaluate(
    ([i, v]) => window.mapLifecycle.resolve(i, v),
    [index, version],
  );
const snapshot = (page: Page) => page.getByTestId("snapshot");

// These exercise the real hooks in React, with controllable transport completion.
test("publishes a graph and its absolute-window topology atomically", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await resolve(page, 0);
  await count(page, 2);
  expect((await requests(page))[1]).toMatchObject({
    earliest: "1791373500",
    latest: "1791374400",
    timezone: "Pacific/Honolulu",
  });
  await expect(snapshot(page)).toHaveAttribute("data-visible", "false");
  await resolve(page, 1);
  await expect(snapshot(page)).toHaveAttribute("data-visible", "true");
  await expect(snapshot(page)).toContainText('"graph-1"');
  await expect(snapshot(page)).toContainText('"topology-1"');
  await action(page, "refresh");
  await count(page, 3);
  await resolve(page, 2, 2);
  await count(page, 4);
  await expect(snapshot(page)).toContainText('"graph-1"');
  await expect(snapshot(page)).not.toContainText('"graph-2"');
  await resolve(page, 3, 2);
  await expect(snapshot(page)).toContainText('"graph-2"');
  await expect(snapshot(page)).toContainText('"topology-2"');
});

test("cancels an obsolete client and never publishes its late graph", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await action(page, "replace");
  await expect.poll(async () => (await requests(page))[0].aborted).toBe(true);
  await resolve(page, 0, 9);
  await expect(snapshot(page)).toHaveAttribute("data-busy", "false");
  await expect(snapshot(page)).toHaveAttribute("data-visible", "false");
  expect(await requests(page)).toHaveLength(1);
  await action(page, "refresh");
  await count(page, 2);
  expect((await requests(page))[1].client).toBe("b");
  await resolve(page, 1, 2);
  await count(page, 3);
  await resolve(page, 2, 2);
  await expect(snapshot(page)).toContainText('"client":"b"');
  await expect(snapshot(page)).not.toContainText('"graph-9"');
});

test("retains loaded provenance after draft edits and failed rebuilds", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await resolve(page, 0);
  await count(page, 2);
  await resolve(page, 1);
  await expect(snapshot(page)).toHaveAttribute("data-visible", "true");
  await action(page, "edit");
  await expect(snapshot(page)).toContainText('"namespace":"unbuilt"');
  const state = JSON.parse(await snapshot(page).innerText());
  expect(state.loaded).toMatchObject({
    namespace: "shop",
    earliest: "-1h",
    latest: "now",
    timezone: "Pacific/Honolulu",
  });
  await action(page, "refresh");
  await count(page, 3);
  await page.evaluate(() => window.mapLifecycle.reject(2));
  await expect(snapshot(page)).toContainText("Expected graph failure");
  await expect(snapshot(page)).toContainText('"graph-1"');
  await expect(snapshot(page)).toContainText('"topology-1"');
});

test("scope edits cancel inventory completion without replacing the snapshot", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await resolve(page, 0);
  await count(page, 2);
  await action(page, "edit");
  await resolve(page, 1);
  await expect(snapshot(page)).toHaveAttribute("data-visible", "false");
  await expect(snapshot(page)).toHaveAttribute("data-busy", "false");
  await expect(snapshot(page)).not.toContainText('"graph-1"');
});

test("a newer build wins when an older transport completes afterward", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await action(page, "refresh");
  await count(page, 2);
  await resolve(page, 1, 2);
  await count(page, 3);
  await resolve(page, 2, 2);
  await expect(snapshot(page)).toContainText('"graph-2"');
  await resolve(page, 0, 1);
  await expect(snapshot(page)).not.toContainText('"graph-1"');
  expect(await requests(page)).toHaveLength(3);
});

test("demo refresh replaces graph and topology from the same fixture revision", async ({
  page,
}) => {
  await page.goto(`${url}?mode=demo`);
  await expect(snapshot(page)).toContainText('"id":"demo-1"');
  await expect(snapshot(page)).toContainText('"topologyWarnings":["demo-1"]');
  await action(page, "refreshDemo");
  await expect(snapshot(page)).toContainText('"id":"demo-2"');
  await expect(snapshot(page)).toContainText('"topologyWarnings":["demo-2"]');
  expect(await requests(page)).toHaveLength(0);
});

test("switching to demo suppresses a pending live snapshot", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await action(page, "demo");
  await expect(snapshot(page)).toContainText('"mode":"demo"');
  await resolve(page, 0);
  await expect(snapshot(page)).toContainText('"id":"demo-1"');
  expect((await requests(page))[0].aborted).toBe(true);
});

test("unmount aborts the active search", async ({ page }) => {
  await page.goto(url);
  await count(page, 1);
  await action(page, "unmount");
  expect((await requests(page))[0].aborted).toBe(true);
});

test("keyboard dismissal returns focus to the selected map card", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?scenario=aci");
  const card = page.locator(".map-canvas .item[role=button]").first();
  await expect(card).toBeVisible();
  await card.focus();
  await card.press("Enter");
  await expect(card).toHaveAttribute("aria-pressed", "true");
  await page
    .getByRole("button", { name: "Clear selection", exact: true })
    .focus();
  await page.keyboard.press("Escape");
  await expect(card).toHaveAttribute("aria-pressed", "false");
  await expect(card).toBeFocused();
});

test("a replaced client cannot publish inventory for its already completed graph", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await resolve(page, 0);
  await count(page, 2);
  await action(page, "replace");
  await resolve(page, 1);
  await expect(snapshot(page)).toHaveAttribute("data-visible", "false");
  await expect(snapshot(page)).not.toContainText('"graph-1"');
  expect((await requests(page))[1].aborted).toBe(true);
});

test("optional inventory failure publishes only the new graph with a visible warning", async ({
  page,
}) => {
  await page.goto(url);
  await count(page, 1);
  await resolve(page, 0);
  await count(page, 2);
  await page.evaluate(() => window.mapLifecycle.reject(1));
  await expect(snapshot(page)).toHaveAttribute("data-visible", "true");
  await expect(snapshot(page)).toContainText('"graph-1"');
  await expect(snapshot(page)).toContainText(
    "Network inventory unavailable. Expected graph failure",
  );
  await expect(snapshot(page)).toHaveAttribute("data-busy", "false");
});

const mapSurfaceURL = `${url}?surface=map`;
const details = (page: Page) =>
  page.getByRole("complementary", { name: "Details" });
const mapCard = (page: Page, label: string) =>
  page.locator(".map-canvas .item[role=button]").filter({ hasText: label });
const exportText = async (page: Page, name: RegExp): Promise<string> => {
  const menu = page.getByRole("region", { name: "Export", exact: true });
  if (!(await menu.isVisible()))
    await page.getByRole("button", { name: "Export", exact: true }).click();
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name }).click();
  return readFile((await (await downloading).path())!, "utf8");
};
const exportedGraph = async (page: Page): Promise<Graph> =>
  JSON.parse(await exportText(page, /Map data \(JSON\)/)) as Graph;
const loadMapSurface = async (page: Page) => {
  await page.goto(mapSurfaceURL);
  await count(page, 1);
  await resolve(page, 0, 1);
  await count(page, 2);
  await resolve(page, 1, 1);
  await expect(page.locator('.adm[data-loaded="true"]')).toBeVisible();
};

test("MapPage refresh removes a selected client and replaces attachment, inventory, filters and exports atomically", async ({
  page,
}) => {
  await loadMapSurface(page);
  const oldCard = mapCard(page, OLD_CLIENT_LABEL);
  await expect(oldCard).toBeVisible();
  await page.getByLabel("Hide infrastructure", { exact: true }).check();
  await oldCard.focus();
  await oldCard.press("Enter");
  await page
    .getByLabel("Focus around selected card", { exact: true })
    .selectOption("1");
  await expect(details(page)).toContainText("CAMPUS-SW-01");
  await page.getByRole("button", { name: "Export", exact: true }).click();
  await page.getByRole("button", { name: "Build map", exact: true }).click();
  await count(page, 3);
  await resolve(page, 2, 2);
  await count(page, 4);

  // New graph rows have returned, while the old inventory is still loaded.
  // The visible map, selected inspector and full-data export must all remain
  // the complete previous pair until new inventory has finished.
  await expect(oldCard).toBeVisible();
  await expect(mapCard(page, NEW_CLIENT_LABEL)).toHaveCount(0);
  await expect(details(page)).toContainText("CAMPUS-SW-01");
  await expect(
    page.getByLabel("Hide infrastructure", { exact: true }),
  ).toBeChecked();
  const beforePublication = await exportedGraph(page);
  expect(beforePublication.nodes.some((node) => node.id === OLD_CLIENT)).toBe(
    true,
  );
  expect(beforePublication.nodes.some((node) => node.id === NEW_CLIENT)).toBe(
    false,
  );
  expect(JSON.stringify(beforePublication)).toContain(OLD_ATTACHMENT);
  await resolve(page, 3, 2);

  await expect(oldCard).toHaveCount(0);
  await expect(mapCard(page, NEW_CLIENT_LABEL)).toBeVisible();
  await expect(
    page.getByLabel("Hide infrastructure", { exact: true }),
  ).not.toBeChecked();
  await expect(
    page.getByLabel("Focus around selected card", { exact: true }),
  ).toHaveValue("0");
  await expect(
    details(page).getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
  await expect(details(page)).not.toContainText(OLD_CLIENT_LABEL);
  await mapCard(page, NEW_CLIENT_LABEL).focus();
  await mapCard(page, NEW_CLIENT_LABEL).press("Enter");
  await expect(details(page)).toContainText(NEW_ATTACHMENT_LABEL);
  await expect(details(page)).not.toContainText("CAMPUS-SW-01");

  const current = await exportedGraph(page);
  expect(current.nodes.some((node) => node.id === OLD_CLIENT)).toBe(false);
  expect(
    current.edges.some(
      (edge) => edge.source === OLD_CLIENT || edge.target === OLD_CLIENT,
    ),
  ).toBe(false);
  expect(
    current.nodes.find((node) => node.id === NEW_CLIENT)?.attributes,
  ).toMatchObject({
    source: "catalyst_client_snapshot",
    source_authority: "https://catalyst-center.example.invalid",
    native_id: "02:61:00:00:00:21",
    attachment_device_id: NEW_ATTACHMENT,
  });
  expect(
    current.edges.find((edge) => edge.id === NEW_OBSERVATION)
      ?.attachment_evidence?.[0].device_name,
  ).toBe(NEW_ATTACHMENT_LABEL);
  expect(JSON.stringify(current)).not.toContain(OLD_ATTACHMENT);
  expect(JSON.stringify(current)).not.toContain("CAMPUS-SW-01");
  const contextCsv = await exportText(page, /Context evidence \(CSV\)/);
  expect(contextCsv).toContain(NEW_ATTACHMENT_LABEL);
  expect(contextCsv).not.toContain("CAMPUS-SW-01");
  expect(contextCsv).not.toContain(OLD_CLIENT);
  await page.getByRole("button", { name: "Devices", exact: true }).click();
  await expect(
    page.getByRole("region", { name: "Client attachment devices" }),
  ).toContainText(NEW_ATTACHMENT_LABEL);
  await expect(page.locator(".map-area")).not.toContainText("CAMPUS-SW-01");

  // A comparison is a separate query over the preceding absolute window.
  // Resolve it with the original captured membership, not the current rows.
  await page.getByRole("button", { name: "Changes", exact: true }).click();
  await page
    .getByRole("button", { name: "Compare previous window", exact: true })
    .click();
  await count(page, 5);
  const currentStart = Number(lifecycleWindow.earliest);
  const currentDuration = Number(lifecycleWindow.latest) - currentStart;
  expect((await requests(page))[4]).toMatchObject({
    earliest: String(currentStart - currentDuration),
    latest: lifecycleWindow.earliest,
  });
  await resolve(page, 4, 1);
  await expect(page.locator(".atlas-changes")).toContainText(
    "1 connections added · 3 removed",
  );
  await page
    .locator(".atlas-changes summary")
    .filter({ hasText: "Removed connections" })
    .click();
  await expect(page.locator(".atlas-changes")).toContainText(OLD_CLIENT_LABEL);
});

test("MapPage refresh replaces selected-client handoff and preserves conflicting attachment uncertainty", async ({
  page,
}) => {
  await loadMapSurface(page);
  const initial = await exportedGraph(page);
  const backendLabel = initial.nodes.find(
    (node) => node.id === CLIENT_BACKEND,
  )!.label;
  const conversation = () =>
    page
      .locator(".table-view table")
      .first()
      .locator("tbody button")
      .filter({ hasText: "win-client-01" })
      .filter({ hasText: "checkout-api" });
  await page.getByLabel("Filter port", { exact: true }).selectOption("8080");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await conversation().click();
  await expect(details(page)).toContainText(backendLabel);
  await details(page)
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  await expect(
    page
      .getByRole("region", { name: /^Candidate path:/ })
      .getByTitle(backendLabel, { exact: false }),
  ).toHaveCount(1);
  await page.getByRole("button", { name: "Build map", exact: true }).click();
  await count(page, 3);
  await resolve(page, 2, 3);
  await count(page, 4);
  await expect(details(page)).toContainText(backendLabel);
  await expect(details(page)).not.toContainText(
    "Client handoff coverage is partial",
  );
  await resolve(page, 3, 3);
  await expect(
    page.getByRole("region", { name: /^Candidate path:/ }),
  ).toHaveCount(0);
  await expect(
    details(page).getByRole("button", { name: "Clear selection", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await conversation().click();
  await expect(details(page)).toContainText(
    "Client handoff coverage is partial (1 of 2 connections determined; 1 unresolved).",
  );
  await expect(details(page)).not.toContainText(backendLabel);
  await expect(
    details(page).getByText("Received on", { exact: true }),
  ).toHaveCount(0);
  await details(page)
    .getByRole("button", { name: "Show candidate path", exact: true })
    .click();
  const path = page.getByRole("region", { name: /^Candidate path:/ });
  await expect(path).toContainText("Not determined");
  await expect(path).toContainText("Client handoff coverage is partial");
  await expect(path.getByTitle(backendLabel, { exact: false })).toHaveCount(0);
  await expect(path).not.toContainText(
    "Kubernetes node · received the traffic",
  );
  const current = await exportedGraph(page);
  const selected = current.edges.find((edge) => edge.id === CLIENT_EDGE)!;
  expect(selected).toMatchObject({
    client_handoff_coverage: "partial",
    client_handoff_connections: 2,
    client_handoff_determined: 1,
    client_handoff_unresolved: 1,
  });
  expect(selected.client_handoffs).toHaveLength(1);
  expect(selected.via_node).toBeUndefined();
  // The aggregate backend is still valid evidence for other clients, and may
  // remain in the graph; it must not replace this client's partial evidence.
  expect(
    current.edges.some(
      (edge) =>
        edge.relationship === "forwards_to" && edge.target === CLIENT_BACKEND,
    ),
  ).toBe(true);
  const requiredCsv = await exportText(page, /Required flows \(CSV\)/);
  const selectedCsvRow = requiredCsv
    .split("\n")
    .find(
      (line) => line.includes("win-client-01") && line.includes("checkout-api"),
    )!;
  expect(selectedCsvRow).toContain("handoff coverage is partial");
  expect(selectedCsvRow).not.toContain(backendLabel);
  await page.getByRole("button", { name: "Network", exact: true }).click();
  await mapCard(page, NEW_CLIENT_LABEL).focus();
  await mapCard(page, NEW_CLIENT_LABEL).press("Enter");
  await expect(details(page)).toContainText(
    "Conflicting client attachment evidence; ownership is unresolved.",
  );
  await expect(details(page)).not.toContainText("CAMPUS-SW-01");
  const conflictCsv = await exportText(page, /Context evidence \(CSV\)/);
  expect(conflictCsv).toContain("conflict");
  expect(conflictCsv).toContain(NEW_ATTACHMENT_LABEL);
  expect(conflictCsv).toContain(CONFLICT_ATTACHMENT_LABEL);
  expect(conflictCsv).not.toContain("CAMPUS-SW-01");
  await page.getByRole("button", { name: /warning/ }).click();
  await expect(
    page.getByRole("region", { name: "Search warnings" }),
  ).toContainText(
    "conflicting attachment observations and partial client handoff remain unresolved",
  );
});
