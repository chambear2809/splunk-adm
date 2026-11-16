import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("same-event legs stay separate and protected evidence download requires a choice", async ({
  page,
}) => {
  await page.goto("/tests/browser/journeys.html");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  const firewall = page.getByRole("region", {
    name: "Firewall translation evidence",
    exact: true,
  });
  await expect(
    firewall.getByText("Reported tuple", { exact: true }),
  ).toBeVisible();
  await expect(
    firewall.getByText("NAT translated tuple", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: /Proxy request · Same request event/ }),
  ).toBeVisible();
  await firewall
    .getByText("Download journey evidence", { exact: true })
    .first()
    .click();
  const downloadButton = firewall.getByRole("button", {
    name: "Download journey evidence",
    exact: true,
  });
  await expect(downloadButton).toBeDisabled();
  await firewall.getByRole("checkbox").check();
  const pending = page.waitForEvent("download");
  await downloadButton.click();
  const payload = JSON.parse(
    await readFile((await (await pending).path())!, "utf8"),
  );
  expect(payload.version).toBe(1);
  expect(payload.journeys).toHaveLength(1);
  expect(payload.journeys[0].relation).toBe("same_event");
  expect(payload.journeys[0].evidence.event_fingerprint).toBe("a".repeat(64));
  expect(JSON.stringify(payload)).not.toContain("edge-gateway-01");
  const handoff = page.getByRole("region", {
    name: "Service forwarding evidence",
  });
  await handoff
    .getByText("Download journey evidence", { exact: true })
    .first()
    .click();
  await handoff.getByRole("checkbox").check();
  const handoffDownload = page.waitForEvent("download");
  await handoff
    .getByRole("button", { name: "Download journey evidence", exact: true })
    .click();
  const handoffPayload = JSON.parse(
    await readFile((await (await handoffDownload).path())!, "utf8"),
  );
  expect(handoffPayload.scope).toBe("prod");
  expect(handoffPayload.handoffMetadata.records[0].receiving_nodes).toEqual([
    "node-a",
  ]);
  expect(handoffPayload.selectedWindow).toEqual(payload.selectedWindow);
  await page
    .getByRole("button", { name: "Next synthetic firewall event" })
    .click();
  await expect(firewall.getByRole("checkbox")).not.toBeChecked();
  await expect(downloadButton).toBeDisabled();
});

test("missing upstream, retries, capped input and inferred handoffs stay explicit", async ({
  page,
}) => {
  await page.goto("/tests/browser/journeys.html?mode=missing");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(
    page.getByText("Selected upstream endpoint was not reported."),
  ).toBeVisible();
  await page.goto("/tests/browser/journeys.html?mode=retry");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(page.getByText(/3 upstream attempts reported/)).toBeVisible();
  await page.goto("/tests/browser/journeys.html?mode=capped");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(
    page.getByRole("heading", {
      name: /Proxy request · Association unavailable/,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("Proxy input was capped; associations are suppressed."),
  ).toBeVisible();
  await page.goto("/tests/browser/journeys.html?mode=inferred");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(
    page.getByRole("heading", { name: /Inferred candidate/ }),
  ).toBeVisible();
  await page.goto("/tests/browser/journeys.html?mode=partial");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  await expect(
    page.getByRole("region", { name: "Service forwarding evidence" }),
  ).toContainText("coverage is partial");
});

test("journey tuples and details fit a narrow dark layout", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/tests/browser/journeys.html?mode=retry&theme=dark");
  await page
    .getByRole("button", { name: "Open proxy request evidence" })
    .click();
  for (const details of await page
    .getByText("Source details", { exact: true })
    .all())
    await details.click();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(320);
});
