import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";

const SHOT_DIR = "test-results/protocol-ux";

async function measureChromeWords(page: Page): Promise<number> {
  return page.evaluate(() => {
    const root = document.querySelector(".pl-page");
    if (!root) return 999;
    const clone = root.cloneNode(true) as HTMLElement;
    clone
      .querySelectorAll("[data-pl-data='true']")
      .forEach((el) => el.remove());
    clone
      .querySelectorAll(".atlas-visually-hidden, svg")
      .forEach((el) => el.remove());
    const text = (clone.textContent ?? "").trim();
    if (!text) return 0;
    return text.split(/\s+/).filter(Boolean).length;
  });
}

test.describe("Protocol Lens UX contract", () => {
  test.beforeAll(() => {
    mkdirSync(SHOT_DIR, { recursive: true });
  });

  for (const theme of ["light", "dark"] as const) {
    for (const viewport of [
      { width: 1440, height: 900 },
      { width: 1280, height: 800 },
    ]) {
      test(`sample lens meets UX contract at ${viewport.width}x${viewport.height} (${theme})`, async ({
        page,
      }) => {
        await page.setViewportSize(viewport);
        await page.goto(
          `/tests/browser/protocols.html?scenario=sample_lens&theme=${theme}`,
        );
        const verdict = page.getByTestId("protocol-verdict");
        await expect(verdict).toBeVisible();
        const box = await verdict.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeLessThanOrEqual(160);
        expect(box!.y + box!.height).toBeLessThan(viewport.height);

        const kpiCount = await page.getByTestId("protocol-kpi-tile").count();
        expect(kpiCount).toBeLessThanOrEqual(4);

        const cols = await page
          .locator('[data-testid="protocol-overview-table"] thead th')
          .count();
        expect(cols).toBeLessThanOrEqual(8);

        const chromeWords = await measureChromeWords(page);
        expect(chromeWords).toBeLessThan(60);

        const overflow = await page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth,
        );
        expect(overflow).toBe(false);

        await page.screenshot({
          path: `${SHOT_DIR}/sample-overview-${viewport.width}x${viewport.height}-${theme}.png`,
          fullPage: false,
        });
      });
    }
  }

  for (const theme of ["light", "dark"] as const) {
    test(`hub renders standalone Multicast and 13 lens cards without overflow (${theme})`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=hub&theme=${theme}`,
      );
      await expect(page.getByTestId("protocol-card-multicast")).toBeVisible();
      await expect(page.getByTestId("protocol-card-tcp_tls")).toBeVisible();
      await expect(page.getByTestId("protocol-card-lb_health")).toBeVisible();
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth >
          document.documentElement.clientWidth,
      );
      expect(overflow).toBe(false);
      await page.screenshot({
        path: `${SHOT_DIR}/hub-1280x800-${theme}.png`,
        fullPage: false,
      });
    });
  }

  test("supports roving keyboard navigation in Matrix, focuses drawer, and restores focus on Escape", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=sample_lens&view=matrix&theme=dark",
    );
    const firstCell = page.locator(".pl-cell-btn").first();
    await firstCell.focus();
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press("Enter");
    const drawer = page.getByTestId("protocol-detail-drawer");
    await expect(drawer).toBeVisible();
    await expect(drawer.locator("h2")).toBeFocused();
    await page.screenshot({
      path: `${SHOT_DIR}/sample-matrix-drawer-1280x800-dark.png`,
      fullPage: false,
    });
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(page.locator(".pl-cell-btn").nth(1)).toBeFocused();
  });

  test("renders drawer cleanly in light theme", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=sample_lens&drawer=open&theme=light",
    );
    await expect(page.getByTestId("protocol-detail-drawer")).toBeVisible();
    await page.screenshot({
      path: `${SHOT_DIR}/sample-drawer-1280x800-light.png`,
      fullPage: false,
    });
  });

  for (const state of [
    "loading",
    "empty",
    "partial",
    "blocked",
    "unavailable",
    "stale_config",
    "estimate_only",
  ] as const) {
    test(`renders shared ${state} state banner cleanly`, async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=sample_lens&state=${state}&theme=light`,
      );
      await expect(page.getByTestId(`protocol-state-${state}`)).toBeVisible();
      if (state === "loading") {
        await expect(
          page.getByTestId("protocol-loading-skeleton"),
        ).toBeVisible();
        await expect(page.getByTestId("protocol-overview-table")).toHaveCount(
          0,
        );
      }
      if (state === "empty" || state === "blocked" || state === "unavailable") {
        await expect(page.getByTestId("protocol-kpi-strip")).toHaveCount(0);
        await expect(page.getByTestId("protocol-overview-table")).toHaveCount(
          0,
        );
      }
      await page.screenshot({
        path: `${SHOT_DIR}/sample-state-${state}-1280x800-light.png`,
        fullPage: false,
      });
    });
  }
});
