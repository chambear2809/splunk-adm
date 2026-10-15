import { expect, test } from "@playwright/test";

test.describe("health polling lifecycle", () => {
  test("starts hidden, pauses on hide, resumes on show, and skips Help/Setup", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      let visible = false;
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        get: () => (visible ? "visible" : "hidden"),
      });
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility = (next) => {
        visible = next;
        document.dispatchEvent(new Event("visibilitychange"));
      };
    });
    await page.goto("/tests/browser/browser.html?mode=live");
    await page.waitForTimeout(500);
    const hidden = await page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((request) =>
          request.spl.includes("adm_health"),
        ).length,
    );
    expect(hidden).toBe(0);
    await page.clock.install();
    await page.evaluate(() =>
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility?.(true),
    );
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            (window.__ADM_REQUESTS__ ?? []).filter((request) =>
              request.spl.includes("adm_health"),
            ).length,
        ),
      )
      .toBe(3);
    await page.evaluate(() =>
      (
        window as Window & { __setVisibility?: (next: boolean) => void }
      ).__setVisibility?.(false),
    );
    const before = await page.evaluate(
      () =>
        (window.__ADM_REQUESTS__ ?? []).filter((request) =>
          request.spl.includes("adm_health"),
        ).length,
    );
    await page.clock.fastForward(300001);
    await page.waitForTimeout(0);
    expect(
      await page.evaluate(
        () =>
          (window.__ADM_REQUESTS__ ?? []).filter((request) =>
            request.spl.includes("adm_health"),
          ).length,
      ),
    ).toBe(before);
    for (const target of ["help", "setup"]) {
      await page.goto(`/tests/browser/browser.html?page=${target}&mode=live`);
      await page.evaluate(() =>
        (
          window as Window & { __setVisibility?: (next: boolean) => void }
        ).__setVisibility?.(true),
      );
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await page.waitForTimeout(300);
      expect(
        await page.evaluate(
          () =>
            (window.__ADM_REQUESTS__ ?? []).filter((request) =>
              request.spl.includes("adm_health"),
            ).length,
        ),
      ).toBe(0);
    }
  });
});
