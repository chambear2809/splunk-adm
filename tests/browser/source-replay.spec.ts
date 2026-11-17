import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
const sample = JSON.parse(
  readFileSync(
    new URL(
      "../../fixtures/feature-replay/sanitized-source-sample.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  observations: Array<{
    source_ip: string;
    destination_ip: string;
    verdict: string;
    transport: string;
    is_reply: boolean;
    record_fingerprint: string;
  }>;
};

test.use({ timezoneId: "America/New_York" });

for (const width of [1440, 320]) {
  for (const theme of ["light", "dark"]) {
    test(`sanitized source evidence renders at ${width}px in ${theme}`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(`/tests/browser/source-replay.html?theme=${theme}`);
      await expect(
        page.getByRole("heading", {
          name: "Sanitized source sample",
          exact: true,
        }),
      ).toBeVisible();
      await expect(page.getByText(/4 Hubble observations/)).toBeVisible();
      const evidence = page.getByRole("region", {
        name: "Traffic observations",
      });
      await expect(evidence.getByRole("listitem")).toHaveCount(4);
      for (const [index, observation] of sample.observations.entries()) {
        const row = evidence.getByRole("listitem").nth(index);
        await expect(row).toContainText(`Source IP ${observation.source_ip}`);
        await expect(row).toContainText(
          `Destination IP ${observation.destination_ip}`,
        );
        await expect(row).toContainText(`Verdict ${observation.verdict}`);
        await expect(row).toContainText(`Transport ${observation.transport}`);
        await expect(row).toContainText(`Reply ${observation.is_reply}`);
        await expect(row).toContainText("1 flow record");
        await expect(row).toContainText("2026-01-01");
        await expect(row).toContainText(" UTC");
        await expect(row).not.toContainText("12/31/2025");
        await expect(row).toContainText(observation.record_fingerprint);
      }
      await expect(evidence).toContainText(
        "do not establish physical adjacency or packet route",
      );
      await expect(evidence).toContainText("counters are not authoritative");
      const provenance = page.getByText("Replay provenance", { exact: true });
      await provenance.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByText(/transformed source samples/)).toBeVisible();
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
      expect(
        await evidence.evaluate(
          (element) => element.scrollWidth <= element.clientWidth,
        ),
      ).toBe(true);
      if (process.env.ADM_SOURCE_REVIEW_SCREENSHOTS)
        await page.screenshot({
          path: `/tmp/atlas-source-replay-review/source-${width}-${theme}.png`,
          fullPage: true,
        });
    });
  }
}
