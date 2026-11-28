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

  for (const theme of ["light", "dark"] as const) {
    test(`tcp_tls pilot lens meets UX contract at 1280x800 (${theme})`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=tcp_tls&theme=${theme}`,
      );
      const verdict = page.getByTestId("protocol-verdict");
      await expect(verdict).toBeVisible();
      const box = await verdict.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.y).toBeLessThanOrEqual(160);
      expect(
        await page.getByTestId("protocol-kpi-tile").count(),
      ).toBeLessThanOrEqual(4);
      expect(
        await page
          .locator('[data-testid="protocol-overview-table"] thead th')
          .count(),
      ).toBeLessThanOrEqual(8);
      expect(await measureChromeWords(page)).toBeLessThan(60);
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth >
          document.documentElement.clientWidth,
      );
      expect(overflow).toBe(false);
      await page.screenshot({
        path: `${SHOT_DIR}/tcp-tls-overview-1280x800-${theme}.png`,
        fullPage: false,
      });
    });
  }

  test("tcp_tls matrix, drawer, and NetFlow fallback render truthfully", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=tcp_tls&view=matrix&drawer=open&theme=dark",
    );
    await expect(page.getByTestId("protocol-heat-matrix")).toBeVisible();
    await expect(page.getByTestId("protocol-detail-drawer")).toBeVisible();
    // Verify long cert subject wraps without overflowing the detail drawer.
    const drawerOverflow = await page.evaluate(() => {
      const el = document.querySelector(
        '[data-testid="protocol-detail-drawer"]',
      );
      return el ? el.scrollWidth > el.clientWidth + 1 : true;
    });
    expect(drawerOverflow).toBe(false);
    await page.screenshot({
      path: `${SHOT_DIR}/tcp-tls-matrix-drawer-1280x800-dark.png`,
      fullPage: false,
    });

    await page.goto(
      "/tests/browser/protocols.html?scenario=tcp_tls&view=matrix&theme=light",
    );
    await expect(page.getByTestId("protocol-heat-matrix")).toBeVisible();
    await page.screenshot({
      path: `${SHOT_DIR}/tcp-tls-matrix-1280x800-light.png`,
      fullPage: false,
    });

    for (const theme of ["light", "dark"] as const) {
      await page.goto(
        `/tests/browser/protocols.html?scenario=tcp_tls_netflow&theme=${theme}`,
      );
      await expect(page.getByTestId("protocol-verdict")).toContainText(
        /NetFlow/i,
      );
      // NetFlow-only rows must NEVER render as green OK.
      await expect(
        page.locator('[data-testid="protocol-overview-table"] .pl-status-ok'),
      ).toHaveCount(0);
      await page.screenshot({
        path: `${SHOT_DIR}/tcp-tls-netflow-1280x800-${theme}.png`,
        fullPage: false,
      });
    }
  });

  test("tcp_tls aborts in-flight search on scope switch and drops stale responses", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=tcp_tls_race&theme=light",
    );
    await page.getByRole("button", { name: "Investigate" }).click();
    await page.getByLabel("Scope").selectOption("lab:dc2");
    await expect(page.getByTestId("scope-race-root")).toHaveAttribute(
      "data-aborted-count",
      "1",
    );
    // Wait past the 200ms slow response and confirm lab:dc1 row NEVER renders under lab:dc2.
    await page.waitForTimeout(350);
    await expect(page.getByText("198.18.99.1")).toHaveCount(0);
    await expect(page.getByTestId("protocol-verdict")).toContainText(
      /Click Investigate/i,
    );
    await expect(page.getByTestId("scope-race-root")).toHaveAttribute(
      "data-search-count",
      "1",
    );
  });

  test("tcp_tls preempts in-flight first investigation when switching UTC window preset", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=tcp_tls_race&theme=light",
    );
    await page.getByRole("button", { name: "Investigate" }).click();
    // Switch window while the initial search (200ms) is still in flight.
    await page.getByTestId("protocol-window-select").selectOption("60");
    await expect(page.getByTestId("scope-race-root")).toHaveAttribute(
      "data-aborted-count",
      "1",
    );
    await expect(page.getByTestId("scope-race-root")).toHaveAttribute(
      "data-search-count",
      "2",
    );
    await expect(
      page.locator("table.pl-table").getByText("198.18.99.1"),
    ).toBeVisible();
  });

  for (const lens of [
    "dns_ops",
    "routing",
    "l2_control",
    "interface_health",
  ] as const) {
    for (const theme of ["light", "dark"] as const) {
      test(`Wave 2 ${lens} lens meets UX contract at 1280x800 (${theme})`, async ({
        page,
      }) => {
        await page.setViewportSize({ width: 1280, height: 800 });
        await page.goto(
          `/tests/browser/protocols.html?scenario=${lens}&theme=${theme}`,
        );
        const verdict = page.getByTestId("protocol-verdict");
        await expect(verdict).toBeVisible();
        const box = await verdict.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeLessThanOrEqual(160);
        expect(
          await page.getByTestId("protocol-kpi-tile").count(),
        ).toBeLessThanOrEqual(4);
        expect(
          await page
            .locator('[data-testid="protocol-overview-table"] thead th')
            .count(),
        ).toBeLessThanOrEqual(8);
        expect(await measureChromeWords(page)).toBeLessThan(60);
        const overflow = await page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth,
        );
        expect(overflow).toBe(false);
        await page.screenshot({
          path: `${SHOT_DIR}/w2-${lens}-overview-1280x800-${theme}.png`,
          fullPage: false,
        });
      });
    }

    test(`Wave 2 ${lens} Matrix view renders without overflow`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=${lens}&view=matrix&theme=dark`,
      );
      await expect(page.getByTestId("protocol-heat-matrix")).toBeVisible();
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth >
          document.documentElement.clientWidth,
      );
      expect(overflow).toBe(false);
      await page.screenshot({
        path: `${SHOT_DIR}/w2-${lens}-matrix-1280x800-dark.png`,
        fullPage: false,
      });
    });
  }

  for (const lens of [
    "qos_icmp",
    "enterprise_l7",
    "drops",
    "endpoint_mobility",
  ] as const) {
    for (const theme of ["light", "dark"] as const) {
      test(`Wave 3 ${lens} lens meets UX contract at 1280x800 (${theme})`, async ({
        page,
      }) => {
        await page.setViewportSize({ width: 1280, height: 800 });
        await page.goto(
          `/tests/browser/protocols.html?scenario=${lens}&theme=${theme}`,
        );
        const verdict = page.getByTestId("protocol-verdict");
        await expect(verdict).toBeVisible();
        const box = await verdict.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeLessThanOrEqual(160);
        expect(
          await page.getByTestId("protocol-kpi-tile").count(),
        ).toBeLessThanOrEqual(4);
        expect(
          await page
            .locator('[data-testid="protocol-overview-table"] thead th')
            .count(),
        ).toBeLessThanOrEqual(8);
        expect(await measureChromeWords(page)).toBeLessThan(60);
        const overflow = await page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth,
        );
        expect(overflow).toBe(false);
        await page.screenshot({
          path: `${SHOT_DIR}/w3-${lens}-overview-1280x800-${theme}.png`,
          fullPage: false,
        });
      });
    }

    test(`Wave 3 ${lens} Matrix view renders without overflow`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=${lens}&view=matrix&theme=dark`,
      );
      await expect(page.getByTestId("protocol-heat-matrix")).toBeVisible();
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth >
          document.documentElement.clientWidth,
      );
      expect(overflow).toBe(false);
      await page.screenshot({
        path: `${SHOT_DIR}/w3-${lens}-matrix-1280x800-dark.png`,
        fullPage: false,
      });
    });
  }

  for (const lens of [
    "app_transactions",
    "state_events",
    "mgmt_plane",
    "lb_health",
  ] as const) {
    for (const theme of ["light", "dark"] as const) {
      test(`Wave 4 ${lens} lens meets UX contract at 1280x800 (${theme})`, async ({
        page,
      }) => {
        await page.setViewportSize({ width: 1280, height: 800 });
        await page.goto(
          `/tests/browser/protocols.html?scenario=${lens}&theme=${theme}`,
        );
        const verdict = page.getByTestId("protocol-verdict");
        await expect(verdict).toBeVisible();
        const box = await verdict.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeLessThanOrEqual(160);
        expect(
          await page.getByTestId("protocol-kpi-tile").count(),
        ).toBeLessThanOrEqual(4);
        expect(
          await page
            .locator('[data-testid="protocol-overview-table"] thead th')
            .count(),
        ).toBeLessThanOrEqual(8);
        expect(await measureChromeWords(page)).toBeLessThan(60);
        const overflow = await page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth,
        );
        expect(overflow).toBe(false);
        await page.screenshot({
          path: `${SHOT_DIR}/w4-${lens}-overview-1280x800-${theme}.png`,
          fullPage: false,
        });
      });
    }

    test(`Wave 4 ${lens} Matrix view renders without overflow`, async ({
      page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 800 });
      await page.goto(
        `/tests/browser/protocols.html?scenario=${lens}&view=matrix&theme=dark`,
      );
      await expect(page.getByTestId("protocol-heat-matrix")).toBeVisible();
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth >
          document.documentElement.clientWidth,
      );
      expect(overflow).toBe(false);
      await page.screenshot({
        path: `${SHOT_DIR}/w4-${lens}-matrix-1280x800-dark.png`,
        fullPage: false,
      });
    });
  }

  test("live hub does zero SPL searches on mount, loads traffic mix on click, and gates deep-linked lens on config state", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.route(
      "**/storage/collections/data/adm_protocol_profiles*",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify([
            {
              _key: "active",
              configuration: JSON.stringify({
                version: 1,
                profiles: [
                  {
                    id: "p-qos-live",
                    source: "protocol_qos_icmp",
                    lens: "qos_icmp",
                    scope: "lab:dc1",
                    index: "netflow",
                    observer: "stream-01",
                    validFrom: 1700000000,
                    validUntil: 1900000000,
                    extra: { sourceKind: "stream_netflow" },
                  },
                ],
              }),
            },
          ]),
        });
      },
    );

    await page.goto(
      "/tests/browser/protocols.html?scenario=hub_live&theme=light",
    );
    await expect(page.getByText("1/13 configured")).toBeVisible();
    const mountSearches = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: string[] })
          .__protocolHarnessSearches ?? [],
    );
    expect(mountSearches).toHaveLength(0);

    await page.getByRole("button", { name: "Load traffic mix" }).click();
    await expect(page.getByText("HTTPS/TLS (443) 60%")).toBeVisible();
    await expect(page.getByText("Other TCP 20%")).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeVisible();
    const afterClickSearches = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: string[] })
          .__protocolHarnessSearches ?? [],
    );
    expect(afterClickSearches).toHaveLength(1);

    // Deep-linked lens while KV Store config request is pending -> loading gate,
    // then config error banner once the held request rejects.
    await page.unroute("**/storage/collections/data/adm_protocol_profiles*");
    let releaseConfigRoute!: () => void;
    const configRouteHold = new Promise<void>((resolve) => {
      releaseConfigRoute = resolve;
    });
    await page.route(
      "**/storage/collections/data/adm_protocol_profiles*",
      async (route) => {
        await configRouteHold;
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ messages: [{ text: "KV Store error" }] }),
        });
      },
    );
    await page.goto(
      "/tests/browser/protocols.html?scenario=hub_live&p_lens=tcp_tls&theme=light",
      { waitUntil: "domcontentloaded" },
    );
    await expect(page.getByTestId("protocol-lens-loading")).toBeVisible();
    releaseConfigRoute();
    await expect(page.getByTestId("protocol-lens-config-error")).toBeVisible();
  });

  test("protocol filter bar, instant table search, Focus flow, and window presets work end to end", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(
      "/tests/browser/protocols.html?scenario=tcp_tls&theme=light",
    );

    // Zero searches on mount
    const initialSearches = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: unknown[] })
          .__protocolHarnessSearches ?? [],
    );
    expect(initialSearches).toHaveLength(0);

    // Instant client-side table search filters loaded rows without running SPL
    const searchInput = page.getByTestId("protocol-table-search");
    await expect(searchInput).toBeVisible();
    await searchInput.fill("198.18.38.12");
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await expect(page.locator("tbody")).toContainText("198.18.38.12");
    const afterTableSearch = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: unknown[] })
          .__protocolHarnessSearches ?? [],
    );
    expect(afterTableSearch).toHaveLength(0);
    await searchInput.fill("");
    await expect(page.locator("tbody tr")).toHaveCount(2);

    // Inline validation rejects invalid port before issuing SPL
    await page.getByTestId("protocol-filter-port").fill("99999");
    await page.getByTestId("protocol-filter-apply").click();
    await expect(page.getByTestId("protocol-filter-error")).toBeVisible();
    const afterInvalid = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: unknown[] })
          .__protocolHarnessSearches ?? [],
    );
    expect(afterInvalid).toHaveLength(0);

    // Valid src + dst + port + bidirectional toggle triggers SPL with both directions + port
    await page.getByTestId("protocol-filter-src").fill("198.18.38.11");
    await page.getByTestId("protocol-filter-dst").fill("198.18.38.21");
    await page.getByTestId("protocol-filter-port").fill("443");
    await page.getByTestId("protocol-filter-bidir").click();
    await page.getByTestId("protocol-filter-apply").click();

    await expect
      .poll(async () => {
        const list = await page.evaluate(
          () =>
            (
              window as unknown as {
                __protocolHarnessSearches?: Array<{ spl: string }>;
              }
            ).__protocolHarnessSearches ?? [],
        );
        return list.length;
      })
      .toBeGreaterThanOrEqual(1);

    const filterSpl = await page.evaluate(() => {
      const list =
        (
          window as unknown as {
            __protocolHarnessSearches?: Array<{ spl: string }>;
          }
        ).__protocolHarnessSearches ?? [];
      return list[list.length - 1]?.spl ?? "";
    });
    expect(filterSpl).toContain('src_ip="198.18.38.11"');
    expect(filterSpl).toContain('dest_ip="198.18.38.21"');
    expect(filterSpl).toContain('src_ip="198.18.38.21"');
    expect(filterSpl).toContain('dest_ip="198.18.38.11"');
    expect(filterSpl).toContain('(dest_port="443" OR src_port="443")');

    // Window preset selector switches 15m -> 30m and re-runs SPL with wider earliest
    const countBeforeWindow = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: unknown[] })
          .__protocolHarnessSearches?.length ?? 0,
    );
    await page.getByTestId("protocol-window-select").selectOption("30");
    await expect
      .poll(async () =>
        page.evaluate(
          () =>
            (window as unknown as { __protocolHarnessSearches?: unknown[] })
              .__protocolHarnessSearches?.length ?? 0,
        ),
      )
      .toBeGreaterThan(countBeforeWindow);
    const windowSearch = await page.evaluate(() => {
      const list =
        (
          window as unknown as {
            __protocolHarnessSearches?: Array<{
              earliest?: string;
              latest?: string;
            }>;
          }
        ).__protocolHarnessSearches ?? [];
      return list[list.length - 1];
    });
    expect(Number(windowSearch?.latest) - Number(windowSearch?.earliest)).toBe(
      1800,
    );

    // Clicking a row opens the drawer with Focus flow button, which populates filter and runs SPL
    await page.locator("tbody tr").first().click();
    const focusBtn = page.getByTestId("protocol-focus-flow");
    await expect(focusBtn).toBeVisible();
    const countBeforeFocus = await page.evaluate(
      () =>
        (window as unknown as { __protocolHarnessSearches?: unknown[] })
          .__protocolHarnessSearches?.length ?? 0,
    );
    await focusBtn.click();
    await expect
      .poll(async () =>
        page.evaluate(
          () =>
            (window as unknown as { __protocolHarnessSearches?: unknown[] })
              .__protocolHarnessSearches?.length ?? 0,
        ),
      )
      .toBeGreaterThan(countBeforeFocus);
  });
});
