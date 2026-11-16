import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { expect, test } from "@playwright/test";

// Scale benchmark for the map and table. Opt-in (ADM_SCALE_BENCH=1) because
// timings are environment-dependent; the assertions encode the interactive
// budget (pan/zoom frame p95 < 100 ms, initial layout+render < 2 s at 4k/10k).
test.skip(!process.env.ADM_SCALE_BENCH, "set ADM_SCALE_BENCH=1 to run");
test.describe.configure({ mode: "serial" });
test.setTimeout(600_000);

const ONLY = process.env.ADM_SCALE_CASES?.split(",");
const MAP_CASES: [number, number][] = (
  [
    [500, 2000],
    [2000, 10000],
    [4000, 10000],
    [4000, 20000],
    [4000, 50000],
    [4000, 100000],
  ] as [number, number][]
).filter(([n, e]) => !ONLY || ONLY.includes(`${n}/${e}`));
const TABLE_CASES = [10000, 100000, 400000].filter(
  (n) => !ONLY || ONLY.includes(`table/${n}`),
);

test("map and table scale", async ({ page }) => {
  // The dev server may reload the page when a dependency is optimized or a
  // shared source file changes; each case therefore loads a fresh page.
  const measure = async <T>(run: () => Promise<T>): Promise<T> => {
    for (let attempt = 0; ; attempt++) {
      await page.goto("/frontend/src/scale/bench.html");
      await page.waitForSelector("body[data-ready='1']");
      try {
        return await run();
      } catch (error) {
        if (attempt >= 3 || !/context was destroyed/.test(String(error)))
          throw error;
      }
    }
  };
  const results: Record<string, unknown>[] = [];
  for (const [nodes, edges] of MAP_CASES) {
    for (const variant of process.env.ADM_SCALE_BASELINE
      ? (["default"] as const)
      : (["default", "expanded"] as const)) {
      const r = await measure(() =>
        page.evaluate(
          ([n, e, v]) =>
            window.atlasBench.map(
              n as number,
              e as number,
              v === "expanded" ? { aggregate: false } : {},
            ),
          [nodes, edges, variant] as const,
        ),
      );
      results.push({ kind: "map", variant, ...r });
      save(results);
    }
  }
  for (const rows of TABLE_CASES) {
    const r = await measure(() =>
      page.evaluate((n) => window.atlasBench.table(n), rows),
    );
    results.push({ kind: "table", ...r });
    save(results);
  }
  console.log(JSON.stringify(results));
  if (process.env.ADM_SCALE_NO_ASSERT) return;
  const budget = results.find(
    (r) =>
      r.kind === "map" &&
      r.variant === "default" &&
      r.nodes === 4000 &&
      r.edges === 10000,
  ) as { initialMs: number; panP95: number };
  expect(budget.initialMs).toBeLessThan(2000);
  expect(budget.panP95).toBeLessThan(100);
  const table = results.find(
    (r) => r.kind === "table" && r.rows === 100000,
  ) as { scrollP95: number };
  expect(table.scrollP95).toBeLessThan(100);
});

function save(results: Record<string, unknown>[]) {
  const out = process.env.ADM_SCALE_OUTPUT;
  if (!out) return;
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(results, null, 2));
}
