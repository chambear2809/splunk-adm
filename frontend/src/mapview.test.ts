import { describe, expect, it } from "vitest";
import { ensureVisible } from "./MapView";

describe("ensureVisible", () => {
  const view = { w: 800, h: 600 };
  it("leaves a visible box alone", () => {
    const t = { k: 1, x: 0, y: 0 };
    expect(ensureVisible(t, { x: 100, y: 100, w: 50, h: 30 }, view)).toBe(t);
  });
  it("pans the least distance to bring an off-screen box into view", () => {
    const t = ensureVisible(
      { k: 0.85, x: 0, y: 0 },
      { x: 1200, y: 100, w: 200, h: 34 },
      view,
    );
    expect(t.k).toBe(0.85);
    expect(t.x + 1400 * 0.85).toBeCloseTo(800 - 24);
    expect(t.y).toBe(0);
  });
  it("centres a box larger than the viewport", () => {
    const t = ensureVisible(
      { k: 1, x: 0, y: 0 },
      { x: 0, y: 0, w: 2000, h: 100 },
      view,
    );
    expect(t.x + 1000).toBeCloseTo(400);
  });
});
