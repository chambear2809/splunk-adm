/** A polyline to hit-test, in layout coordinates. */
export interface HitLine {
  id: string;
  points: [number, number][];
}

const CELL = 96;

function segmentDistance(
  px: number,
  py: number,
  [ax, ay]: [number, number],
  [bx, by]: [number, number],
): number {
  const dx = bx - ax,
    dy = by - ay;
  const len = dx * dx + dy * dy;
  const t = len
    ? Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / len))
    : 0;
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/**
 * Uniform-grid index over polyline segments. Each segment is registered in
 * the cells it passes through (sampled every half cell), so building is
 * O(total length / cell) and a query only measures nearby segments.
 */
export function createHitIndex<T extends HitLine>(lines: readonly T[]) {
  const cells = new Map<number, number[]>();
  const key = (cx: number, cy: number) => cx * 73856093 + cy * 19349663;
  const add = (cx: number, cy: number, ref: number) => {
    const k = key(cx, cy);
    const list = cells.get(k);
    if (!list) cells.set(k, [ref]);
    else if (list[list.length - 1] !== ref) list.push(ref);
  };
  lines.forEach((line, li) => {
    for (let s = 0; s + 1 < line.points.length; s++) {
      const [ax, ay] = line.points[s],
        [bx, by] = line.points[s + 1];
      const steps = Math.max(
        1,
        Math.ceil(Math.hypot(bx - ax, by - ay) / (CELL / 2)),
      );
      for (let i = 0; i <= steps; i++) {
        const x = ax + ((bx - ax) * i) / steps,
          y = ay + ((by - ay) * i) / steps;
        add(Math.floor(x / CELL), Math.floor(y / CELL), li);
      }
    }
  });
  return {
    /** Closest line within `tolerance` of (x, y), in layout units. */
    hit(x: number, y: number, tolerance: number): T | undefined {
      const cx = Math.floor(x / CELL),
        cy = Math.floor(y / CELL);
      const reach = Math.ceil(tolerance / CELL);
      let best: T | undefined;
      let bestD = tolerance;
      const seen = new Set<number>();
      for (let gx = cx - reach; gx <= cx + reach; gx++)
        for (let gy = cy - reach; gy <= cy + reach; gy++)
          for (const li of cells.get(key(gx, gy)) ?? []) {
            if (seen.has(li)) continue;
            seen.add(li);
            const pts = lines[li].points;
            for (let s = 0; s + 1 < pts.length; s++) {
              const d = segmentDistance(x, y, pts[s], pts[s + 1]);
              if (d <= bestD) {
                bestD = d;
                best = lines[li];
              }
            }
          }
      return best;
    },
  };
}
