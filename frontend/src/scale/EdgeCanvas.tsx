import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { RoutedEdge } from "../layout";

export interface CanvasTransform {
  k: number;
  x: number;
  y: number;
}
interface LineStyle {
  stroke: string;
  width: number;
  dash: number[];
}
interface Bucket {
  style: LineStyle;
  dim: boolean;
  lines: Path2D;
  arrows: Path2D;
}

const FALLBACK: LineStyle = { stroke: "#5b6b7f", width: 1.75, dash: [] };

/** Reads the themed SVG edge style for a class list, so canvas and SVG match. */
function probeStyles(
  host: HTMLElement,
  classes: readonly string[],
): Map<string, LineStyle> {
  const result = new Map<string, LineStyle>();
  if (typeof getComputedStyle !== "function") return result;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("aria-hidden", "true");
  svg.style.position = "absolute";
  svg.style.width = "0";
  svg.style.height = "0";
  host.appendChild(svg);
  for (const cls of classes) {
    const g = document.createElementNS(ns, "g");
    g.setAttribute("class", `edge ${cls}`);
    const path = document.createElementNS(ns, "path");
    path.setAttribute("class", "edge-line");
    g.appendChild(path);
    svg.appendChild(g);
    const cs = getComputedStyle(path);
    const dash = cs.strokeDasharray;
    result.set(cls, {
      stroke: cs.stroke && cs.stroke !== "none" ? cs.stroke : FALLBACK.stroke,
      width: parseFloat(cs.strokeWidth) || FALLBACK.width,
      dash:
        dash && dash !== "none"
          ? dash
              .split(/[\s,]+/)
              .map(parseFloat)
              .filter((n) => Number.isFinite(n))
          : [],
    });
  }
  host.removeChild(svg);
  return result;
}

function arrowHead(path: Path2D, pts: [number, number][], size = 7) {
  if (pts.length < 2) return;
  const [x, y] = pts[pts.length - 1];
  const [px, py] = pts[pts.length - 2];
  const a = Math.atan2(y - py, x - px);
  path.moveTo(x, y);
  path.lineTo(x - size * Math.cos(a - 0.45), y - size * Math.sin(a - 0.45));
  path.lineTo(x - size * Math.cos(a + 0.45), y - size * Math.sin(a + 0.45));
  path.closePath();
}

function trace(path: Path2D, pts: [number, number][]) {
  path.moveTo(pts[0][0], pts[0][1]);
  for (let i = 1; i < pts.length; i++) path.lineTo(pts[i][0], pts[i][1]);
}

/**
 * Draws routed lines on one canvas: lines are batched into one Path2D per
 * style, so a pan or zoom is a transform change plus a few stroke calls
 * regardless of the edge count. Cards stay in SVG for focus and labels;
 * hit-testing lives in hitIndex.ts.
 */
export function EdgeCanvas({
  edges,
  classOf,
  dimOf,
  transform,
  width,
  height,
  highlight,
}: {
  edges: readonly RoutedEdge[];
  classOf: (r: RoutedEdge) => string;
  dimOf: (r: RoutedEdge) => boolean;
  transform: CanvasTransform;
  width: number;
  height: number;
  /** Lines drawn on top in the selection colour (selected, hovered). */
  highlight: readonly RoutedEdge[];
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [styles, setStyles] = useState<ReadonlyMap<string, LineStyle>>(
    () => new Map(),
  );
  const classes = useMemo(() => edges.map(classOf), [edges, classOf]);
  useLayoutEffect(() => {
    const host = canvas.current?.parentElement;
    if (!host) return;
    const missing = [...new Set([...classes, "selected"])].filter(
      (c) => !styles.has(c),
    );
    if (!missing.length) return;
    const probed = probeStyles(host, missing);
    setStyles((cur) => new Map([...cur, ...probed]));
  }, [classes, styles]);
  const buckets = useMemo(() => {
    if (typeof Path2D === "undefined") return [];
    const map = new Map<string, Bucket>();
    edges.forEach((r, i) => {
      const cls = classes[i];
      const dim = dimOf(r);
      const base = styles.get(cls) ?? FALLBACK;
      const w = r.width ?? base.width;
      const key = `${cls}|${dim ? 1 : 0}|${Math.round(w * 2)}`;
      let b = map.get(key);
      if (!b) {
        b = {
          style: { ...base, width: Math.round(w * 2) / 2 },
          dim,
          lines: new Path2D(),
          arrows: new Path2D(),
        };
        map.set(key, b);
      }
      trace(b.lines, r.points);
      if (r.arrow === "end") arrowHead(b.arrows, r.points);
    });
    // Dimmed lines first, emphasized ones on top.
    return [...map.values()].sort((a, b) => Number(b.dim) - Number(a.dim));
  }, [edges, classes, dimOf, styles]);

  const frame = useRef(0);
  useEffect(() => {
    const el = canvas.current;
    if (!el || !width || !height) return;
    cancelAnimationFrame(frame.current);
    frame.current = requestAnimationFrame(() => {
      const dpr = window.devicePixelRatio || 1;
      if (el.width !== Math.round(width * dpr))
        el.width = Math.round(width * dpr);
      if (el.height !== Math.round(height * dpr))
        el.height = Math.round(height * dpr);
      const ctx = el.getContext("2d");
      if (!ctx) return;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, el.width, el.height);
      const { k, x, y } = transform;
      ctx.setTransform(dpr * k, 0, 0, dpr * k, dpr * x, dpr * y);
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      for (const b of buckets) {
        ctx.globalAlpha = b.dim ? 0.3 : 1;
        ctx.strokeStyle = b.style.stroke;
        ctx.fillStyle = b.style.stroke;
        ctx.lineWidth = b.style.width;
        ctx.setLineDash(b.style.dash);
        ctx.stroke(b.lines);
        ctx.fill(b.arrows);
      }
      if (highlight.length) {
        const ink = styles.get("selected") ?? FALLBACK;
        const path = new Path2D(),
          arrows = new Path2D();
        for (const r of highlight) {
          trace(path, r.points);
          if (r.arrow === "end") arrowHead(arrows, r.points);
        }
        ctx.globalAlpha = 1;
        ctx.setLineDash([]);
        ctx.strokeStyle = ink.stroke;
        ctx.fillStyle = ink.stroke;
        ctx.lineWidth = Math.max(3, ink.width);
        ctx.stroke(path);
        ctx.fill(arrows);
      }
    });
    return () => cancelAnimationFrame(frame.current);
  }, [buckets, transform, width, height, highlight, styles]);

  return (
    <canvas
      ref={canvas}
      className="atlas-edge-canvas"
      aria-hidden="true"
      style={{ width: width || undefined, height: height || undefined }}
    />
  );
}
