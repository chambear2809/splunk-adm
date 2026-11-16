import type { GraphEdge } from "../graph";

/** Volume used to rank and draw a relationship: bytes, else its count. */
export const edgeVolume = (e: GraphEdge): number =>
  e.bytes ?? e.raw_bytes ?? e.count ?? 0;

/** Stroke width on a log scale between 1.25 and 7 px. */
export function strokeWidth(volume: number, max: number): number {
  if (!(volume > 0) || !(max > 0)) return 1.25;
  const ratio = Math.log1p(volume) / Math.log1p(max);
  return Math.round((1.25 + Math.min(1, ratio) * 5.75) * 100) / 100;
}
