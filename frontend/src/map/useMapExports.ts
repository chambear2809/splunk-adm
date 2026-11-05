import { useState, type RefObject } from "react";
import { type Graph, type indexGraph } from "../graph";
import type { indexTopology } from "../topology";
import { contextEvidenceCsv, requiredFlowsCsv } from "../csv";
import { downloadBlob as download } from "../download";
import { exportMapPng, printMap } from "../exportMap";
import type { RoutedEdge } from "../layout";

const SVG_NS = "http://www.w3.org/2000/svg";
const exportEdgeClass = (r: RoutedEdge) =>
  r.blocked
    ? "conv blocked"
    : r.edge.relationship === "calls"
      ? "call"
      : r.edge.relationship === "communicates_with"
        ? "conv"
        : r.edge.relationship === "traffic_observation"
          ? "traffic-observation"
          : "forward";

/**
 * Dense maps draw lines on a canvas, which an SVG export would drop. Adds the
 * routed lines to the live SVG for the synchronous serialization only; the
 * returned function removes them again.
 */
export function withExportEdges(
  svg: SVGSVGElement,
  edges: readonly RoutedEdge[] | undefined,
): () => void {
  if (!edges?.length || !svg.closest(".atlas-canvas-mode")) return () => {};
  const root = svg.querySelector("[data-export-root]") ?? svg;
  const group = document.createElementNS(SVG_NS, "g");
  group.setAttribute("data-export-edges", "");
  group.setAttribute("aria-hidden", "true");
  for (const r of edges) {
    const g = document.createElementNS(SVG_NS, "g");
    g.setAttribute("class", `edge ${exportEdgeClass(r)}`);
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("class", "edge-line");
    path.setAttribute("d", r.d);
    path.setAttribute("fill", "none");
    g.append(path);
    group.append(g);
  }
  root.insertBefore(group, root.firstChild);
  return () => group.remove();
}
/** Data exports use loaded evidence; images use the currently rendered map. */
export function useMapExports({
  graph,
  index,
  topo,
  root,
  close,
  edges,
}: {
  graph: Graph;
  index: ReturnType<typeof indexGraph>;
  topo: ReturnType<typeof indexTopology>;
  root: RefObject<HTMLDivElement>;
  close: () => void;
  /** Routed lines of the rendered layout; needed when they are on a canvas. */
  edges?: readonly RoutedEdge[];
}) {
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState("");
  const fileStem = `adm-${graph.boundary.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const exportCsv = () => {
    download(
      `${fileStem}-required-flows.csv`,
      "text/csv;charset=utf-8",
      requiredFlowsCsv(graph, index, topo),
    );
    close();
  };
  const exportContextEvidenceCsv = () => {
    download(
      `${fileStem}-context-evidence.csv`,
      "text/csv;charset=utf-8",
      contextEvidenceCsv(graph),
    );
    close();
  };
  const exportPng = async () => {
    setExportBusy(true);
    setExportError("");
    try {
      const svg =
        root.current?.querySelector<SVGSVGElement>(".map-canvas > svg");
      if (!svg)
        throw new Error("Choose Network or Services to export a map image.");
      const restore = withExportEdges(svg, edges);
      let pending: Promise<Blob>;
      try {
        // Serialization is synchronous; the lines leave before the next paint.
        pending = exportMapPng(svg, { filename: `${fileStem}.png` });
      } finally {
        restore();
      }
      await pending;
    } catch (e) {
      setExportError(
        e instanceof Error ? e.message : "Map image could not be exported.",
      );
    } finally {
      setExportBusy(false);
    }
  };
  const exportJson = () => {
    download(
      `${fileStem}.json`,
      "application/json",
      JSON.stringify(graph, null, 2),
    );
    close();
  };
  const exportPrint = () => {
    const svg = root.current?.querySelector<SVGSVGElement>(".map-canvas > svg");
    if (!svg) return;
    const restore = withExportEdges(svg, edges);
    try {
      printMap(
        svg,
        `Application Atlas · ${graph.boundary.service} · ${graph.window.start} – ${graph.window.end}`,
      );
    } finally {
      restore();
    }
  };
  return {
    exportBusy,
    exportError,
    exportCsv,
    exportContextEvidenceCsv,
    exportJson,
    exportPng,
    exportPrint,
  };
}
