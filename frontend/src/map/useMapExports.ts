import { useState, type RefObject } from "react";
import { type Graph, type indexGraph } from "../graph";
import type { indexTopology } from "../topology";
import { contextEvidenceCsv, requiredFlowsCsv } from "../csv";
import { downloadBlob as download } from "../download";
import { exportMapPng, printMap } from "../exportMap";
/** Data exports use loaded evidence; images use the currently rendered map. */
export function useMapExports({
  graph,
  index,
  topo,
  root,
  close,
}: {
  graph: Graph;
  index: ReturnType<typeof indexGraph>;
  topo: ReturnType<typeof indexTopology>;
  root: RefObject<HTMLDivElement>;
  close: () => void;
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
      await exportMapPng(svg, { filename: `${fileStem}.png` });
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
    if (svg)
      printMap(
        svg,
        `Application Atlas · ${graph.boundary.service} · ${graph.window.start} – ${graph.window.end}`,
      );
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
