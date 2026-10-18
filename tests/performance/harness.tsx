import { Profiler } from "react";
import { createRoot, type Root } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "@atlas/app/interop";
import { MapPage } from "@atlas/pages/MapPage";
import { parseUrlState } from "@atlas/app/urlState";
import { indexGraph, type Graph } from "@atlas/graph";
import { rowsToGraph } from "@atlas/rows";
import {
  rowsToTopology,
  indexTopology,
  clientHandoffResolution,
  buildPath,
  deviceSummaries,
  resolveDevice,
} from "@atlas/topology";
import { computeLayout } from "@atlas/layout";
import { filterGraph } from "@atlas/filters";
import { workload, type Scenario, type Size } from "./workloads";
import "@atlas/styles.css";

const ThemeProvider = toolkitDefault(ThemeProviderExport);
type Sample = { name: string; start: number; duration: number };
const samples: Sample[] = [];
const tasks: { start: number; duration: number }[] = [];
const renders: {
  phase: string;
  duration: number;
  start: number;
  commit: number;
}[] = [];
const longTasksSupported =
  PerformanceObserver.supportedEntryTypes.includes("longtask");
const observer = longTasksSupported
  ? new PerformanceObserver((list) => {
      tasks.push(
        ...list.getEntries().map((entry) => ({
          start: entry.startTime,
          duration: entry.duration,
        })),
      );
    })
  : undefined;
observer?.observe({ type: "longtask", buffered: true });
const flushTasks = () =>
  tasks.push(
    ...(observer?.takeRecords() ?? []).map((entry) => ({
      start: entry.startTime,
      duration: entry.duration,
    })),
  );
function measure<T>(name: string, action: () => T): T {
  const start = performance.now();
  const result = action();
  samples.push({ name, start, duration: performance.now() - start });
  return result;
}
let root: Root | undefined;
let current: Awaited<ReturnType<typeof workload>>;
let prepared: Awaited<ReturnType<typeof workload>>["expected"] & {
  sha256: string;
  inputBytes: number;
  preparationMs: number;
  scenario: Scenario;
  size: Size;
  partial: boolean;
};
let graph: Graph;
let start = 0;
let actionStart = 0;
let downloadAt = 0;
const originalAnchorClick = HTMLAnchorElement.prototype.click;
HTMLAnchorElement.prototype.click = function () {
  if (this.download && this.href.startsWith("blob:"))
    downloadAt = performance.now();
  return originalAnchorClick.call(this);
};

/** Wait for font metrics, ResizeObserver fitting and React effects to settle. */
async function settle(requireMap = true) {
  await document.fonts.ready;
  let previous = "";
  let same = 0;
  const deadline = performance.now() + 15000;
  while (performance.now() < deadline) {
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
    const app = document.querySelector<HTMLElement>(".adm");
    const svg = app?.querySelector<SVGSVGElement>("svg.map-svg");
    const content =
      svg?.querySelector<SVGGraphicsElement>("[data-export-root]");
    const bounds = svg?.getBoundingClientRect();
    const b = content?.getBBox();
    const targets = svg?.querySelectorAll("[data-hit]").length ?? 0;
    const valid =
      !!app &&
      document.fonts.status === "loaded" &&
      app.dataset.loaded === "true" &&
      (!requireMap ||
        !!(
          bounds &&
          bounds.width > 0 &&
          bounds.height > 0 &&
          b &&
          b.width > 0 &&
          b.height > 0 &&
          [b.x, b.y, b.width, b.height].every(Number.isFinite) &&
          targets > 0 &&
          content?.getAttribute("transform") &&
          !content.getAttribute("transform")?.match(/NaN|Infinity/)
        ));
    const signature = JSON.stringify([
      app?.dataset.nodeCount,
      app?.dataset.edgeCount,
      bounds?.width,
      bounds?.height,
      content?.getAttribute("transform"),
      svg?.dataset.exportWidth,
      svg?.dataset.exportHeight,
      targets,
      app?.querySelectorAll(".match,.selected").length,
      app?.querySelector(".atlas-filter-status")?.textContent,
      app?.querySelectorAll(".table-view tr").length,
      app?.querySelectorAll(".devices-view li, .devices-view tr").length,
      app?.querySelector(".attachment-references")?.textContent,
      app?.querySelector('[aria-label="Details"]')?.textContent,
    ]);
    same = valid && signature === previous ? same + 1 : 0;
    previous = signature;
    if (same >= 3) return performance.now();
  }
  throw new Error("Map did not reach deterministic usable readiness");
}
const read = () => {
  flushTasks();
  return {
    samples: [...samples],
    longTasksSupported,
    longTasks: [...tasks],
    renders: [...renders],
  };
};
const api = {
  readyAt: performance.now(),
  startup() {
    const navigation = performance.getEntriesByType("navigation")[0] as
      PerformanceNavigationTiming | undefined;
    return {
      harnessReadyMsSinceNavigation: api.readyAt,
      navigation: navigation
        ? {
            responseEnd: navigation.responseEnd,
            domContentLoadedEventEnd: navigation.domContentLoadedEventEnd,
            loadEventEnd: navigation.loadEventEnd,
            transferSize: navigation.transferSize,
          }
        : undefined,
      resources: (
        performance.getEntriesByType("resource") as PerformanceResourceTiming[]
      ).map((resource) => ({
        path: new URL(resource.name).pathname,
        type: resource.initiatorType,
        start: resource.startTime,
        duration: resource.duration,
        responseEnd: resource.responseEnd,
        transferSize: resource.transferSize,
        encodedBodySize: resource.encodedBodySize,
        decodedBodySize: resource.decodedBodySize,
      })),
    };
  },
  async prepare(scenario: Scenario, size: Size, partial = false) {
    const preparationStart = performance.now();
    root?.unmount();
    current = await workload(scenario, size, partial);
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        args: current.args,
        rows: current.rows,
        topology: current.topoRows,
      }),
    );
    const sha256 = [
      ...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    ]
      .map((n) => n.toString(16).padStart(2, "0"))
      .join("");
    prepared = {
      ...current.expected,
      sha256,
      inputBytes: bytes.length,
      preparationMs: performance.now() - preparationStart,
      scenario,
      size,
      partial,
    };
    return prepared;
  },
  async mount() {
    if (!prepared) throw new Error("Prepare a workload before mounting");
    samples.length = 0;
    tasks.length = 0;
    renders.length = 0;
    root = createRoot(document.getElementById("adm-root")!);
    const initialState = parseUrlState(
      new URLSearchParams({ scenario: prepared.scenario, tab: "network" }),
    );
    start = performance.now();
    root.render(
      <Profiler
        id="atlas"
        onRender={(_id, phase, duration, _base, renderStart, commit) =>
          renders.push({ phase, duration, start: renderStart, commit })
        }
      >
        <ThemeProvider family="enterprise" colorScheme="light">
          <MapPage
            initialState={initialState}
            theme="light"
            demoData={{
              graph: () =>
                measure(
                  "rowsToGraph.integrated",
                  () =>
                    (graph = rowsToGraph(current.rows, current.args, {
                      demo: true,
                    })),
                ),
              topology: () =>
                measure("rowsToTopology.integrated", () =>
                  rowsToTopology(current.topoRows),
                ),
            }}
          />
        </ThemeProvider>
      </Profiler>,
    );
    const usableAt = await settle();
    return {
      ...prepared,
      start,
      usableAt,
      mountToUsableMs: usableAt - start,
      ...read(),
      longTasks: tasks.filter(
        (task) => task.start < usableAt && task.start + task.duration > start,
      ),
      displayed: {
        cards: document.querySelectorAll(".map-svg .item[data-hit]").length,
        edges: document.querySelectorAll(".map-svg .edge[data-hit]").length,
        collapsed: document.querySelectorAll('[aria-expanded="false"].item')
          .length,
      },
    };
  },
  startAction(name: string) {
    const now = performance.now();
    performance.mark(`action:${name}`);
    return now;
  },
  armAction(event: "click" | "input" | "change" | "keydown") {
    actionStart = 0;
    downloadAt = 0;
    document.addEventListener(
      event,
      () => {
        actionStart = performance.now();
      },
      { capture: true, once: true },
    );
  },
  async endAction(requireMap = true) {
    if (!actionStart)
      throw new Error("Expected user input event was not observed");
    return api.finishAction(actionStart, requireMap);
  },
  downloadTiming() {
    if (!actionStart || !downloadAt)
      throw new Error("Expected export dispatch was not observed");
    return {
      start: actionStart,
      dispatch: downloadAt,
      generationMs: downloadAt - actionStart,
    };
  },
  selectionCase() {
    const conversations = graph.edges.filter(
      (edge) => edge.relationship === "communicates_with",
    );
    const selected =
      conversations.find(
        (edge) =>
          edge.client_handoff_coverage ===
          (current.partial ? "partial" : "unresolved"),
      ) ??
      conversations.find((edge) => edge.confidence === "unresolved") ??
      conversations[0];
    return {
      index: conversations.indexOf(selected),
      id: selected.id,
      coverage: selected.client_handoff_coverage,
    };
  },
  async finishAction(actionStart: number, requireMap = true) {
    const end = await settle(requireMap);
    flushTasks();
    return {
      start: actionStart,
      end,
      duration: end - actionStart,
      longTasks: tasks.filter(
        (task) => task.start < end && task.start + task.duration > actionStart,
      ),
      renderDuration: renders
        .filter((render) => render.start >= actionStart && render.commit <= end)
        .reduce((sum, render) => sum + render.duration, 0),
    };
  },
  async expand() {
    const actionStart = performance.now();
    // Use the same public UI action as keyboard users, expanding every summary.
    for (let pass = 0; pass < 20; pass++) {
      const summaries = [
        ...document.querySelectorAll<SVGElement>(
          '.item[aria-expanded="false"]',
        ),
      ];
      if (!summaries.length) break;
      summaries.forEach((summary) =>
        summary.dispatchEvent(new MouseEvent("click", { bubbles: true })),
      );
      await settle();
    }
    return {
      ...(await api.finishAction(actionStart)),
      cards: document.querySelectorAll(".map-svg .item[data-hit]").length,
      remainingSummaries: document.querySelectorAll(
        '.item[aria-expanded="false"]',
      ).length,
    };
  },
  benchmark() {
    const topology = rowsToTopology(current.topoRows);
    const index = indexGraph(graph);
    const topo = indexTopology(topology);
    const pathEdges = graph.edges.filter(
      (edge) => edge.relationship === "communicates_with",
    );
    const operations = {
      rowsToGraph: () =>
        rowsToGraph(current.rows, current.args, { demo: true }),
      rowsToTopology: () => rowsToTopology(current.topoRows),
      indexGraph: () => indexGraph(graph),
      indexTopology: () => indexTopology(topology),
      layoutNetwork: () => computeLayout(graph, index, "network"),
      layoutCollapsed: () =>
        computeLayout(graph, index, "network", { collapse: true }),
      layoutServices: () => computeLayout(graph, index, "services"),
      filterExternal: () => filterGraph(graph, { identity: "external" }),
      paths: () => pathEdges.map((edge) => buildPath(edge, graph, index, topo)),
      deviceSummaries: () => deviceSummaries(graph.edges, topo, index),
    };
    const timings: Record<string, number[]> = {};
    for (const [name, action] of Object.entries(operations)) {
      action();
      timings[name] = [];
      for (let i = 0; i < 5; i++) {
        const begin = performance.now();
        action();
        timings[name].push(performance.now() - begin);
      }
    }
    const layout = computeLayout(graph, index, "network");
    const sound =
      [...layout.items.values()].every((item) =>
        [item.x, item.y, item.w, item.h].every(Number.isFinite),
      ) &&
      layout.edges.every(
        (edge) =>
          edge.points.every((point) => point.every(Number.isFinite)) &&
          edge.members.every((id) => index.edge.has(id)),
      );
    if (!sound)
      throw new Error(
        "Layout contains invalid geometry or missing edge evidence",
      );
    const handoffs = graph.edges
      .filter((edge) => edge.client_handoff_coverage)
      .map((edge) => ({
        id: edge.id,
        coverage: edge.client_handoff_coverage,
        sourceRecordCount: edge.client_handoffs?.length ?? 0,
        resolution: clientHandoffResolution(
          edge,
          index.node.get(edge.target),
          index,
        ),
      }));
    const summaries = deviceSummaries(graph.edges, topo, index);
    const controlledClients = graph.nodes.filter((node) =>
      node.label.startsWith("perf-client-"),
    );
    const qualifiedClientChecks = controlledClients.map((node) => {
      const context = {
        scope: node.attributes?.scope,
        cluster: node.cluster,
        authority: node.attributes?.source_authority,
        families: ["network_client"],
      };
      const native = node.attributes?.native_id;
      return {
        qualified: resolveDevice(native, topo, context)?.id === node.id,
        ambiguousWithoutAuthority:
          resolveDevice(native, topo, { ...context, authority: undefined }) ===
          undefined,
      };
    });
    return {
      timings,
      geometrySound: sound,
      layoutItems: layout.items.size,
      layoutEdges: layout.edges.length,
      handoffs,
      graph,
      evidence: {
        topologyDevices: topology.devices.length,
        topologyLinks: topology.links.length,
        attachments: graph.edges.reduce(
          (n, edge) => n + (edge.attachment_evidence?.length ?? 0),
          0,
        ),
        traffic: graph.edges.reduce(
          (n, edge) => n + (edge.traffic_observations?.length ?? 0),
          0,
        ),
        unresolved: graph.edges.filter(
          (edge) => edge.confidence === "unresolved",
        ).length,
        attachmentReferences: summaries.attachmentReferences.length,
        resolvedAttachmentReferences: summaries.attachmentReferences.filter(
          (reference) => !!reference.device,
        ).length,
        unresolvedAttachmentReferences: summaries.attachmentReferences.filter(
          (reference) => !!reference.unresolvedReason,
        ).length,
        ambiguousClientAliases: [...topo.aliasCandidates.values()].filter(
          (candidates) =>
            candidates.filter((device) => device.kind === "network_client")
              .length > 1,
        ).length,
        ambiguousAccessAliases: [...topo.aliasCandidates.values()].filter(
          (candidates) =>
            candidates.filter(
              (device) =>
                device.kind === "access_point" || device.kind === "switch",
            ).length > 1,
        ).length,
        mismatchedAuthorityReferences: summaries.attachmentReferences.filter(
          (reference) => reference.unresolvedReason?.includes("authority"),
        ).length,
        nonCanonicalAttachmentReferences: summaries.attachmentReferences.filter(
          (reference) =>
            reference.unresolvedReason?.includes("source-qualified device ID"),
        ).length,
        qualifiedClientChecks: qualifiedClientChecks.filter(
          (check) => check.qualified,
        ).length,
        ambiguousClientChecks: qualifiedClientChecks.filter(
          (check) => check.ambiguousWithoutAuthority,
        ).length,
        controlledClientCount: controlledClients.length,
      },
    };
  },
  read,
};
window.__ATLAS_PERF__ = api;
export type PerfApi = typeof api;
declare global {
  interface Window {
    __ATLAS_PERF__: PerfApi;
  }
}
