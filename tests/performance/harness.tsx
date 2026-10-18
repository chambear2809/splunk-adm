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
import { capturedAction, committedFrames } from "./readiness";

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
function readinessFrame(requireMap: boolean) {
  const app = document.querySelector<HTMLElement>(".adm");
  const svg = app?.querySelector<SVGSVGElement>("svg.map-svg");
  const content = svg?.querySelector<SVGGraphicsElement>("[data-export-root]");
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
  return { valid, signature };
}
async function settle(requireMap = true) {
  await document.fonts.ready;
  let previous = "";
  let same = 0;
  const deadline = performance.now() + 15000;
  while (performance.now() < deadline) {
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
    const { valid, signature } = readinessFrame(requireMap);
    same = valid && signature === previous ? same + 1 : 0;
    previous = signature;
    if (same >= 3) return performance.now();
  }
  throw new Error("Map did not reach deterministic usable readiness");
}
function nextFrame(signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    signal.throwIfAborted();
    const abort = () => {
      cancelAnimationFrame(frame);
      reject(signal.reason);
    };
    const frame = requestAnimationFrame(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    });
    signal.addEventListener("abort", abort, { once: true });
  });
}
export type ActionIntent =
  | {
      kind:
        | "highlight"
        | "highlightJump"
        | "selectCard"
        | "clearSelection"
        | "filterExternal"
        | "clearFilter"
        | "table"
        | "devices"
        | "network";
    }
  | { kind: "selectEdge"; index: number; coverage?: string };
function actionExpectation(intent: ActionIntent) {
  const query = <T extends Element = HTMLElement>(selector: string) =>
    document.querySelector<T>(selector);
  const button = (text: string) =>
    [...document.querySelectorAll<HTMLButtonElement>("button")].find(
      (e) =>
        e.textContent?.trim() === text || e.getAttribute("aria-label") === text,
    );
  const details = () => query('[aria-label="Details"]');
  const highlight = () =>
    query<HTMLInputElement>(
      '[aria-label="Highlight by name, IP, EPG, port or device"]',
    );
  const filter = () =>
    query<HTMLSelectElement>('[aria-label="Filter identity"]');
  const status = () => query(".atlas-filter-status");
  let target: Element | null | undefined;
  let precondition: () => boolean;
  let committed: () => boolean;
  let requireMap = true;
  switch (intent.kind) {
    case "highlight":
      target = highlight();
      precondition = () =>
        !!highlight() &&
        highlight()!.value !== "checkout" &&
        !query(".match-count");
      committed = () =>
        highlight()?.value === "checkout" &&
        !!query(".match-count") &&
        !!query(".item[data-hit].match");
      break;
    case "highlightJump":
      target = highlight();
      precondition = () =>
        !!query(".item[data-hit].match") &&
        !/^1 of /.test(query(".match-count")?.textContent ?? "");
      committed = () => /^1 of /.test(query(".match-count")?.textContent ?? "");
      break;
    case "selectCard": {
      target = query(".item[data-hit].match");
      const label = target?.getAttribute("aria-label");
      const selected = () =>
        [...document.querySelectorAll(".item[data-hit].selected")].find(
          (e) =>
            e.getAttribute("aria-label") === label &&
            e.getAttribute("aria-pressed") === "true",
        );
      precondition = () =>
        !!target &&
        target.getAttribute("aria-pressed") === "false" &&
        !button("Clear selection");
      committed = () =>
        !!selected() &&
        !!button("Clear selection") &&
        !!details()?.textContent?.trim();
      break;
    }
    case "clearSelection":
      target = button("Clear selection");
      precondition = () =>
        !!button("Clear selection") &&
        !!query(".item.selected, .table-view tr.selected");
      committed = () =>
        !button("Clear selection") &&
        !query(".item.selected, .table-view tr.selected");
      break;
    case "filterExternal":
      target = filter();
      precondition = () =>
        !!filter() && filter()!.value !== "external" && !status();
      committed = () =>
        filter()?.value === "external" && !!status()?.textContent?.trim();
      break;
    case "clearFilter":
      target = filter();
      precondition = () => filter()?.value === "external" && !!status();
      committed = () => filter()?.value === "" && !status();
      break;
    case "selectEdge": {
      requireMap = false;
      const row = () =>
        document.querySelectorAll(".table-view tbody tr")[intent.index];
      target = row()?.querySelector("button");
      precondition = () =>
        !!target &&
        !row()?.classList.contains("selected") &&
        !button("Clear selection");
      committed = () =>
        !!row()?.classList.contains("selected") &&
        !!button("Clear selection") &&
        !!details()?.textContent?.trim() &&
        (!(intent.coverage === "partial" || intent.coverage === "unresolved") ||
          !!details()?.textContent?.includes(
            `Client handoff coverage is ${intent.coverage}`,
          ));
      break;
    }
    default: {
      const tab =
        intent.kind === "table"
          ? "Table"
          : intent.kind === "devices"
            ? "Devices"
            : "Network";
      target = button(tab);
      requireMap = intent.kind === "network";
      const content =
        intent.kind === "table"
          ? ".table-view tbody tr"
          : intent.kind === "devices"
            ? ".devices-view"
            : ".map-svg [data-hit]";
      precondition = () =>
        !!target &&
        target.getAttribute("aria-pressed") === "false" &&
        !query(content);
      committed = () =>
        button(tab)?.getAttribute("aria-pressed") === "true" &&
        !!query(content);
    }
  }
  return { target, precondition, committed, requireMap };
}
let pendingAction: ReturnType<typeof capturedAction> | undefined;
let removeActionListener: (() => void) | undefined;
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
  armExport(event: "click" | "input" | "change" | "keydown") {
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
  armAction(
    event: "click" | "input" | "change" | "keydown",
    intent: ActionIntent,
  ) {
    if (pendingAction) throw new Error("Previous action was not consumed");
    const expected = actionExpectation(intent);
    const counts = () => {
      const app = document.querySelector<HTMLElement>(".adm");
      return (
        app?.dataset.nodeCount === String(prepared.nodes) &&
        app?.dataset.edgeCount === String(prepared.edges)
      );
    };
    pendingAction = capturedAction({
      name: intent.kind,
      precondition: expected.precondition,
      now: () => performance.now(),
      settle: async (signal) => {
        await document.fonts.ready;
        return committedFrames({
          signal,
          now: () => performance.now(),
          nextFrame,
          read: () => readinessFrame(expected.requireMap),
          committed: () => counts() && expected.committed(),
        });
      },
    });
    const listener = (input: Event) => {
      if (
        !(input.target instanceof Node) ||
        !expected.target?.contains(input.target) ||
        (intent.kind === "highlightJump" &&
          (input as KeyboardEvent).key !== "Enter")
      ) {
        pendingAction?.triggerFailed(
          new Error(`Unexpected action event target: ${intent.kind}`),
        );
        return;
      }
      pendingAction?.capture();
    };
    document.addEventListener(event, listener, { capture: true, once: true });
    removeActionListener = () =>
      document.removeEventListener(event, listener, true);
  },
  actionTriggerCompleted() {
    if (!pendingAction) throw new Error("No armed action");
    pendingAction.triggerCompleted();
  },
  actionTriggerFailed(message: string) {
    pendingAction?.triggerFailed(new Error(message));
    removeActionListener?.();
    removeActionListener = undefined;
    pendingAction = undefined;
  },
  async endAction() {
    if (!pendingAction) throw new Error("No armed action");
    try {
      const timing = await pendingAction.result();
      flushTasks();
      return {
        ...timing,
        longTasks: tasks.filter(
          (task) =>
            task.start < timing.end &&
            task.start + task.duration > timing.start,
        ),
        renderDuration: renders
          .filter(
            (render) =>
              render.start >= timing.start && render.commit <= timing.end,
          )
          .reduce((sum, render) => sum + render.duration, 0),
      };
    } finally {
      removeActionListener?.();
      removeActionListener = undefined;
      pendingAction = undefined;
    }
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
