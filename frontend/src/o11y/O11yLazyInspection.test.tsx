import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { indexGraph, type Graph } from "../graph";
import {
  MapServiceHealthLazyInspection,
  loadO11yUi,
} from "./O11yLazyInspection";

vi.mock("@splunk/splunk-utils/url", () => ({
  createStaticURL: (path: string) => `/${path}`,
}));

type Element = {
  tag: string;
  src?: string;
  href?: string;
  rel?: string;
  onload?: (() => void) | null;
  onerror?: (() => void) | null;
  remove: () => void;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasO11y?: unknown;
  __AtlasO11yHost?: Record<string, Record<string, unknown>>;
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

const rootId = "service:checkout-api";
const graph: Graph = {
  schema_version: 1,
  snapshot_id: "o11y-lazy-test",
  generated_at: "2026-10-23T12:00:00Z",
  demo: false,
  window: { start: "1792763000", end: "1792763990" },
  boundary: {
    id: "boundary-checkout",
    service: "checkout-api",
    environment: "production",
    cluster: "eks-prod-east",
    namespace: "commerce",
    root_node_id: rootId,
  },
  nodes: [
    {
      id: rootId,
      label: "checkout-api",
      kind: "service",
      namespace: "commerce",
      cluster: "eks-prod-east",
    },
    {
      id: "pod:checkout/api",
      label: "checkout-pod",
      kind: "workload",
    },
  ],
  edges: [],
  coverage: {
    spans: 0,
    conversations: 0,
    matched_conversations: 0,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
};
const index = indexGraph(graph);
const client = {
  search: async () => ({ rows: [], warnings: [], errors: [] }),
};

function stubPage() {
  const appended: Element[] = [];
  vi.stubGlobal("__ADM_O11Y_ASSET_VERSION__", "c".repeat(24));
  vi.stubGlobal("location", {
    href: "https://search.example/en-US/app/splunk_adm/map",
    origin: "https://search.example",
  });
  vi.stubGlobal("document", {
    createElement: (tag: string): Element => ({ tag, remove: vi.fn() }),
    head: { append: (...elements: Element[]) => appended.push(...elements) },
  });
  (globalThis as Runtime).__ADM_FORCE_SPLUNK_BUILD__ = true;
  return appended;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
  delete (globalThis as Runtime).ApplicationAtlasO11y;
  delete (globalThis as Runtime).__ADM_FORCE_SPLUNK_BUILD__;
});

describe("MapServiceHealthLazyInspection", () => {
  it("renders nothing when selection is unsupported or not live", () => {
    expect(
      renderToStaticMarkup(
        <MapServiceHealthLazyInspection
          graph={graph}
          index={index}
          selection={{ kind: "node", id: "pod:checkout/api" }}
          client={client}
          live
        />,
      ),
    ).toBe("");
    expect(
      renderToStaticMarkup(
        <MapServiceHealthLazyInspection
          graph={graph}
          index={index}
          selection={{ kind: "node", id: rootId }}
          client={client}
          live={false}
        />,
      ),
    ).toBe("");
  });

  it("announces loading for a supported root service selection", () => {
    const html = renderToStaticMarkup(
      <MapServiceHealthLazyInspection
        graph={graph}
        index={index}
        selection={{ kind: "node", id: rootId }}
        client={client}
        live
      />,
    );
    expect(html).toContain("Loading service health evidence…");
  });

  it("imports the O11y entry directly outside the Splunk build", async () => {
    const [ui, entry] = await Promise.all([
      loadO11yUi(),
      import("../MapServiceHealthInspection"),
    ]);
    expect(ui.MapServiceHealthInspection).toBe(
      entry.MapServiceHealthInspection,
    );
  });

  it("registers frozen host modules and pins versioned same-origin assets in Splunk mode", async () => {
    const appended = stubPage();
    const { loadO11yUi: loadSplunkO11y } = await import("./O11yLazyInspection");
    const loading = loadSplunkO11y();
    const host = (globalThis as Runtime).__AtlasO11yHost!;
    expect(Object.isFrozen(host)).toBe(true);
    expect(Object.keys(host).sort()).toEqual([
      "assetVersion",
      "deploymentHealth",
      "evidence",
      "evidenceConfig",
      "jsxRuntime",
      "optionalJobs",
      "react",
      "searchClient",
      "supplementalEvidence",
    ]);
    const [style, script] = appended;
    expect(script.src).toBe(
      `https://search.example/app/splunk_adm/pages/o11y.js?v=${"c".repeat(24)}`,
    );
    expect(style.href).toBe(
      `https://search.example/app/splunk_adm/o11y.css?v=${"c".repeat(24)}`,
    );
    const ui = {
      assetVersion: "c".repeat(24),
      MapServiceHealthInspection: () => null,
    };
    (globalThis as Runtime).ApplicationAtlasO11y = ui;
    script.onload?.();
    style.onload?.();
    await expect(loading).resolves.toBe(ui);
    expect(loadSplunkO11y()).toBe(loading);
  });

  it("rejects an asset from another app version and allows a retry", async () => {
    const appended = stubPage();
    const { loadO11yUi: loadSplunkO11y } = await import("./O11yLazyInspection");
    const loading = loadSplunkO11y();
    (globalThis as Runtime).ApplicationAtlasO11y = {
      assetVersion: "d".repeat(24),
      MapServiceHealthInspection: () => null,
    };
    appended[1].onload?.();
    appended[0].onload?.();
    await expect(loading).rejects.toThrow("asset unavailable");
    expect(appended[1].remove).toHaveBeenCalled();
    const retry = loadSplunkO11y();
    expect(retry).not.toBe(loading);
    expect(appended).toHaveLength(4);
    appended[3].onerror?.();
    await expect(retry).rejects.toThrow("asset unavailable");
  });
});
