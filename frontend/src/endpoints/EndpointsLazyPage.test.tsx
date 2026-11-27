import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { indexGraph, type Graph } from "../graph";
import {
  EndpointsLazyPage,
  MapDnsLazyInspection,
  loadEndpointsUi,
} from "./EndpointsLazyPage";

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
  ApplicationAtlasEndpoints?: unknown;
  __AtlasEndpointsHost?: Record<string, Record<string, unknown>>;
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

const graph: Graph = {
  schema_version: 1,
  snapshot_id: "endpoints-lazy-test",
  generated_at: "2026-10-25T12:00:00Z",
  demo: false,
  window: { start: "2026-10-25T11:00:00Z", end: "2026-10-25T12:00:00Z" },
  boundary: {
    id: "b",
    service: "checkout",
    environment: "prod",
    cluster: "prod",
    namespace: "commerce",
    root_node_id: "service:checkout",
  },
  nodes: [
    { id: "service:checkout", label: "checkout", kind: "service" },
    {
      id: "pod:checkout/api",
      label: "checkout-pod",
      kind: "workload",
      addresses: ["192.0.2.10"],
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
  vi.stubGlobal("__ADM_ENDPOINTS_ASSET_VERSION__", "e".repeat(24));
  vi.stubGlobal("location", {
    href: "https://search.example/en-US/app/splunk_adm/endpoints",
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
  delete (globalThis as Runtime).ApplicationAtlasEndpoints;
  delete (globalThis as Runtime).__ADM_FORCE_SPLUNK_BUILD__;
});

describe("EndpointsLazyPage and MapDnsLazyInspection", () => {
  it("announces loading before the Endpoints view is available", () => {
    const html = renderToStaticMarkup(<EndpointsLazyPage live={false} />);
    expect(html).toContain("Loading endpoint investigation…");
  });

  it("renders MapDnsLazyInspection only for supported live selections", () => {
    expect(
      renderToStaticMarkup(
        <MapDnsLazyInspection
          graph={graph}
          index={index}
          selection={{ kind: "node", id: "service:checkout" }}
          client={client}
          live
        />,
      ),
    ).toBe("");
    expect(
      renderToStaticMarkup(
        <MapDnsLazyInspection
          graph={graph}
          index={index}
          selection={{ kind: "node", id: "pod:checkout/api" }}
          client={client}
          live={false}
        />,
      ),
    ).toBe("");
    expect(
      renderToStaticMarkup(
        <MapDnsLazyInspection
          graph={graph}
          index={index}
          selection={{ kind: "node", id: "pod:checkout/api" }}
          client={client}
          live
        />,
      ),
    ).toContain("Loading optional DNS investigation…");
  });

  it("imports the Endpoints entry directly outside the Splunk build", async () => {
    const [ui, entry] = await Promise.all([
      loadEndpointsUi(),
      import("./endpoints-entry"),
    ]);
    expect(ui.EndpointsView).toBe(entry.EndpointsView);
    expect(ui.MapDnsInspection).toBe(entry.MapDnsInspection);
  });

  it("registers frozen host modules and pins versioned same-origin assets in Splunk mode", async () => {
    const appended = stubPage();
    const { loadEndpointsUi: loadSplunkEndpoints } =
      await import("./EndpointsLazyPage");
    const loading = loadSplunkEndpoints();
    const host = (globalThis as Runtime).__AtlasEndpointsHost!;
    expect(Object.isFrozen(host)).toBe(true);
    expect(host.assetVersion).toBe("e".repeat(24));
    expect(host.thousandEyes.ThousandEyesLazyInspection).toBeTypeOf("function");
    expect(host.ecosystem.LazyEcosystemEvidencePanel).toBeTypeOf("function");
    expect(host.history.LazyChangeTimelineInspection).toBeTypeOf("function");
    const [style, script] = appended;
    expect(script.src).toBe(
      `https://search.example/app/splunk_adm/pages/endpoints.js?v=${"e".repeat(24)}`,
    );
    expect(style.href).toBe(
      `https://search.example/app/splunk_adm/endpoints.css?v=${"e".repeat(24)}`,
    );
    const ui = {
      assetVersion: "e".repeat(24),
      EndpointsView: () => null,
      MapDnsInspection: () => null,
    };
    (globalThis as Runtime).ApplicationAtlasEndpoints = ui;
    script.onload?.();
    style.onload?.();
    await expect(loading).resolves.toBe(ui);
    expect(loadSplunkEndpoints()).toBe(loading);
  });

  it("rejects an asset from another app version and allows a retry", async () => {
    const appended = stubPage();
    const { loadEndpointsUi: loadSplunkEndpoints } =
      await import("./EndpointsLazyPage");
    const loading = loadSplunkEndpoints();
    (globalThis as Runtime).ApplicationAtlasEndpoints = {
      assetVersion: "f".repeat(24),
      EndpointsView: () => null,
      MapDnsInspection: () => null,
    };
    appended[1].onload?.();
    appended[0].onload?.();
    await expect(loading).rejects.toThrow("asset unavailable");
    expect(appended[1].remove).toHaveBeenCalled();
    const retry = loadSplunkEndpoints();
    expect(retry).not.toBe(loading);
    expect(appended).toHaveLength(4);
    appended[3].onerror?.();
    await expect(retry).rejects.toThrow("asset unavailable");
  });
});
