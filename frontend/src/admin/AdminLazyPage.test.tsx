import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminLazyPage, loadAdminUi } from "./AdminLazyPage";

vi.mock("@splunk/splunk-utils/url", () => ({
  createStaticURL: (path: string) => `/${path}`,
  createRESTURL: (path: string) => `/splunkd/${path}`,
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
  ApplicationAtlasAdmin?: unknown;
  __AtlasAdminHost?: Record<string, unknown>;
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

function stubPage() {
  const appended: Element[] = [];
  vi.stubGlobal("__ADM_ADMIN_ASSET_VERSION__", "a".repeat(24));
  vi.stubGlobal("location", {
    href: "https://search.example/en-US/app/splunk_adm/setup",
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
  delete (globalThis as Runtime).ApplicationAtlasAdmin;
  delete (globalThis as Runtime).__ADM_FORCE_SPLUNK_BUILD__;
});

describe("AdminLazyPage", () => {
  it("announces loading before the Admin view is available", () => {
    const setupHtml = renderToStaticMarkup(
      <AdminLazyPage
        tab="setup"
        live={false}
        setupLive={false}
        inSplunk={false}
      />,
    );
    expect(setupHtml).toContain("Loading Setup…");
    const healthHtml = renderToStaticMarkup(
      <AdminLazyPage
        tab="data_health"
        live={false}
        setupLive={false}
        inSplunk={false}
      />,
    );
    expect(healthHtml).toContain("Loading Data health…");
  });

  it("imports the Admin entry directly outside the Splunk build", async () => {
    const [ui, entry] = await Promise.all([
      loadAdminUi(),
      import("./admin-entry"),
    ]);
    expect(ui.AdminView).toBe(entry.AdminView);
  });

  it("registers the frozen host modules and pins versioned same-origin assets in Splunk mode", async () => {
    const appended = stubPage();
    const { loadAdminUi: loadSplunkAdmin } = await import("./AdminLazyPage");
    const loading = loadSplunkAdmin();
    const host = (globalThis as Runtime).__AtlasAdminHost!;
    expect(Object.isFrozen(host)).toBe(true);
    expect(host.assetVersion).toBe("a".repeat(24));
    // Rolldown's CJS default-import interop wraps external default imports in
    // { default: mod }; the host must expose the raw default exports directly.
    expect(host.simpleTable).toBeTypeOf("function");
    expect((host.simpleTable as { Head?: unknown }).Head).toBeTypeOf(
      "function",
    );
    expect(host.splunkButton).toBeDefined();
    expect(host.splunkText).toBeDefined();
    expect(
      (host.observerMappingClient as Record<string, unknown>)
        .observerMappingClient,
    ).toBeDefined();
    const [style, script] = appended;
    expect(script.src).toBe(
      `https://search.example/app/splunk_adm/pages/admin.js?v=${"a".repeat(24)}`,
    );
    expect(style.href).toBe(
      `https://search.example/app/splunk_adm/admin.css?v=${"a".repeat(24)}`,
    );
    const ui = { assetVersion: "a".repeat(24), AdminView: () => null };
    (globalThis as Runtime).ApplicationAtlasAdmin = ui;
    script.onload?.();
    style.onload?.();
    await expect(loading).resolves.toBe(ui);
    expect(loadSplunkAdmin()).toBe(loading);
  });

  it("rejects an asset from another app version and allows a retry", async () => {
    const appended = stubPage();
    const { loadAdminUi: loadSplunkAdmin } = await import("./AdminLazyPage");
    const loading = loadSplunkAdmin();
    (globalThis as Runtime).ApplicationAtlasAdmin = {
      assetVersion: "b".repeat(24),
      AdminView: () => null,
    };
    appended[1].onload?.();
    appended[0].onload?.();
    await expect(loading).rejects.toThrow("asset unavailable");
    expect(appended[1].remove).toHaveBeenCalled();
    const retry = loadSplunkAdmin();
    expect(retry).not.toBe(loading);
    expect(appended).toHaveLength(4);
    appended[3].onerror?.();
    await expect(retry).rejects.toThrow("asset unavailable");
  });
});
