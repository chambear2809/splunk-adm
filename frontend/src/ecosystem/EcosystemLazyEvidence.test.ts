import { afterEach, describe, expect, it, vi } from "vitest";

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
  ApplicationAtlasEcosystem?: unknown;
  __AtlasEcosystemHost?: Record<string, unknown>;
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

function stubPage() {
  const appended: Element[] = [];
  vi.stubGlobal("__ADM_ECOSYSTEM_ASSET_VERSION__", "a".repeat(24));
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
  delete (globalThis as Runtime).ApplicationAtlasEcosystem;
  delete (globalThis as Runtime).__ADM_FORCE_SPLUNK_BUILD__;
});

describe("ecosystem optional asset loader", () => {
  it("registers the host modules the externalized bundle needs and pins versioned same-origin assets", async () => {
    const appended = stubPage();
    const { loadEcosystemUi } = await import("./EcosystemLazyEvidence");
    const loading = loadEcosystemUi();
    const host = (globalThis as Runtime).__AtlasEcosystemHost!;
    expect(Object.isFrozen(host)).toBe(true);
    expect(host.assetVersion).toBe("a".repeat(24));
    expect(Object.keys(host).sort()).toEqual([
      "assetVersion",
      "evidence",
      "evidenceConfig",
      "jsxRuntime",
      "optionalJobs",
      "react",
      "searchClient",
      "supplementalEvidence",
    ]);
    const evidence = host.evidence as Record<string, unknown>;
    for (const name of [
      "EVIDENCE_LIMITS",
      "fingerprint",
      "literal",
      "normalizeIp",
      "routingScope",
      "validateSelection",
    ])
      expect(evidence[name]).toBeDefined();
    expect(
      (host.supplementalEvidence as Record<string, unknown>)
        .loadSupplementalEvidence,
    ).toBeTypeOf("function");
    expect(
      (host.evidenceConfig as Record<string, unknown>).evidenceConfigClient,
    ).toBeDefined();
    const [style, script] = appended;
    expect(script.src).toBe(
      `https://search.example/app/splunk_adm/pages/ecosystem.js?v=${"a".repeat(24)}`,
    );
    expect(style.href).toBe(
      `https://search.example/app/splunk_adm/ecosystem.css?v=${"a".repeat(24)}`,
    );
    const ui = {
      assetVersion: "a".repeat(24),
      EcosystemEvidencePanel: () => null,
      EcosystemReceiptPanel: () => null,
    };
    (globalThis as Runtime).ApplicationAtlasEcosystem = ui;
    script.onload?.();
    style.onload?.();
    await expect(loading).resolves.toBe(ui);
    expect(loadEcosystemUi()).toBe(loading);
  });

  it("rejects an asset from another app version and allows a retry", async () => {
    const appended = stubPage();
    const { loadEcosystemUi } = await import("./EcosystemLazyEvidence");
    const loading = loadEcosystemUi();
    (globalThis as Runtime).ApplicationAtlasEcosystem = {
      assetVersion: "b".repeat(24),
      EcosystemEvidencePanel: () => null,
      EcosystemReceiptPanel: () => null,
    };
    appended[1].onload?.();
    appended[0].onload?.();
    await expect(loading).rejects.toThrow("asset unavailable");
    expect(appended[1].remove).toHaveBeenCalled();
    const retry = loadEcosystemUi();
    expect(retry).not.toBe(loading);
    expect(appended).toHaveLength(4);
    appended[3].onerror?.();
    await expect(retry).rejects.toThrow("asset unavailable");
  });

  it("rejects an existing host from a different app version without appending assets", async () => {
    if (!(globalThis as Runtime).__AtlasEcosystemHost) {
      const initialAppended = stubPage();
      const first = await import("./EcosystemLazyEvidence");
      const initial = first.loadEcosystemUi();
      initialAppended[1].onerror?.();
      await initial.catch(() => undefined);
      vi.resetModules();
    }
    const appended = stubPage();
    vi.stubGlobal("__ADM_ECOSYSTEM_ASSET_VERSION__", "c".repeat(24));
    const { loadEcosystemUi } = await import("./EcosystemLazyEvidence");
    await expect(loadEcosystemUi()).rejects.toThrow("different app version");
    expect(appended).toHaveLength(0);
  });
});
