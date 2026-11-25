import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/splunk-utils/url", () => ({
  createStaticURL: (path: string) => `/${path}`,
}));

import { historyAssetUrl } from "./HistoryLazyInspection";

describe("history optional asset URL verification", () => {
  it("pins both origin/path and cache-busting version", () => {
    expect(
      historyAssetUrl(
        "pages/history.js",
        "asset-v1",
        "https://apic.example/app/splunk_adm/map",
      ),
    ).toBe("https://apic.example/app/splunk_adm/pages/history.js?v=asset-v1");
    expect(
      historyAssetUrl(
        "history.css",
        "asset-v1",
        "https://apic.example/en-US/app/map",
        "/en-US/static/@cache/app/splunk_adm/history.css",
      ),
    ).toBe(
      "https://apic.example/en-US/static/@cache/app/splunk_adm/history.css?v=asset-v1",
    );
  });

  it("rejects a cross-origin or path-confused asset URL", () => {
    expect(() =>
      historyAssetUrl(
        "history.css",
        "asset-v1",
        "https://apic.example/app/splunk_adm/map?next=https://evil.example",
        "https://evil.example/app/splunk_adm/history.css",
      ),
    ).toThrow("origin could not be verified");
    expect(() =>
      historyAssetUrl(
        "history.css",
        "asset-v1",
        "https://evil.example/app/splunk_adm/map",
        "/app/splunk_adm/other.css",
      ),
    ).toThrow("origin could not be verified");
  });
});
