import { describe, expect, it, vi } from "vitest";
import {
  checkInstalledModifiedVendorTas,
  loadModifiedVendorTaReport,
  parseModifiedVendorTaSearchRows,
} from "./vendorTaCheck";
import type { SearchClient } from "./searchClient";

describe("vendorTaCheck", () => {
  it("reports clean when neither custom input stanza exists (404)", async () => {
    const fetcher = vi.fn(async () => ({ ok: false, status: 404 }));
    const report = await checkInstalledModifiedVendorTas(undefined, fetcher);
    expect(report.findings).toEqual([]);
    expect(report.unavailable).toEqual([]);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("flags installed custom modified vendor TA input stanzas (200)", async () => {
    const fetcher = vi.fn(async (url: string) => ({
      ok: url.includes("atlas_aci_snapshot"),
      status: url.includes("atlas_aci_snapshot") ? 200 : 404,
    }));
    const report = await checkInstalledModifiedVendorTas(undefined, fetcher);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({
      app: "cisco_dc_networking_app_for_splunk",
      input: "atlas_aci_snapshot",
      evidence: "installed_input",
    });
    expect(report.findings[0]?.official).toContain("7777");
    expect(report.unavailable).toEqual([]);
  });

  it("reports unavailable honestly on 403/500 or network errors", async () => {
    const fetcher = vi.fn(async (url: string) => {
      if (url.includes("atlas_aci_snapshot")) {
        return { ok: false, status: 403 };
      }
      throw new Error("network down");
    });
    const report = await checkInstalledModifiedVendorTas(undefined, fetcher);
    expect(report.findings).toEqual([]);
    expect(report.unavailable).toHaveLength(2);
    expect(report.unavailable.join(" ")).toContain("HTTP 403");
    expect(report.unavailable.join(" ")).toContain("network down");
  });

  it("parses indexed modified vendor TA probe rows and ignores unrelated rows", () => {
    const findings = parseModifiedVendorTaSearchRows([
      {
        kind: "modified_vendor_ta",
        app: "cisco_dc_networking_app_for_splunk",
        input: "atlas_aci_snapshot",
        official_ta: "Cisco DC Networking 2.0.10 (Splunkbase 7777)",
        sourcetype: "adm:aci_poll:v2",
        source: "atlas:aci_poll",
        records: "14",
      },
      {
        kind: "modified_vendor_ta",
        app: "Splunk_TA_AppDynamics",
        input: "atlas_appdynamics_inventory",
        official_ta: "Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)",
        sourcetype: "appdynamics:inventory",
        source: "atlas_appdynamics_inventory://prod",
        records: "3",
      },
      {
        kind: "other",
        records: "99",
      },
    ]);
    expect(findings).toHaveLength(2);
    expect(findings[0]?.detail).toBe("14 events (adm:aci_poll:v2)");
    expect(findings[1]?.detail).toBe("3 events (appdynamics:inventory)");
  });

  it("combines REST and indexed-event probes in loadModifiedVendorTaReport", async () => {
    const fetcher = vi.fn(async () => ({ ok: false, status: 404 }));
    const client: SearchClient = {
      search: vi.fn(async () => ({
        rows: [
          {
            kind: "modified_vendor_ta",
            app: "Splunk_TA_AppDynamics",
            input: "atlas_appdynamics_inventory",
            official_ta:
              "Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)",
            sourcetype: "appdynamics:inventory",
            records: "2",
          },
        ],
        warnings: [],
        errors: [],
      })),
    };
    const report = await loadModifiedVendorTaReport(client, undefined, fetcher);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.evidence).toBe("indexed_events");
    expect(report.unavailable).toEqual([]);
  });
});
