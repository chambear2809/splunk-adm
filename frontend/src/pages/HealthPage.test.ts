import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => `/splunkd/${path}`,
}));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({
    headers: new Headers({ "X-Splunk-Form-Key": "csrf-token" }),
  }),
}));

import {
  hasAdminCapability,
  healthWindow,
  probeAdminCapability,
  shouldCheckModifiedVendorTas,
  shouldProbeAdminCapability,
} from "./HealthPage";

describe("Data health window", () => {
  const now = 1793833200; // 2026-11-04 23:00 UTC
  it("defaults to the current seven-day check", () => {
    expect(healthWindow("", now)).toEqual({ earliest: "-7d", latest: "now" });
  });
  it("evaluates an absolute past window at its end", () => {
    expect(
      healthWindow("?earliest=1793772000&latest=1793800800", now, "UTC"),
    ).toEqual({
      earliest: "1793772000",
      latest: "1793800800",
      asOf: 1793800800,
    });
  });
  it("resolves a relative end", () => {
    expect(healthWindow("?earliest=-1d&latest=-9h", now, "UTC").asOf).toBe(
      now - 9 * 3600,
    );
  });
  it("rejects unsafe or reversed bounds", () => {
    expect(healthWindow("?earliest=now&latest=-1d", now)).toEqual({
      earliest: "-7d",
      latest: "now",
    });
    expect(healthWindow("?earliest=x%20OR&latest=now", now).asOf).toBe(
      undefined,
    );
  });
});

describe("Modified vendor TA admin gate", () => {
  it("returns true when current-context grants admin_all_objects", async () => {
    const fetcher = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: ["search", "admin_all_objects"] } }],
      }),
    }));
    await expect(hasAdminCapability(undefined, fetcher)).resolves.toBe(true);
    expect(fetcher).toHaveBeenCalledWith(
      "/splunkd/authentication/current-context?output_mode=json",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("returns false for non-admin viewer roles, HTTP errors, malformed payloads, or network errors", async () => {
    const viewer = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: ["search"] } }],
      }),
    }));
    await expect(hasAdminCapability(undefined, viewer)).resolves.toBe(false);

    const denied = vi.fn(async () => ({
      ok: false,
      json: async () => ({}),
    }));
    await expect(hasAdminCapability(undefined, denied)).resolves.toBe(false);

    const malformed = vi.fn(async () => ({
      ok: true,
      json: async () => ({ entry: [{ content: { capabilities: [123] } }] }),
    }));
    await expect(hasAdminCapability(undefined, malformed)).resolves.toBe(false);

    const failed = vi.fn(async () => {
      throw new Error("offline");
    });
    await expect(hasAdminCapability(undefined, failed)).resolves.toBe(false);
  });

  it("gates modified vendor TA checks on live configured deployments and admin access", () => {
    expect(
      shouldCheckModifiedVendorTas(
        false,
        { state: "configured", canWrite: true },
        true,
      ),
    ).toBe(false);
    expect(
      shouldCheckModifiedVendorTas(
        true,
        { state: "absent", canWrite: true },
        true,
      ),
    ).toBe(false);
    expect(
      shouldCheckModifiedVendorTas(
        true,
        { state: "configured", canWrite: true },
        false,
      ),
    ).toBe(true);
    expect(
      shouldCheckModifiedVendorTas(
        true,
        { state: "configured", canWrite: false },
        true,
      ),
    ).toBe(true);
    expect(
      shouldCheckModifiedVendorTas(
        true,
        { state: "configured", canWrite: false },
        false,
      ),
    ).toBe(false);
  });

  it("probes admin capability as tri-state admin, non-admin, or error", async () => {
    const admin = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: ["search", "admin_all_objects"] } }],
      }),
    }));
    await expect(probeAdminCapability(undefined, admin)).resolves.toBe("admin");

    const nonAdmin = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: ["search", "list_inputs"] } }],
      }),
    }));
    await expect(probeAdminCapability(undefined, nonAdmin)).resolves.toBe(
      "non-admin",
    );

    const httpError = vi.fn(async () => ({
      ok: false,
      json: async () => ({
        entry: [{ content: { capabilities: ["admin_all_objects"] } }],
      }),
    }));
    await expect(probeAdminCapability(undefined, httpError)).resolves.toBe(
      "error",
    );

    const emptyEntries = vi.fn(async () => ({
      ok: true,
      json: async () => ({ entry: [] }),
    }));
    await expect(probeAdminCapability(undefined, emptyEntries)).resolves.toBe(
      "error",
    );

    const multipleEntries = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [
          { content: { capabilities: ["admin_all_objects"] } },
          { content: { capabilities: ["search"] } },
        ],
      }),
    }));
    await expect(
      probeAdminCapability(undefined, multipleEntries),
    ).resolves.toBe("error");

    const nonStringCapabilities = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: ["admin_all_objects", 42] } }],
      }),
    }));
    await expect(
      probeAdminCapability(undefined, nonStringCapabilities),
    ).resolves.toBe("error");

    const nonArrayCapabilities = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        entry: [{ content: { capabilities: "admin_all_objects" } }],
      }),
    }));
    await expect(
      probeAdminCapability(undefined, nonArrayCapabilities),
    ).resolves.toBe("error");

    const networkError = vi.fn(async () => {
      throw new Error("network down");
    });
    await expect(probeAdminCapability(undefined, networkError)).resolves.toBe(
      "error",
    );
  });

  it("retries admin capability probe on idle or error and caches confirmed outcomes", () => {
    expect(shouldProbeAdminCapability(true, false, "idle")).toBe(true);
    expect(shouldProbeAdminCapability(true, false, "error")).toBe(true);

    expect(shouldProbeAdminCapability(true, false, "admin")).toBe(false);
    expect(shouldProbeAdminCapability(true, false, "non-admin")).toBe(false);

    expect(shouldProbeAdminCapability(false, false, "idle")).toBe(false);
    expect(shouldProbeAdminCapability(false, false, "error")).toBe(false);
    expect(shouldProbeAdminCapability(true, true, "idle")).toBe(false);
    expect(shouldProbeAdminCapability(true, true, "error")).toBe(false);
  });
});
