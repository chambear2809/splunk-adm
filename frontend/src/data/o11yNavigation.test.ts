import { describe, expect, it } from "vitest";
import {
  buildO11yNavigation,
  configuredHttpsOrigin,
  observabilityRealmOrigin,
} from "./o11yNavigation";
import type { ServiceHealthSelection } from "./evidence";

const selection: ServiceHealthSelection = {
  schemaVersion: 1,
  workflow: "service",
  selectionId: "snapshot:service-a",
  scope: "prod-east",
  window: { start: 1790000000, end: 1790000900 },
  service: {
    name: "checkout-api",
    environment: "production",
    cluster: "eks-prod-east",
    namespace: "commerce",
    serviceNamespace: "payments",
  },
  workloads: [{ podUid: "pod-uid-001", validFrom: 1789990000 }],
  identityBasis: "Exact graph-boundary service identity",
  configurationFingerprint: "a".repeat(64),
};

describe("Observability Cloud navigation context", () => {
  it("uses a documented realm origin and product-home links without filter claims", () => {
    const model = buildO11yNavigation({
      selection,
      realm: "us1",
      organizationId: "org-123",
      detectorIds: ["detector-abc"],
      incidentIds: ["incident-xyz"],
    });

    expect(model.origin).toBe("https://app.us1.observability.splunkcloud.com");
    expect(model.actions.map((action) => action.product)).toEqual([
      "apm",
      "infrastructure",
      "logs",
      "detectors",
      "alert_lifecycle",
      "incidents",
    ]);
    expect(
      model.actions.every((action) => action.href === `${model.origin}/`),
    ).toBe(true);
    expect(model.actions.map((action) => action.href).join(" ")).not.toContain(
      "checkout-api",
    );
    expect(model.actions.map((action) => action.href).join(" ")).not.toContain(
      "1790000000",
    );
    expect(
      model.actions.find((action) => action.product === "apm")?.searchHint,
    ).toBe("service: checkout-api");
  });

  it("uses only an explicit validated HTTPS origin when configured", () => {
    const model = buildO11yNavigation({
      selection,
      realm: "us1",
      organizationId: "org-123",
      configuredOrigin: "https://customer.observability.splunkcloud.com/",
    });
    expect(model.origin).toBe("https://customer.observability.splunkcloud.com");
    expect(configuredHttpsOrigin("http://customer.example")).toBeUndefined();
    expect(configuredHttpsOrigin("https://user:pass@customer.example")).toBe(
      undefined,
    );
    expect(
      configuredHttpsOrigin("https://customer.example/app"),
    ).toBeUndefined();
    expect(configuredHttpsOrigin("https://customer.example/?next=/map")).toBe(
      undefined,
    );
    expect(configuredHttpsOrigin("https://customer.example/#map")).toBe(
      undefined,
    );
  });

  it("withholds every link for an invalid configured origin instead of guessing", () => {
    const model = buildO11yNavigation({
      selection,
      realm: "us1",
      organizationId: "org-123",
      configuredOrigin: "javascript:alert(1)",
    });
    expect(model.origin).toBeUndefined();
    expect(model.actions.every((action) => action.href === undefined)).toBe(
      true,
    );
  });

  it("keeps identity, time, MMS and native IDs in visible/copy context only", () => {
    const model = buildO11yNavigation({
      selection,
      realm: "us1",
      organizationId: "org-123",
      apmMmsId: "checkout_mms_v1",
      detectorIds: ["detector-abc", "detector-def"],
      incidentIds: ["incident-xyz"],
    });
    expect(model).toMatchObject({
      organizationId: "org-123",
      realm: "us1",
      apmMmsId: "checkout_mms_v1",
      service: selection.service,
      podUids: ["pod-uid-001"],
      startUtc: new Date(1790000000 * 1000).toISOString(),
      endUtc: new Date(1790000900 * 1000).toISOString(),
      detectorIds: ["detector-abc", "detector-def"],
      incidentIds: ["incident-xyz"],
    });
    expect(model.copyText).toContain("Kubernetes namespace: commerce");
    expect(model.copyText).toContain("OTel service namespace: payments");
    expect(model.copyText).toContain("APM MMS ID: checkout_mms_v1");
    expect(model.copyText).toContain("pod-uid-001");
    expect(model.copyText).toContain("detector-abc, detector-def");
    expect(model.copyText).toContain(
      "Detector alert-lifecycle incident IDs: incident-xyz",
    );
    expect(
      model.actions.find((action) => action.product === "detectors")?.ids,
    ).toEqual(["detector-abc", "detector-def"]);
    expect(
      model.actions.find((action) => action.product === "alert_lifecycle")?.ids,
    ).toEqual(["incident-xyz"]);
    expect(
      model.actions.find((action) => action.product === "incidents")?.ids,
    ).toEqual([]);
    expect(
      model.actions.every((action) => !action.href?.includes("detector-abc")),
    ).toBe(true);
  });

  it("rejects malformed realm, MMS identity and native identifier lists", () => {
    expect(observabilityRealmOrigin("../map")).toBeUndefined();
    expect(() =>
      buildO11yNavigation({
        selection,
        realm: "../map",
        organizationId: "org",
      }),
    ).toThrow();
    expect(() =>
      buildO11yNavigation({
        selection,
        realm: "us1",
        organizationId: "org",
        apmMmsId: "bad|mms",
      }),
    ).toThrow();
    expect(() =>
      buildO11yNavigation({
        selection,
        realm: "us1",
        organizationId: "org",
        detectorIds: ["bad\nidentifier"],
      }),
    ).toThrow();
    expect(() =>
      buildO11yNavigation({
        selection,
        realm: "us1",
        organizationId: "org",
        incidentIds: Array.from(
          { length: 65 },
          (_, index) => `incident-${index}`,
        ),
      }),
    ).toThrow();
  });
});
