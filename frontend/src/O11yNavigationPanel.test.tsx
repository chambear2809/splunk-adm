import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { O11yNavigationPanel } from "./O11yNavigationPanel";
import type { ServiceHealthSelection } from "./data/evidence";

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

describe("Observability Cloud navigation panel", () => {
  it("keeps product headings uniquely labelled when health and event navigation coexist", () => {
    const props = { selection, realm: "us1", organizationId: "org-123" };
    const html = renderToStaticMarkup(
      <>
        <O11yNavigationPanel {...props} />
        <O11yNavigationPanel {...props} />
      </>,
    );
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
    const labels = [...html.matchAll(/aria-labelledby="([^"]+)"/g)].map(
      (match) => match[1],
    );
    expect(new Set(ids).size).toBe(ids.length);
    expect(labels.length).toBeGreaterThan(0);
    expect(labels.every((label) => ids.includes(label))).toBe(true);
  });
  it("shows exact service/time/native IDs and manual product destinations", () => {
    const html = renderToStaticMarkup(
      <O11yNavigationPanel
        selection={selection}
        realm="us1"
        organizationId="org-123"
        apmMmsId="checkout_mms_v1"
        detectorIds={["detector-abc"]}
        incidentIds={["incident-xyz"]}
      />,
    );

    expect(html).toContain("Organization");
    expect(html).toContain("org-123");
    expect(html).toContain("checkout-api");
    expect(html).toContain("production");
    expect(html).toContain("eks-prod-east");
    expect(html).toContain("commerce");
    expect(html).toContain("payments");
    expect(html).toContain("checkout_mms_v1");
    expect(html).toContain("pod-uid-001");
    expect(html).toContain(new Date(1790000000 * 1000).toISOString());
    expect(html).toContain("detector-abc");
    expect(html).toContain("incident-xyz");
    for (const product of [
      "APM services",
      "Infrastructure navigators",
      "Logs",
      "Detectors and alerts",
      "Incidents",
    ])
      expect(html).toContain(product);
    expect(html).toContain(
      'href="https://app.us1.observability.splunkcloud.com/"',
    );
    expect(html).toContain("service: checkout-api");
    expect(html).toContain("does not open an ID-specific route");
    expect(html).not.toContain("?service=");
    expect(html).not.toContain("&earliest=");
  });

  it("does not render an anchor for an invalid explicitly configured origin", () => {
    const html = renderToStaticMarkup(
      <O11yNavigationPanel
        selection={selection}
        realm="us1"
        organizationId="org-123"
        configuredOrigin="http://example.invalid"
      />,
    );
    expect(html).not.toContain("<a ");
    expect(html).toContain(
      "Configure a valid HTTPS Observability Cloud origin",
    );
  });
});
