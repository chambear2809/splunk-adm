import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { EndpointEvidencePanels } from "./EndpointEvidencePanels";
import type { EvidenceSelection } from "./data/evidence";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "endpoint-1",
  trafficContract: 2,
  window: { start: 100, end: 200 },
  scope: "prod",
  addresses: ["10.0.0.1"],
  contexts: [],
  identityBasis: "Scoped endpoint investigation",
  configurationFingerprint: "a".repeat(64),
};

describe("scoped endpoint evidence", () => {
  it("keeps every optional source in one investigation and starts no search during render", () => {
    const search = vi.fn();
    const html = renderToStaticMarkup(
      <EndpointEvidencePanels selection={selection} client={{ search }} />,
    );
    expect(html).toContain("Scoped endpoint evidence");
    expect(html).toContain("DNS evidence");
    expect(html).toContain("Proxy evidence");
    expect(html).toContain("AWS VPC Flow Logs");
    expect(html).toContain("Asset history");
    expect(search).not.toHaveBeenCalled();
  });
});
