import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import { O11yDetectorEventsPanel } from "./O11yDetectorEventsPanel";
import type { ServiceHealthSelection } from "./data/evidence";
it("requires an explicit detector inspection and explains service association limits", () => {
  const search = vi.fn();
  const selection: ServiceHealthSelection = {
    schemaVersion: 1,
    workflow: "service",
    selectionId: "checkout",
    scope: "prod-east",
    window: { start: 100, end: 200 },
    service: {
      name: "checkout",
      environment: "prod",
      cluster: "east",
      namespace: "commerce",
    },
    identityBasis: "graph boundary",
    configurationFingerprint: "a".repeat(64),
  };
  const html = renderToStaticMarkup(
    <O11yDetectorEventsPanel selection={selection} client={{ search }} />,
  );
  expect(html).toContain("Inspect detector events");
  expect(html).toContain("does not establish");
  expect(search).not.toHaveBeenCalled();
});
