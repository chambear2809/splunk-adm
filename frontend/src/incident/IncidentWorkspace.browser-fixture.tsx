import { createRoot } from "react-dom/client";
import { demoGraph } from "../provider";
import { IncidentWorkspace } from "./IncidentWorkspace";
import type { AuditBatch, AuditProducer } from "./audit";

const incident = {
  ...demoGraph(),
  window: { start: "2026-01-01T01:00:00Z", end: "2026-01-01T02:00:00Z" },
};
let resolveAudit:
  | ((value: {
      producerId: string;
      applicationId: string;
      batch: AuditBatch;
    }) => void)
  | undefined;
const producer: AuditProducer = {
  load: () =>
    new Promise((resolve) => {
      resolveAudit = resolve;
    }),
};
declare global {
  interface Window {
    finishSyntheticAudit: () => void;
  }
}
window.finishSyntheticAudit = () =>
  resolveAudit?.({
    producerId: "synthetic",
    applicationId: "app",
    batch: {
      coverage: { ...incident.window, gaps: [] },
      events: [],
      bindings: [],
    },
  });
createRoot(document.getElementById("root")!).render(
  <IncidentWorkspace
    incident={incident}
    auditProducer={producer}
    loadWindow={async (window) => ({ ...incident, window, edges: [] })}
  />,
);
