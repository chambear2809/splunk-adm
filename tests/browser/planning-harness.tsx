import { useState } from "react";
import { createRoot } from "react-dom/client";
import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { ImpactMaintenancePlanner } from "../../frontend/src/maintenance/ImpactMaintenancePlanner";
import type { ImpactData } from "../../frontend/src/impact/data";
import type { FailsResult } from "../../frontend/src/impact/model";
import { MaintenancePlanner } from "../../frontend/src/maintenance/MaintenancePlanner";
import type {
  AssessmentInput,
  Evidence,
} from "../../frontend/src/maintenance/model";
import { DependencyMonitor } from "../../frontend/src/drift/DependencyMonitor";
import {
  BaselineWriteError,
  type BaselineMetadata,
  type BaselineRecord,
  type BaselineRepository,
  type DependencySource,
} from "../../frontend/src/drift/client";
import type { Capture, WatchDefinition } from "../../frontend/src/drift/model";
import "../../frontend/src/styles.css";

const base = 1791373400;
const params = new URLSearchParams(location.search);
const mode = params.get("mode");
const theme = params.get("theme") === "dark" ? "dark" : "light";
let allowed = true,
  readCount = 0,
  lost = false;
const references = new Map<string, Capture>();
const baselineCapture = (start: number, changed = false): Capture => ({
  id: `synthetic-${start}`,
  coverage: {
    requested: { start, end: start + 300 },
    returned: { start, end: start + 300 },
    authority: "synthetic-collector",
    scope: "synthetic-scope",
    sourceRevision: "v1",
    configRevision: "c1",
    normalizationRevision: "n1",
    signatureVersion: 1,
    permission: "allowed",
    complete: mode !== "incomplete",
    capped: false,
    progressive: mode === "incomplete",
    sampled: false,
    stale: false,
    knowledgeHorizon: start + 360,
    requiredLatenessSeconds: 60,
  },
  dependencies: (changed ? [443, 8443] : [443]).map((port) => ({
    authority: "synthetic-collector",
    scope: "synthetic-scope",
    source: "service:checkout",
    destination: "service:orders",
    protocol: "tcp",
    port,
    relation: "calls",
    direction: "forward",
    blocked: false,
  })),
});
const source: DependencySource = {
  async capture(window, signal) {
    readCount++;
    if (!allowed || (mode === "denied" && readCount > 1))
      throw new Error("Source access denied.");
    if (signal.aborted) throw new Error("Cancelled");
    const capture = baselineCapture(window.start, true),
      reference = `reference-${window.start}`;
    references.set(reference, capture);
    return { reference, capture };
  },
};
const records = new Map<string, BaselineRecord>([
  [
    "initial",
    {
      id: "initial",
      name: "Saved service dependencies",
      revision: 1,
      version: 1,
      capture: baselineCapture(base - 300),
    },
  ],
]);
const watches = new Map<string, WatchDefinition[]>();
const receipts = new Map<string, BaselineMetadata>();
const repository: BaselineRepository = {
  async list() {
    if (!allowed) throw new Error("Baseline access denied.");
    return {
      items: [...records.values()].map(({ id, name, revision, version }) => ({
        id,
        name,
        revision,
        version,
      })),
      next: null,
    };
  },
  async get(id) {
    if (!allowed) throw new Error("Baseline access denied.");
    return structuredClone(records.get(id)!);
  },
  async create(name, reference, requestId) {
    if (!allowed)
      throw new BaselineWriteError("Baseline access denied.", false);
    if (receipts.has(requestId)) return receipts.get(requestId)!;
    const record = {
      id: `saved-${records.size}`,
      name,
      revision: 1,
      version: 1,
      capture: structuredClone(references.get(reference)!),
    };
    records.set(record.id, record);
    receipts.set(requestId, record);
    if (mode === "lost" && !lost) {
      lost = true;
      throw new BaselineWriteError("The result is unknown.", true);
    }
    return record;
  },
  async version(id, expected, reference, requestId) {
    if (receipts.has(requestId)) return receipts.get(requestId)!;
    const record = records.get(id)!;
    if (record.revision !== expected)
      throw new BaselineWriteError("Revision changed.", false);
    const next = {
      ...record,
      revision: expected + 1,
      version: record.version + 1,
      capture: structuredClone(references.get(reference)!),
    };
    records.set(id, next);
    receipts.set(requestId, next);
    return next;
  },
  async setWatch(id, expected, definition, requestId) {
    if (receipts.has(requestId)) return receipts.get(requestId)!;
    const record = records.get(id)!;
    if (record.revision !== expected)
      throw new BaselineWriteError("Revision changed.", false);
    watches.set(id, [...(watches.get(id) ?? []), structuredClone(definition)]);
    const next = { ...record, revision: expected + 1 };
    records.set(id, next);
    receipts.set(requestId, next);
    return next;
  },
  async watches(id) {
    if (!allowed) throw new Error("Baseline access denied.");
    return structuredClone(watches.get(id) ?? []);
  },
};
function maintenance(later: boolean): AssessmentInput {
  const start = base + (later ? 300 : 0),
    end = start + 300,
    at = end + 10;
  const evidence = <T,>(value: T): Evidence<T> => ({
    value,
    scope: "synthetic-scope",
    source: "synthetic qualified replay",
    qualified: true,
    state: "complete",
    observedAt: end,
    validFrom: start,
    validUntil: at + 600,
  });
  return {
    id: later ? "after-source" : "before-source",
    capturedAt: at,
    window: { start, end },
    selectedElements: ["synthetic-host-a"],
    services: [
      {
        id: "service:checkout",
        name: "Synthetic checkout",
        scope: "synthetic-scope",
        topology: evidence("exposed"),
        alternatives: [
          {
            name: "Synthetic backend B",
            reachable: evidence(true),
            healthy: evidence(later),
            ready: evidence(true),
            substitutable: evidence(true),
            independentFailureDomain: evidence(true),
            capacity: evidence({
              sufficientPeakHeadroom: true,
              value: 120,
              unit: "Mbps",
              interval: { start, end },
              direction: "egress",
              sampling: "unsampled synthetic fixture",
              deduplication: "one interval per backend",
              capacitySource: "synthetic lab specification",
              assumptions: ["Synthetic shape, not operational capacity"],
            }),
          },
        ],
      },
    ],
  };
}
const syntheticImpact = (later: boolean): ImpactData =>
  ({
    source: "synthetic impact replay",
    elements: [{ token: "synthetic-leaf-a" }],
    capped: false,
    truncated: false,
    graph: {
      window: {
        start: new Date((base + (later ? 300 : 0)) * 1000).toISOString(),
        end: new Date((base + (later ? 600 : 300)) * 1000).toISOString(),
      },
    },
  }) as unknown as ImpactData;
const syntheticFails = {
  rows: [
    {
      traversal: "observed",
      alternate: ["synthetic-leaf-b"],
      conv: { app: "Synthetic checkout", lastSeen: base + 300 },
    },
  ],
} as unknown as FailsResult;
function ImpactReplay() {
  const [phase, setPhase] = useState<
    "initial" | "loading" | "updated" | "denied"
  >("initial");
  const [data, setData] = useState(() => syntheticImpact(false));
  return (
    <ThemeProvider
      family="enterprise"
      colorScheme={theme}
      density="comfortable"
    >
      <Shell page="impact">
        <main className="adm atlas-page" data-adm-theme={theme}>
          <h1>Synthetic impact planning replay</h1>
          <button type="button" onClick={() => setPhase("loading")}>
            Begin synthetic refresh
          </button>
          <button
            type="button"
            onClick={() => {
              setData(syntheticImpact(true));
              setPhase("updated");
            }}
          >
            Complete synthetic refresh
          </button>
          <button type="button" onClick={() => setPhase("denied")}>
            Deny synthetic impact access
          </button>
          <ImpactMaintenancePlanner
            data={data}
            result={syntheticFails}
            loading={phase === "loading"}
            denied={phase === "denied"}
            selection={{
              elements: ["synthetic-leaf-a"],
              earliest: "-5m",
              scope: "synthetic-scope",
              demo: true,
            }}
          />
        </main>
      </Shell>
    </ThemeProvider>
  );
}
const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
function Replay() {
  const [later, setLater] = useState(false);
  return (
    <ThemeProvider
      family="enterprise"
      colorScheme={theme}
      density="comfortable"
    >
      <Shell page="impact">
        <main className="adm atlas-page" data-adm-theme={theme}>
          <h1>Synthetic planning replay</h1>
          <p>
            No deployed source or persistence target is qualified by this
            replay.
          </p>
          <button type="button" onClick={() => setLater(true)}>
            Use later synthetic maintenance evidence
          </button>
          <button
            type="button"
            onClick={() => {
              allowed = false;
            }}
          >
            Revoke synthetic source access
          </button>
          <MaintenancePlanner
            input={maintenance(later)}
            description="Synthetic qualification shapes only. No infrastructure operations."
          />
          <DependencyMonitor
            window={{ start: base, end: base + 300 }}
            source={source}
            repository={repository}
          />
        </main>
      </Shell>
    </ThemeProvider>
  );
}
createRoot(document.getElementById("root")!).render(
  mode === "impact" ? <ImpactReplay /> : <Replay />,
);
