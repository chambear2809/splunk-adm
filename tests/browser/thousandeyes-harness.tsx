import { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ThousandEyesEvidenceInspection,
  type ThousandEyesEvidenceLoader,
  type ThousandEyesMeasurementComparator,
} from "../../frontend/src/ThousandEyesEvidencePanel";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../frontend/src/data/searchClient";
import type { EvidenceSelection } from "../../frontend/src/data/evidence";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesComparison,
  ThousandEyesEvidenceResult,
  ThousandEyesLifecycle,
} from "../../frontend/src/data/thousandEyesTypes";
import "../../frontend/src/styles.css";

interface SearchLog {
  search: string;
  earliest: string;
  aborted: boolean;
  released: boolean;
  settled: boolean;
}

interface TestState {
  searches: SearchLog[];
  comparisons: {
    before: { start: number; end: number };
    after: { start: number; end: number };
  }[];
  lateResults: number;
}

declare global {
  interface Window {
    __THOUSANDEYES_TEST__?: TestState;
  }
}

const fault = new URLSearchParams(location.search).get("fault") ?? "success";
const now = Math.floor(Date.now() / 1000);

function selection(selectionId: string, scope: string): EvidenceSelection {
  return {
    schemaVersion: 1,
    workflow: "endpoint",
    selectionId,
    trafficContract: 1,
    window: { start: now - 3600, end: now - 3000 },
    scope,
    addresses: ["192.0.2.10"],
    contexts: [],
    identityBasis: "disposable ThousandEyes browser selection",
    configurationFingerprint: "a".repeat(64),
  };
}

const primarySelection = selection("te-selected-east", "prod-east");
const alternateSelection = selection("te-selected-west", "prod-west");

function observation(
  active: EvidenceSelection,
  family: ThousandEyesAttributedObservation["family"] = "metric",
): ThousandEyesAttributedObservation {
  const base: ThousandEyesAttributedObservation = {
    schemaVersion: 1,
    family,
    authority: "te-browser-authority",
    authorityBasis: "configured_account_binding",
    accountGroupId: "1234",
    accountId: "5678",
    organizationId: family === "alert" ? "org-browser" : undefined,
    adapterVersion: "0.9.0",
    producerVersion: "0.9.0",
    dataModelVersion: "2",
    testId: "17",
    agentId: "9",
    testName: "Checkout API synthetic test",
    agentName: "Branch probe",
    agentLocation: "Chicago",
    configurationId: "test-config-v1",
    target: { hostname: "api.example.test", protocol: "https", port: 443 },
    interval: {
      start: active.window.start + 30,
      end: active.window.end - 30,
    },
    intervalBasis: family === "event" ? "reported_event" : "measurement",
    eventTime: active.window.end - 30,
    indexedTime: now - 10,
    receiptTime: now - 10,
    collectionTime: now - 20,
    index: "atlas_te",
    source:
      family === "path"
        ? "atlas:thousandeyes:path"
        : "cisco:thousandeyes:stream",
    sourcetype:
      family === "path"
        ? "atlas:thousandeyes:path"
        : family === "metric"
          ? "cisco:thousandeyes:metric"
          : `cisco:thousandeyes:${family}`,
    fingerprint: `synthetic-${family}-fingerprint`,
    navigationOrigin: "https://app.thousandeyes.example.test",
    outcome: "failure",
    quality: {
      stale: false,
      complete: true,
      conflicting: false,
      truncated: false,
    },
    measurements:
      family === "metric"
        ? [
            {
              name: "network.latency",
              value: 0.125,
              unit: "seconds",
              sourceUnit: "seconds",
              aggregation: "mean",
              direction: "source_to_target",
              denominator: "successful probes",
              timeBasis: "measurement interval",
            },
          ]
        : [],
    hops: [],
    spans: [],
    lifecycle:
      family === "event" || family === "alert"
        ? ({
            id: family === "event" ? "event-browser-1" : "alert-browser-1",
            type: "threshold",
            state: "cleared",
            startedAt: active.window.end - 120,
            endedAt: active.window.end - 60,
            severity: "major",
            title: "Synthetic test threshold",
            historyComplete: false,
          } satisfies ThousandEyesLifecycle)
        : undefined,
    activity:
      family === "activity"
        ? {
            id: "activity-browser-1",
            action: "updated",
            actor: "synthetic-user@example.test",
            objectId: "17",
            objectType: "test",
          }
        : undefined,
    attribution: {
      state: "bound",
      bindingIds: ["binding-te-browser-v1"],
      reason:
        "Exact authority, test, agent, target and time-qualified binding.",
      observedDependency: false,
      configurationId: "test-config-v1",
    },
    limitations: ["Synthetic browser fixture; no live producer was queried."],
  };
  return base;
}

function result(
  active: EvidenceSelection,
  overrides: Partial<ThousandEyesEvidenceResult> = {},
): ThousandEyesEvidenceResult {
  return {
    schemaVersion: 1,
    source: "thousandeyes",
    selection: active,
    capturedAt: now,
    inspectedWindow: { start: now - 7200, end: now + 60 },
    configurationFingerprint: active.configurationFingerprint,
    configurationChanged: false,
    state: "complete",
    schemaQualified: true,
    inputCount: 1,
    inputCapped: false,
    outputCapped: false,
    rejected: 0,
    oversized: 0,
    records: [observation(active)],
    coverage: ["Synthetic browser evidence only."],
    ...overrides,
  };
}

const testState: TestState = { searches: [], comparisons: [], lateResults: 0 };
window.__THOUSANDEYES_TEST__ = testState;

let attempt = 0;
const client: SearchClient = {
  search: (request) => {
    attempt++;
    const log: SearchLog = {
      search: request.search,
      earliest: request.earliest,
      aborted: false,
      released: false,
      settled: false,
    };
    testState.searches.push(log);
    const sid = `thousandeyes-browser-${attempt}`;
    request.onLifecycle?.({ state: "creating" });
    request.onLifecycle?.({ state: "created", sid });
    request.signal.addEventListener(
      "abort",
      () => {
        log.aborted = true;
      },
      { once: true },
    );
    const release = () => {
      request.onLifecycle?.({ state: "released", sid });
      log.released = true;
    };

    if (fault === "slow" && attempt === 1) {
      return new Promise((resolve, reject) => {
        const abort = () => {
          log.aborted = true;
          release();
          window.setTimeout(() => {
            log.settled = true;
            reject(new Error("cancelled"));
          }, 0);
        };
        if (request.signal.aborted) abort();
        else request.signal.addEventListener("abort", abort, { once: true });
      });
    }
    if (fault === "denied") {
      release();
      log.settled = true;
      return Promise.reject(new SearchAccessDeniedError());
    }
    release();
    log.settled = true;
    return Promise.resolve({ rows: [], warnings: [], errors: [] });
  },
};

const loadEvidence: ThousandEyesEvidenceLoader = async (
  searchClient,
  active,
  signal,
) => {
  const noSearch = fault === "off";
  if (fault === "late") {
    await searchClient.search({
      search: "search index=atlas_te source=browser-fixture",
      earliest: String(active.window.start),
      latest: String(active.window.end),
      maxRows: 65,
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      signal,
      optionalSource: "thousandeyes",
    });
    await new Promise<void>((resolve) => window.setTimeout(resolve, 350));
    testState.lateResults++;
    return result(primarySelection);
  }
  if (!noSearch) {
    await searchClient.search({
      search: "search index=atlas_te source=browser-fixture",
      earliest: String(active.window.start),
      latest: String(active.window.end),
      maxRows: 65,
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      signal,
      optionalSource: "thousandeyes",
    });
  }
  if (fault === "off")
    return result(active, { state: "not_selected", records: [] });
  if (fault === "config-changed")
    return result(active, {
      state: "unavailable",
      configurationChanged: true,
      records: [],
      errorCode: "configuration",
    });
  if (fault === "empty") return result(active, { records: [] });
  if (fault === "no-metric")
    return result(active, { records: [observation(active, "event")] });
  if (fault === "receipt-stale")
    return result(active, {
      receiptFreshness: {
        state: "stale",
        basis: "selected_evidence_indexed_receipt",
        latestIndexedTime: now - 6000,
        assessedAt: now,
      },
    });
  return result(active);
};

const compareMeasurements: ThousandEyesMeasurementComparator = (
  _records,
  before,
  after,
): ThousandEyesComparison[] => {
  testState.comparisons.push({ before, after });
  return [
    {
      key: "17:9:network.latency:seconds",
      authority: "te-browser-authority",
      accountGroupId: "1234",
      testId: "17",
      agentId: "9",
      agentLocation: "Chicago",
      metric: "network.latency",
      unit: "seconds",
      beforeCount: 1,
      afterCount: 1,
      beforeMean: 0.1,
      afterMean: 0.125,
      delta: 0.025,
      comparable: true,
      reasons: [],
    },
  ];
};

function Harness() {
  const [active, setActive] = useState(primarySelection);
  const inspectionSelection = fault === "no-selection" ? undefined : active;
  return (
    <div className="adm atlas">
      <button type="button" onClick={() => setActive(alternateSelection)}>
        Use another selection
      </button>
      <ThousandEyesEvidenceInspection
        selection={inspectionSelection}
        client={client}
        loadEvidence={loadEvidence}
        compareMeasurements={compareMeasurements}
      />
    </div>
  );
}

document.documentElement.dataset.theme =
  new URLSearchParams(location.search).get("theme") === "dark"
    ? "dark"
    : "light";
createRoot(document.getElementById("thousandeyes-root")!).render(<Harness />);
