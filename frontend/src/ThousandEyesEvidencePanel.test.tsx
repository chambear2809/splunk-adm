import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement } from "react";
import {
  ThousandEyesEvidenceInspection,
  ThousandEyesEvidencePanel,
} from "./ThousandEyesEvidencePanel";
import type { EvidenceSelection } from "./data/evidence";
import type { EvidenceConfigClient } from "./data/evidenceConfig";
import type { SearchClient } from "./data/searchClient";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesEvidenceResult,
} from "./data/thousandEyesTypes";

const hookHarness = vi.hoisted(() => ({
  active: false,
  cursor: 0,
  stateSlots: [] as unknown[],
  refSlots: [] as { current: unknown }[],
  memoSlots: [] as { dependencies: readonly unknown[]; value: unknown }[],
  pendingEffects: [] as {
    index: number;
    effect: () => void | (() => void);
    dependencies?: readonly unknown[];
  }[],
  effectDependencies: [] as (readonly unknown[] | undefined)[],
  effectCleanups: [] as (undefined | (() => void))[],
}));

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  const sameDependencies = (
    left: readonly unknown[] | undefined,
    right: readonly unknown[] | undefined,
  ) =>
    left === right ||
    (left !== undefined &&
      right !== undefined &&
      left.length === right.length &&
      left.every((value, index) => Object.is(value, right[index])));
  return {
    ...actual,
    useState<T>(initial: T | (() => T)) {
      if (!hookHarness.active) return actual.useState<T>(initial);
      const index = hookHarness.cursor++;
      if (!(index in hookHarness.stateSlots))
        hookHarness.stateSlots[index] =
          typeof initial === "function" ? (initial as () => T)() : initial;
      const setState = (next: T | ((previous: T) => T)) => {
        const previous = hookHarness.stateSlots[index] as T;
        hookHarness.stateSlots[index] =
          typeof next === "function"
            ? (next as (previous: T) => T)(previous)
            : next;
      };
      return [hookHarness.stateSlots[index] as T, setState] as const;
    },
    useRef<T>(initial?: T) {
      if (!hookHarness.active) return actual.useRef<T>(initial as T);
      const index = hookHarness.cursor++;
      hookHarness.refSlots[index] ??= { current: initial };
      return hookHarness.refSlots[index] as { current: T };
    },
    useMemo<T>(factory: () => T, dependencies: readonly unknown[]) {
      if (!hookHarness.active) return actual.useMemo(factory, dependencies);
      const index = hookHarness.cursor++;
      const previous = hookHarness.memoSlots[index];
      if (!previous || !sameDependencies(previous.dependencies, dependencies))
        hookHarness.memoSlots[index] = {
          dependencies,
          value: factory(),
        };
      return hookHarness.memoSlots[index].value as T;
    },
    useEffect(
      effect: Parameters<typeof actual.useEffect>[0],
      dependencies?: Parameters<typeof actual.useEffect>[1],
    ) {
      if (!hookHarness.active) {
        actual.useEffect(effect, dependencies);
        return;
      }
      const index = hookHarness.cursor++;
      hookHarness.pendingEffects.push({
        index,
        effect,
        dependencies,
      });
    },
  };
});

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "te-panel-test",
  trafficContract: 1,
  window: { start: 600, end: 1200 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "fixture",
  configurationFingerprint: "a".repeat(64),
};

function observation(
  overrides: Partial<ThousandEyesAttributedObservation> = {},
): ThousandEyesAttributedObservation {
  return {
    schemaVersion: 1,
    family: "metric",
    authority: "te-account.example.test",
    authorityBasis: "configured_account_binding",
    accountGroupId: "12345",
    adapterVersion: "0.9.0",
    producerVersion: "0.9.0",
    dataModelVersion: "1",
    testId: "test-17",
    testDomain: "endpoint",
    relatedTestIds: ["test-related-18"],
    agentId: "agent-4",
    relatedAgentIds: ["agent-related-8"],
    testName: "API check",
    agentName: "branch probe",
    agentLocation: "Chicago",
    streamId: "stream-3",
    monitorId: "monitor-6",
    targetAgentId: "target-agent-1",
    pathDirection: "to-target",
    targetIsProxy: false,
    configurationId: "config-9",
    target: { hostname: "api.example.test", protocol: "https", port: 443 },
    interval: { start: 1050, end: 1100 },
    intervalBasis: "measurement",
    eventTime: 1100,
    indexedTime: 1110,
    rowTime: 1099,
    sourceTimes: [
      { field: "time_unix_nano", value: "10000000000", unit: "ns" },
    ],
    collectionTime: 1120,
    index: "te_metrics",
    source: "cisco:thousandeyes:stream",
    sourcetype: "cisco:thousandeyes:metric",
    fingerprint: "metric-fingerprint-1",
    navigationOrigin: "https://app.thousandeyes.example",
    outcome: "failure",
    quality: {
      stale: false,
      complete: true,
      conflicting: false,
      truncated: false,
    },
    measurements: [
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
      {
        name: "network.loss",
        unit: "percent",
        sourceUnit: "percent",
        aggregation: "ratio",
        direction: "source_to_target",
        denominator: "probes sent",
        timeBasis: "round",
      },
    ],
    hops: [],
    spans: [],
    attribution: {
      state: "ambiguous",
      bindingIds: ["binding-1", "binding-2"],
      reason: "Two configured bindings remain valid for this interval.",
      observedDependency: false,
      configurationId: "config-9",
    },
    limitations: [
      "The source result does not establish coverage outside this interval.",
    ],
    ...overrides,
  };
}

function result(
  overrides: Partial<ThousandEyesEvidenceResult> = {},
): ThousandEyesEvidenceResult {
  return {
    schemaVersion: 1,
    source: "thousandeyes",
    selection,
    capturedAt: 1200,
    inspectedWindow: { start: 0, end: 1200 },
    configurationFingerprint: selection.configurationFingerprint,
    configurationChanged: false,
    state: "complete",
    schemaQualified: true,
    inputCount: 2,
    inputCapped: false,
    outputCapped: false,
    rejected: 0,
    oversized: 0,
    records: [observation()],
    coverage: [],
    ...overrides,
  };
}

describe("ThousandEyes evidence panel", () => {
  it("renders typed metric units and labels missing measurements without inventing values", () => {
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result()} />,
    );
    expect(html).toContain("Reported outcome: failure");
    expect(html).toContain("network.latency");
    expect(html).toContain("successful probes");
    expect(html).toContain("network.loss");
    expect(html).toContain("10000000000");
    expect(html).toContain("Not supplied");
    expect(html).toContain("Agent location");
    expect(html).toContain("Group by");
    expect(html).toContain("Chicago");
    expect(html).toContain("ENDPOINT");
    expect(html).toContain("stream-3");
    expect(html).toContain("test-related-18");
    expect(html).toContain("Original Splunk row time (_time)");
    expect(html).toContain("basis not qualified; not measurement time");
    expect(html).not.toContain("Attested Splunk receipt time");
    expect(html).toContain("ambiguous configured-binding attribution");
    expect(html).toContain("Copy exact IDs and times");
    expect(html).toContain("Native measurement window");
    expect(html).toContain("Retained-index scan diagnostics");
    expect(html).toContain("not the ThousandEyes measurement window");
    expect(html).not.toContain("Inspected window:");
  });

  it("separates measured ordered hops from inventory route candidates", () => {
    const record = observation({
      family: "path",
      targetIsProxy: true,
      pathDirection: "from-target",
      hops: [
        {
          pathId: "path-a",
          number: 2,
          ip: "192.0.2.2",
          latencyMilliseconds: 8,
          missing: false,
        },
        {
          pathId: "path-a",
          number: 1,
          ip: "192.0.2.1",
          latencyMilliseconds: 2,
          missing: true,
        },
        {
          pathId: "path-b",
          number: 1,
          ip: "192.0.2.3",
          latencyMilliseconds: 4,
          missing: false,
        },
      ],
    });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [record] })} />,
    );
    expect(html).toContain("Measured probe path");
    expect(html).toContain("ordered probe observations");
    expect(html).toContain("not an inventory candidate route");
    expect(html.indexOf("192.0.2.1")).toBeLessThan(html.indexOf("192.0.2.2"));
    expect(html).toContain("Hop marked missing");
    expect(html).toContain("missing hops do not establish forwarding loss");
    expect(html).toContain("Path iteration ID path-a");
    expect(html).toContain("Path iteration ID path-b");
    expect(html).toContain("downstream path coverage is unknown");
    expect(html).toContain("from-target");
  });

  it("does not claim a route when path iteration IDs are absent", () => {
    const record = observation({
      family: "path",
      hops: [
        { number: 1, ip: "192.0.2.1", missing: false },
        { number: 1, ip: "192.0.2.2", missing: false },
      ],
    });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [record] })} />,
    );
    expect(html).toContain("Path iteration ID not supplied");
    expect(html).toContain("these are unassigned hops, not one inferred route");
  });

  it("shows trace hierarchy as synthetic evidence, not production service calls", () => {
    const record = observation({
      family: "trace",
      spans: [
        {
          traceId: "trace-1",
          spanId: "span-2",
          parentSpanId: "span-1",
          name: "HTTP request",
          start: 100,
          end: 200,
          startTimeUnixNano: "100000000000",
          endTimeUnixNano: "200000000000",
          status: "ERROR",
        },
      ],
    });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [record] })} />,
    );
    expect(html).toContain("Synthetic trace spans");
    expect(html).toContain("span-1");
    expect(html).toContain("100000000000");
    expect(html).toContain("not production service-call edges");
    expect(html).toContain("no conversion is inferred");
  });

  it("keeps lifecycle and activity in ThousandEyes-specific sections", () => {
    const event = observation({
      family: "event",
      lifecycle: {
        id: "event-22",
        type: "threshold",
        state: "cleared",
        startedAt: 100,
        endedAt: 200,
        severity: "major",
        title: "Synthetic test threshold",
        historyComplete: false,
      },
    });
    const activity = observation({
      family: "activity",
      activity: {
        id: "activity-4",
        action: "updated",
        actor: "operator@example.test",
        objectId: "test-17",
        objectType: "test",
      },
    });
    const eventHtml = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [event] })} />,
    );
    const activityHtml = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [activity] })} />,
    );
    expect(eventHtml).toContain("Detected event lifecycle");
    expect(eventHtml).toContain("Source history is incomplete or unverified");
    expect(eventHtml).not.toContain("ThousandEyes-only activity");
    expect(activityHtml).toContain("ThousandEyes-only activity");
    expect(activityHtml).toContain("not general infrastructure change history");
  });

  it("renders only the selected observation detail while retaining compact result summaries", () => {
    const event = observation({ family: "event" });
    const activity = observation({ family: "activity" });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ records: [event, activity] })}
      />,
    );
    expect(html).toContain("Observation summaries");
    expect(html).toContain("Inspect observation");
    expect(html.match(/class="te-observation"/g)).toHaveLength(1);
  });

  it("keeps identical native test IDs separate across test domains", () => {
    const cea = observation({
      testDomain: "cea",
      fingerprint: "cea-record",
    });
    const endpoint = observation({
      testDomain: "endpoint",
      fingerprint: "endpoint-record",
    });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ records: [cea, endpoint] })}
      />,
    );
    expect(html).toContain("CEA ID test-17");
    expect(html).toContain("ENDPOINT ID test-17");
    expect(html.match(/class="te-group"/g)).toHaveLength(2);
  });

  it("renders only a safe configured origin and never a producer event URL", () => {
    const record = observation({
      navigationOrigin: "https://te.example.test/path?event=secret",
      limitations: ["https://event.example.test/should-not-be-linked"],
    });
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [record] })} />,
    );
    const safeHtml = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ records: [observation()] })}
      />,
    );
    expect(html).not.toContain('href="https://te.example.test');
    expect(html).not.toContain('href="https://event.example.test');
    expect(safeHtml).toContain('href="https://app.thousandeyes.example"');
    expect(html).toContain("Copy exact IDs and times");
  });

  it("distinguishes denied, unselected, staged, empty, capped, unqualified and stale states", () => {
    const denied = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ state: "unavailable", errorCode: "denied" })}
      />,
    );
    const off = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ state: "not_selected" })} />,
    );
    const staged = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ state: "staged" })} />,
    );
    const empty = renderToStaticMarkup(
      <ThousandEyesEvidencePanel result={result({ records: [] })} />,
    );
    const capped = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({
          inputCapped: true,
          outputCapped: true,
          schemaQualified: false,
        })}
      />,
    );
    const stale = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({
          receiptFreshness: {
            state: "stale",
            basis: "selected_evidence_indexed_receipt",
            latestIndexedTime: 800,
            assessedAt: 1200,
          },
        })}
        compareMeasurements={() => []}
      />,
    );
    const incomplete = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ state: "unavailable", errorCode: "completion" })}
      />,
    );
    expect(denied).toContain("Access denied");
    expect(off).toContain("source not selected");
    expect(staged).toContain("source is staged");
    expect(empty).toContain("No visible ThousandEyes observations");
    expect(capped).toContain("input scan capped");
    expect(capped).toContain("schema is not qualified");
    expect(incomplete).toContain("evidence is incomplete");
    expect(stale).toContain("selected evidence-index receipt is stale");
    expect(stale).toContain("does not invalidate historical measurements");
    const comparisonButton = stale.match(
      /<button[^>]*>Compare loaded measurements<\/button>/,
    )?.[0];
    expect(comparisonButton).toBeDefined();
    expect(comparisonButton).not.toContain("disabled");
  });

  it("defaults to native-window halves while allowing historical measurement evidence", () => {
    const compareMeasurements = vi.fn(() => [
      {
        key: "test-17:agent-4:network.latency",
        authority: "te-account.example.test",
        accountGroupId: "12345",
        testId: "test-17",
        testDomain: "endpoint" as const,
        agentId: "agent-4",
        metric: "network.latency",
        unit: "seconds",
        beforeCount: 2,
        afterCount: 2,
        beforeMean: 0.12,
        afterMean: 0.15,
        delta: 0.03,
        comparable: true,
        reasons: [],
      },
    ]);
    hookHarness.cursor = 0;
    hookHarness.pendingEffects = [];
    hookHarness.active = true;
    let panelTree: ReactElement;
    try {
      panelTree = ThousandEyesEvidencePanel({
        result: result({
          receiptFreshness: {
            state: "historical",
            basis: "selected_evidence_indexed_receipt",
            latestIndexedTime: 700,
            assessedAt: 1200,
          },
        }),
        compareMeasurements,
      });
    } finally {
      hookHarness.active = false;
    }

    const comparison = findComponent(panelTree, "ComparisonSection");
    expect(comparison).toBeDefined();
    const comparisonComponent = comparison?.type as (
      props: Record<string, unknown>,
    ) => ReactElement;
    const comparisonProps = comparison?.props as Record<string, unknown>;
    hookHarness.stateSlots = [];
    hookHarness.refSlots = [];
    hookHarness.memoSlots = [];
    const comparisonTree = renderDirectComponent(
      comparisonComponent,
      comparisonProps,
    );
    clickButton(comparisonTree, "Compare loaded measurements");
    const completedTree = renderDirectComponent(
      comparisonComponent,
      comparisonProps,
    );

    expect(compareMeasurements).toHaveBeenCalledOnce();
    expect(compareMeasurements).toHaveBeenCalledWith(
      [expect.objectContaining({ testId: "test-17" })],
      { start: 600, end: 900 },
      { start: 900, end: 1200 },
    );
    expect(treeText(completedTree)).toContain(
      "Comparator results by authority, account group, test domain",
    );
    expect(treeText(completedTree)).toContain("0.03");
    expect(treeText(completedTree)).toContain("seconds");
  });

  it("rejects edited comparison windows outside the native measurement window", () => {
    const compareMeasurements = vi.fn(() => []);
    hookHarness.cursor = 0;
    hookHarness.pendingEffects = [];
    hookHarness.active = true;
    let panelTree: ReactElement;
    try {
      panelTree = ThousandEyesEvidencePanel({
        result: result(),
        compareMeasurements,
      });
    } finally {
      hookHarness.active = false;
    }
    const comparison = findComponent(panelTree, "ComparisonSection");
    const comparisonComponent = comparison?.type as (
      props: Record<string, unknown>,
    ) => ReactElement;
    const comparisonProps = comparison?.props as Record<string, unknown>;
    hookHarness.stateSlots = [];
    hookHarness.refSlots = [];
    hookHarness.memoSlots = [];
    const initialTree = renderDirectComponent(
      comparisonComponent,
      comparisonProps,
    );
    const dateInputs = findDateInputs(initialTree);
    expect(dateInputs).toHaveLength(4);
    expect(dateInputs[0].props.value).toBe(localDateTimeInput(600));
    expect(dateInputs[1].props.value).toBe(localDateTimeInput(900));
    expect(dateInputs[2].props.value).toBe(localDateTimeInput(900));
    expect(dateInputs[3].props.value).toBe(localDateTimeInput(1200));

    dateInputs[0].props.onChange?.({
      target: { value: localDateTimeInput(599) },
    } as never);
    const editedTree = renderDirectComponent(
      comparisonComponent,
      comparisonProps,
    );
    const compareButton = findButton(editedTree, "Compare loaded measurements");
    expect(compareButton?.props.disabled).toBe(true);
    expect(treeText(editedTree)).toContain(
      "inside the native measurement window",
    );
    expect(compareMeasurements).not.toHaveBeenCalled();
  });

  it("blocks the comparison control when the search input was capped", () => {
    const html = renderToStaticMarkup(
      <ThousandEyesEvidencePanel
        result={result({ inputCapped: true })}
        compareMeasurements={() => []}
      />,
    );
    expect(html).toContain("Comparison unavailable: the input scan was capped");
    expect(html).not.toContain("Compare loaded measurements");
  });

  it("does not search without a scoped selection and exposes an injected loader boundary", () => {
    const client: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    const loadEvidence = vi.fn(async () => result());
    const html = renderToStaticMarkup(
      <ThousandEyesEvidenceInspection
        client={client}
        loadEvidence={loadEvidence}
      />,
    );
    expect(html).toContain("No application or endpoint selection is active");
    expect(html).not.toContain("Inspect ThousandEyes evidence</button>");
    expect(loadEvidence).not.toHaveBeenCalled();
  });

  it("aborts and ignores a late result after the selection fingerprint changes", async () => {
    const pending = deferred<ThousandEyesEvidenceResult>();
    const client: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    const loadEvidence = vi.fn(
      async (...args: [SearchClient, EvidenceSelection, AbortSignal]) => {
        void args[0];
        void args[1];
        void args[2];
        return pending.promise;
      },
    );
    const originalProps = { selection, client, loadEvidence };
    installFakeWindow();

    const firstTree = renderInspection(originalProps);
    flushEffects();
    clickButton(firstTree, "Inspect ThousandEyes evidence");
    const signal = loadEvidence.mock.calls[0][2];
    expect(signal.aborted).toBe(false);

    const nextSelection = {
      ...selection,
      selectionId: "te-panel-test-next",
      configurationFingerprint: "b".repeat(64),
    };
    const nextTree = renderInspection({
      ...originalProps,
      selection: nextSelection,
    });
    flushEffects();
    expect(signal.aborted).toBe(true);

    pending.resolve(result({ selection: nextSelection }));
    await Promise.resolve();
    await Promise.resolve();
    const settledTree = renderInspection({
      ...originalProps,
      selection: nextSelection,
    });
    flushEffects();
    expect(treeText(settledTree)).not.toContain("Search complete:");
    expect(treeText(nextTree)).toContain("No ThousandEyes search has run");
  });

  it("aborts on page navigation and does not commit a loader that ignores cancellation", async () => {
    const pending = deferred<ThousandEyesEvidenceResult>();
    const client: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    const loadEvidence = vi.fn(
      async (...args: [SearchClient, EvidenceSelection, AbortSignal]) => {
        void args[0];
        void args[1];
        void args[2];
        return pending.promise;
      },
    );
    const props = { selection, client, loadEvidence };
    const listeners = installFakeWindow();

    const tree = renderInspection(props);
    flushEffects();
    clickButton(tree, "Inspect ThousandEyes evidence");
    const signal = loadEvidence.mock.calls[0][2];
    const loadingTree = renderInspection(props);
    flushEffects();
    expect(treeText(loadingTree)).toContain(
      "Loading optional ThousandEyes evidence",
    );

    listeners.get("pagehide")?.();
    expect(signal.aborted).toBe(true);
    pending.resolve(result());
    await Promise.resolve();
    await Promise.resolve();

    const settledTree = renderInspection(props);
    flushEffects();
    expect(treeText(settledTree)).not.toContain("Search complete:");
    expect(treeText(settledTree)).toContain(
      "Search cancelled as navigation started",
    );
  });

  it("aborts an in-flight search when the configuration client changes", async () => {
    const pending = deferred<ThousandEyesEvidenceResult>();
    const client: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    const configurationClient = {} as EvidenceConfigClient;
    const nextConfigurationClient = {} as EvidenceConfigClient;
    const loadEvidence = vi.fn(
      async (...args: [SearchClient, EvidenceSelection, AbortSignal]) => {
        void args[0];
        void args[1];
        void args[2];
        return pending.promise;
      },
    );
    const props = { selection, client, configurationClient, loadEvidence };
    installFakeWindow();

    const tree = renderInspection(props);
    flushEffects();
    clickButton(tree, "Inspect ThousandEyes evidence");
    const signal = loadEvidence.mock.calls[0][2];
    const nextProps = {
      ...props,
      configurationClient: nextConfigurationClient,
    };
    const nextTree = renderInspection(nextProps);
    flushEffects();
    expect(signal.aborted).toBe(true);

    pending.resolve(result());
    await Promise.resolve();
    await Promise.resolve();
    const settledTree = renderInspection(nextProps);
    flushEffects();
    expect(treeText(nextTree)).not.toContain("Search complete:");
    expect(treeText(settledTree)).not.toContain("Search complete:");
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function renderInspection(props: {
  selection?: EvidenceSelection;
  client: SearchClient;
  loadEvidence: (
    client: SearchClient,
    selection: EvidenceSelection,
    signal: AbortSignal,
  ) => Promise<ThousandEyesEvidenceResult>;
}) {
  hookHarness.cursor = 0;
  hookHarness.pendingEffects = [];
  hookHarness.active = true;
  try {
    return ThousandEyesEvidenceInspection(props);
  } finally {
    hookHarness.active = false;
  }
}

function renderDirectComponent(
  component: (props: Record<string, unknown>) => ReactElement,
  props: Record<string, unknown>,
) {
  hookHarness.cursor = 0;
  hookHarness.pendingEffects = [];
  hookHarness.active = true;
  try {
    return component(props);
  } finally {
    hookHarness.active = false;
  }
}

function flushEffects() {
  for (const pending of hookHarness.pendingEffects) {
    const previous = hookHarness.effectDependencies[pending.index];
    const unchanged =
      previous === pending.dependencies ||
      (previous !== undefined &&
        pending.dependencies !== undefined &&
        previous.length === pending.dependencies.length &&
        previous.every((value, index) =>
          Object.is(value, pending.dependencies?.[index]),
        ));
    if (unchanged) continue;
    hookHarness.effectCleanups[pending.index]?.();
    const cleanup = pending.effect();
    hookHarness.effectDependencies[pending.index] = pending.dependencies;
    hookHarness.effectCleanups[pending.index] =
      typeof cleanup === "function" ? cleanup : undefined;
  }
  hookHarness.pendingEffects = [];
}

function installFakeWindow() {
  const listeners = new Map<string, () => void>();
  vi.stubGlobal("window", {
    addEventListener: (type: string, listener: () => void) =>
      listeners.set(type, listener),
    removeEventListener: (type: string) => listeners.delete(type),
  });
  return listeners;
}

function treeText(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean")
    return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(treeText).join(" ");
  if (typeof node === "object" && "props" in node) {
    const element = node as ReactElement<{ children?: unknown }>;
    return treeText(element.props.children);
  }
  return "";
}

function findButton(
  node: unknown,
  label: string,
):
  | ReactElement<{
      onClick?: (event: never) => void;
      disabled?: boolean;
    }>
  | undefined {
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findButton(item, label);
      if (found) return found;
    }
  } else if (
    typeof node === "object" &&
    node !== null &&
    "props" in node &&
    "type" in node
  ) {
    const element = node as ReactElement<{
      children?: unknown;
      onClick?: (event: never) => void;
      disabled?: boolean;
    }>;
    if (
      element.type === "button" &&
      treeText(element.props.children).includes(label)
    )
      return element;
    return findButton(element.props.children, label);
  }
  return undefined;
}

function findDateInputs(node: unknown): ReactElement<{
  type?: string;
  value?: string;
  onChange?: (event: never) => void;
}>[] {
  if (Array.isArray(node)) return node.flatMap(findDateInputs);
  if (
    typeof node !== "object" ||
    node === null ||
    !("props" in node) ||
    !("type" in node)
  )
    return [];

  const element = node as ReactElement<{
    children?: unknown;
    type?: string;
    value?: string;
    onChange?: (event: never) => void;
  }>;
  if (
    typeof element.type === "function" &&
    element.type.name === "WindowEditor"
  ) {
    const renderWindowEditor = element.type as (
      props: Record<string, unknown>,
    ) => ReactElement;
    return findDateInputs(renderWindowEditor(element.props));
  }
  const inputs =
    element.type === "input" && element.props.type === "datetime-local"
      ? [
          element as ReactElement<{
            type?: string;
            value?: string;
            onChange?: (event: never) => void;
          }>,
        ]
      : [];
  return [...inputs, ...findDateInputs(element.props.children)];
}

function localDateTimeInput(value: number): string {
  const date = new Date(value * 1000);
  const pad = (number: number) => String(number).padStart(2, "0");
  const milliseconds = date.getMilliseconds();
  const fraction = milliseconds
    ? `.${String(milliseconds).padStart(3, "0")}`
    : "";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${fraction}`;
}

function findComponent(node: unknown, name: string): ReactElement | undefined {
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findComponent(item, name);
      if (found) return found;
    }
  } else if (
    typeof node === "object" &&
    node !== null &&
    "props" in node &&
    "type" in node
  ) {
    const element = node as ReactElement<{ children?: unknown }>;
    if (typeof element.type === "function" && element.type.name === name)
      return element;
    return findComponent(element.props.children, name);
  }
  return undefined;
}

function clickButton(tree: unknown, label: string) {
  const button = findButton(tree, label);
  if (!button?.props.onClick) throw new Error(`Button not found: ${label}`);
  button.props.onClick({} as never);
}

afterEach(() => {
  for (const cleanup of hookHarness.effectCleanups) cleanup?.();
  hookHarness.active = false;
  hookHarness.cursor = 0;
  hookHarness.stateSlots = [];
  hookHarness.refSlots = [];
  hookHarness.memoSlots = [];
  hookHarness.pendingEffects = [];
  hookHarness.effectDependencies = [];
  hookHarness.effectCleanups = [];
  vi.unstubAllGlobals();
});
