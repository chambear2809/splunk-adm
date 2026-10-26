#!/usr/bin/env node
/**
 * Measure Atlas's ThousandEyes query builder, strict adapters, attribution, and
 * comparison pipeline using deterministic synthetic package-shaped fixtures.
 * This tool never contacts Splunk, ThousandEyes, Docker, or customer systems.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "vite";
import { cpus, freemem, platform, release, totalmem, arch } from "node:os";
import { dirname, join, resolve, relative } from "node:path";
import { performance } from "node:perf_hooks";

const ROOT = resolve(import.meta.dirname, "..");
const FIXTURE_DIR = join(ROOT, "fixtures", "thousandeyes");
const BASE = 1_700_000_000;
const WINDOW = { start: BASE, end: BASE + 3_600 };
const RUN_DEFAULT = 7;
const WARMUP_DEFAULT = 2;
const SOURCE_FILES = [
  "frontend/src/data/evidence.ts",
  "frontend/src/data/evidenceConfig.ts",
  "frontend/src/data/supplementalEvidence.ts",
  "frontend/src/data/thousandEyesTypes.ts",
  "frontend/src/data/thousandEyesConfiguration.ts",
  "frontend/src/data/thousandEyesAdapters.ts",
  "frontend/src/data/thousandEyesAttribution.ts",
  "frontend/src/data/thousandEyesEvidence.ts",
  "tools/benchmark_thousandeyes.mjs",
  "package.json",
  "package-lock.json",
  "fixtures/thousandeyes/activity-v2.json",
  "fixtures/thousandeyes/alert.json",
  "fixtures/thousandeyes/event.json",
  "fixtures/thousandeyes/metric-v2.json",
  "fixtures/thousandeyes/path-cea-anonymous.json",
  "fixtures/thousandeyes/path-export-wrapper.json",
  "fixtures/thousandeyes/trace-v2.json",
];
const FAMILY_MIX = [
  ...Array(24).fill("metric"),
  ...Array(16).fill("path"),
  ...Array(12).fill("trace"),
  ...Array(4).fill("event"),
  ...Array(4).fill("alert"),
  ...Array(4).fill("activity"),
];

function help() {
  process.stdout.write(
    `Usage: node tools/benchmark_thousandeyes.mjs --output PATH [options]\n\nOptions:\n  --output PATH    Write the source-fingerprinted JSON report (required)\n  --runs N         Timed runs per operation, 3..30 (default ${RUN_DEFAULT})\n  --warmup N       Untimed warmups per operation, 0..10 (default ${WARMUP_DEFAULT})\n  --help           Show this help\n\nThe benchmark uses only deterministic local fixtures and Atlas modules. It does\nnot query ThousandEyes or Splunk and does not start Docker or a lab.\n`,
  );
}

function parseArgs(args) {
  const options = {
    output: undefined,
    runs: RUN_DEFAULT,
    warmup: WARMUP_DEFAULT,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return { help: true };
    if (!["--output", "--runs", "--warmup"].includes(argument))
      throw new Error(`CLI: unknown option ${argument}`);
    const value = args[index + 1];
    if (!value || value.startsWith("--"))
      throw new Error(`CLI: ${argument} requires a value.`);
    index += 1;
    if (argument === "--output") options.output = value;
    else {
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed))
        throw new Error(`CLI: ${argument} requires an integer.`);
      if (argument === "--runs") options.runs = parsed;
      else options.warmup = parsed;
    }
  }
  if (!options.output) throw new Error("CLI: --output PATH is required.");
  if (options.runs < 3 || options.runs > 30)
    throw new Error("CLI: --runs must be in 3..30.");
  if (options.warmup < 0 || options.warmup > 10)
    throw new Error("CLI: --warmup must be in 0..10.");
  return options;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function idHex(number, length) {
  return number.toString(16).padStart(length, "0").slice(-length);
}

function iso(seconds) {
  return new Date(seconds * 1_000).toISOString();
}

function setOtelAttribute(attributes, key, value) {
  const entry = attributes.find((item) => item.key === key);
  if (!entry) throw new Error(`Fixture is missing OTel attribute ${key}.`);
  const current = entry.value;
  if (current.string_value !== undefined) current.string_value = String(value);
  else if (current.int_value !== undefined) current.int_value = Number(value);
  else throw new Error(`Fixture has an unsupported OTel type for ${key}.`);
}

function setOtelTimes(raw, seconds) {
  if (raw.resource_metrics) {
    for (const resource of raw.resource_metrics) {
      for (const scope of resource.scope_metrics ?? []) {
        for (const metric of scope.metrics ?? []) {
          for (const point of metric.gauge?.data_points ?? [])
            point.time_unix_nano = String(BigInt(seconds) * 1_000_000_000n);
          for (const point of metric.sum?.data_points ?? [])
            point.time_unix_nano = String(BigInt(seconds) * 1_000_000_000n);
        }
      }
    }
  }
  if (raw.resource_spans) {
    for (const resource of raw.resource_spans) {
      for (const scope of resource.scope_spans ?? []) {
        for (const span of scope.spans ?? []) {
          span.start_time_unix_nano = String(BigInt(seconds) * 1_000_000_000n);
          span.end_time_unix_nano = String(
            BigInt(seconds + 1) * 1_000_000_000n,
          );
        }
      }
    }
  }
  if (raw.resource_logs) {
    for (const resource of raw.resource_logs) {
      for (const scope of resource.scope_logs ?? []) {
        for (const log of scope.log_records ?? []) {
          log.time_unix_nano = String(BigInt(seconds) * 1_000_000_000n);
          log.observed_time_unix_nano = String(
            BigInt(seconds + 1) * 1_000_000_000n,
          );
        }
      }
    }
  }
}

function buildConfig({
  mappingCount = 1,
  bindingsPerMapping = 32,
  overlapHeavy = false,
} = {}) {
  const indexes = [
    "te_metrics",
    "te_traces",
    "te_activity",
    "te_events",
    "te_alerts",
    "te_paths",
  ];
  const mappings = [];
  const authorities = [];
  for (let mappingIndex = 0; mappingIndex < mappingCount; mappingIndex += 1) {
    const authority = `te-benchmark-${String(mappingIndex).padStart(2, "0")}`;
    const accountGroupId = String(123_400 + mappingIndex);
    const streamAccountId = String(567_800 + mappingIndex);
    const alertAccountId = String(678_900 + mappingIndex);
    const families =
      mappingIndex === 0
        ? ["metric", "path", "trace", "event", "alert", "activity"]
        : ["metric", "trace", "event", "alert", "activity"];
    const bindings = [];
    for (
      let bindingIndex = 0;
      bindingIndex < bindingsPerMapping;
      bindingIndex += 1
    ) {
      const testSlot = overlapHeavy ? 0 : Math.floor(bindingIndex / 8);
      const agentSlot = overlapHeavy ? 0 : Math.floor(bindingIndex / 2) % 4;
      const domain = overlapHeavy
        ? "cea"
        : bindingIndex % 2 === 0
          ? "cea"
          : "endpoint";
      bindings.push({
        id: `binding-${mappingIndex}-${bindingIndex}`,
        authority,
        accountGroupId,
        scope: "benchmark-site",
        testId: overlapHeavy ? "17000" : String(17_000 + testSlot),
        agentId: overlapHeavy ? "29000" : String(29_000 + agentSlot),
        testDomain: domain,
        target: { ip: "198.51.100.20", protocol: "tcp", port: 443 },
        endpointAddresses: ["192.0.2.8"],
        validFrom: BASE,
        validTo: BASE + 3_600,
        configurationId: overlapHeavy
          ? `overlap-config-${bindingIndex}`
          : `config-${testSlot}-${agentSlot}-${domain}`,
      });
    }
    authorities.push(authority);
    mappings.push({
      observer_kind: "thousandeyes_account_group",
      observer: authority,
      scope: "benchmark-site",
      cluster: "",
      mapping_status: "verified",
      te_account_group_id: accountGroupId,
      te_stream_account_id: streamAccountId,
      te_alert_account_id: alertAccountId,
      te_organization_id: `org-benchmark-${mappingIndex}`,
      te_families: JSON.stringify(families),
      te_bindings: JSON.stringify(bindings),
      te_path_sources:
        mappingIndex === 0
          ? JSON.stringify([
              { index: "te_paths", source: "test_metrics_stream://benchmark" },
              { index: "te_paths", source: "atlas:thousandeyes:path" },
            ])
          : "[]",
      thousandeyes_origin: "https://app.thousandeyes.com",
    });
  }
  return {
    source: "thousandeyes",
    state: "active",
    indexes,
    authorities,
    schemaQualified: true,
    staleAfterSeconds: 1_200,
    mappings,
  };
}

function buildSelection() {
  return {
    schemaVersion: 1,
    workflow: "endpoint",
    selectionId: "endpoint:192.0.2.8",
    trafficContract: 1,
    window: WINDOW,
    scope: "benchmark-site",
    addresses: ["192.0.2.8"],
    identityAddresses: ["192.0.2.8"],
    contexts: [],
    identityBasis: "synthetic benchmark endpoint",
    configurationFingerprint: "b".repeat(64),
  };
}

function cloneRowTemplate(templates, family, sequence, options = {}) {
  const index = sequence;
  const testId = options.testId ?? String(17_000 + (index % 8));
  const agentId =
    options.agentId ?? String(29_000 + (Math.floor(index / 2) % 4));
  const domain = options.domain ?? (index % 2 === 0 ? "cea" : "endpoint");
  const eventTime =
    options.eventTime ??
    BASE + 20 + (index % 2 === 0 ? 400 : 2_200) + (index % 100);
  let raw = structuredClone(templates[family]);
  let origin;

  switch (family) {
    case "metric": {
      origin = {
        index: "te_metrics",
        source: "cisco:thousandeyes:stream",
        sourcetype: "cisco:thousandeyes:metric",
      };
      const resource = raw.resource_metrics[0];
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.account.id",
        "567800",
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.test.id",
        testId,
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.test.domain",
        domain,
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.source.agent.id",
        agentId,
      );
      if (options.value !== undefined) {
        resource.scope_metrics[0].metrics[0].gauge.data_points[0].as_double =
          options.value;
      }
      setOtelTimes(raw, eventTime);
      break;
    }
    case "trace": {
      origin = {
        index: "te_traces",
        source: "cisco:thousandeyes:stream",
        sourcetype: "cisco:thousandeyes:trace",
      };
      const resource = raw.resource_spans[0];
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.account.id",
        "567800",
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.test.id",
        testId,
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.test.domain",
        domain,
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.source.agent.id",
        agentId,
      );
      const span = resource.scope_spans[0].spans[0];
      span.trace_id = idHex(sequence + 1, 32);
      span.span_id = idHex(sequence + 1, 16);
      setOtelTimes(raw, eventTime);
      break;
    }
    case "activity": {
      origin = {
        index: "te_activity",
        source: "cisco:thousandeyes:stream",
        sourcetype: "cisco:thousandeyes:activity",
      };
      const resource = raw.resource_logs[0];
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.account.id",
        "567800",
      );
      setOtelAttribute(
        resource.resource.attributes,
        "thousandeyes.stream.id",
        `activity-stream-${sequence}`,
      );
      resource.scope_logs[0].log_records[0].body.string_value = `Synthetic activity ${sequence}`;
      setOtelTimes(raw, eventTime);
      break;
    }
    case "path": {
      origin = {
        index: "te_paths",
        source: "atlas:thousandeyes:path",
        sourcetype: "atlas:thousandeyes:path",
      };
      raw.capture_id = `capture-${sequence}`;
      raw.authority = "te-benchmark-00";
      raw.account_group_id = "123400";
      raw.test_id = options.testId ?? "17000";
      raw.test_domain = "cea";
      raw.collection_started_at = eventTime + 2;
      raw.collection_completed_at = eventTime + 5;
      raw.result.date = iso(eventTime);
      raw.result.roundId = eventTime;
      raw.result.startTime = eventTime;
      raw.result.endTime = eventTime + 4;
      raw.result.agent.agentId = options.agentId ?? "29000";
      raw.result.agent.agentName = `Synthetic agent ${sequence % 4}`;
      const pathCount = options.pathCount ?? 1;
      const hopCount = options.hopCount ?? 16;
      raw.result.pathTraces = Array.from(
        { length: pathCount },
        (_, pathIndex) => ({
          pathId: `path-${sequence}-${pathIndex}`,
          numberOfHops: hopCount,
          responseTime: 25.5 + pathIndex,
          hops: Array.from({ length: hopCount }, (_, hopIndex) => ({
            hop: hopIndex + 1,
            ipAddress:
              hopIndex === hopCount - 1
                ? "198.51.100.20"
                : `203.0.113.${(hopIndex % 240) + 1}`,
            responseTime: Number((1.2 + hopIndex * 0.45).toFixed(2)),
          })),
        }),
      );
      break;
    }
    case "event": {
      origin = {
        index: "te_events",
        source: "test_metrics_stream://benchmark",
        sourcetype: "cisco:thousandeyes:event",
      };
      raw.aid = "123400";
      raw.id = `event-${sequence}`;
      raw.startDate = iso(eventTime);
      raw.endDate = null;
      raw.affectedTargets = {
        total: 1,
        affectedTestIds: [testId],
        affectedAgentIds: [agentId],
      };
      break;
    }
    case "alert": {
      origin = {
        index: "te_alerts",
        source: "cisco:thousandeyes:webhook",
        sourcetype: "cisco:thousandeyes:alerts",
      };
      raw.eventId = `alert-${sequence}`;
      raw.accountId = "678900";
      raw.orgId = "org-benchmark-0";
      raw.alert.triggered.epochMilli = eventTime * 1_000;
      raw.alert.cleared = false;
      raw.alert.test.id = testId;
      raw.alert.test.name = `Synthetic test ${testId}`;
      break;
    }
    default:
      throw new Error(`Unknown fixture family: ${family}`);
  }

  return makeRow(raw, origin, eventTime);
}

function makeRow(rawValue, origin, eventTime, rawOverride) {
  const raw = rawOverride ?? JSON.stringify(rawValue);
  const eventFingerprint = sha256(
    JSON.stringify([origin.index, origin.source, origin.sourcetype, raw]),
  );
  return {
    kind: "supplemental_record",
    ...origin,
    _raw: raw,
    event_fingerprint: eventFingerprint,
    row_time_epoch: eventTime + 30,
    indexed_time_epoch: eventTime + 45,
    record_truncated: false,
    input_capped: false,
    output_capped: false,
  };
}

function makeRows(templates, families, options = {}) {
  const rows = [];
  const counts = Object.fromEntries(
    ["metric", "path", "trace", "event", "alert", "activity"].map((family) => [
      family,
      0,
    ]),
  );
  for (const family of families) {
    const familyIndex = counts[family]++;
    const sequence = rows.length;
    rows.push(
      cloneRowTemplate(templates, family, sequence, {
        testId: String(17_000 + (familyIndex % 4)),
        agentId: String(29_000 + (Math.floor(familyIndex / 4) % 4)),
        domain:
          family === "path" ? "cea" : familyIndex % 2 ? "endpoint" : "cea",
        ...options.rowOptions?.[family],
      }),
    );
  }
  return rows;
}

function makeTypicalRows(templates, options = {}) {
  return makeRows(templates, FAMILY_MIX, options);
}

function makeReplayMalformedRows(templates) {
  const valid = makeRows(
    templates,
    Array.from(
      { length: 48 },
      (_, index) =>
        ["metric", "trace", "path", "event", "alert", "activity"][index % 6],
    ),
  );
  const seed = valid.find(
    (row) => row.sourcetype === "cisco:thousandeyes:metric",
  );
  if (!seed) throw new Error("Replay scenario has no metric seed.");
  const exactReplay = Array.from({ length: 4 }, () => ({ ...seed }));
  const seedPayload = JSON.parse(seed._raw);
  const metric = seedPayload.resource_metrics[0].scope_metrics[0].metrics[0];
  metric.gauge.data_points[0].as_double += 0.25;
  const conflictRaw = JSON.stringify(seedPayload);
  const conflictingReplays = Array.from({ length: 4 }, () =>
    makeRow(
      seedPayload,
      {
        index: seed.index,
        source: seed.source,
        sourcetype: seed.sourcetype,
      },
      seed.row_time_epoch - 30,
      conflictRaw,
    ),
  );
  const malformed = Array.from({ length: 4 }, (_, index) =>
    makeRow(
      {},
      {
        index: "te_metrics",
        source: "cisco:thousandeyes:stream",
        sourcetype: "cisco:thousandeyes:metric",
      },
      BASE + 60 + index,
      '{"resource_metrics":[{"resource":{},"resource":{}}]}',
    ),
  );
  const anonymousPath = JSON.parse(templates["path-anonymous"]);
  const anonymousRows = Array.from({ length: 4 }, (_, index) =>
    makeRow(
      anonymousPath,
      {
        index: "te_paths",
        source: "test_metrics_stream://benchmark",
        sourcetype: "cisco:thousandeyes:path-vis",
      },
      BASE + 70 + index,
    ),
  );
  return [
    ...valid,
    ...exactReplay,
    ...conflictingReplays,
    ...malformed,
    ...anonymousRows,
  ];
}

function makePathExpansionRows(
  templates,
  count,
  pathCount,
  hopCount,
  overlapHeavy = false,
) {
  return Array.from({ length: count }, (_, index) =>
    cloneRowTemplate(templates, "path", index, {
      testId: overlapHeavy ? "17000" : String(17_000 + (index % 4)),
      agentId: overlapHeavy
        ? "29000"
        : String(29_000 + (Math.floor(index / 4) % 4)),
      pathCount,
      hopCount,
    }),
  );
}

function percentile(samples, percentileValue) {
  if (!samples.length) return 0;
  const sorted = [...samples].sort((left, right) => left - right);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil(percentileValue * sorted.length) - 1),
  );
  return sorted[index];
}

function summarizeSamples(samples) {
  const durations = samples.map((sample) => sample.durationMilliseconds);
  const heapDeltas = samples.map((sample) => sample.heapDeltaBytes);
  const retainedDeltas = samples
    .map((sample) => sample.retainedHeapDeltaBytesAfterGc)
    .filter((value) => value !== null);
  return {
    runs: samples.length,
    medianMilliseconds: Number(percentile(durations, 0.5).toFixed(3)),
    p95Milliseconds: Number(percentile(durations, 0.95).toFixed(3)),
    maxMilliseconds: Number(Math.max(...durations).toFixed(3)),
    medianHeapDeltaBytes: Math.round(percentile(heapDeltas, 0.5)),
    medianRetainedHeapDeltaBytesAfterGc:
      retainedDeltas.length > 0
        ? Math.round(percentile(retainedDeltas, 0.5))
        : null,
    memoryMethod:
      retainedDeltas.length > 0
        ? "heapUsed delta after full GC with returned value retained; not peak memory"
        : "heapUsed delta during operation; no forced GC available; not peak memory",
  };
}

function measure(operation, { runs, warmup }) {
  let lastValue;
  for (let index = 0; index < warmup; index += 1) lastValue = operation();
  const samples = [];
  for (let index = 0; index < runs; index += 1) {
    if (globalThis.gc) globalThis.gc();
    const heapBefore = process.memoryUsage().heapUsed;
    const started = performance.now();
    let value = operation();
    const durationMilliseconds = performance.now() - started;
    const heapAfterOperation = process.memoryUsage().heapUsed;
    let retainedHeapDeltaBytesAfterGc = null;
    if (globalThis.gc) {
      globalThis.gc();
      retainedHeapDeltaBytesAfterGc =
        process.memoryUsage().heapUsed - heapBefore;
    }
    samples.push({
      durationMilliseconds,
      heapDeltaBytes: heapAfterOperation - heapBefore,
      retainedHeapDeltaBytesAfterGc,
    });
    lastValue = value;
    value = undefined;
  }
  return { stats: summarizeSamples(samples), value: lastValue };
}

function stateCounts(records) {
  return records.reduce(
    (counts, record) => {
      counts[record.attribution.state] += 1;
      return counts;
    },
    { bound: 0, context_only: 0, ambiguous: 0, unmatched: 0 },
  );
}

function rowBytes(rows) {
  return rows.reduce(
    (total, row) => total + Buffer.byteLength(row._raw ?? "", "utf8"),
    0,
  );
}

function contractSummary(search, limits) {
  const coarseFilter = search.indexOf("| where case(");
  const inputCap = search.indexOf(`| head ${limits.input + 1}`);
  const outputCap = search.indexOf(`| head ${limits.records}`);
  return {
    inputCapRows: limits.input,
    scanSentinelRows: limits.input + 1,
    displayedRows: limits.records,
    nativeTimeFilterBeforeInputCap:
      coarseFilter >= 0 && inputCap > coarseFilter,
    displayCapAfterInputCap: outputCap > inputCap,
    usesSplunkTimeAsMeasurementBound: /\b_time\s*(?:>=|<=|>|<|=)/.test(search),
    usesIndexTimeAsMeasurementBound: /\b_indextime\s*(?:>=|<=|>|<|=)/.test(
      search,
    ),
    caveat:
      "This benchmark measures local Atlas builders/adapters only; it does not execute SPL or measure Splunk scan, license, storage, concurrency, or cancellation cost.",
  };
}

async function loadTemplates() {
  const [metric, trace, pathWrapper, pathAnonymous, activity, event, alert] =
    await Promise.all(
      [
        "metric-v2.json",
        "trace-v2.json",
        "path-export-wrapper.json",
        "path-cea-anonymous.json",
        "activity-v2.json",
        "event.json",
        "alert.json",
      ].map(async (name) =>
        JSON.parse(await readFile(join(FIXTURE_DIR, name), "utf8")),
      ),
    );
  return {
    metric,
    trace,
    path: pathWrapper,
    "path-anonymous": JSON.stringify(pathAnonymous),
    activity,
    event,
    alert,
  };
}

function makeScenarios(templates, limits) {
  const maxRows = limits.records;
  const typicalConfig = buildConfig({
    mappingCount: 1,
    bindingsPerMapping: 32,
  });
  const maxBindingConfig = buildConfig({
    mappingCount: 1,
    bindingsPerMapping: 64,
  });
  const maxGroupConfig = buildConfig({
    mappingCount: 32,
    bindingsPerMapping: 64,
  });
  const overlapConfig = buildConfig({
    mappingCount: 1,
    bindingsPerMapping: 64,
    overlapHeavy: true,
  });
  const selection = buildSelection();
  const expansionConfig = buildConfig({
    mappingCount: 1,
    bindingsPerMapping: 64,
  });
  const allFamilies = makeTypicalRows(templates);
  return [
    {
      name: "representative-six-family-mix",
      config: typicalConfig,
      selection,
      rows: allFamilies,
      workload: {
        accountGroups: 1,
        exercisedTests: 4,
        exercisedAgents: 4,
        testDomains: ["cea", "endpoint"],
        configuredBindings: 32,
        inputRowsByFamily: {
          metric: 24,
          path: 16,
          trace: 12,
          event: 4,
          alert: 4,
          activity: 4,
        },
        hopsPerPath: 16,
        interpretation:
          "Synthetic bounded UI result mix; it is a reproducible workload shape, not a claim about a real tenant's family distribution.",
      },
    },
    {
      name: "maximum-bindings-one-account-group",
      config: maxBindingConfig,
      selection,
      rows: allFamilies,
      workload: {
        accountGroups: 1,
        exercisedTests: 4,
        exercisedAgents: 4,
        testDomains: ["cea", "endpoint"],
        configuredBindings: 64,
        inputRows: allFamilies.length,
        hopsPerPath: 16,
        interpretation:
          "One mapping at the current 64-binding configuration limit; selected rows use synthetic CEA and Endpoint IDs.",
      },
    },
    {
      name: "maximum-mapping-and-binding-cardinality",
      config: maxGroupConfig,
      selection,
      rows: allFamilies,
      workload: {
        accountGroups: 32,
        testsPerAccountGroup: 8,
        agentsPerAccountGroup: 4,
        testDomains: ["cea", "endpoint"],
        bindingsPerAccountGroup: 64,
        configuredBindings: 2_048,
        selectedInputRows: allFamilies.length,
        interpretation:
          "Upper configuration cardinality of 32 account-group mappings and 64 bindings each; the rows belong to one synthetic account group.",
      },
    },
    {
      name: "overlap-heavy-binding-ambiguity",
      config: overlapConfig,
      selection,
      rows: makePathExpansionRows(templates, maxRows, 1, 32, true),
      workload: {
        accountGroups: 1,
        tests: 1,
        agents: 1,
        overlappingBindings: 64,
        inputRows: maxRows,
        pathTracesPerRow: 1,
        hopsPerPath: 32,
        expectedAttribution: "ambiguous",
      },
    },
    {
      name: "path-detail-expansion-at-display-cap",
      config: expansionConfig,
      selection,
      rows: makePathExpansionRows(templates, 32, 2, 24),
      workload: {
        accountGroups: 1,
        exercisedTests: 4,
        exercisedAgents: 4,
        configuredBindings: 64,
        inputRows: 32,
        pathTracesPerRow: 2,
        hopsPerPath: 24,
        expectedNormalizedRecords: 64,
      },
    },
    {
      name: "replay-conflict-and-malformed-rows",
      config: maxBindingConfig,
      selection,
      rows: makeReplayMalformedRows(templates),
      workload: {
        accountGroups: 1,
        bindings: 64,
        inputRows: maxRows,
        exactReplayRows: 4,
        conflictingReplayRows: 4,
        malformedJsonRows: 4,
        anonymousCeaPathRows: 4,
        interpretation:
          "Exact duplicate rows are replayed, conflicting copies change one metric value under the same native identity, and malformed/anonymous source forms remain rejected.",
      },
    },
    {
      name: "adapter-row-count-over-cap",
      config: maxBindingConfig,
      selection,
      rows: [...allFamilies, allFamilies[0]],
      workload: {
        accountGroups: 1,
        bindings: 64,
        inputRows: maxRows + 1,
        inputLimit: maxRows,
        expected: "normalizer rejects the oversized client adapter batch",
        interpretation:
          "Exercises the adapter's 64-row result boundary; the 10,000-row server scan cap is inspected in the generated SPL but not executed here.",
      },
    },
    {
      name: "path-detail-expansion-over-cap",
      config: expansionConfig,
      selection,
      rows: makePathExpansionRows(
        templates,
        Math.floor(maxRows / 2) + 1,
        2,
        24,
      ),
      workload: {
        accountGroups: 1,
        bindings: 64,
        inputRows: 33,
        pathTracesPerRow: 2,
        hopsPerPath: 24,
        expectedNormalizedRecordCap: maxRows,
        interpretation:
          "Expands 33 rows into 66 path records; the adapter keeps at most 64 and reports the overflow as rejected/incomplete.",
      },
    },
  ];
}

async function hashSources() {
  const files = [];
  for (const name of SOURCE_FILES) {
    const bytes = await readFile(join(ROOT, name));
    files.push({ path: name, bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  const sourceFingerprint = sha256(
    files.map((entry) => `${entry.path}\0${entry.sha256}\n`).join(""),
  );
  let gitRevision = null;
  try {
    gitRevision = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    // The content fingerprint is authoritative when source archives omit Git.
  }
  return { files, sourceFingerprint, gitRevision };
}

async function packageVersion() {
  try {
    const packageJson = JSON.parse(
      await readFile(join(ROOT, "package.json"), "utf8"),
    );
    const [viteInstalled, typescriptInstalled] = await Promise.all([
      readFile(join(ROOT, "node_modules/vite/package.json"), "utf8"),
      readFile(join(ROOT, "node_modules/typescript/package.json"), "utf8"),
    ]);
    return {
      viteDeclared: packageJson.devDependencies?.vite ?? null,
      viteInstalled: JSON.parse(viteInstalled).version,
      typescriptDeclared: packageJson.devDependencies?.typescript ?? null,
      typescriptInstalled: JSON.parse(typescriptInstalled).version,
    };
  } catch {
    return {
      viteDeclared: null,
      viteInstalled: null,
      typescriptDeclared: null,
      typescriptInstalled: null,
    };
  }
}

async function runBenchmark(options) {
  const templates = await loadTemplates();
  const source = await hashSources();
  const vite = await createServer({
    configFile: false,
    root: ROOT,
    define: { __ADM_SPLUNK_BUILD__: "false" },
    appType: "custom",
    logLevel: "silent",
    server: { middlewareMode: true },
  });
  try {
    const evidenceCore = await vite.ssrLoadModule(
      "/frontend/src/data/evidence.ts",
    );
    const limits = evidenceCore.EVIDENCE_LIMITS;
    const scenarios = makeScenarios(templates, limits);
    const evidence = await vite.ssrLoadModule(
      "/frontend/src/data/thousandEyesEvidence.ts",
    );
    const adapters = await vite.ssrLoadModule(
      "/frontend/src/data/thousandEyesAdapters.ts",
    );
    const attribution = await vite.ssrLoadModule(
      "/frontend/src/data/thousandEyesAttribution.ts",
    );
    const configuration = await vite.ssrLoadModule(
      "/frontend/src/data/thousandEyesConfiguration.ts",
    );
    const results = [];
    for (const scenario of scenarios) {
      const search = evidence.buildThousandEyesSearch(
        scenario.config,
        scenario.selection,
      );
      const contract = contractSummary(search, limits);
      if (
        !contract.nativeTimeFilterBeforeInputCap ||
        !contract.displayCapAfterInputCap ||
        contract.usesSplunkTimeAsMeasurementBound ||
        contract.usesIndexTimeAsMeasurementBound
      )
        throw new Error(`Search cap/time contract changed: ${scenario.name}`);

      const parsedMappings = configuration.thousandEyesMappings(
        scenario.config,
        scenario.selection,
      );
      const bindings = parsedMappings.flatMap((mapping) => mapping.bindings);
      const timed = {
        queryBuild: measure(
          () =>
            evidence.buildThousandEyesSearch(
              scenario.config,
              scenario.selection,
            ),
          options,
        ),
        adapterNormalization: measure(
          () =>
            adapters.normalizeThousandEyesRows(
              scenario.rows,
              scenario.selection,
              scenario.config,
            ),
          options,
        ),
        attribution: measure(
          () =>
            attribution.attributeThousandEyesRecords(
              adapters.normalizeThousandEyesRows(
                scenario.rows,
                scenario.selection,
                scenario.config,
              ).records,
              scenario.selection,
              bindings,
            ),
          options,
        ),
        integratedNormalizeAndAttribute: measure(
          () =>
            evidence.normalizeThousandEyesEvidence(
              scenario.rows,
              scenario.selection,
              scenario.config,
            ),
          options,
        ),
      };
      const integrated = timed.integratedNormalizeAndAttribute.value;
      const comparison = measure(
        () =>
          attribution.compareThousandEyesMeasurements(
            integrated.records,
            { start: BASE, end: BASE + 1_800 },
            { start: BASE + 1_800, end: BASE + 3_600 },
          ),
        options,
      );
      results.push({
        name: scenario.name,
        workload: scenario.workload,
        inputRawBytes: rowBytes(scenario.rows),
        configurationBytes: Buffer.byteLength(
          JSON.stringify(scenario.config.mappings),
          "utf8",
        ),
        configuredAccountGroups: scenario.config.mappings.length,
        configuredBindings: bindings.length,
        searchContract: contract,
        queryBuild: timed.queryBuild.stats,
        adapterNormalization: {
          ...timed.adapterNormalization.stats,
          normalizedRecords: timed.adapterNormalization.value.records.length,
          rejectedRows: timed.adapterNormalization.value.rejected,
        },
        attribution: {
          ...timed.attribution.stats,
          attributedRecords: timed.attribution.value.length,
          states: stateCounts(timed.attribution.value),
        },
        integratedNormalizeAndAttribute: {
          ...timed.integratedNormalizeAndAttribute.stats,
          normalizedRecords: integrated.records.length,
          rejectedRows: integrated.rejected,
          attributionStates: stateCounts(integrated.records),
          outputHopCount: integrated.records.reduce(
            (count, record) => count + record.hops.length,
            0,
          ),
          outputSpanCount: integrated.records.reduce(
            (count, record) => count + record.spans.length,
            0,
          ),
        },
        measurementComparison: {
          ...comparison.stats,
          comparisonGroups: comparison.value.length,
        },
      });
      // Use the integrated actual output for an overall structural checksum.
      results.at(-1).outputFingerprint = sha256(
        JSON.stringify(
          integrated.records.map((record) => [
            record.family,
            record.fingerprint,
            record.interval.start,
            record.interval.end,
            record.attribution.state,
          ]),
        ),
      );
    }

    return {
      schemaVersion: "thousandeyes.benchmark.v1",
      capturedAt: new Date().toISOString(),
      purpose:
        "Local deterministic measurement of Atlas query building, normalization, attribution, and measurement comparison; not a Splunk or ThousandEyes capacity qualification.",
      safety: {
        externalNetworkCalls: false,
        splunkCalls: false,
        thousandEyesApiCalls: false,
        dockerOrLab: false,
        customerData: false,
      },
      source: {
        ...source,
        fingerprintAlgorithm:
          "sha256 over sorted relative-path and file-SHA256 pairs",
      },
      runtime: {
        node: process.version,
        v8: process.versions.v8,
        platform: platform(),
        platformRelease: release(),
        architecture: arch(),
        cpu: cpus()[0]?.model ?? "unknown",
        logicalCpuCount: cpus().length,
        totalMemoryBytes: totalmem(),
        freeMemoryBytesAtReport: freemem(),
        gcExposed: typeof globalThis.gc === "function",
        runs: options.runs,
        warmupRuns: options.warmup,
        packageVersions: await packageVersion(),
      },
      limits: {
        inputRows: limits.input,
        sourceScanSentinelRows: limits.input + 1,
        displayedRows: limits.records,
        perRawRecordBytes: limits.recordBytes,
        totalConfiguredIndexes: 16,
        accountGroupMappings: 32,
        bindingsPerAccountGroup: 64,
        pathSourcesPerAccountGroup: 16,
        actualSplunkSearchExecuted: false,
      },
      workloadNotes: [
        "Fixture values use documentation-only address ranges and synthetic IDs.",
        "The six-family mix is an explicit synthetic profile; no live tenant distribution was available or assumed.",
        "The application query's 10,000-input scan cap is validated by inspecting generated SPL ordering; indexer execution and scan cost are not measured.",
        "The client adapter accepts at most 64 input rows and at most 64 normalized records; cap scenarios measure those local boundaries.",
        "Memory deltas use Node heapUsed. Retained-after-GC values keep the result live and are not peak-memory measurements; run with --expose-gc for both views.",
      ],
      scenarios: results,
    };
  } finally {
    await vite.close();
  }
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    help();
    process.exit(0);
  }
  const report = await runBenchmark(options);
  const output = resolve(options.output);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
  });
  const summary = {
    output: relative(ROOT, output) || output,
    sourceFingerprint: report.source.sourceFingerprint,
    gitRevision: report.source.gitRevision,
    scenarios: report.scenarios.map((scenario) => ({
      name: scenario.name,
      integratedMedianMs:
        scenario.integratedNormalizeAndAttribute.medianMilliseconds,
      integratedP95Ms: scenario.integratedNormalizeAndAttribute.p95Milliseconds,
      normalizedRecords:
        scenario.integratedNormalizeAndAttribute.normalizedRecords,
      rejectedRows: scenario.integratedNormalizeAndAttribute.rejectedRows,
      attributionStates:
        scenario.integratedNormalizeAndAttribute.attributionStates,
    })),
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} catch (error) {
  if (error instanceof Error && error.message.startsWith("CLI:")) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  } else {
    process.stderr.write(
      `${error instanceof Error ? error.message : "Benchmark failed."}\n`,
    );
    process.exitCode = 1;
  }
}
