import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";

const [
  baselinePath,
  candidatePath,
  destination = "dist/performance/report.md",
] = process.argv.slice(2);
if (!baselinePath)
  throw new Error(
    "Usage: node tests/performance/report.mjs baseline.json [candidate.json] [report.md]",
  );
const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
const candidate = candidatePath
  ? JSON.parse(await readFile(candidatePath, "utf8"))
  : undefined;
function valid(report) {
  if (
    !report.complete ||
    !report.source.unchangedDuringRun ||
    !report.harnessUnchangedDuringRun
  )
    throw new Error(
      "Incomplete evidence or source/harness changed during the run",
    );
}
valid(baseline);
if (candidate) valid(candidate);
const key = (sample) =>
  `${sample.scenario}/${sample.size}${sample.partial ? "/partial" : ""}/${sample.cache}`;
const quantile = (sorted, p) =>
  sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)];
function stats(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    samples: sorted.length,
    min: sorted[0],
    median:
      sorted.length % 2
        ? sorted[(sorted.length - 1) / 2]
        : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2,
    p95: quantile(sorted, 0.95),
    max: sorted.at(-1),
  };
}
const sum = (rows, get) => rows.reduce((total, row) => total + get(row), 0);
function values(sample) {
  const timing = {
    mountMs: sample.mount.mountToUsableMs,
    startupMs: sample.startup.harnessReadyMsSinceNavigation,
    rowsTransformMs: sum(
      sample.mount.samples.filter(
        (row) => row.name === "rowsToGraph.integrated",
      ),
      (row) => row.duration,
    ),
    rowTransformCalls: sample.mount.samples.filter(
      (row) => row.name === "rowsToGraph.integrated",
    ).length,
    topologyTransformMs: sum(
      sample.mount.samples.filter(
        (row) => row.name === "rowsToTopology.integrated",
      ),
      (row) => row.duration,
    ),
    reactRenderMs: sum(sample.mount.renders, (row) => row.duration),
    browserLayoutMs: sample.browserMetricsMount.LayoutDuration,
    browserScriptMs: sample.browserMetricsMount.ScriptDuration,
    browserTaskMs: sample.browserMetricsMount.TaskDuration,
    mountLongTasks: sample.mount.longTasks.length,
    mountLongTaskMs: sum(sample.mount.longTasks, (row) => row.duration),
  };
  for (const [name, action] of Object.entries(sample.interactions))
    timing[`${name}Ms`] = action.duration;
  for (const item of sample.exports)
    timing[`${item.format}ExportMs`] = item.generationMs;
  for (const [name, measurements] of Object.entries(
    sample.microbenchmark.timings,
  ))
    timing[`isolated.${name}Ms`] = stats(measurements).median;
  return timing;
}
function groups(report) {
  const grouped = new Map();
  for (const sample of report.results) {
    const id = key(sample);
    if (!grouped.has(id)) grouped.set(id, []);
    grouped.get(id).push(sample);
  }
  return Object.fromEntries(
    [...grouped].map(([id, samples]) => {
      if (
        samples.some(
          (sample) => sample.mount.sha256 !== samples[0].mount.sha256,
        )
      )
        throw new Error(`Workload fingerprint varied within ${id}`);
      const measurements = samples.map(values);
      return [
        id,
        {
          workload: {
            nodes: samples[0].mount.nodes,
            edges: samples[0].mount.edges,
            topologyRows: samples[0].mount.topologyRows,
            inputBytes: samples[0].mount.inputBytes,
            sha256: samples[0].mount.sha256,
            networkClients: samples[0].mount.networkClients,
            clientAuthorities: samples[0].mount.clientAuthorities,
            attachmentRecords: samples[0].mount.attachmentRecords,
            trafficRecords: samples[0].mount.trafficRecords,
            uniqueTrafficFingerprints:
              samples[0].mount.uniqueTrafficFingerprints,
            handoffRecords: samples[0].mount.handoffRecords,
            handoffCoverage: samples[0].mount.handoffCoverage,
            topologyDevices: samples[0].mount.topologyDevices,
            topologyLinks: samples[0].mount.topologyLinks,
            sharedNativeClientGroups: samples[0].mount.sharedNativeClientGroups,
          },
          metrics: Object.fromEntries(
            Object.keys(measurements[0]).map((name) => [
              name,
              stats(measurements.map((row) => row[name])),
            ]),
          ),
        },
      ];
    }),
  );
}
const baseGroups = groups(baseline),
  nextGroups = candidate ? groups(candidate) : undefined;
if (candidate) {
  if (
    baseline.methodology.repetitionsPerCacheState !==
    candidate.methodology.repetitionsPerCacheState
  )
    throw new Error("Repetition counts differ");
  if (baseline.harnessSha256 !== candidate.harnessSha256)
    throw new Error("Harness hashes differ; remeasure with the same harness");
  if (JSON.stringify(baseline.runtime) !== JSON.stringify(candidate.runtime))
    throw new Error(
      "Runtime/hardware parameters differ; compare as separate environments",
    );
  if (
    JSON.stringify(Object.keys(baseGroups)) !==
    JSON.stringify(Object.keys(nextGroups))
  )
    throw new Error("Workload/cache matrices differ");
  for (const [id, base] of Object.entries(baseGroups))
    if (
      JSON.stringify(base.workload) !== JSON.stringify(nextGroups[id].workload)
    )
      throw new Error(`Workload differs: ${id}`);
}
// These investigation budgets are derived only after reading a measured baseline.
// They are intentionally not pass/fail assertions or product service objectives.
const investigationBudgets = Object.fromEntries(
  Object.entries(baseGroups).map(([id, group]) => [
    id,
    Object.fromEntries(
      Object.entries(group.metrics)
        .filter(([name]) => name.endsWith("Ms"))
        .map(([name, metric]) => [
          name,
          {
            baselineP95: metric.p95,
            provisionalMs:
              metric.p95 * 1.25 + (name.startsWith("isolated.") ? 2 : 10),
            candidateMedianExceeds: nextGroups
              ? nextGroups[id].metrics[name].median >
                metric.p95 * 1.25 + (name.startsWith("isolated.") ? 2 : 10)
              : undefined,
          },
        ]),
    ),
  ]),
);
const summary = {
  schemaVersion: 1,
  baseline: {
    source: baseline.source,
    runtime: baseline.runtime,
    harnessSha256: baseline.harnessSha256,
    samples: baseline.results.length,
    groups: baseGroups,
  },
  candidate: candidate
    ? {
        source: candidate.source,
        samples: candidate.results.length,
        groups: nextGroups,
      }
    : undefined,
  provisionalInvestigationBudgets: investigationBudgets,
};
const f = (number) => number.toFixed(1);
const lines = [
  "# Atlas browser performance evidence",
  "",
  `Baseline source: \`${baseline.source.sha}\`; tree hash \`${baseline.source.treeSha256}\`.`,
  "",
  `Harness: \`${baseline.harnessSha256}\`. Chromium ${baseline.runtime.browser}; Node ${baseline.runtime.node}; ${baseline.runtime.cpu}, ${baseline.runtime.logicalCpus} logical CPUs, ${Math.round(baseline.runtime.memoryBytes / 1024 ** 3)} GiB; ${baseline.runtime.platform}/${baseline.runtime.architecture}.`,
  "",
  `${baseline.results.length} baseline samples; ${baseline.methodology.repetitionsPerCacheState} repetitions per workload/cache state. One discarded warmup per warm context. Production ReactDOM profiling build; 1440×1000, DPR 1, headless, UTC. Browser process and OS cache are reused; “cold” means a fresh browser context. OS/desktop background activity remains uncontrolled; consult the environment note for agent workload and idle-lab state.`,
  "",
  "Each cell below is median / p95 in milliseconds. With five samples, nearest-rank p95 is the maximum; these values do not estimate population tail latency. Mount usability includes fonts and three stable animation frames. Module/download startup is reported separately in raw evidence. React render, row transforms and browser script/layout overlap and must not be added together.",
  "",
  "| Workload/cache | Nodes/edges | Mount | Row transforms | React render | Browser layout | PNG generation |",
  "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
];
for (const [id, group] of Object.entries(baseGroups)) {
  const cell = (name) =>
    `${f(group.metrics[name].median)} / ${f(group.metrics[name].p95)}`;
  lines.push(
    `| ${id} | ${group.workload.nodes}/${group.workload.edges} | ${cell("mountMs")} | ${cell("rowsTransformMs")} | ${cell("reactRenderMs")} | ${cell("browserLayoutMs")} | ${cell("pngExportMs")} |`,
  );
}
lines.push(
  "",
  "| Evidence workload | Clients / authorities | Attachment records | Traffic records | Handoff records (complete/partial/unresolved edges) | Topology rows |",
  "| --- | ---: | ---: | ---: | ---: | ---: |",
);
for (const [id, group] of Object.entries(baseGroups).filter(([id]) =>
  id.endsWith("/cold"),
)) {
  const w = group.workload;
  const coverage = w.handoffCoverage;
  lines.push(
    `| ${id.slice(0, -5)} | ${w.networkClients ?? "n/a"} / ${w.clientAuthorities ?? "n/a"} | ${w.attachmentRecords ?? "n/a"} | ${w.trafficRecords ?? "n/a"} | ${w.handoffRecords ?? "n/a"} (${coverage ? `${coverage.complete}/${coverage.partial}/${coverage.unresolved}` : "n/a"}) | ${w.topologyRows} |`,
  );
}
if (candidate) {
  lines.push(
    "",
    `Candidate source: \`${candidate.source.sha}\`; tree hash \`${candidate.source.treeSha256}\`; ${candidate.results.length} samples. Dirty-source details and complete measurements are retained in JSON.`,
    "",
    "| Workload/cache | Baseline mount median | Candidate mount median | Change | Baseline edge selection | Candidate edge selection | Baseline PNG | Candidate PNG |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  );
  for (const [id, group] of Object.entries(baseGroups)) {
    const next = nextGroups[id];
    lines.push(
      `| ${id} | ${f(group.metrics.mountMs.median)} | ${f(next.metrics.mountMs.median)} | ${f((next.metrics.mountMs.median / group.metrics.mountMs.median - 1) * 100)}% | ${f(group.metrics.edgeSelectionMs.median)} | ${f(next.metrics.edgeSelectionMs.median)} | ${f(group.metrics.pngExportMs.median)} | ${f(next.metrics.pngExportMs.median)} |`,
    );
  }
}
lines.push(
  "",
  "The JSON summary retains distributions for highlight/jump, card/edge selection, filters, expansion, table/Devices rendering, CSV/JSON/PNG export, browser script/layout/task time, long tasks, and isolated transforms/indexes/layout/path/device-summary batches. Each isolated operation has one unrecorded warmup and five repetitions; summaries aggregate each sample’s median.",
  "",
  "Correctness checks preserve full graph export equality, exact input counts, finite geometry, PNG signature/allocation, every attachment/traffic CSV record, qualified identity resolution, rejection of ambiguous/mismatched authority evidence, the Devices reference-cap disclosure, and visible partial/unresolved client handoff warnings. Partial records remain in the graph/export while backend assignment stays unavailable. Controlled additions preserve every captured node/edge row; they are graph-contract browser workloads, not claims about collected telemetry or deployment capacity.",
  "",
  "Provisional investigation budgets in the summary are measured baseline p95 × 1.25 + 10 ms (isolated operations: +2 ms). These are local engineering prompts for investigation, not CI gates or service objectives. Long-task counts/durations are retained directly; browser long-task entries use the browser’s 50 ms definition. Search dispatch, Splunk execution/result download, filesystem artifact reading, and microbenchmark batches are excluded from mount/interaction/export-generation timing.",
  "",
);
await mkdir(dirname(resolve(destination)), { recursive: true });
await writeFile(destination, lines.join("\n"));
await writeFile(
  destination.replace(/\.md$/, "") + ".summary.json",
  JSON.stringify(summary, null, 2) + "\n",
);
console.log(`Wrote ${destination}`);
