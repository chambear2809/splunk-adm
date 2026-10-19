import { expect, test, type Page, type CDPSession } from "@playwright/test";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { cpus, totalmem, platform, release, arch } from "node:os";
import { resolve } from "node:path";
import type { PerfApi, ActionIntent } from "./harness";
import type { Scenario, Size } from "./workloads";
const scenarios = ["aci", "nxos", "catalyst-aci", "meraki-nxos"] as const;

const sourceRoot = process.env.ADM_PERF_SOURCE_ROOT ?? process.cwd();
const repetitions = Number(process.env.ADM_PERF_REPETITIONS ?? "5");
if (!Number.isSafeInteger(repetitions) || repetitions < 1)
  throw new Error("Invalid ADM_PERF_REPETITIONS");
const sizes = (
  process.env.ADM_PERF_SIZES ?? "captured,realistic,near-limit"
).split(",") as Size[];
const selected = (process.env.ADM_PERF_SCENARIOS ?? scenarios.join(",")).split(
  ",",
) as Scenario[];
if (
  sizes.some(
    (size) => !["captured", "realistic", "near-limit"].includes(size),
  ) ||
  selected.some((scenario) => !scenarios.includes(scenario))
)
  throw new Error("Invalid performance workload selection");
const results: Record<string, unknown>[] = [];
const pageSessions = new WeakMap<Page, CDPSession>();
const traceSelection = process.env.ADM_PERF_TRACE_SELECTION === "1";
const traceCategories =
  process.env.ADM_PERF_TRACE_CATEGORIES ??
  "toplevel,devtools.timeline,v8,blink.user_timing,disabled-by-default-devtools.timeline,disabled-by-default-v8.cpu_profiler";
const experimentalCss = process.env.ADM_PERF_EXPERIMENT_CSS;
const drainSelection = process.env.ADM_PERF_DRAIN_SELECTION === "1";
const selectionDiagnostic = process.env.ADM_PERF_SELECTION_DIAGNOSTIC === "1";
let traceNumber = 0;
const failures: {
  title: string;
  status: string | undefined;
  errors: string[];
}[] = [];
test.describe.configure({ mode: "serial" });
let sourceHashBefore = "";
let harnessHashBefore = "";
const importedFiles = [
  "config/deployment-health.json",
  "research/cisco-pipeline-interface.json",
];
const builtRoot = resolve(process.cwd(), "dist/performance-app");
let importedBefore: Awaited<ReturnType<typeof fingerprintFiles>>;
let builtBefore: Awaited<ReturnType<typeof fingerprintFiles>>;
const harnessFiles = [
  "browser.perf.spec.ts",
  "harness.tsx",
  "readiness.ts",
  "workloads.ts",
  "ciscoWorkloads.ts",
  "index.html",
  "vite.config.ts",
  "playwright.config.ts",
  "tsconfig.json",
].map((file) => `tests/performance/${file}`);
const sourceFiles = () =>
  git(
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "frontend/src",
    "fixtures",
    "package-lock.json",
  )
    .split("\n")
    .filter(Boolean);
test.beforeAll(async () => {
  sourceHashBefore = await hashFiles(sourceRoot, sourceFiles());
  harnessHashBefore = await hashFiles(process.cwd(), harnessFiles);
  importedBefore = await fingerprintFiles(sourceRoot, importedFiles);
  builtBefore = await fingerprintFiles(builtRoot, await builtFiles());
});
test.afterEach(async ({}, info) => {
  if (info.status !== "passed")
    failures.push({
      title: info.title,
      status: info.status,
      errors: info.errors.map((error) => error.message ?? String(error)),
    });
});
const contextOptions = {
  viewport: { width: 1440, height: 1000 },
  deviceScaleFactor: 1,
  locale: "en-US",
  timezoneId: "UTC",
  colorScheme: "light" as const,
};
let browserVersion = "";
let outputPath = "";
const git = (...args: string[]) =>
  execFileSync("git", ["-C", sourceRoot, ...args], { encoding: "utf8" }).trim();
async function hashFiles(root: string, files: string[]) {
  const hash = createHash("sha256");
  for (const file of [...files].sort()) {
    hash.update(file);
    hash.update(await readFile(resolve(root, file)));
  }
  return hash.digest("hex");
}
async function builtFiles(prefix = ""): Promise<string[]> {
  const entries = await readdir(resolve(builtRoot, prefix), {
    withFileTypes: true,
  });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      return entry.isDirectory() ? builtFiles(path) : [path];
    }),
  );
  return files.flat().sort();
}
async function fingerprintFiles(root: string, files: string[]) {
  const records: Record<
    string,
    { present: boolean; sha256?: string; bytes?: number }
  > = {};
  for (const file of [...files].sort()) {
    try {
      const bytes = await readFile(resolve(root, file));
      records[file] = {
        present: true,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        bytes: bytes.length,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      records[file] = { present: false };
    }
  }
  return records;
}
async function metrics(cdp: CDPSession) {
  const response = await cdp.send("Performance.getMetrics");
  return Object.fromEntries(
    response.metrics
      .filter((entry: { name: string }) =>
        [
          "ScriptDuration",
          "LayoutDuration",
          "RecalcStyleDuration",
          "TaskDuration",
          "JSHeapUsedSize",
          "Nodes",
        ].includes(entry.name),
      )
      .map((entry: { name: string; value: number }) => [
        entry.name,
        entry.value,
      ]),
  );
}
const deltas = (
  before: Record<string, number>,
  after: Record<string, number>,
) =>
  Object.fromEntries(
    Object.keys(after).map((key) => [
      key,
      key.endsWith("Duration") ? (after[key] - before[key]) * 1000 : after[key],
    ]),
  );
async function action(
  page: Page,
  event: "click" | "input" | "change" | "keydown",
  intent: ActionIntent,
  trigger: () => Promise<unknown>,
) {
  const cdp = pageSessions.get(page);
  // Diagnostic control: flush the previous action's compositor work before
  // capture. This is never enabled for the retained comparison matrix.
  if (drainSelection && intent.kind === "selectCard" && cdp)
    await cdp.send("Page.captureScreenshot", { format: "png" });
  const trace = traceSelection && intent.kind === "selectCard" && cdp;
  if (trace)
    await cdp.send("Tracing.start", {
      categories: traceCategories,
      transferMode: "ReturnAsStream",
    });
  const before = cdp ? await metrics(cdp) : undefined;
  await page.evaluate(
    ({ event, intent }) => window.__ATLAS_PERF__.armAction(event, intent),
    { event, intent },
  );
  const triggerStarted = performance.now();
  try {
    await trigger();
  } catch (error) {
    await page
      .evaluate(
        (message) => window.__ATLAS_PERF__.actionTriggerFailed(message),
        String(error),
      )
      .catch(() => {});
    throw error;
  }
  const playwrightTriggerDurationMs = performance.now() - triggerStarted;
  await page.evaluate(() => window.__ATLAS_PERF__.actionTriggerCompleted());
  const timing = await page.evaluate(() => window.__ATLAS_PERF__.endAction());
  const after = cdp ? await metrics(cdp) : undefined;
  let tracePath: string | undefined;
  if (trace) {
    const complete = new Promise<{ stream?: string }>((resolve) =>
      cdp.once("Tracing.tracingComplete", resolve),
    );
    await cdp.send("Tracing.end");
    const { stream } = await complete;
    if (!stream) throw new Error("Selection trace did not return a stream");
    let data = "";
    for (;;) {
      const chunk = await cdp.send("IO.read", { handle: stream });
      data += chunk.base64Encoded
        ? Buffer.from(chunk.data, "base64").toString("utf8")
        : chunk.data;
      if (chunk.eof) break;
    }
    await cdp.send("IO.close", { handle: stream });
    const directory = resolve(
      process.env.ADM_PERF_TRACE_DIR ??
        "dist/final-qualification/performance/traces",
    );
    await mkdir(directory, { recursive: true });
    tracePath = resolve(
      directory,
      `selection-${String(++traceNumber).padStart(3, "0")}.json`,
    );
    await writeFile(tracePath, data);
  }
  expect(timing.committedPostcondition).toBe(true);
  return {
    ...timing,
    playwrightTriggerDurationMs,
    tracePath,
    // This CDP envelope includes automation and evaluation outside event-to-ready.
    // Use tracing timestamps to attribute work to the exact browser interval.
    cdpActionEnvelope: before && after ? deltas(before, after) : undefined,
  };
}
async function download(page: Page, name: RegExp, format: string) {
  if (!(await page.getByRole("button", { name }).isVisible()))
    await page.getByRole("button", { name: "Export", exact: true }).click();
  await page.evaluate(() => window.__ATLAS_PERF__.armExport("click"));
  const begin = performance.now();
  const pending = page.waitForEvent("download");
  await page.getByRole("button", { name }).click();
  const artifact = await pending;
  const dispatchToBrowserEventUpperBoundMs = performance.now() - begin;
  const timing = await page.evaluate(() =>
    window.__ATLAS_PERF__.downloadTiming(),
  );
  const body = await readFile((await artifact.path())!);
  expect(await artifact.failure()).toBeNull();
  expect(body.length).toBeGreaterThan(0);
  return {
    format,
    ...timing,
    dispatchToBrowserEventUpperBoundMs,
    bytes: body.length,
    body,
  };
}
function csvRecords(csv: string) {
  const rows: string[][] = [];
  let row: string[] = [],
    cell = "",
    quoted = false;
  for (let i = 0; i < csv.length; i++) {
    const char = csv[i];
    if (char === '"') {
      if (quoted && csv[i + 1] === '"') {
        cell += '"';
        i++;
      } else quoted = !quoted;
    } else if (char === "," && !quoted) {
      row.push(cell);
      cell = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && csv[i + 1] === "\n") i++;
      row.push(cell);
      if (row.some(Boolean)) rows.push(row);
      row = [];
      cell = "";
    } else cell += char;
  }
  if (quoted) throw new Error("Malformed CSV export");
  return rows;
}
type Mount = Awaited<ReturnType<PerfApi["mount"]>>;
async function sample(
  page: Page,
  cdp: CDPSession,
  scenario: Scenario,
  size: Size,
  partial: boolean,
) {
  pageSessions.set(page, cdp);
  const sampleStarted = performance.now();
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const navigationBegin = performance.now();
  await page.goto("/");
  if (experimentalCss) await page.addStyleTag({ content: experimentalCss });
  await page.waitForFunction(() => !!window.__ATLAS_PERF__);
  const navigationToHarnessReadyUpperBoundMs =
    performance.now() - navigationBegin;
  const startup = await page.evaluate(() => window.__ATLAS_PERF__.startup());
  const prepared = await page.evaluate(
    ({ scenario, size, partial }) =>
      window.__ATLAS_PERF__.prepare(scenario, size, partial),
    { scenario, size, partial },
  );
  const previous = results.find(
    (result) =>
      result.scenario === scenario &&
      result.size === size &&
      result.partial === partial,
  );
  if (previous) expect(prepared.sha256).toBe((previous.mount as Mount).sha256);
  const before = await metrics(cdp);
  const mount: Mount = await page.evaluate(() => window.__ATLAS_PERF__.mount());
  const after = await metrics(cdp);
  const mountedAt = performance.now();
  expect(pageErrors).toEqual([]);
  await expect(page.locator(".adm")).toHaveAttribute(
    "data-node-count",
    String(mount.nodes),
  );
  await expect(page.locator(".adm")).toHaveAttribute(
    "data-edge-count",
    String(mount.edges),
  );
  const highlight = page.getByLabel(
    "Highlight by name, IP, EPG, port or device",
  );
  const highlightTiming = await action(
    page,
    "input",
    { kind: "highlight" },
    () => highlight.fill("checkout"),
  );
  await expect(page.locator(".item[data-hit].match").first()).toBeAttached();
  const highlightJumpTiming = await action(
    page,
    "keydown",
    { kind: "highlightJump" },
    () => highlight.press("Enter"),
  );
  const selectionTiming = await action(
    page,
    "click",
    { kind: "selectCard" },
    () => page.locator(".item[data-hit].match").first().click(),
  );
  await expect(
    page.getByRole("complementary", { name: "Details" }),
  ).toBeVisible();
  if (selectionDiagnostic) {
    expect(pageErrors).toEqual([]);
    return {
      scenario,
      size,
      partial,
      mount,
      startup,
      navigationToHarnessReadyUpperBoundMs,
      browserMetricsMount: deltas(before, after),
      interactions: {
        highlight: highlightTiming,
        highlightJump: highlightJumpTiming,
        selection: selectionTiming,
      },
      diagnosticOnly: true,
      outsideMeasuredWallStages: {
        navigationPreparationMountMs: mountedAt - sampleStarted,
        selectionWorkflowMs: performance.now() - mountedAt,
        totalSampleMs: performance.now() - sampleStarted,
      },
      correctness: {
        intendedSelection: true,
        fullCountsAndFiniteGeometry: true,
      },
    };
  }
  const clearSelectionTiming = await action(
    page,
    "click",
    { kind: "clearSelection" },
    () => page.getByRole("button", { name: "Clear selection" }).click(),
  );
  await highlight.fill("");
  const filterTiming = await action(
    page,
    "change",
    { kind: "filterExternal" },
    () =>
      page
        .getByLabel("Filter identity", { exact: true })
        .selectOption("external"),
  );
  await expect(page.locator(".atlas-filter-status")).toBeVisible();
  const clearFilterTiming = await action(
    page,
    "change",
    { kind: "clearFilter" },
    () => page.getByLabel("Filter identity", { exact: true }).selectOption(""),
  );
  await expect(page.locator(".atlas-filter-status")).toHaveCount(0);
  const tableTiming = await action(page, "click", { kind: "table" }, () =>
    page.getByRole("button", { name: "Table", exact: true }).click(),
  );
  const selectedCase = await page.evaluate(() =>
    window.__ATLAS_PERF__.selectionCase(),
  );
  const edgeSelectionTiming = await action(
    page,
    "click",
    {
      kind: "selectEdge",
      index: selectedCase.index,
      coverage: selectedCase.coverage,
    },
    () =>
      page
        .getByRole("table", { name: "Network conversations" })
        .getByRole("button")
        .nth(selectedCase.index)
        .click(),
  );
  const details = page.getByRole("complementary", { name: "Details" });
  await expect(details).toBeVisible();
  if (
    selectedCase.coverage === "partial" ||
    selectedCase.coverage === "unresolved"
  )
    await expect(details).toContainText(
      `Client handoff coverage is ${selectedCase.coverage}`,
    );
  await page.getByRole("button", { name: "Clear selection" }).click();
  const devicesTiming = await action(page, "click", { kind: "devices" }, () =>
    page.getByRole("button", { name: "Devices", exact: true }).click(),
  );
  const attachmentUi = {
    visibleReferences: await page.locator(".attachment-references li").count(),
    text: await page.locator(".attachment-references").allTextContents(),
  };
  await action(page, "click", { kind: "network" }, () =>
    page.getByRole("button", { name: "Network", exact: true }).click(),
  );
  const expansionTiming = await page.evaluate(() =>
    window.__ATLAS_PERF__.expand(),
  );
  expect(expansionTiming.remainingSummaries).toBe(0);
  await page.getByRole("button", { name: "Export", exact: true }).click();
  const json = await download(page, /Map data \(JSON\)/, "json");
  const csv = await download(page, /Required flows \(CSV\)/, "flows-csv");
  const context = scenario.includes("-")
    ? await download(page, /Context evidence \(CSV\)/, "context-csv")
    : undefined;
  const png = await download(page, /Map image \(PNG\)/, "png");
  expect(png.body.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a");
  const pngWidth = png.body.readUInt32BE(16),
    pngHeight = png.body.readUInt32BE(20);
  expect(pngWidth * pngHeight).toBeLessThanOrEqual(32000000);
  expect(csv.body.toString()).toContain("traffic_observations");
  const benchmark = await page.evaluate(() =>
    window.__ATLAS_PERF__.benchmark(),
  );
  const correctnessStarted = performance.now();
  const exported = JSON.parse(json.body.toString());
  // Full export equality protects IDs, handoff records, attachment/traffic evidence and warnings.
  expect(exported).toEqual(benchmark.graph);
  expect(benchmark.geometrySound).toBe(true);
  if (scenario.includes("-")) {
    expect(benchmark.evidence.attachments).toBe(mount.attachmentRecords);
    expect(benchmark.evidence.traffic).toBe(mount.trafficRecords);
    expect(
      benchmark.handoffs.reduce(
        (total, handoff) => total + handoff.sourceRecordCount,
        0,
      ),
    ).toBe(mount.handoffRecords);
    expect(benchmark.evidence.topologyDevices).toBe(mount.topologyDevices);
    expect(benchmark.evidence.topologyLinks).toBe(mount.topologyLinks);
    expect(
      benchmark.handoffs
        .filter((handoff) => handoff.coverage === "complete")
        .every(
          (handoff) =>
            handoff.resolution.complete &&
            handoff.resolution.records.length === handoff.sourceRecordCount,
        ),
    ).toBe(true);
    expect(context).toBeDefined();
    expect(context!.body.toString()).toContain("attachment_evidence");
    expect(context!.body.toString()).toContain("traffic_observation");
    const contextRows = csvRecords(context!.body.toString());
    const kindIndex = contextRows[0].indexOf("evidence_kind");
    const evidenceIndex = contextRows[0].indexOf("evidence_json");
    expect(
      contextRows
        .slice(1)
        .filter((row) => row[kindIndex] === "attachment_evidence"),
    ).toHaveLength(benchmark.evidence.attachments);
    expect(
      contextRows
        .slice(1)
        .filter((row) => row[kindIndex] === "traffic_observation"),
    ).toHaveLength(benchmark.evidence.traffic);
    // Parse every evidence row, retaining the same malformed-row failure.
    // One assertion avoids retaining thousands of Playwright reporter steps
    // per sample; this bookkeeping is outside all browser timing intervals.
    expect(() => {
      for (const row of contextRows.slice(1)) JSON.parse(row[evidenceIndex]);
    }).not.toThrow();
    expect(attachmentUi.visibleReferences).toBe(
      Math.min(32, benchmark.evidence.attachmentReferences),
    );
    if (benchmark.evidence.attachmentReferences > 32)
      expect(attachmentUi.text.join(" ")).toContain(
        `${benchmark.evidence.attachmentReferences - 32} additional attachment`,
      );
    expect(
      benchmark.handoffs
        .filter((handoff) => handoff.coverage !== "complete")
        .every(
          (handoff) =>
            !handoff.resolution.complete &&
            handoff.resolution.records.length === 0,
        ),
    ).toBe(true);
    if (scenario === "catalyst-aci")
      expect(
        benchmark.handoffs.some((handoff) => handoff.coverage === "unresolved"),
      ).toBe(true);
    if (size !== "captured") {
      expect(mount.capturedEvidencePreserved).toBe(true);
      expect(mount.networkClients).toBeGreaterThanOrEqual(
        size === "near-limit" ? 400 : 60,
      );
      expect(mount.clientAuthorities).toBeGreaterThanOrEqual(4);
      expect(mount.sharedNativeClientGroups).toBeGreaterThan(0);
      expect(mount.topologyRows).toBeGreaterThan(64);
      expect(mount.topologyLinks).toBeGreaterThanOrEqual(
        mount.networkClients * 2 - 4,
      );
      expect(mount.trafficRecords).toBeGreaterThanOrEqual(
        mount.trafficObservationEdges * 2,
      );
      expect(mount.uniqueTrafficFingerprints).toBe(mount.trafficRecords);
      expect(mount.attachmentRecords).toBeGreaterThanOrEqual(
        mount.trafficObservationEdges * 2 - 4,
      );
      for (const coverage of ["complete", "partial", "unresolved"])
        expect(mount.handoffCoverage[coverage]).toBeGreaterThan(0);
      expect(benchmark.evidence.resolvedAttachmentReferences).toBeGreaterThan(
        0,
      );
      expect(benchmark.evidence.unresolvedAttachmentReferences).toBeGreaterThan(
        0,
      );
      expect(benchmark.evidence.ambiguousClientAliases).toBeGreaterThan(0);
      expect(benchmark.evidence.ambiguousAccessAliases).toBeGreaterThan(0);
      expect(benchmark.evidence.mismatchedAuthorityReferences).toBeGreaterThan(
        0,
      );
      expect(
        benchmark.evidence.nonCanonicalAttachmentReferences,
      ).toBeGreaterThan(0);
      expect(benchmark.evidence.qualifiedClientChecks).toBe(
        benchmark.evidence.controlledClientCount,
      );
      // The final authority group can contain fewer than four clients.
      expect(benchmark.evidence.ambiguousClientChecks).toBeGreaterThanOrEqual(
        benchmark.evidence.controlledClientCount - 3,
      );
    }
  }
  if (partial)
    expect(
      benchmark.handoffs.some(
        (handoff) =>
          handoff.coverage === "partial" &&
          !handoff.resolution.complete &&
          handoff.sourceRecordCount > 0 &&
          handoff.resolution.records.length === 0,
      ),
    ).toBe(true);
  const state = await page.evaluate(() => window.__ATLAS_PERF__.read());
  const sampleFinished = performance.now();
  expect(pageErrors).toEqual([]);
  const { graph: _graph, ...microbenchmark } = benchmark;
  const exports = [json, csv, context, png].filter(Boolean).map((item) => {
    const { body: _body, ...data } = item!;
    return data;
  });
  return {
    scenario,
    size,
    partial,
    mount,
    navigationToHarnessReadyUpperBoundMs,
    startup,
    browserMetricsMount: deltas(before, after),
    outsideMeasuredWallStages: {
      navigationPreparationMountMs: mountedAt - sampleStarted,
      interactionsExportsMicrobenchmarkMs: correctnessStarted - mountedAt,
      fullRecordValidationAndTelemetryMs: sampleFinished - correctnessStarted,
      totalSampleMs: sampleFinished - sampleStarted,
    },
    interactions: {
      highlight: highlightTiming,
      highlightJump: highlightJumpTiming,
      selection: selectionTiming,
      clearSelection: clearSelectionTiming,
      filter: filterTiming,
      clearFilter: clearFilterTiming,
      expand: expansionTiming,
      table: tableTiming,
      edgeSelection: edgeSelectionTiming,
      devices: devicesTiming,
    },
    exports,
    png: { width: pngWidth, height: pngHeight },
    microbenchmark,
    attachmentUi,
    totalLongTasks: state.longTasks,
    correctness: {
      counts: true,
      fullExportEquality: true,
      pngSignatureAndAllocation: true,
      finiteLayoutGeometry: true,
      retainedContextEvidence: true,
      partialAndUnresolvedHandoffs: scenario.includes("-")
        ? true
        : "not-applicable",
      pageErrors,
    },
  };
}

test.afterAll(async () => {
  const stamp = new Date().toISOString().replaceAll(":", "-");
  outputPath = resolve(
    process.env.ADM_PERF_OUTPUT ??
      `dist/performance/${git("rev-parse", "--short", "HEAD")}-${stamp}.json`,
  );
  await mkdir(resolve(outputPath, ".."), { recursive: true });
  const sourceHashAfter = await hashFiles(sourceRoot, sourceFiles());
  const harnessHashAfter = await hashFiles(process.cwd(), harnessFiles);
  const importedAfter = await fingerprintFiles(sourceRoot, importedFiles);
  const builtAfter = await fingerprintFiles(builtRoot, await builtFiles());
  const importedUnchanged =
    JSON.stringify(importedBefore) === JSON.stringify(importedAfter);
  const builtUnchanged =
    JSON.stringify(builtBefore) === JSON.stringify(builtAfter);
  const expectedWorkloads = selected.reduce(
    (total, scenario) =>
      total +
      sizes.length +
      (scenario.includes("-") && sizes.includes("realistic") ? 1 : 0),
    0,
  );
  const report = {
    schemaVersion: 2,
    recordedAt: new Date().toISOString(),
    source: {
      sha: git("rev-parse", "HEAD"),
      dirty: git(
        "status",
        "--porcelain",
        "--",
        "frontend/src",
        "fixtures",
        "package-lock.json",
      ),
      treeSha256: sourceHashBefore,
      treeSha256After: sourceHashAfter,
      unchangedDuringRun:
        sourceHashBefore === sourceHashAfter &&
        importedUnchanged &&
        builtUnchanged,
      importedDependencies: {
        before: importedBefore,
        after: importedAfter,
        unchangedDuringRun: importedUnchanged,
      },
      builtServedAssets: {
        before: builtBefore,
        after: builtAfter,
        unchangedDuringRun: builtUnchanged,
      },
      lockSha256: createHash("sha256")
        .update(await readFile(resolve(sourceRoot, "package-lock.json")))
        .digest("hex"),
    },
    harnessSha256: harnessHashBefore,
    harnessUnchangedDuringRun: harnessHashBefore === harnessHashAfter,
    expectedWorkloads,
    expectedSamples: expectedWorkloads * repetitions * 2,
    complete:
      results.length === expectedWorkloads * repetitions * 2 &&
      failures.length === 0,
    failures,
    runtime: {
      node: process.version,
      playwright: JSON.parse(
        await readFile(
          resolve(process.cwd(), "node_modules/@playwright/test/package.json"),
          "utf8",
        ),
      ).version,
      browser: browserVersion,
      platform: platform(),
      osRelease: release(),
      architecture: arch(),
      cpu: cpus()[0]?.model,
      logicalCpus: cpus().length,
      memoryBytes: totalmem(),
      viewport: { width: 1440, height: 1000 },
      deviceScaleFactor: 1,
      headless: true,
      locale: "en-US",
      timezone: "UTC",
      colorScheme: "light",
      reactDomBuild:
        "Production profiling build; identical instrumentation for baseline and candidate",
      tracing: traceSelection,
      traceCategories: traceSelection ? traceCategories : undefined,
      experimentalCss,
      drainSelection,
      selectionDiagnostic,
    },
    methodology: {
      interactionProtocol:
        "capture-started browser readiness promise; action-specific precondition and committed DOM postcondition; three unchanged frames after the first committed frame; Playwright trigger completion separate",
      repetitionsPerCacheState: repetitions,
      cold: "Fresh browser context and page per sample; browser process reused, OS and server caches uncontrolled",
      warm: "Same context, one discarded warmup, fresh page per measured sample",
      measurementScope: selectionDiagnostic
        ? "Supplemental mount/highlight/jump/card-selection diagnostic only; no filtering, exports, or isolated-operation acceptance"
        : "Complete selected workload matrix with filtering, evidence/export correctness and isolated operations",
      wholeCaseTimeoutMs: Math.max(300000, repetitions * 180000),
      outsideMeasuredWallStages:
        "Node wall-clock workflow staging includes automation and full-record validation; never added to browser phase timings",
      isolatedOperationWarmup: selectionDiagnostic ? 0 : 1,
      isolatedOperationRepetitions: selectionDiagnostic ? 0 : 5,
      usable:
        "Fonts ready; loaded counts, SVG geometry and hit targets valid; transform/dimensions/counts stable for three consecutive animation frames",
      network:
        "Local prebuilt production bundle only; no Splunk dispatch or result download",
      thresholds:
        "None; measured baseline precedes provisional engineering budgets",
      environment:
        "Local developer machine; concurrent background activity possible; no CPU/network throttling",
    },
    results,
  };
  await writeFile(outputPath, JSON.stringify(report, null, 2) + "\n");
  console.log(
    `Performance evidence: ${outputPath} (${results.length} measured samples)`,
  );
});

for (const scenario of selected)
  for (const size of sizes) {
    for (const partial of scenario.includes("-") && size === "realistic"
      ? [false, true]
      : [false]) {
      test(`${scenario}/${size}${partial ? "/partial-handoff" : ""}`, async ({
        browser,
      }) => {
        browserVersion = browser.version();
        for (const cache of ["cold", "warm"] as const) {
          const warmContext =
            cache === "warm"
              ? await browser.newContext(contextOptions)
              : undefined;
          for (
            let repetition = cache === "warm" ? -1 : 0;
            repetition < repetitions;
            repetition++
          ) {
            const context =
              warmContext ?? (await browser.newContext(contextOptions));
            const page = await context.newPage();
            await page.setViewportSize({ width: 1440, height: 1000 });
            const cdp = await context.newCDPSession(page);
            await cdp.send("Performance.enable");
            try {
              const result = await sample(page, cdp, scenario, size, partial);
              if (repetition >= 0)
                results.push({ cache, repetition, ...result });
            } finally {
              await cdp.detach();
              await page.close();
              if (!warmContext) await context.close();
            }
          }
          await warmContext?.close();
        }
      });
    }
  }
