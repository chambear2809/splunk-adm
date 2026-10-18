import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { HealthPanel, HealthResults } from "./HealthPanel";
import {
  jobRows,
  jobStatus,
  sourceRows,
  sourceStatus,
  sourceAssessment,
  jobAssessment,
  jobRunAssessment,
  loadHealth,
  loadHealthJobs,
  SOURCE_NAMES,
  JOB_NAMES,
  qualityRows,
  type HealthReport,
} from "./health";
import {
  defaultExpectations,
  type DeploymentSnapshot,
} from "./data/deploymentHealth";
import type { SearchClient } from "./data/searchClient";
const now = 200000;
const report: HealthReport = {
  sources: sourceRows([]),
  jobs: jobRows([]),
  quality: qualityRows([]),
  warnings: [],
  checkedAt: now,
};
const search = vi.fn();
const client: SearchClient = { search };
describe("pipeline health", () => {
  it("preserves unknown values instead of inventing successful empty results", () => {
    expect(sourceRows([])).toHaveLength(SOURCE_NAMES.length);
    expect(jobRows([])).toHaveLength(JOB_NAMES.length);
    expect(sourceStatus(sourceRows([])[0], now)).toBe("Unavailable");
    expect(jobStatus(jobRows([])[0], now)).toBe("Configuration unavailable");
    const source = sourceRows([
      { kind: "source", name: "NetFlow", records: "0" },
    ])[0];
    expect(sourceStatus(source, now)).toBe("No visible data in 24 hours");
  });
  it("classifies source silence and clock skew without asserting outage", () => {
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now - 10 },
        now,
      ),
    ).toBe("Data received within 20 minutes");
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now - 1300 },
        now,
      ),
    ).toBe("No data received in 20 minutes");
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now + 100 },
        now,
      ),
    ).toBe("Clock is ahead");
  });
  it("retains Catalyst and Meraki source mapping and identity warnings", () => {
    const sources = sourceRows([
      {
        kind: "source",
        name: "Catalyst client observations",
        records: 4,
        unmapped: 2,
        unresolved: 1,
        warning: "One controller authority is unavailable",
      },
    ]);
    expect(
      sources.find((s) => s.name === "Catalyst client observations"),
    ).toMatchObject({
      records: 4,
      unmapped: 2,
      unresolved: 1,
      warning: "One controller authority is unavailable",
    });
    expect(sources.map((s) => s.name)).toContain(
      "Meraki wireless associations",
    );
    expect(sources.map((s) => s.name)).toContain("Catalyst SD-WAN IPFIX");
  });
  it("reads Catalyst Center and Meraki rows emitted by the health macro", () => {
    const sources = sourceRows([
      {
        kind: "source",
        name: "Catalyst Center",
        records: "4",
        max_ingest_lag: "12",
        status: "ok",
      },
      { kind: "source", name: "Meraki", records: "0", max_ingest_lag: "7" },
    ]);
    expect(
      sources.find((s) => s.name === "Catalyst client observations"),
    ).toMatchObject({ records: 4, maxIngestLag: 12 });
    expect(
      sources.find((s) => s.name === "Meraki wireless associations"),
    ).toMatchObject({ records: 0, maxIngestLag: 7 });
  });
  it("distinguishes disabled, unobserved, failed, and overdue jobs", () => {
    const job = {
      name: "ADM - Identity builder",
      disabled: false,
      lastRun: now - 10,
      lastSuccess: now - 10,
      lastStatus: "success",
    };
    expect(jobStatus(job, now)).toBe("Recent successful run");
    expect(jobStatus({ ...job, disabled: true }, now)).toBe("Disabled");
    expect(jobStatus({ ...job, lastRun: undefined }, now)).toBe(
      "No visible run in 24 hours",
    );
    expect(jobStatus({ ...job, lastStatus: "skipped" }, now)).toBe(
      "Last run: skipped",
    );
    expect(jobStatus({ ...job, lastSuccess: now - 1300 }, now)).toBe(
      "Successful run is overdue",
    );
    expect(
      jobStatus(
        { ...job, name: "ADM - Interface inventory", lastSuccess: now - 3600 },
        now,
      ),
    ).toBe("Recent successful run");
    expect(
      jobStatus(
        {
          ...job,
          name: "ADM - Application catalog v2",
          lastSuccess: now - 3600,
        },
        now,
      ),
    ).toBe("Recent successful run");
    expect(
      jobStatus(
        { ...job, name: "ADM - Identity prune", lastSuccess: now - 23 * 3600 },
        now,
      ),
    ).toBe("Recent successful run");
  });
  it("rejects invalid timestamps and counters", () => {
    const s = sourceRows([
      {
        kind: "source",
        name: "NetFlow",
        records: "oops",
        latest_event: -1,
        latest_indexed: "NaN",
        max_ingest_lag: -2,
      },
    ])[0];
    expect(s).toMatchObject({
      name: "NetFlow",
      records: undefined,
      latestEvent: undefined,
      latestIndexed: undefined,
      maxIngestLag: undefined,
      unmapped: undefined,
      unresolved: undefined,
      warning: undefined,
    });
  });
  it("keeps successful source evidence when scheduler visibility fails", async () => {
    search
      .mockReset()
      .mockImplementation(async (request: { search: string }) => {
        if (request.search.includes("adm_health_jobs"))
          throw new Error("Permission denied");
        if (request.search.includes("adm_health_source_netflow"))
          return {
            rows: [{ kind: "source", name: "NetFlow", records: 1 }],
            warnings: ["Search may be incomplete"],
            errors: [],
          };
        if (request.search.includes("adm_health_quality_netflow"))
          return {
            rows: [
              {
                kind: "quality",
                source: "netflow",
                status: "accepted",
                reason: "evaluated",
                records: 0,
              },
            ],
            warnings: [],
            errors: [],
          };
        return { rows: [], warnings: [], errors: [] };
      });
    const result = await loadHealth(
      client,
      new AbortController().signal,
      deployment("netflow"),
    );
    expect(search.mock.calls.map((call) => call[0].search)).toEqual([
      "| `adm_health_source_netflow`",
      "| `adm_health_source_summary`",
      "| `adm_health_jobs`",
      "| `adm_health_quality_netflow`",
    ]);
    expect(result.sources[0].records).toBe(1);
    expect(result.jobs.every((j) => j.disabled === undefined)).toBe(true);
    expect(result.warnings.join(" ")).toContain("Permission denied");
    expect(result.warnings.join(" ")).toContain("Search may be incomplete");
  });
  it("treats a health search with ERROR job messages as unavailable", async () => {
    search.mockReset().mockResolvedValue({
      rows: [{ kind: "source", name: "NetFlow", records: 1 }],
      warnings: ["peer down"],
      errors: ["peer down"],
    });
    const result = await loadHealth(
      client,
      new AbortController().signal,
      deployment("netflow"),
    );
    expect(result.sources.every((s) => s.records === undefined)).toBe(true);
    expect(result.warnings.join(" ")).toContain("sources health unavailable");
    expect(result.warnings.join(" ")).toContain("peer down");
  });
  it("counts excluded records once while showing overlapping reasons", () => {
    const quality = qualityRows([
      {
        kind: "quality",
        source: "all",
        status: "checked",
        reason: "evaluated",
        records: 10,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "evaluated",
        records: 2,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "invalid_source_ip",
        records: 2,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "invalid_time",
        records: 1,
      },
    ]);
    expect(quality.evaluated).toBe(10);
    expect(quality.excluded).toBe(2);
    expect(quality.issues).toHaveLength(2);
    const html = renderToStaticMarkup(
      <HealthResults report={{ ...report, quality }} />,
    );
    expect(html).toContain("2 excluded");
    expect(html).toContain("Invalid source address");
    expect(qualityRows([]).excluded).toBeUndefined();
    expect(
      qualityRows([
        {
          kind: "quality",
          source: "all",
          status: "checked",
          reason: "evaluated",
          records: "bad",
        },
      ]).evaluated,
    ).toBeUndefined();
  });
  it("retains V2 diagnostic reasons without double-counting population", () => {
    const quality = qualityRows([
      {
        kind: "quality",
        source: "all",
        status: "checked",
        reason: "evaluated",
        records: 4,
      },
      {
        kind: "quality",
        source: "stream_ipfix_v2",
        status: "unmapped",
        reason: "new_contract_reason",
        records: 2,
      },
      {
        kind: "quality",
        source: "stream_ipfix_v2",
        status: "mapped",
        reason: "counter_semantics_unknown",
        records: 1,
      },
    ]);
    expect(quality.evaluated).toBe(4);
    expect(quality.issues.map((issue) => issue.reason)).toEqual(
      expect.arrayContaining([
        "new_contract_reason",
        "counter_semantics_unknown",
      ]),
    );
  });
  it("labels unmapped scope as isolated authority", () => {
    const quality = qualityRows([
      {
        kind: "quality",
        source: "netflow",
        status: "accepted",
        reason: "unmapped_scope",
        records: 1,
      },
    ]);
    expect(quality.issues[0]?.reason).toBe(
      "No observer mapping; source authority remains isolated",
    );
  });
  it("does not publish a cancelled check", async () => {
    search
      .mockReset()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    const c = new AbortController();
    c.abort();
    await expect(loadHealth(client, c.signal)).rejects.toThrow("cancelled");
  });
  it("renders accessible partial health and treats messages as text", () => {
    const html = renderToStaticMarkup(
      <HealthResults
        report={{ ...report, warnings: ["<script>bad</script>"] }}
      />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("Health check is incomplete");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain('scope="col"');
    expect(html).toContain("Configuration unavailable");
  });
  it("does not present demo fixtures as live health", () => {
    const html = renderToStaticMarkup(
      <HealthPanel live={false} close={() => {}} />,
    );
    expect(html).toContain(
      "Synthetic demo data cannot establish pipeline health",
    );
    expect(html).not.toContain("Recent successful run");
  });
});

const deployment = (id: string, contract: 1 | 2 = 1): DeploymentSnapshot => {
  const settings = defaultExpectations();
  settings.sources[id].state = "active";
  return {
    state: "configured",
    activeContract: contract,
    settings,
    canWrite: true,
  };
};
describe("deployment health evidence", () => {
  it("preserves staged V2 and unselected sources without demanding their receipt", () => {
    const result = sourceRows([], deployment("sdwan"));
    expect(result.find((row) => row.id === "sdwan")?.expectation).toBe(
      "staged",
    );
    expect(
      sourceStatus(
        result.find((row) => row.id === "meraki")!,
        now,
      ),
    ).toBe("Not selected for this deployment");
    expect(
      sourceStatus(sourceRows([], { state: "absent", canWrite: true })[0], now),
    ).toBe("Deployment expectation unknown");
  });
  it("uses source cadence, and keeps quiet event streams unconfirmed", () => {
    const settings = deployment("catalyst", 2);
    settings.settings!.sources.catalyst.staleAfterSeconds = 10800;
    const source = sourceRows(
      [
        {
          kind: "source",
          name: "Catalyst Center",
          records: 1,
          latest_indexed: now - 3600,
          probe_lookback_seconds: 604800,
        },
      ],
      settings,
    ).find((row) => row.id === "catalyst")!;
    expect(sourceStatus(source, now)).toBe(
      "Data received within expected cadence",
    );
    const meraki = sourceRows(
      [
        {
          kind: "source",
          name: "Meraki",
          records: 0,
          probe_lookback_seconds: 604800,
        },
      ],
      deployment("meraki", 2),
    ).find((row) => row.id === "meraki")!;
    expect(sourceStatus(meraki, now)).toContain("collection health unknown");
  });
  it("parses V2 summary and complete profile evidence and rejects duplicate rows", () => {
    const rows = sourceRows(
      [
        {
          kind: "summary",
          name: "Conversation summary v2",
          records: 3,
          latest_indexed: now,
        },
        {
          kind: "source",
          name: "Stream source scope profiles",
          records: 2,
          status: "incomplete",
          incomplete_records: 1,
        },
      ],
      deployment("netflow", 2),
    );
    expect(rows.find((row) => row.id === "summary_v2")?.records).toBe(3);
    expect(
      sourceStatus(
        rows.find((row) => row.id === "profiles_stream")!,
        now,
      ),
    ).toBe("Configuration requires review");
    expect(
      sourceRows([
        { kind: "source", name: "NetFlow", records: 1 },
        { kind: "source", name: "NetFlow", records: 1 },
      ])[0].records,
    ).toBeUndefined();
  });
  it("rejects coercible counters and keeps unknown quality dispositions visible", () => {
    for (const records of [true, [], " ", 0.5, Number.MAX_SAFE_INTEGER + 1])
      expect(
        sourceRows([{ kind: "source", name: "NetFlow", records }])[0].records,
      ).toBeUndefined();
    const quality = qualityRows([
      {
        kind: "quality",
        source: "v2",
        status: "unsupported",
        reason: "profile_unsupported",
        records: 1,
      },
    ]);
    expect(quality.issues[0]).toMatchObject({
      reason: "profile_unsupported",
      status: "Disposition: unsupported",
    });
    expect(
      qualityRows([
        {
          kind: "quality",
          source: "all",
          status: "checked",
          reason: "evaluated",
          records: 1,
        },
        {
          kind: "quality",
          source: "all",
          status: "checked",
          reason: "evaluated",
          records: 2,
        },
      ]).evaluated,
    ).toBeUndefined();
  });
  it("loads only scheduler evidence for Setup and distinguishes unscheduled jobs", async () => {
    const search = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    const report = await loadHealthJobs(
      { search },
      new AbortController().signal,
      deployment("k8s"),
    );
    expect(search).toHaveBeenCalledTimes(1);
    expect(search.mock.calls[0][0]).toMatchObject({
      search: "| `adm_health_jobs`",
      earliest: "-7d",
    });
    expect(report.sources).toEqual([]);
    const job = jobRows(
      [
        {
          kind: "job",
          name: "ADM - Identity builder",
          disabled: 0,
          is_scheduled: 0,
        },
      ],
      deployment("k8s"),
    )[0];
    expect(jobStatus(job, now)).toBe("Not scheduled");
  });
});

it("uses only selected source quality evaluations, with family coverage and contract-specific aliases", async () => {
  const config = deployment("sdwan", 2);
  const search = vi.fn(async (request: { search: string }) => ({
    rows: request.search.includes("adm_health_quality_stream_v2")
      ? [
          {
            kind: "quality",
            source: "all",
            reason: "evaluated",
            status: "checked",
            records: 100,
          },
          {
            kind: "quality",
            source: "stream_ipfix_v2",
            reason: "evaluated",
            status: "mapped",
            records: 9,
          },
          {
            kind: "quality",
            source: "sdwan_ipfix_v2",
            reason: "evaluated",
            status: "mapped",
            records: 3,
          },
          {
            kind: "quality",
            source: "sdwan_ipfix_v2",
            reason: "profile_mapped",
            status: "mapped",
            records: 3,
          },
        ]
      : [],
    warnings: [],
    errors: [],
  }));
  const result = await loadHealth(
    { search },
    new AbortController().signal,
    config,
  );
  expect(result.quality.evaluated).toBe(3);
  expect(result.quality.incomplete).toBe(false);
  config.settings!.sources.ftd.state = "active";
  const missingFamily = await loadHealth(
    { search },
    new AbortController().signal,
    config,
  );
  expect(missingFamily.quality.incomplete).toBe(true);
  const unrelated = vi.fn().mockResolvedValue({
    rows: [
      {
        kind: "quality",
        source: "all",
        reason: "evaluated",
        status: "checked",
        records: 100,
      },
    ],
    warnings: [],
    errors: [],
  });
  expect(
    (
      await loadHealth(
        { search: unrelated },
        new AbortController().signal,
        config,
      )
    ).quality.evaluated,
  ).toBeUndefined();
});

it("does not issue nonapplicable job or flow quality probes for NX-OS inventory", async () => {
  const search = vi.fn().mockResolvedValue({
    rows: [{ kind: "source", name: "NX-OS", records: 1, latest_indexed: now }],
    warnings: [],
    errors: [],
  });
  const result = await loadHealth(
    { search },
    new AbortController().signal,
    deployment("nxos"),
  );
  expect(search.mock.calls.map(([request]) => request.search)).toEqual([
    "| `adm_health_source_nxos`",
  ]);
  expect(result.qualityRequired).toBe(false);
  expect(result.warnings).toEqual([]);
});

it("requires retained probe coverage and consistent receipt evidence for configured sources", () => {
  const observed = {
    kind: "source",
    name: "NetFlow",
    records: 1,
    latest_indexed: now - 10,
  };
  const source = (extra = {}) =>
    sourceRows([{ ...observed, ...extra }], deployment("netflow"))[0];
  expect(sourceAssessment(source(), now).state).toBe("unknown");
  expect(
    sourceAssessment(source({ probe_lookback_seconds: 300 }), now).state,
  ).toBe("unknown");
  expect(
    sourceAssessment(source({ probe_lookback_seconds: 604800 }), now).state,
  ).toBe("healthy");
  expect(
    sourceAssessment(
      source({ probe_lookback_seconds: 604800, latest_indexed: undefined }),
      now,
    ).state,
  ).toBe("unknown");
  expect(
    sourceAssessment(
      source({ probe_lookback_seconds: 604800, records: 0 }),
      now,
    ).state,
  ).toBe("unknown");
  expect(
    sourceAssessment(
      source({ probe_lookback_seconds: 604800, latest_indexed: now - 604900 }),
      now,
    ).state,
  ).toBe("unknown");
});
it("labels unreadable optional schedules separately and retains historical run outcomes", () => {
  expect(
    jobAssessment({ name: "Optional", required: false }, now),
  ).toMatchObject({
    state: "not_required",
    label: "Not required for this deployment",
  });
  const run = {
    name: "ADM - Identity builder",
    required: true,
    disabled: true,
    lastRun: now,
    lastSuccess: now - 2000,
  };
  expect(jobRunAssessment({ ...run, lastStatus: "failed" }, now).label).toBe(
    "Last run: failed",
  );
  expect(jobRunAssessment({ ...run, lastStatus: "skipped" }, now).label).toBe(
    "Last run: skipped",
  );
  expect(jobRunAssessment({ ...run, lastStatus: "success" }, now).label).toBe(
    "Successful run is overdue",
  );
  expect(
    jobRunAssessment(
      { ...run, lastStatus: "success", lastSuccess: now + 1 },
      now,
    ).state,
  ).toBe("unknown");
});

it("does not scan unselected family indexes and attributes selected probe failures", async () => {
  const permitted = new Set([
    "| `adm_health_source_netflow`",
    "| `adm_health_source_summary`",
    "| `adm_health_jobs`",
    "| `adm_health_quality_netflow`",
  ]);
  const search = vi.fn(async (request: { search: string }) => {
    if (!permitted.has(request.search))
      throw new Error("Unselected index permission denied");
    return { rows: [], warnings: [], errors: [] };
  });
  const report = await loadHealth(
    { search },
    new AbortController().signal,
    deployment("netflow"),
  );
  expect(search).toHaveBeenCalledTimes(4);
  expect(report.warnings.join(" ")).not.toContain(
    "Unselected index permission denied",
  );
});
it("limits concurrent health searches and cancels the remaining queue", async () => {
  const config = deployment("netflow", 2);
  for (const source of Object.values(config.settings!.sources))
    source.state = "active";
  const controller = new AbortController();
  let pending = 0;
  let maximum = 0;
  const search = vi.fn(
    () =>
      new Promise<{ rows: []; warnings: []; errors: [] }>((resolve) => {
        pending++;
        maximum = Math.max(maximum, pending);
        controller.signal.addEventListener(
          "abort",
          () => {
            pending--;
            resolve({ rows: [], warnings: [], errors: [] });
          },
          { once: true },
        );
      }),
  );
  const result = loadHealth({ search }, controller.signal, config);
  expect(search).toHaveBeenCalledTimes(4);
  controller.abort();
  await expect(result).rejects.toThrow("cancelled");
  expect(maximum).toBe(4);
  expect(search).toHaveBeenCalledTimes(4);
});
it("skips flow-quality probes for partial Kubernetes and trace deployments", async () => {
  for (const id of ["k8s", "traces"]) {
    const search = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    const report = await loadHealth(
      { search },
      new AbortController().signal,
      deployment(id),
    );
    expect(
      search.mock.calls.some(([request]) => request.search.includes("quality")),
    ).toBe(false);
    expect(report.qualityRequired).toBe(false);
  }
});

it("does not claim jobs are unneeded when deployment expectations are unreadable", () => {
  expect(
    jobRows([], { state: "unavailable", canWrite: false })[0].required,
  ).toBeUndefined();
});

it("uses explicit source configuration before receipt evidence and distinguishes missing profiles", () => {
  const settings = deployment("netflow");
  settings.sourceConfiguration = { netflow: "not_configured" };
  const raw = {
    kind: "source",
    name: "NetFlow",
    records: 1,
    latest_indexed: now,
    probe_lookback_seconds: 604800,
  };
  expect(sourceAssessment(sourceRows([raw], settings)[0], now)).toMatchObject({
    state: "attention",
    label: "Selected; not configured",
  });
  settings.sourceConfiguration.netflow = "unavailable";
  expect(sourceAssessment(sourceRows([raw], settings)[0], now).state).toBe(
    "unknown",
  );
  settings.sourceConfiguration.netflow = "configured";
  expect(sourceAssessment(sourceRows([raw], settings)[0], now).state).toBe(
    "healthy",
  );
  const profile = sourceRows(
    [
      {
        kind: "source",
        name: "Stream source scope profiles",
        records: 0,
        status: "no_visible_records",
      },
    ],
    deployment("netflow", 2),
  ).find((row) => row.id === "profiles_stream")!;
  expect(sourceAssessment(profile, now)).toMatchObject({
    state: "attention",
    label: "Selected; not configured",
  });
});

it.each(["unmapped", "ambiguous", "unsupported", "incomplete"])(
  "retains complete evaluated %s evidence as an actionable disposition",
  (status) => {
    const quality = qualityRows([
      {
        kind: "quality",
        source: "all",
        status: "checked",
        reason: "evaluated",
        records: 2,
      },
      {
        kind: "quality",
        source: "meraki_association",
        status,
        reason: "evaluated",
        records: 2,
      },
    ]);
    expect(quality.incomplete).toBe(false);
    expect(quality.evaluated).toBe(2);
    expect(quality.issues).toEqual([
      {
        source: "meraki_association",
        reason: `Source disposition: ${status}`,
        status: `Disposition: ${status}`,
        records: 2,
      },
    ]);
    const html = renderToStaticMarkup(
      <HealthResults report={{ ...report, quality }} />,
    );
    expect(html).toContain("2 candidate records evaluated");
    expect(html).not.toContain("candidate flow records");
    expect(html).not.toContain("excluded from rollup");
  },
);

it("retains PR11 excluded-uncorrelated accounting and context-only diagnostics", () => {
  const quality = qualityRows([
    {
      kind: "quality",
      source: "all",
      status: "checked",
      reason: "evaluated",
      records: 4,
    },
    {
      kind: "quality",
      source: "stream_ipfix_v2",
      status: "excluded_uncorrelated",
      reason: "evaluated",
      records: 2,
    },
    {
      kind: "quality",
      source: "stream_ipfix_v2",
      status: "excluded_uncorrelated",
      reason: "unmapped_profile",
      records: 2,
    },
    {
      kind: "quality",
      source: "meraki_association",
      status: "context_only",
      reason: "evaluated",
      records: 2,
    },
    {
      kind: "quality",
      source: "meraki_association",
      status: "context_only",
      reason: "client_observation",
      records: 2,
    },
    {
      kind: "quality",
      source: "stream_ipfix_v2",
      status: "checked",
      reason: "profile_checked",
      records: 2,
    },
  ]);
  expect(quality.evaluated).toBe(4);
  expect(quality.excluded).toBe(2);
  expect(quality.incomplete).toBe(false);
  expect(quality.issues.map((issue) => issue.status)).toEqual([
    "Excluded",
    "Context only",
    "Checked",
  ]);
});

describe("active contract writer conflicts", () => {
  it.each([
    ["ADM - Conversation rollup v2", 1],
    ["ADM - Conversation rollup", 2],
  ] as const)(
    "flags observed enabled %s on contract %s without inventing schedule evidence",
    (name, contract) => {
      const config = deployment("netflow", contract);
      const job = jobRows([{ kind: "job", name, disabled: 0 }], config).find(
        (row) => row.name === name,
      )!;
      expect(job.scheduled).toBeUndefined();
      expect(jobAssessment(job, now)).toMatchObject({
        state: "attention",
        reason: "contract_conflict",
      });
      expect(jobStatus(job, now)).toContain("Ask an administrator");
      const html = renderToStaticMarkup(
        <HealthResults
          report={{ ...report, deployment: config, jobs: [job] }}
        />,
      );
      expect(html).toContain(
        "Enabled writer conflicts with the active data contract",
      );
      expect(html).not.toContain("Enabled and scheduled");
    },
  );
  it("keeps disabled staged, maintenance, unknown flags and compatible unselected jobs outside operational failures", () => {
    const config = deployment("netflow");
    const scenarios = [
      { name: "ADM - Conversation rollup v2", disabled: 1 },
      { name: "ADM - Conversation rollup v2" },
      { name: "ADM - Network client history prune", disabled: 0 },
      { name: "ADM - Service binding", disabled: 0, last_status: "failed" },
    ];
    for (const scenario of scenarios) {
      const job = jobRows([{ kind: "job", ...scenario }], config).find(
        (row) => row.name === scenario.name,
      )!;
      expect(job.contractConflict).toBe(false);
      expect(jobAssessment(job, now).state).toBe("not_required");
    }
    const unknown = jobRows(
      [{ kind: "job", name: "ADM - Conversation rollup v2", disabled: 0 }],
      { ...config, activeContract: undefined },
    ).find((job) => job.name === "ADM - Conversation rollup v2")!;
    expect(unknown.contractConflict).toBeUndefined();
  });
});
