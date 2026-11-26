import { csvRow } from "../csv";
import type {
  DependencyEdge,
  MovePlan,
  PlannerOverrides,
  PlannerRules,
  SeedGroupInput,
  SharedReason,
} from "../ops/moveGroup";
import type { PlannerDataset } from "./data";
import type { VmwareInventoryLabel } from "./vmwareInventory";

export const PLAN_EXPORT_SCHEMA = "application-atlas/move-group-plan" as const;

const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

export function describeReason(reason: SharedReason): string {
  switch (reason.kind) {
    case "port":
      return `Serves ${reason.transport}/${reason.port} (${reason.service}) to ${reason.clients} clients`;
    case "fan_in":
      return `${reason.peers} distinct peers, at or above the p${reason.percentile} threshold of ${reason.threshold}`;
    case "pinned":
      return "Pinned as shared by the planner";
  }
}

function metadata(dataset: PlannerDataset, plan: MovePlan): unknown[] {
  return [
    "metadata",
    dataset.selection.scope,
    iso(dataset.selection.start),
    iso(dataset.selection.end),
    iso(dataset.capturedAt),
    plan.complete &&
    !dataset.capped &&
    dataset.coverage.coveredBuckets === dataset.coverage.expectedBuckets
      ? "complete"
      : "incomplete",
    `${dataset.coverage.coveredBuckets}/${dataset.coverage.expectedBuckets} summary buckets`,
    [
      ...dataset.warnings,
      ...plan.notes,
      plan.truncated.blockers ? "Blocker list truncated" : "",
      plan.truncated.sharedDependencies
        ? "Shared-service dependency list truncated"
        : "",
      plan.truncated.outsidePlan ? "Outside-plan list truncated" : "",
    ]
      .filter(Boolean)
      .join(" "),
  ];
}

const METADATA_COLUMNS = [
  "record_type",
  "scope",
  "window_start",
  "window_end",
  "captured_at",
  "completeness",
  "coverage",
  "notes",
];

export function groupsCsv(
  dataset: PlannerDataset,
  plan: MovePlan,
  labels: VmwareInventoryLabel[] = [],
): string {
  const byAddress = new Map(labels.map((l) => [l.address, l]));
  const vm = (address: string) => {
    const label = byAddress.get(address);
    return label
      ? `${label.vmName}${label.claims > 1 ? " (ambiguous)" : ""}`
      : "";
  };
  const rows: unknown[][] = [
    METADATA_COLUMNS,
    metadata(dataset, plan),
    [
      "record_type",
      "group_id",
      "group_label",
      "address",
      "membership_basis",
      "evidence",
      "depth",
      "via",
      "distinct_peers",
      "expansion",
      "shared_rule_match",
      "vmware_name_inferred",
    ],
  ];
  for (const group of plan.groups)
    for (const m of group.members)
      rows.push([
        "group_member",
        group.id,
        group.label,
        m.address,
        m.basis,
        m.basis === "manual"
          ? "planner assignment"
          : m.basis === "seed"
            ? "planner seed"
            : "inferred from observed conversations",
        m.depth ?? "",
        m.via ?? "",
        m.peers,
        m.expansion,
        m.sharedMatch.map(describeReason).join("; "),
        vm(m.address),
      ]);
  for (const s of plan.shared)
    rows.push([
      "shared_service",
      "shared",
      "Shared services",
      s.address,
      s.basis === "user" ? "pinned" : "detected",
      s.basis === "user"
        ? "planner assertion"
        : "inferred from observed conversations",
      "",
      "",
      s.peers,
      "not_expanded",
      s.reasons.map(describeReason).join("; "),
      vm(s.address),
    ]);
  return rows.map(csvRow).join("\r\n");
}

const EDGE_COLUMNS = [
  "record_type",
  "client_group",
  "server_group",
  "client",
  "server",
  "port",
  "transport",
  "direction",
  "flow_records_max_observer",
  "bytes_max_observer",
  "observers",
  "observers_capped",
  "sources",
  "sampled",
  "first_seen",
  "last_seen",
];

const edgeRow = (e: DependencyEdge) => [
  e.kind,
  e.clientGroup,
  e.serverGroup,
  e.client,
  e.server,
  e.port ?? "",
  e.transport,
  e.directed ? "observed" : "unknown (endpoints ordered by address)",
  e.records,
  e.bytes ?? "unknown",
  e.observers.join("|"),
  e.observersCapped,
  e.sources.join("|"),
  e.sampled,
  iso(e.first),
  iso(e.last),
];

export function blockersCsv(dataset: PlannerDataset, plan: MovePlan): string {
  return [
    METADATA_COLUMNS,
    metadata(dataset, plan),
    EDGE_COLUMNS,
    ...plan.blockers.map(edgeRow),
    ...plan.sharedDependencies.map(edgeRow),
    ...plan.outsidePlan.map(edgeRow),
  ]
    .map(csvRow)
    .join("\r\n");
}

export function planJson(
  dataset: PlannerDataset,
  plan: MovePlan,
  seeds: SeedGroupInput[],
  rules: PlannerRules,
  overrides: PlannerOverrides,
  labels: VmwareInventoryLabel[] = [],
): string {
  return JSON.stringify(
    {
      schema: PLAN_EXPORT_SCHEMA,
      schemaVersion: 1,
      draft: true,
      evidence: {
        conversations:
          "observed: Application Atlas conversation summaries for the window",
        groups:
          "inferred: seeded traversal over observed conversations plus planner assignments",
        sharedServices:
          "inferred from observed ports and peer counts, or asserted by the planner",
        vmwareLabels:
          "inferred context: primary guest IP reported by vCenter, unscoped address match",
      },
      selection: dataset.selection,
      capturedAt: dataset.capturedAt,
      source: {
        inputCount: dataset.inputCount,
        loaded: dataset.conversations.length,
        capped: dataset.capped,
        unprotectedRows: dataset.unprotectedRows,
        coverage: dataset.coverage,
        warnings: dataset.warnings,
      },
      seeds,
      rules,
      overrides,
      plan,
      vmwareLabels: labels,
    },
    null,
    2,
  );
}
