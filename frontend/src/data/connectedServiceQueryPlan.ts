import { canonicalJson, sha256Hex } from "../changeCorrelation/canonicalJson";
import type { GraphArgs } from "../rows";

export const CONNECTED_QUERY_KEYS = [
  "graph.baseline",
  "graph.change",
  "graph.impact",
  "graph.recovery",
  "topology.baseline",
  "topology.impact",
  "topology.recovery",
  "catalog.selected",
  "find.service",
] as const;
export type ConnectedQueryKey = (typeof CONNECTED_QUERY_KEYS)[number];

export interface ConnectedQueryWindow {
  earliest: number;
  latest: number;
}

export interface ConnectedQuerySpec {
  application: GraphArgs;
  queryNamespace: string;
  key: ConnectedQueryKey;
  window: ConnectedQueryWindow;
  literal: string;
  sha256: string;
}

export interface ConnectedQueryBuilder {
  (input: {
    application: GraphArgs;
    key: ConnectedQueryKey;
    queryNamespace: string;
    window: ConnectedQueryWindow;
  }): Promise<{ literal: string; sha256: string }>;
}

/** Build bounded child query metadata only; this never dispatches or fabricates receipts. */
export async function buildConnectedQueryPlan(
  scopes: readonly GraphArgs[],
  windows: Readonly<Record<string, ConnectedQueryWindow>>,
  build: ConnectedQueryBuilder,
): Promise<ConnectedQuerySpec[]> {
  if (
    scopes.length !== 2 ||
    scopes[0].service !== "inventory" ||
    scopes[1].service !== "pricing"
  )
    throw new Error(
      "Connected query plan requires ordered inventory and pricing scopes.",
    );
  const phases = ["baseline", "change", "impact", "recovery"];
  for (const phase of phases) {
    const window = windows[phase];
    if (
      !window ||
      !Number.isSafeInteger(window.earliest) ||
      !Number.isSafeInteger(window.latest) ||
      window.earliest >= window.latest
    )
      throw new Error(`Connected query plan has invalid ${phase} window.`);
  }
  const plan: ConnectedQuerySpec[] = [];
  for (const application of scopes) {
    const namespace = `connected.${application.service}`;
    for (const key of CONNECTED_QUERY_KEYS) {
      const phase = key.split(".")[1];
      const window = windows[phase] ?? windows.impact;
      const query = await build({
        application,
        key,
        queryNamespace: namespace,
        window,
      });
      if (
        !query ||
        typeof query.literal !== "string" ||
        !query.literal ||
        query.literal.length > 65536
      )
        throw new Error(
          `Connected query builder returned an invalid ${namespace}.${key} literal.`,
        );
      const digest = await sha256Hex(query.literal);
      if (query.sha256 !== digest)
        throw new Error(
          `Connected query builder hash mismatch for ${namespace}.${key}.`,
        );
      plan.push({
        application,
        queryNamespace: namespace,
        key,
        window,
        literal: query.literal,
        sha256: digest,
      });
    }
  }
  if (
    plan.length !== 18 ||
    new Set(plan.map((item) => canonicalJson(item.application))).size !== 2
  )
    throw new Error("Connected query plan is incomplete.");
  return plan;
}
