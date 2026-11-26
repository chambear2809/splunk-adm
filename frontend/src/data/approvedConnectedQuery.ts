import { sha256Hex } from "../changeCorrelation/canonicalJson";
import type { GraphArgs } from "../rows";
import {
  CONNECTED_QUERY_KEYS,
  type ConnectedQueryKey,
  type ConnectedQueryWindow,
} from "./connectedServiceQueryPlan";

const ARG = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/;
const ENV = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const K8S = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const MAX_EPOCH = 253402300799;

function quote(value: string, pattern: RegExp, label: string) {
  if (!pattern.test(value)) throw new Error(`Invalid connected ${label}.`);
  return value;
}

function validateWindow(window: ConnectedQueryWindow) {
  if (
    !window ||
    !Number.isSafeInteger(window.earliest) ||
    !Number.isSafeInteger(window.latest) ||
    window.earliest < 0 ||
    window.latest <= window.earliest ||
    window.latest > MAX_EPOCH
  )
    throw new Error("Invalid connected query window.");
}

/** Build only the fixed, reviewed connected-service macro queries. */
export async function buildApprovedConnectedQuery(input: {
  application: GraphArgs;
  key: ConnectedQueryKey;
  window: ConnectedQueryWindow;
}): Promise<{ literal: string; sha256: string }> {
  if (!CONNECTED_QUERY_KEYS.includes(input.key))
    throw new Error("Unsupported connected query key.");
  const service = quote(input.application.service, ARG, "service");
  const environment = quote(input.application.environment, ENV, "environment");
  const cluster = quote(input.application.cluster, ENV, "cluster");
  const namespace = quote(input.application.namespace, K8S, "namespace");
  validateWindow(input.window);
  const start = input.window.earliest;
  const end = input.window.latest;
  const suffix = ` | where _time>=${start} AND _time<${end}`;
  const literal = input.key.startsWith("graph.")
    ? `| \`adm_graph("${service}","${environment}","${cluster}","${namespace}")\`${suffix}`
    : input.key.startsWith("topology.")
      ? `| \`adm_topology\`${suffix}`
      : input.key === "catalog.selected"
        ? `| \`adm_catalog_build\` | search service="${service}"${suffix}`
        : `| \`adm_find("${service}")\`${suffix}`;
  return { literal, sha256: await sha256Hex(literal) };
}
