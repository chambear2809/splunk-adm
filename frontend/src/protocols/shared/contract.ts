import type { ComponentType } from "react";
import type { SearchClient } from "../../data/searchClient";
import type { ProtocolSource } from "../../data/evidence";

export const PROTOCOL_VERSION = 1 as const;
export const MAX_WINDOW_SECONDS = 3600;
export const MAX_INPUT_ROWS = 256;
export const MAX_EVIDENCE_ROWS = 256;
export const MAX_PROFILES = 64;

export const PROTOCOL_LENS_IDS = [
  "tcp_tls",
  "dns_ops",
  "routing",
  "l2_control",
  "interface_health",
  "qos_icmp",
  "enterprise_l7",
  "drops",
  "endpoint_mobility",
  "app_transactions",
  "state_events",
  "mgmt_plane",
  "lb_health",
] as const;

export type ProtocolLensId = (typeof PROTOCOL_LENS_IDS)[number];

export type ProtocolLensSource = Exclude<
  ProtocolSource,
  "protocol_stream_readiness" | "protocol_traffic_mix"
>;

export type ProtocolStatus =
  "ok" | "attention" | "not_covered" | "none_observed" | "unknown";

export const STATUS_LABELS: Record<ProtocolStatus, string> = {
  ok: "OK",
  attention: "Attention",
  not_covered: "Not covered",
  none_observed: "None observed",
  unknown: "Unknown",
};

export type ProtocolViewMode = "overview" | "matrix";

export type ProtocolLensCategory =
  "transport" | "control_plane" | "fabric_qos" | "application" | "operations";

export interface ProtocolFilter {
  src?: string;
  dst?: string;
  device?: string;
  /** Optional VXLAN VNI facet (1..16777215). */
  vni?: string;
  /** Optional L4 TCP/UDP port (1..65535). */
  port?: string;
  /** Match src/dst in either direction (A ↔ B) on flow lenses. */
  bidirectional?: boolean;
  /** Optional interface name filter (e.g., eth1/1, Po100). */
  iface?: string;
}

export type ProtocolFilterFieldKey =
  "src" | "dst" | "device" | "port" | "vni" | "iface";

export interface ProtocolFilterFieldSpec {
  key: ProtocolFilterFieldKey;
  label: string;
  placeholder: string;
  /** Primary fields render inline; secondary fields expand under "More". */
  primary?: boolean;
}

export interface ProtocolRequest {
  version: 1;
  lens: ProtocolLensId;
  scope: string;
  earliest: number;
  latest: number;
  filter?: ProtocolFilter;
}

export interface BaseProtocolProfile {
  id: string;
  source: ProtocolLensSource;
  lens: ProtocolLensId;
  scope: string;
  index: string;
  observer: string;
  validFrom: number;
  validUntil: number;
  /** Optional lens-specific vetted fields validated by the registered per-lens validator. */
  extra?: Record<string, unknown>;
}

export type LensProfileValidator = (
  extra: Record<string, unknown> | undefined,
  profile: Omit<BaseProtocolProfile, "extra">,
) => Record<string, unknown> | undefined;

export interface ProtocolConfiguration {
  profiles: BaseProtocolProfile[];
  fingerprint: string;
}

export interface ProtocolSourceOutcome {
  source: string;
  profile?: string;
  state: "complete" | "partial" | "blocked" | "unavailable" | "estimate_only";
  detail?: string;
  inputRows?: number;
  capped?: boolean;
}

export interface ProtocolKpi {
  id: string;
  label: string;
  value: string;
  unit?: string;
  status?: ProtocolStatus;
  sparkline?: number[];
  hint?: string;
}

export interface ProtocolMatrixCell {
  row: string;
  col: string;
  status: ProtocolStatus;
  value: string;
  count?: number;
  detail?: string;
  itemId?: string;
}

export interface ProtocolTimelineEvent {
  id: string;
  lane: string;
  timestamp: number;
  kind: "ok" | "attention" | "info" | "neutral";
  label: string;
  detail?: string;
}

export interface ProtocolDistributionMetric {
  id: string;
  label: string;
  p50: number;
  p95: number;
  max?: number;
  /** Exact aggregate total used when `DistributionBar` renders in `mode="count"`. */
  count?: number;
  unit: string;
  status?: ProtocolStatus;
}

export interface ProtocolAdjacencyNode {
  id: string;
  label: string;
  role?: string;
  status: ProtocolStatus;
}

export interface ProtocolAdjacencyEdge {
  id: string;
  from: string;
  to: string;
  label?: string;
  status: ProtocolStatus;
  detail?: string;
}

export interface ProtocolLensSummary {
  lens: ProtocolLensId;
  status: ProtocolStatus;
  verdict: string;
  checkedAt: number;
  capped: boolean;
  outcomes: ProtocolSourceOutcome[];
}

export interface ProtocolLensComponentProps {
  client?: SearchClient;
  live: boolean;
  timezone?: string;
  theme?: "light" | "dark";
  scope: string;
  scopes: string[];
  earliest: number;
  latest: number;
  view: ProtocolViewMode;
  filter?: ProtocolFilter;
  selectedItem?: string;
  configuration: ProtocolConfiguration;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
  onChangeParams: (patch: {
    scope?: string;
    earliest?: number;
    latest?: number;
    view?: ProtocolViewMode;
    filter?: ProtocolFilter;
    item?: string;
  }) => void;
  onBackToHub: () => void;
  onRefreshConfig: () => void;
}

export interface ProtocolLensRegistration {
  id: ProtocolLensId;
  source: ProtocolLensSource;
  title: string;
  shortTitle: string;
  category: ProtocolLensCategory;
  summary: string;
  /** Primary sourcetypes or datasets read by this lens. */
  sources: readonly string[];
  /** Splunk Stream stream IDs whose Estimate-mode status applies to this lens. */
  streamIds: readonly string[];
  /** Operator setup doc path relative to docs/operators/. */
  operatorDoc: string;
  /** Optional per-lens profile extra validator. */
  validateExtra?: LensProfileValidator;
  /** Optional summary runner used when the operator explicitly clicks "Check all". */
  summarize?: (
    client: SearchClient,
    request: ProtocolRequest,
    configuration: ProtocolConfiguration,
    signal: AbortSignal,
  ) => Promise<ProtocolLensSummary>;
  /** Lazy component loader (IIFE asset in Splunk build, dynamic import in dev/tests). */
  loadComponent?: () => Promise<ComponentType<ProtocolLensComponentProps>>;
}

export type ProtocolLensSummaryRunner = NonNullable<
  ProtocolLensRegistration["summarize"]
>;

export function sourceForLens(lens: ProtocolLensId): ProtocolLensSource {
  return `protocol_${lens}`;
}
