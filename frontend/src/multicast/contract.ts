export const MULTICAST_VERSION = 1 as const;
export const MAX_WINDOW_SECONDS = 3600;
export const MAX_INPUT_ROWS = 256;
export const MAX_EVIDENCE_ROWS = 256;
export const MAX_PROFILES = 16;

export type MulticastSource =
  "multicast_igmp" | "multicast_netflow" | "multicast_nxos";
export interface MulticastRequest {
  version: 1;
  scope: string;
  group: string;
  sender?: string;
  earliest: number;
  latest: number;
}

export interface Segment {
  kind: "vlan" | "bridge-domain" | "vni";
  id: string;
  /** Stable operator-defined bridge/VLAN namespace within the routing scope. */
  domain: string;
}

interface Profile {
  id: string;
  scope: string;
  index: string;
  observer: string;
  validFrom: number;
  validUntil: number;
}

export interface IgmpProfile extends Profile {
  source: "multicast_igmp";
  captureInterface: string;
  segment: Segment;
  /** Only an attested endpoint-facing capture may attribute reports to hosts. */
  placement: "endpoint" | "transit";
  endpointReporters: string[];
  proxyReporters: string[];
  v3Encoding: "flat-counted" | "single-record";
}

export interface FlowProfile extends Profile {
  source: "multicast_netflow";
  observationDomain: string;
  template: string;
  direction: "ingress" | "egress";
  /** Exporter-attested sampling policy and meaning of emitted counters. */
  samplingInterval: number;
  replication: "before" | "after" | "unknown";
  counters: "delta" | "total";
}

export interface ForwardingProfile extends Profile {
  source: "multicast_nxos";
}
export type StreamProfile = IgmpProfile | FlowProfile;
export type MulticastProfile = StreamProfile | ForwardingProfile;
export interface MulticastConfiguration {
  profiles: MulticastProfile[];
  fingerprint: string;
}

interface Evidence {
  id: string;
  /** Only a producer/packet identity proven unique within the observer may deduplicate. */
  replayKey?: string;
  scope: string;
  group: string;
  observer: string;
  timestamp: number;
  interface?: string;
  segment?: Segment;
  limits: string[];
}

export type IgmpOperation =
  | "query"
  | "report-v1"
  | "report-v2"
  | "leave"
  | "include"
  | "exclude"
  | "change-to-include"
  | "change-to-exclude"
  | "allow-new-sources"
  | "block-old-sources";

export interface IgmpEvidence extends Evidence {
  kind: "igmp";
  source: "multicast_igmp";
  operation: IgmpOperation;
  reporter?: string;
  reporterKind: "endpoint" | "proxy" | "anonymous" | "unknown";
  sources: string[];
  /** Set only for queries: general (group 0.0.0.0) or group-specific. */
  queryScope?: "general" | "group";
}

export interface FlowEvidence extends Evidence {
  kind: "flow";
  source: "multicast_netflow";
  sender: string;
  observationDomain: string;
  template: string;
  direction: "ingress" | "egress";
  samplingInterval: number;
  replication: "before" | "after" | "unknown";
  counters: "delta" | "total";
  packets?: number;
  bytes?: number;
}

export interface ForwardingEvidence extends Evidence {
  kind: "forwarding";
  source: "device_state";
  sender?: string;
  validUntil: number;
  input?: string;
  outputs: string[];
}

export interface MulticastAdjacency {
  scope: string;
  from: { observer: string; interface: string };
  to: { observer: string; interface: string };
  validFrom: number;
  validUntil: number;
}

export type MulticastEvidence =
  IgmpEvidence | FlowEvidence | ForwardingEvidence;
export interface SourceOutcome {
  source: MulticastSource | "device_state";
  profile?: string;
  state: "complete" | "partial" | "blocked" | "unavailable";
  detail?: string;
}

export interface ReceiverInterest {
  reporter: string;
  segment: Segment;
  evidenceId: string;
  state: "observed" | "uncertain";
}
export interface ForwardingBranch {
  from: string;
  output: string;
  to?: string;
  evidenceId: string;
  state: "supported" | "unresolved" | "stale";
}
export interface MulticastTopology {
  evidence: MulticastEvidence[];
  senders: { address: string; evidenceIds: string[] }[];
  receivers: ReceiverInterest[];
  branches: ForwardingBranch[];
  capped: boolean;
}

export interface MulticastResult extends MulticastTopology {
  version: 1;
  request: MulticastRequest;
  capturedAt: number;
  configurationFingerprint: string;
  outcomes: SourceOutcome[];
}

export const MAX_GROUPS = 256;
export interface ScopeWindow {
  version: 1;
  scope: string;
  earliest: number;
  latest: number;
}
export interface IgmpGroupSummary {
  kind: "igmp";
  profile: string;
  group: string;
  segment: Segment;
  reports: number;
  leaves: number;
  groupQueries: number;
  endpointReporters: string[];
  otherReporters: number;
  firstSeen: number;
  lastSeen: number;
  lastLeave?: number;
  lastGroupQuery?: number;
}
export interface FlowGroupSummary {
  kind: "flow";
  profile: string;
  group: string;
  observer: string;
  direction: "ingress" | "egress";
  senders: string[];
  packets?: number;
  bytes?: number;
  samplingInterval: number;
  replication: "before" | "after" | "unknown";
  counters: "delta" | "total";
  firstSeen: number;
  lastSeen: number;
}
export interface PointQueries {
  profile: string;
  querySenders: { address: string; first: number; last: number }[];
  lastGeneralQuery?: number;
}
export type GroupSummary = IgmpGroupSummary | FlowGroupSummary;
export interface ProfileSummary {
  summaries: GroupSummary[];
  queries?: PointQueries;
  droppedGroups: number;
  outcome: SourceOutcome;
}
