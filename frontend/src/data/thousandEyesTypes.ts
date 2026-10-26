import type { EvidenceWindow } from "./evidence";
import type { SupplementalResult } from "./supplementalEvidence";

/** Versioned Atlas projection; native producer version remains separate. */
export type ThousandEyesFamily =
  "metric" | "path" | "trace" | "event" | "alert" | "activity";

export interface ThousandEyesApplication {
  service: string;
  environment: string;
  cluster: string;
  namespace: string;
}

/** Configured or producer-reported target; a hostname never resolves to an IP here. */
export interface ThousandEyesTarget {
  ip?: string;
  hostname?: string;
  protocol?: string;
  port?: number;
}

/** Administrator attestation with explicit historical validity, never a name join. */
export interface ThousandEyesBinding {
  id: string;
  authority: string;
  accountGroupId: string;
  scope: string;
  testId: string;
  agentId: string;
  target: ThousandEyesTarget;
  endpointAddresses: string[];
  application?: ThousandEyesApplication;
  validFrom: number;
  validTo: number;
  configurationId: string;
  agentLocation?: string;
}

export interface ThousandEyesMeasurement {
  name: string;
  value?: number;
  unit: string;
  sourceUnit: string;
  aggregation: string;
  direction: string;
  denominator: string;
  timeBasis: string;
}

export interface ThousandEyesHop {
  number: number;
  ip?: string;
  name?: string;
  prefix?: string;
  network?: string;
  latencyMilliseconds?: number;
  lossPercent?: number;
  missing: boolean;
}

export interface ThousandEyesSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  start: number;
  end: number;
  status?: string;
}

export interface ThousandEyesLifecycle {
  id: string;
  type?: string;
  state?: string;
  startedAt?: number;
  endedAt?: number;
  severity?: string;
  title?: string;
  /** The indexed source cannot prove omitted pages or upstream delivery continuity. */
  historyComplete: boolean;
}

export interface ThousandEyesActivity {
  id?: string;
  action: string;
  actor?: string;
  objectId?: string;
  objectType?: string;
}

export interface ThousandEyesObservation {
  schemaVersion: 1;
  family: ThousandEyesFamily;
  authority: string;
  authorityBasis:
    | "producer_account"
    | "configured_account_binding"
    | "configured_input_source";
  accountGroupId: string;
  accountId?: string;
  organizationId?: string;
  adapterVersion: string;
  producerVersion: string;
  dataModelVersion: string;
  testId?: string;
  agentId?: string;
  testName?: string;
  agentName?: string;
  agentLocation?: string;
  testType?: string;
  configurationId?: string;
  target: ThousandEyesTarget;
  interval: EvidenceWindow;
  intervalBasis: "measurement" | "point" | "reported_event";
  eventTime: number;
  indexedTime: number;
  collectionTime?: number;
  index: string;
  source: string;
  sourcetype: string;
  fingerprint: string;
  navigationOrigin?: string;
  outcome: "success" | "failure" | "unknown";
  measurements: ThousandEyesMeasurement[];
  hops: ThousandEyesHop[];
  spans: ThousandEyesSpan[];
  lifecycle?: ThousandEyesLifecycle;
  activity?: ThousandEyesActivity;
  limitations: string[];
}

export interface ThousandEyesAttribution {
  state: "bound" | "context_only" | "ambiguous" | "unmatched";
  bindingIds: string[];
  reason: string;
  observedDependency: boolean;
  configurationId?: string;
}

export type ThousandEyesAttributedObservation = ThousandEyesObservation & {
  attribution: ThousandEyesAttribution;
};

export type ThousandEyesEvidenceResult =
  SupplementalResult<ThousandEyesAttributedObservation>;

export interface ThousandEyesComparison {
  key: string;
  authority: string;
  accountGroupId: string;
  testId: string;
  agentId: string;
  agentLocation?: string;
  metric: string;
  unit: string;
  beforeCount: number;
  afterCount: number;
  beforeMean?: number;
  afterMean?: number;
  delta?: number;
  comparable: boolean;
  reasons: string[];
}
