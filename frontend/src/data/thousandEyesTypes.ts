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
  testDomain: "cea" | "endpoint";
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
  pathId?: string;
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
  startTimeUnixNano?: string;
  endTimeUnixNano?: string;
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
  relatedTestIds?: string[];
  relatedAgentIds?: string[];
  testDomain?: "cea" | "endpoint";
  streamId?: string;
  monitorId?: string;
  targetAgentId?: string;
  testName?: string;
  agentName?: string;
  agentLocation?: string;
  testType?: string;
  configurationId?: string;
  target: ThousandEyesTarget;
  pathDirection?: "to-target" | "from-target";
  targetIsProxy?: boolean;
  interval: EvidenceWindow;
  intervalBasis: "measurement" | "point" | "reported_event";
  eventTime: number;
  indexedTime: number;
  /** Populated only when receipt-time semantics are independently attested. */
  receiptTime?: number;
  /** Original Splunk _time; HEC event metadata may supply this independently of raw time extraction. */
  rowTime?: number;
  sourceTimes?: {
    field: string;
    value: string;
    unit: "ns" | "ms" | "s" | "iso8601";
  }[];
  collectionTime?: number;
  index: string;
  source: string;
  sourcetype: string;
  fingerprint: string;
  navigationOrigin?: string;
  outcome: "success" | "failure" | "unknown";
  /** Structural record quality; it does not assert upstream history continuity. */
  quality: {
    stale: boolean;
    complete: boolean;
    conflicting: boolean;
    truncated: boolean;
  };
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
  SupplementalResult<ThousandEyesAttributedObservation> & {
    receiptFreshness?: {
      state: "historical" | "stale" | "observed_receipt" | "unknown";
      basis: "selected_evidence_indexed_receipt";
      latestIndexedTime?: number;
      assessedAt: number;
    };
  };

export interface ThousandEyesComparison {
  key: string;
  authority: string;
  accountGroupId: string;
  testId: string;
  agentId: string;
  testDomain?: "cea" | "endpoint";
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
