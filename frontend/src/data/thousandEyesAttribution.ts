import { normalizeIp } from "./evidence";
import type { EvidenceSelection, EvidenceWindow } from "./evidence";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesBinding,
  ThousandEyesComparison,
  ThousandEyesMeasurement,
  ThousandEyesObservation,
} from "./thousandEyesTypes";

const MAX_EPOCH = 253_402_300_799;
const UNKNOWN_SEMANTIC_VALUES = new Set([
  "",
  "unknown",
  "not_reported",
  "not reported",
  "unreported",
  "unspecified",
  "not_available",
  "not available",
  "n/a",
  "na",
  "null",
]);

function isKnownMetadata(value: string | undefined): value is string {
  return (
    typeof value === "string" &&
    !UNKNOWN_SEMANTIC_VALUES.has(value.trim().toLowerCase())
  );
}

function isTestDomain(value: unknown): value is "cea" | "endpoint" {
  return value === "cea" || value === "endpoint";
}

function finiteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function canonicalIp(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    return normalizeIp(value);
  } catch {
    return undefined;
  }
}

function validWindow(window: EvidenceWindow): boolean {
  return (
    !!window &&
    finiteNumber(window.start) &&
    finiteNumber(window.end) &&
    window.start >= 0 &&
    window.end <= MAX_EPOCH &&
    window.end > window.start
  );
}

/** A point at the window end is excluded; a span must be wholly inside it. */
function containedInWindow(
  interval: EvidenceWindow,
  window: EvidenceWindow,
): boolean {
  if (
    !interval ||
    !validWindow(window) ||
    !finiteNumber(interval.start) ||
    !finiteNumber(interval.end) ||
    interval.start < 0 ||
    interval.end > MAX_EPOCH ||
    interval.end < interval.start
  )
    return false;
  if (interval.start === interval.end)
    return interval.start >= window.start && interval.start < window.end;
  return interval.start >= window.start && interval.end <= window.end;
}

/** Binding validity is half-open. A point at validTo is outside the binding. */
function containedInBinding(
  interval: EvidenceWindow,
  binding: ThousandEyesBinding,
): boolean {
  if (
    !finiteNumber(binding.validFrom) ||
    !finiteNumber(binding.validTo) ||
    binding.validFrom < 0 ||
    binding.validTo > MAX_EPOCH ||
    binding.validTo <= binding.validFrom ||
    !finiteNumber(interval?.start) ||
    !finiteNumber(interval?.end) ||
    interval.start < 0 ||
    interval.end > MAX_EPOCH ||
    interval.end < interval.start
  )
    return false;
  if (interval.start === interval.end)
    return (
      interval.start >= binding.validFrom && interval.start < binding.validTo
    );
  return interval.start >= binding.validFrom && interval.end <= binding.validTo;
}

function sameApplication(
  left: ThousandEyesBinding["application"],
  right: EvidenceSelection["application"],
): boolean {
  return (
    !!left &&
    !!right &&
    left.service === right.service &&
    left.environment === right.environment &&
    left.cluster === right.cluster &&
    left.namespace === right.namespace
  );
}

function bindingMatchesSelection(
  binding: ThousandEyesBinding,
  selection: EvidenceSelection,
): boolean {
  if (binding.scope !== selection.scope) return false;
  if (
    selection.application &&
    !sameApplication(binding.application, selection.application)
  )
    return false;

  // These are the addresses revalidated for the selected endpoint/application.
  // Equality is literal IP equality; hostnames and current DNS are never joined.
  const selectedAddresses = selection.identityAddresses ?? selection.addresses;
  if (
    !Array.isArray(selectedAddresses) ||
    !Array.isArray(binding.endpointAddresses)
  )
    return false;
  const selected = new Set(
    selectedAddresses
      .map(canonicalIp)
      .filter((address): address is string => !!address),
  );
  return (
    selected.size > 0 &&
    binding.endpointAddresses.some((address) => {
      const canonical = canonicalIp(address);
      return !!canonical && selected.has(canonical);
    })
  );
}

function targetMatches(
  observed: ThousandEyesObservation["target"],
  configured: ThousandEyesBinding["target"],
): boolean {
  if (!observed || !configured) return false;
  let hasTargetIdentity = false;

  if (configured.ip !== undefined) {
    hasTargetIdentity = true;
    const expected = canonicalIp(configured.ip);
    const actual = canonicalIp(observed.ip);
    if (!expected || !actual || expected !== actual) return false;
  }
  if (configured.hostname !== undefined) {
    hasTargetIdentity = true;
    if (
      typeof observed.hostname !== "string" ||
      observed.hostname.toLowerCase() !== configured.hostname.toLowerCase()
    )
      return false;
  }
  if (
    configured.protocol !== undefined &&
    observed.protocol !== configured.protocol
  )
    return false;
  if (configured.port !== undefined && observed.port !== configured.port)
    return false;

  // Optional producer IPs must still be literal and valid. Do not infer aliases
  // or resolve configured hostnames against current DNS.
  if (
    configured.ip === undefined &&
    observed.ip !== undefined &&
    !canonicalIp(observed.ip)
  )
    return false;
  if (
    configured.hostname === undefined &&
    typeof observed.hostname === "string" &&
    observed.hostname.length === 0
  )
    return false;

  return hasTargetIdentity;
}

function intervalsOverlapContext(
  interval: EvidenceWindow,
  first: number,
  last: number,
): boolean {
  if (
    !finiteNumber(interval?.start) ||
    !finiteNumber(interval?.end) ||
    !finiteNumber(first) ||
    !finiteNumber(last) ||
    interval.end < interval.start ||
    last < first
  )
    return false;
  if (interval.start === interval.end)
    return interval.start >= first && interval.start <= last;
  return interval.start <= last && interval.end > first;
}

function hasCompatibleSelectedContext(
  record: ThousandEyesObservation,
  selection: EvidenceSelection,
): boolean {
  if (record.family !== "metric" && record.family !== "path") return false;
  const targetIp = canonicalIp(record.target?.ip);
  const targetProtocol =
    typeof record.target?.protocol === "string"
      ? record.target.protocol.toLowerCase()
      : undefined;
  const targetPort = record.target?.port;
  if (
    !targetIp ||
    !isKnownMetadata(targetProtocol) ||
    !finiteNumber(targetPort) ||
    !Number.isInteger(targetPort) ||
    targetPort < 1 ||
    targetPort > 65535 ||
    !Array.isArray(selection.contexts)
  )
    return false;
  return selection.contexts.some((context) => {
    if (
      !context ||
      context.capped ||
      context.scope !== selection.scope ||
      context.serverPort !== targetPort ||
      typeof context.transport !== "string" ||
      !isKnownMetadata(context.transport) ||
      context.transport.toLowerCase() !== targetProtocol ||
      !intervalsOverlapContext(record.interval, context.first, context.last)
    )
      return false;
    return canonicalIp(context.server) === targetIp;
  });
}

function qualityLimitations(record: ThousandEyesObservation): string[] {
  const quality = record.quality;
  if (!quality || typeof quality !== "object")
    return ["record quality is missing"];
  const limitations: string[] = [];
  if (quality.stale !== false) limitations.push("record is stale");
  if (quality.complete !== true) limitations.push("record is incomplete");
  if (quality.conflicting !== false)
    limitations.push("record has conflicting identity evidence");
  if (quality.truncated !== false) limitations.push("record is truncated");
  return limitations;
}

/** Attribute only against an explicit, time-qualified authority binding. */
export function attributeThousandEyesRecords(
  records: readonly ThousandEyesObservation[],
  selection: EvidenceSelection,
  bindings: readonly ThousandEyesBinding[],
): ThousandEyesAttributedObservation[] {
  return records.map((record) => {
    const qualityIssues = qualityLimitations(record);
    const observedDependency =
      qualityIssues.length === 0 &&
      isTestDomain(record.testDomain) &&
      record.targetIsProxy !== true &&
      hasCompatibleSelectedContext(record, selection);
    const contextReason = observedDependency
      ? "A compatible uncapped selected traffic context overlaps this target and interval; this does not prove the same route or protocol/port tuple."
      : undefined;
    const contextOnlyReasons: string[] = [];
    if (qualityIssues.length) {
      contextOnlyReasons.push(
        `Record quality prevents attribution: ${qualityIssues.join(", ")}.`,
        "The record remains context only and is not eligible for comparison.",
      );
    }
    if (!isTestDomain(record.testDomain)) {
      contextOnlyReasons.push(
        "The ThousandEyes test domain is missing or invalid; CEA and Endpoint native IDs are not interchangeable.",
      );
    }
    if (record.targetIsProxy === true) {
      contextOnlyReasons.push(
        "The producer marks this target as a proxy; the binding does not prove target role or proxy coverage, so attribution remains context only.",
      );
    }
    if (contextOnlyReasons.length) {
      return {
        ...record,
        attribution: {
          state: "context_only",
          bindingIds: [],
          reason: [
            ...contextOnlyReasons,
            ...(contextReason ? [contextReason] : []),
          ].join(" "),
          observedDependency,
        },
      };
    }
    const exactIdentityPresent =
      typeof record.testId === "string" &&
      record.testId.length > 0 &&
      typeof record.agentId === "string" &&
      record.agentId.length > 0;

    const sameNativeCandidates = exactIdentityPresent
      ? bindings.filter(
          (binding) =>
            binding.authority === record.authority &&
            binding.accountGroupId === record.accountGroupId &&
            binding.testId === record.testId &&
            binding.agentId === record.agentId &&
            bindingMatchesSelection(binding, selection) &&
            containedInBinding(record.interval, binding),
        )
      : [];
    const identityCandidates = sameNativeCandidates.filter(
      (binding) => binding.testDomain === record.testDomain,
    );
    const relocationCandidates = identityCandidates.filter(
      (binding) =>
        binding.agentLocation !== undefined &&
        record.agentLocation !== binding.agentLocation,
    );
    const locationCandidates = identityCandidates.filter(
      (binding) =>
        binding.agentLocation === undefined ||
        record.agentLocation === binding.agentLocation,
    );
    const targetCandidates = locationCandidates.filter((binding) =>
      targetMatches(record.target, binding.target),
    );
    const configurationCandidates =
      record.configurationId === undefined
        ? targetCandidates
        : targetCandidates.filter(
            (binding) => binding.configurationId === record.configurationId,
          );

    let attribution: ThousandEyesAttributedObservation["attribution"];
    if (configurationCandidates.length === 1) {
      const binding = configurationCandidates[0];
      attribution = {
        state: "bound",
        bindingIds: [binding.id],
        reason: [
          "Exactly one historical binding matches authority, account group, native test/agent/domain, routing scope, selected endpoint address, configured target, any explicitly configured agent location, and the whole observation interval.",
          ...(contextReason ? [contextReason] : []),
        ].join(" "),
        observedDependency,
        configurationId: binding.configurationId,
      };
    } else if (
      configurationCandidates.length > 1 ||
      (record.configurationId !== undefined &&
        configurationCandidates.length === 0 &&
        targetCandidates.length > 1)
    ) {
      const candidates =
        configurationCandidates.length > 1
          ? configurationCandidates
          : targetCandidates;
      attribution = {
        state: "ambiguous",
        bindingIds: candidates.map((binding) => binding.id).sort(),
        reason: [
          "Multiple overlapping historical bindings match the selected native test domain, identity, and target; their configuration cannot establish one attribution.",
          ...(record.configurationId !== undefined &&
          configurationCandidates.length === 0
            ? ["The observed configuration ID matches none of those bindings."]
            : []),
          ...(contextReason ? [contextReason] : []),
        ].join(" "),
        observedDependency,
      };
    } else if (
      relocationCandidates.length > 0 &&
      targetCandidates.length === 0
    ) {
      attribution = {
        state: "context_only",
        bindingIds: [],
        reason: [
          "The observed agent location is missing or differs from the explicitly configured historical location; possible agent relocation keeps this record context only.",
          ...(contextReason ? [contextReason] : []),
        ].join(" "),
        observedDependency,
      };
    } else {
      let reason: string;
      if (!exactIdentityPresent) {
        reason =
          "Native test or agent identity is missing; test names and tags are not used for attribution.";
      } else if (
        targetCandidates.length > 0 &&
        record.configurationId !== undefined
      ) {
        reason =
          "The observed configuration ID does not match the historical target binding.";
      } else if (
        sameNativeCandidates.length > 0 &&
        identityCandidates.length === 0
      ) {
        reason =
          "The historical binding uses a different ThousandEyes test domain; CEA and Endpoint IDs are not interchangeable.";
      } else if (identityCandidates.length > 0) {
        reason =
          "The observed target does not exactly match the configured target; hostnames are never resolved.";
      } else {
        reason =
          "No historical binding matches the exact authority, account group, native test/agent/domain, routing scope, selected application, endpoint address, target, and whole observation interval.";
      }
      attribution = {
        state: observedDependency ? "context_only" : "unmatched",
        bindingIds: [],
        reason: [
          reason,
          ...(observedDependency
            ? [contextReason!]
            : [
                "No uncapped selected server tuple matches the target address, interval, protocol, and port.",
              ]),
        ].join(" "),
        observedDependency,
      };
    }

    return { ...record, attribution };
  });
}

interface ComparisonSample {
  record: ThousandEyesAttributedObservation;
  measurement: ThousandEyesMeasurement;
}

interface ComparisonBucket {
  authority: string;
  accountGroupId: string;
  testId: string;
  agentId: string;
  testDomain: "cea" | "endpoint";
  family: "metric" | "path";
  metric: string;
  before: ComparisonSample[];
  after: ComparisonSample[];
}

interface ComparisonRounds {
  before: ThousandEyesAttributedObservation[];
  after: ThousandEyesAttributedObservation[];
}

function producerVersionForComparison(
  value: string | undefined,
): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim().toLowerCase();
  return ["not_reported", "not reported", "unreported"].includes(normalized)
    ? undefined
    : value;
}

function scalarMean(values: readonly number[]): number | undefined {
  if (!values.length) return undefined;
  let mean = 0;
  values.forEach((value, index) => {
    const count = index + 1;
    mean = mean * ((count - 1) / count) + value / count;
  });
  return Number.isFinite(mean) ? mean : undefined;
}

function valuesFor(samples: readonly ComparisonSample[]): number[] {
  return samples
    .map((sample) => sample.measurement.value)
    .filter((value): value is number => finiteNumber(value));
}

function stringSet(
  values: readonly (string | undefined)[],
): Set<string | undefined> {
  return new Set(values);
}

function fieldSet(
  samples: readonly ComparisonSample[],
  get: (sample: ComparisonSample) => string | undefined,
): Set<string | undefined> {
  return stringSet(samples.map(get));
}

function uniqueNonempty(set: Set<string | undefined>): string | undefined {
  return set.size === 1 && typeof [...set][0] === "string" && [...set][0]
    ? [...set][0]
    : undefined;
}

function targetIdentity(sample: ComparisonSample): string | undefined {
  const target = sample.record.target;
  if (!target) return undefined;
  const ip = target.ip === undefined ? undefined : canonicalIp(target.ip);
  const hostname =
    typeof target.hostname === "string"
      ? target.hostname.toLowerCase()
      : undefined;
  if (target.ip !== undefined && !ip) return undefined;
  if (target.protocol !== undefined && typeof target.protocol !== "string")
    return undefined;
  if (target.port !== undefined && !Number.isInteger(target.port))
    return undefined;
  if (!ip && !hostname) return undefined;
  return JSON.stringify([ip, hostname, target.protocol, target.port]);
}

function comparisonKey(bucket: ComparisonBucket): string {
  return JSON.stringify([
    bucket.authority,
    bucket.accountGroupId,
    bucket.testId,
    bucket.agentId,
    bucket.testDomain,
    bucket.family,
    bucket.metric,
  ]);
}

function comparisonIdentityKey(
  record: ThousandEyesAttributedObservation,
): string {
  return JSON.stringify([
    record.authority,
    record.accountGroupId,
    record.testId,
    record.agentId,
    record.testDomain,
    record.family,
  ]);
}

function finiteBoundReading(
  record: ThousandEyesAttributedObservation,
  samples: readonly ComparisonSample[],
  metric: string,
): boolean {
  return samples.some(
    (sample) =>
      sample.record === record &&
      sample.measurement.name === metric &&
      finiteNumber(sample.measurement.value),
  );
}

/** Compare only bound scalar samples wholly covered by ordered before/after windows. */
export function compareThousandEyesMeasurements(
  records: readonly ThousandEyesAttributedObservation[],
  before: EvidenceWindow,
  after: EvidenceWindow,
): ThousandEyesComparison[] {
  if (!validWindow(before) || !validWindow(after)) return [];

  const buckets = new Map<string, ComparisonBucket>();
  const roundsByIdentity = new Map<string, ComparisonRounds>();
  for (const record of records) {
    const inBefore = containedInWindow(record.interval, before);
    const inAfter = containedInWindow(record.interval, after);
    const hasNativeIdentity =
      typeof record.testId === "string" &&
      !!record.testId &&
      typeof record.agentId === "string" &&
      !!record.agentId;
    if (
      hasNativeIdentity &&
      isTestDomain(record.testDomain) &&
      (record.family === "metric" || record.family === "path") &&
      (inBefore || inAfter)
    ) {
      const identityKey = comparisonIdentityKey(record);
      let rounds = roundsByIdentity.get(identityKey);
      if (!rounds) {
        rounds = { before: [], after: [] };
        roundsByIdentity.set(identityKey, rounds);
      }
      if (inBefore) rounds.before.push(record);
      if (inAfter) rounds.after.push(record);
    }

    if (!inBefore && !inAfter) continue;

    if (
      record.attribution?.state !== "bound" ||
      record.attribution.bindingIds.length !== 1 ||
      !record.attribution.configurationId ||
      qualityLimitations(record).length > 0 ||
      !isTestDomain(record.testDomain) ||
      record.targetIsProxy === true ||
      (record.family !== "metric" && record.family !== "path")
    )
      continue;
    for (const measurement of record.measurements ?? []) {
      if (
        !measurement ||
        typeof measurement.name !== "string" ||
        !measurement.name
      )
        continue;
      const key = JSON.stringify([
        record.authority,
        record.accountGroupId,
        record.testId,
        record.agentId,
        record.testDomain,
        record.family,
        measurement.name,
      ]);
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = {
          authority: record.authority,
          accountGroupId: record.accountGroupId,
          testId: record.testId ?? "",
          agentId: record.agentId ?? "",
          testDomain: record.testDomain,
          family: record.family,
          metric: measurement.name,
          before: [],
          after: [],
        };
        buckets.set(key, bucket);
      }
      const sample = { record, measurement };
      if (inBefore) bucket.before.push(sample);
      if (inAfter) bucket.after.push(sample);
    }
  }

  const orderedWindows = before.end <= after.start;
  return [...buckets.values()]
    .sort((a, b) => comparisonKey(a).localeCompare(comparisonKey(b)))
    .map((bucket) => {
      const beforeValues = valuesFor(bucket.before);
      const afterValues = valuesFor(bucket.after);
      const sampleRecord = bucket.before[0]?.record ?? bucket.after[0].record;
      const rounds = roundsByIdentity.get(comparisonIdentityKey(sampleRecord));
      const beforeRounds = rounds?.before ?? [];
      const afterRounds = rounds?.after ?? [];
      const beforeMissingMetric = beforeRounds.filter(
        (round) => !finiteBoundReading(round, bucket.before, bucket.metric),
      ).length;
      const afterMissingMetric = afterRounds.filter(
        (round) => !finiteBoundReading(round, bucket.after, bucket.metric),
      ).length;
      const beforeFailures = beforeRounds.filter(
        (round) => round.outcome === "failure",
      ).length;
      const afterFailures = afterRounds.filter(
        (round) => round.outcome === "failure",
      ).length;
      const beforeUnits = fieldSet(
        bucket.before,
        (sample) => sample.measurement.unit,
      );
      const afterUnits = fieldSet(
        bucket.after,
        (sample) => sample.measurement.unit,
      );
      const allUnits = new Set([...beforeUnits, ...afterUnits]);
      const unit =
        allUnits.size === 1 && typeof [...allUnits][0] === "string"
          ? ([...allUnits][0] as string)
          : "mixed";
      const beforeConfigurations = fieldSet(
        bucket.before,
        (sample) => sample.record.attribution.configurationId,
      );
      const afterConfigurations = fieldSet(
        bucket.after,
        (sample) => sample.record.attribution.configurationId,
      );
      const beforeLocations = fieldSet(
        bucket.before,
        (sample) => sample.record.agentLocation,
      );
      const afterLocations = fieldSet(
        bucket.after,
        (sample) => sample.record.agentLocation,
      );
      const beforeTargets = fieldSet(bucket.before, targetIdentity);
      const afterTargets = fieldSet(bucket.after, targetIdentity);
      const beforeAggregations = fieldSet(
        bucket.before,
        (sample) => sample.measurement.aggregation,
      );
      const afterAggregations = fieldSet(
        bucket.after,
        (sample) => sample.measurement.aggregation,
      );
      const beforeDirections = fieldSet(
        bucket.before,
        (sample) => sample.measurement.direction,
      );
      const afterDirections = fieldSet(
        bucket.after,
        (sample) => sample.measurement.direction,
      );
      const beforePathDirections = fieldSet(
        bucket.before,
        (sample) => sample.record.pathDirection,
      );
      const afterPathDirections = fieldSet(
        bucket.after,
        (sample) => sample.record.pathDirection,
      );
      const beforeDenominators = fieldSet(
        bucket.before,
        (sample) => sample.measurement.denominator,
      );
      const afterDenominators = fieldSet(
        bucket.after,
        (sample) => sample.measurement.denominator,
      );
      const beforeTimeBases = fieldSet(
        bucket.before,
        (sample) => sample.measurement.timeBasis,
      );
      const afterTimeBases = fieldSet(
        bucket.after,
        (sample) => sample.measurement.timeBasis,
      );
      const beforeIntervalBases = fieldSet(
        bucket.before,
        (sample) => sample.record.intervalBasis,
      );
      const afterIntervalBases = fieldSet(
        bucket.after,
        (sample) => sample.record.intervalBasis,
      );
      const beforeAdapterVersions = fieldSet(
        bucket.before,
        (sample) => sample.record.adapterVersion,
      );
      const afterAdapterVersions = fieldSet(
        bucket.after,
        (sample) => sample.record.adapterVersion,
      );
      const beforeDataModelVersions = fieldSet(
        bucket.before,
        (sample) => sample.record.dataModelVersion,
      );
      const afterDataModelVersions = fieldSet(
        bucket.after,
        (sample) => sample.record.dataModelVersion,
      );
      const beforeProducerVersions = fieldSet(bucket.before, (sample) =>
        producerVersionForComparison(sample.record.producerVersion),
      );
      const afterProducerVersions = fieldSet(bucket.after, (sample) =>
        producerVersionForComparison(sample.record.producerVersion),
      );

      const reasons = [
        `Before window: ${beforeValues.length} finite scalar sample(s) across ${beforeRounds.length} same-identity observation(s); ${beforeFailures} failed round(s), ${beforeMissingMetric} round(s) without a finite bound ${bucket.metric} reading.`,
        `After window: ${afterValues.length} finite scalar sample(s) across ${afterRounds.length} same-identity observation(s); ${afterFailures} failed round(s), ${afterMissingMetric} round(s) without a finite bound ${bucket.metric} reading.`,
      ];
      const blockers: string[] = [];
      if (!orderedWindows)
        blockers.push("Before and after windows overlap or are out of order.");
      if (!beforeValues.length)
        blockers.push(
          "No finite scalar measurement is wholly covered by the before window.",
        );
      if (!afterValues.length)
        blockers.push(
          "No finite scalar measurement is wholly covered by the after window.",
        );
      if (beforeMissingMetric > 0 || afterMissingMetric > 0)
        blockers.push(
          "One or more same-identity rounds lack a finite bound reading for this metric; successful-sample coverage may be biased.",
        );

      const compareField = (
        beforeSet: Set<string | undefined>,
        afterSet: Set<string | undefined>,
        label: string,
        requireKnown = false,
      ) => {
        if (!beforeValues.length || !afterValues.length) return;
        if (
          beforeSet.size !== 1 ||
          afterSet.size !== 1 ||
          beforeSet.has(undefined) ||
          afterSet.has(undefined)
        ) {
          blockers.push(
            `${label} is missing or varies within a comparison window.`,
          );
        } else {
          const beforeValue = [...beforeSet][0];
          const afterValue = [...afterSet][0];
          if (
            requireKnown &&
            (!isKnownMetadata(beforeValue) || !isKnownMetadata(afterValue))
          ) {
            blockers.push(`${label} is unknown or unreported.`);
          } else if (beforeValue !== afterValue) {
            blockers.push(`${label} changed between windows.`);
          }
        }
      };

      compareField(beforeUnits, afterUnits, "Measurement unit", true);
      compareField(
        beforeConfigurations,
        afterConfigurations,
        "Test configuration",
        true,
      );
      compareField(beforeLocations, afterLocations, "Agent location", true);
      compareField(beforeTargets, afterTargets, "Target identity");
      compareField(
        beforeAggregations,
        afterAggregations,
        "Measurement aggregation",
        true,
      );
      compareField(
        beforeDirections,
        afterDirections,
        "Measurement direction",
        true,
      );
      if (bucket.family === "path")
        compareField(
          beforePathDirections,
          afterPathDirections,
          "Probe path direction",
          true,
        );
      compareField(
        beforeDenominators,
        afterDenominators,
        "Measurement denominator",
        true,
      );
      compareField(
        beforeTimeBases,
        afterTimeBases,
        "Measurement time basis",
        true,
      );
      compareField(
        beforeIntervalBases,
        afterIntervalBases,
        "Observation interval basis",
        true,
      );
      compareField(
        beforeAdapterVersions,
        afterAdapterVersions,
        "Atlas adapter version",
        true,
      );
      compareField(
        beforeDataModelVersions,
        afterDataModelVersions,
        "ThousandEyes data-model version",
        true,
      );

      if (beforeValues.length && afterValues.length) {
        if (
          beforeProducerVersions.size !== 1 ||
          afterProducerVersions.size !== 1
        ) {
          blockers.push(
            "Producer version is missing or varies within a comparison window.",
          );
        } else {
          const beforeVersion = [...beforeProducerVersions][0];
          const afterVersion = [...afterProducerVersions][0];
          if (beforeVersion === undefined && afterVersion === undefined) {
            reasons.push(
              "Producer version was not reported in either window; no version is inferred, and comparison relies on matching known adapter and data-model versions.",
            );
          } else if (
            (beforeVersion !== undefined && !isKnownMetadata(beforeVersion)) ||
            (afterVersion !== undefined && !isKnownMetadata(afterVersion))
          ) {
            blockers.push("Producer version is unknown or invalid.");
          } else if (
            beforeVersion === undefined ||
            afterVersion === undefined
          ) {
            blockers.push(
              "Producer version is not reported in one window and known in the other.",
            );
          } else if (beforeVersion !== afterVersion) {
            blockers.push("Producer version changed between windows.");
          }
        }
      }

      let comparable = blockers.length === 0;
      const beforeMean = comparable ? scalarMean(beforeValues) : undefined;
      const afterMean = comparable ? scalarMean(afterValues) : undefined;
      let delta =
        beforeMean !== undefined && afterMean !== undefined
          ? afterMean - beforeMean
          : undefined;
      if (delta !== undefined && !Number.isFinite(delta)) {
        blockers.push("Mean delta exceeds the supported numeric range.");
        comparable = false;
        delta = undefined;
      }
      reasons.push(...blockers);

      const agentLocation = uniqueNonempty(
        new Set([...beforeLocations, ...afterLocations]),
      );
      return {
        key: comparisonKey(bucket),
        authority: bucket.authority,
        accountGroupId: bucket.accountGroupId,
        testId: bucket.testId,
        agentId: bucket.agentId,
        testDomain: bucket.testDomain,
        ...(agentLocation ? { agentLocation } : {}),
        metric:
          bucket.family === "path" ? `path: ${bucket.metric}` : bucket.metric,
        unit,
        beforeCount: beforeValues.length,
        afterCount: afterValues.length,
        ...(comparable && beforeMean !== undefined ? { beforeMean } : {}),
        ...(comparable && afterMean !== undefined ? { afterMean } : {}),
        ...(comparable && delta !== undefined ? { delta } : {}),
        comparable,
        reasons,
      } satisfies ThousandEyesComparison;
    });
}
