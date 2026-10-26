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
  if (!targetIp || !Array.isArray(selection.contexts)) return false;
  return selection.contexts.some((context) => {
    if (
      !context ||
      context.capped ||
      context.scope !== selection.scope ||
      !intervalsOverlapContext(record.interval, context.first, context.last)
    )
      return false;
    return (
      canonicalIp(context.client) === targetIp ||
      canonicalIp(context.server) === targetIp
    );
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
    const observedDependency = hasCompatibleSelectedContext(record, selection);
    const contextReason = observedDependency
      ? "A compatible uncapped selected traffic context overlaps this target and interval; this does not prove the same route or protocol/port tuple."
      : undefined;
    const qualityIssues = qualityLimitations(record);
    if (qualityIssues.length) {
      return {
        ...record,
        attribution: {
          state: "context_only",
          bindingIds: [],
          reason: [
            `Record quality prevents attribution: ${qualityIssues.join(", ")}.`,
            "The record remains context only and is not eligible for comparison.",
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

    const identityCandidates = exactIdentityPresent
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
    const targetCandidates = identityCandidates.filter((binding) =>
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
          "Exactly one historical binding matches the authority, account group, native test/agent, routing scope, selected endpoint address, target, and whole observation interval.",
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
          "Multiple overlapping historical bindings match the selected identity and target; their configuration cannot establish one attribution.",
          ...(record.configurationId !== undefined &&
          configurationCandidates.length === 0
            ? ["The observed configuration ID matches none of those bindings."]
            : []),
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
      } else if (identityCandidates.length > 0) {
        reason =
          "The observed target does not exactly match the configured target; hostnames are never resolved.";
      } else {
        reason =
          "No historical binding matches the exact authority, account group, native test/agent, routing scope, selected application, endpoint address, target, and whole observation interval.";
      }
      attribution = {
        state: observedDependency ? "context_only" : "unmatched",
        bindingIds: [],
        reason: [
          reason,
          ...(observedDependency
            ? [contextReason!]
            : ["No compatible uncapped selected traffic context is present."]),
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
  family: "metric" | "path";
  metric: string;
  before: ComparisonSample[];
  after: ComparisonSample[];
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
    bucket.family,
    bucket.metric,
  ]);
}

/** Compare only bound scalar samples wholly covered by ordered before/after windows. */
export function compareThousandEyesMeasurements(
  records: readonly ThousandEyesAttributedObservation[],
  before: EvidenceWindow,
  after: EvidenceWindow,
): ThousandEyesComparison[] {
  if (!validWindow(before) || !validWindow(after)) return [];

  const buckets = new Map<string, ComparisonBucket>();
  for (const record of records) {
    if (
      record.attribution?.state !== "bound" ||
      record.attribution.bindingIds.length !== 1 ||
      !record.attribution.configurationId ||
      qualityLimitations(record).length > 0 ||
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
          family: record.family,
          metric: measurement.name,
          before: [],
          after: [],
        };
        buckets.set(key, bucket);
      }
      const sample = { record, measurement };
      if (containedInWindow(record.interval, before))
        bucket.before.push(sample);
      if (containedInWindow(record.interval, after)) bucket.after.push(sample);
    }
  }

  const orderedWindows = before.end <= after.start;
  return [...buckets.values()]
    .sort((a, b) => comparisonKey(a).localeCompare(comparisonKey(b)))
    .map((bucket) => {
      const beforeValues = valuesFor(bucket.before);
      const afterValues = valuesFor(bucket.after);
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

      const reasons = [
        `Before window: ${beforeValues.length} scalar sample(s).`,
        `After window: ${afterValues.length} scalar sample(s).`,
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

      const compareField = (
        beforeSet: Set<string | undefined>,
        afterSet: Set<string | undefined>,
        label: string,
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
        } else if ([...beforeSet][0] !== [...afterSet][0]) {
          blockers.push(`${label} changed between windows.`);
        }
      };

      compareField(beforeUnits, afterUnits, "Measurement unit");
      compareField(
        beforeConfigurations,
        afterConfigurations,
        "Test configuration",
      );
      compareField(beforeLocations, afterLocations, "Agent location");
      compareField(beforeTargets, afterTargets, "Target identity");
      compareField(
        beforeAggregations,
        afterAggregations,
        "Measurement aggregation",
      );
      compareField(beforeDirections, afterDirections, "Measurement direction");
      compareField(
        beforeDenominators,
        afterDenominators,
        "Measurement denominator",
      );
      compareField(beforeTimeBases, afterTimeBases, "Measurement time basis");
      compareField(
        beforeIntervalBases,
        afterIntervalBases,
        "Observation interval basis",
      );

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
