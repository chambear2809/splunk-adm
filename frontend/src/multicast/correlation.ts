import {
  MAX_EVIDENCE_ROWS,
  MAX_INPUT_ROWS,
  type ForwardingEvidence,
  type IgmpEvidence,
  type MulticastAdjacency,
  type MulticastEvidence,
  type MulticastRequest,
  type MulticastTopology,
  type Segment,
} from "./contract";
import {
  groupAddress,
  scopeName,
  parseSegment,
  sourceAddress,
  validateRequest,
} from "./inputs";

const segmentKey = (segment: Segment) =>
  JSON.stringify([segment.kind, segment.domain, segment.id]);
const endpointKey = (observer: string, port: string) =>
  JSON.stringify([observer, port]);
const nonempty = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

/** Correlate observations, never inferring links from traffic records. */
export function correlateMulticast(
  request: MulticastRequest,
  rows: readonly MulticastEvidence[],
  adjacency: readonly MulticastAdjacency[] = [],
): MulticastTopology {
  const query = validateRequest(request);
  let capped =
    rows.length > MAX_INPUT_ROWS || adjacency.length > MAX_INPUT_ROWS;
  const selected = rows.slice(0, MAX_INPUT_ROWS).filter((row) => {
    if (
      scopeName(row.scope) !== query.scope ||
      groupAddress(row.group) !== query.group ||
      !Number.isFinite(row.timestamp) ||
      row.timestamp < query.earliest ||
      row.timestamp > query.latest ||
      !nonempty(row.observer)
    )
      return false;
    if (row.kind === "flow")
      return (
        !!sourceAddress(row.sender) &&
        (!query.sender || sourceAddress(row.sender) === query.sender)
      );
    if (row.kind === "forwarding" && row.sender)
      return (
        !!sourceAddress(row.sender) &&
        (!query.sender || sourceAddress(row.sender) === query.sender)
      );
    return true;
  });

  // A replay identity is scoped to its observer and source. Conflicting payloads
  // remain visible but cannot support a conclusion.
  const replayGroups = new Map<string, MulticastEvidence[]>();
  for (const row of selected) {
    if (!nonempty(row.replayKey)) continue;
    const key = JSON.stringify([row.source, row.observer, row.replayKey]);
    const group = replayGroups.get(key) ?? [];
    group.push(row);
    replayGroups.set(key, group);
  }
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, item]) => [key, canonical(item)]),
      );
    return value;
  };
  const signature = (row: MulticastEvidence) => {
    return JSON.stringify(
      canonical(
        Object.fromEntries(Object.entries(row).filter(([key]) => key !== "id")),
      ),
    );
  };
  const conflicts = new Set<MulticastEvidence>();
  const duplicates = new Set<MulticastEvidence>();
  for (const group of replayGroups.values()) {
    if (new Set(group.map(signature)).size > 1)
      group.forEach((row) => conflicts.add(row));
    else group.slice(1).forEach((row) => duplicates.add(row));
  }
  const visible = selected.filter((row) => !duplicates.has(row));
  if (visible.length > MAX_EVIDENCE_ROWS) capped = true;
  const evidence = visible.slice(0, MAX_EVIDENCE_ROWS);
  const usable = evidence.filter((row) => !conflicts.has(row));
  const senderMap = new Map<string, string[]>();
  for (const row of usable) {
    if (row.kind !== "flow") continue;
    const address = sourceAddress(row.sender);
    if (!address) continue;
    const ids = senderMap.get(address) ?? [];
    ids.push(row.id);
    senderMap.set(address, ids);
  }

  const reports = new Map<string, IgmpEvidence[]>();
  for (const row of usable) {
    if (row.kind !== "igmp" || row.reporterKind !== "endpoint") continue;
    const reporter = sourceAddress(row.reporter);
    const segment = parseSegment(row.segment);
    if (!reporter || !segment) continue;
    const key = JSON.stringify([reporter, segmentKey(segment)]);
    const list = reports.get(key) ?? [];
    list.push(row);
    reports.set(key, list);
  }
  const receivers: MulticastTopology["receivers"] = [];
  for (const list of reports.values()) {
    list.sort((a, b) => a.timestamp - b.timestamp);
    let mode: "include" | "exclude" | undefined;
    let sources = new Set<string>();
    let lastPositive: IgmpEvidence | undefined;
    let uncertain = false;
    let lastTime = -Infinity;
    for (const row of list) {
      if (row.sources.length > 64) {
        capped = true;
        continue;
      }
      const items = row.sources.map(sourceAddress);
      if (items.some((value) => !value)) continue;
      const values = items as string[];
      const matches = () =>
        query.sender
          ? mode === "include"
            ? sources.has(query.sender)
            : mode === "exclude" && !sources.has(query.sender)
          : mode === "exclude" || (mode === "include" && sources.size > 0);
      if (row.operation === "query") continue;
      const sameTime = row.timestamp === lastTime;
      lastTime = row.timestamp;
      if (row.operation === "leave") {
        if (lastPositive) uncertain = true;
        mode = undefined;
        continue;
      }
      if (row.operation === "report-v1" || row.operation === "report-v2") {
        mode = "exclude";
        sources = new Set();
      } else if (
        row.operation === "include" ||
        row.operation === "change-to-include"
      ) {
        mode = "include";
        sources = new Set(values);
      } else if (
        row.operation === "exclude" ||
        row.operation === "change-to-exclude"
      ) {
        mode = "exclude";
        sources = new Set(values);
      } else if (row.operation === "allow-new-sources") {
        if (!mode) {
          // A positive delta is evidence only for the listed sources.
          mode = "include";
          sources = new Set(values);
        } else if (mode === "include")
          values.forEach((value) => sources.add(value));
        else values.forEach((value) => sources.delete(value));
      } else if (row.operation === "block-old-sources") {
        if (!mode) continue;
        if (mode === "include")
          values.forEach((value) => sources.delete(value));
        else values.forEach((value) => sources.add(value));
      }
      if (matches()) {
        lastPositive = row;
        uncertain = sameTime;
      } else if (lastPositive) uncertain = true;
      if (sameTime && lastPositive) uncertain = true;
    }
    if (lastPositive?.segment && lastPositive.reporter)
      receivers.push({
        reporter: sourceAddress(lastPositive.reporter)!,
        segment: lastPositive.segment,
        evidenceId: lastPositive.id,
        state: uncertain ? "uncertain" : "observed",
      });
  }

  const states = usable.filter(
    (row): row is ForwardingEvidence =>
      row.kind === "forwarding" && Number.isFinite(row.validUntil),
  );
  const links = adjacency
    .slice(0, MAX_INPUT_ROWS)
    .filter(
      (link) =>
        scopeName(link.scope) === query.scope &&
        nonempty(link.from.observer) &&
        nonempty(link.from.interface) &&
        nonempty(link.to.observer) &&
        nonempty(link.to.interface) &&
        Number.isFinite(link.validFrom) &&
        Number.isFinite(link.validUntil),
    );
  const branches: MulticastTopology["branches"] = [];
  for (const state of states) {
    for (const output of state.outputs.slice(0, MAX_EVIDENCE_ROWS)) {
      if (!nonempty(output)) continue;
      if (branches.length >= MAX_EVIDENCE_ROWS) {
        capped = true;
        break;
      }
      const stale =
        state.validUntil < query.latest || state.validUntil < state.timestamp;
      const candidates = links.filter(
        (link) =>
          link.from.observer === state.observer &&
          link.from.interface === output &&
          link.validFrom <= state.timestamp &&
          link.validUntil >= query.latest,
      );
      const link = candidates.length === 1 ? candidates[0] : undefined;
      const uniqueTarget =
        link &&
        links.filter(
          (other) =>
            endpointKey(other.to.observer, other.to.interface) ===
              endpointKey(link.to.observer, link.to.interface) &&
            other.validFrom <= state.timestamp &&
            other.validUntil >= query.latest,
        ).length === 1;
      const targetStates = link
        ? states.filter(
            (target) =>
              target.observer === link.to.observer &&
              target.input === link.to.interface &&
              target.validUntil >= query.latest &&
              target.timestamp <= query.latest &&
              (!query.sender ||
                (!!target.sender &&
                  sourceAddress(target.sender) === query.sender)) &&
              sourceAddress(state.sender) === sourceAddress(target.sender),
          )
        : [];
      const sourceStates = states.filter(
        (candidate) =>
          candidate.observer === state.observer &&
          candidate.validUntil >= query.latest &&
          sourceAddress(candidate.sender) === sourceAddress(state.sender),
      );
      const supported =
        !stale &&
        sourceStates.length === 1 &&
        (!query.sender || !!state.sender) &&
        !!link &&
        uniqueTarget &&
        targetStates.length === 1;
      branches.push({
        from: state.observer,
        output,
        ...(supported ? { to: link.to.observer } : {}),
        evidenceId: state.id,
        state: stale ? "stale" : supported ? "supported" : "unresolved",
      });
    }
    if (state.outputs.length > MAX_EVIDENCE_ROWS) capped = true;
  }
  return {
    evidence,
    senders: Array.from(senderMap, ([address, evidenceIds]) => ({
      address,
      evidenceIds,
    })),
    receivers,
    branches,
    capped,
  };
}
