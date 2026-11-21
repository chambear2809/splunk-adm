import { emptyTopology, indexTopology } from "../topology";
import {
  type Classifier,
  type Failure,
  type ImpactConversation,
} from "./classify";
import type { ImpactData } from "./data";
import { resolveElement } from "./elements";
import type {
  ObservedImpactEvidence,
  ObservedImpactTrial,
} from "./observedEvidence";
import { accessFor, pathContext } from "./paths";

const observedDevices = (trial: ObservedImpactTrial) => [
  ...new Set([
    ...trial.observations.forward,
    ...trial.observations.reverse,
    ...trial.linkedCaptures.map((capture) => capture.device),
  ]),
];

export interface JourneyImpact {
  journey: string;
  app: string;
  actor: ObservedImpactTrial["actor"];
  trials: ObservedImpactTrial[];
  exposed: ObservedImpactTrial[];
  remaining: ObservedImpactTrial[];
  incomplete: ObservedImpactTrial[];
  remainingDevices: Set<string>;
}

/** A comparable repeat needs positive observations in both directions at
 * each selected tier. A linked backend leg establishes exposure only. */
export function observedJourneyImpact(
  cohort: ObservedImpactEvidence,
  failure: Failure,
): JourneyImpact[] {
  const journeys = new Map<string, JourneyImpact>();
  const roles = new Map(
    cohort.devices.map((device) => [device.id, device.role]),
  );
  const selectedRoles = new Set(
    cohort.devices
      .filter((device) => failure.ref(device.id))
      .map((device) => device.role),
  );
  for (const trial of cohort.trials) {
    const key = JSON.stringify([trial.app, trial.actor, trial.journey]);
    const journey = journeys.get(key) ?? {
      journey: trial.journey,
      app: trial.app,
      actor: trial.actor,
      trials: [],
      exposed: [],
      remaining: [],
      incomplete: [],
      remainingDevices: new Set<string>(),
    };
    journey.trials.push(trial);
    if (observedDevices(trial).some(failure.ref)) {
      journey.exposed.push(trial);
    } else if (
      [...selectedRoles].every(
        (role) =>
          trial.observations.forward.some((id) => roles.get(id) === role) &&
          trial.observations.reverse.some((id) => roles.get(id) === role),
      )
    ) {
      journey.remaining.push(trial);
      for (const id of [
        ...trial.observations.forward,
        ...trial.observations.reverse,
      ]) {
        const role = roles.get(id);
        if (role && selectedRoles.has(role)) journey.remainingDevices.add(id);
      }
    } else {
      journey.incomplete.push(trial);
    }
    journeys.set(key, journey);
  }
  return [...journeys.values()];
}

/** Build the native Impact input without loading unscoped topology or assigning
 * routing paths between independent observations. */
export function observedImpactData(
  cohort: ObservedImpactEvidence,
  tokens: string[],
): ImpactData {
  const topology = {
    ...emptyTopology(),
    devices: cohort.devices.map(({ id, name, role }) => ({
      id,
      name,
      role,
      kind: "switch" as const,
      mgmt_ip: id,
      sources: ["qualified Impact evidence"],
      scope: cohort.scope,
    })),
  };
  const topo = indexTopology(topology);
  const elements = tokens.map((token) => resolveElement(token, topology, topo));
  if (
    !elements.length ||
    elements.some((e) => !e.resolved || e.kind !== "device") ||
    new Set(elements.flatMap((e) => [...e.devices])).size !== elements.length
  )
    throw new Error(
      "Select distinct devices covered by this fixed-window Impact cohort.",
    );
  const conversations: ImpactConversation[] = cohort.trials.map((trial) => ({
    id: trial.id,
    src: { key: `ip:${trial.src}`, ip: trial.src },
    dst: { key: `ip:${trial.dst}`, ip: trial.dst },
    app: trial.app,
    port: trial.destination_port,
    protocol: "tcp",
    flows: 1,
    observers: observedDevices(trial),
    directions: trial.observations.reverse.length ? "both" : "forward",
  }));
  return {
    topology,
    topo,
    ctx: pathContext(topo),
    elements,
    conversations,
    total: conversations.length,
    truncated: false,
    capped: false,
    source: "Scoped Trace receipts and native Stream NetFlow",
    observed: cohort,
  };
}

export function observedImpactClassifier(
  ctx: Classifier["ctx"],
  cohort: ObservedImpactEvidence,
): Classifier {
  const trials = new Map(cohort.trials.map((trial) => [trial.id, trial]));
  const devices = new Map(cohort.devices.map((device) => [device.id, device]));
  return {
    ctx,
    classify(conv, failure) {
      const matched = conv.observers.filter(failure.ref);
      const trial = trials.get(conv.id);
      const linkedOnly =
        matched.length > 0 &&
        trial &&
        ![...trial.observations.forward, ...trial.observations.reverse].some(
          failure.ref,
        );
      return {
        conv,
        severity: matched.length ? "unknown" : "unaffected",
        traversal: "observed",
        ...(linkedOnly ? { linkedTraversal: true } : {}),
        alternate: [],
        reason: linkedOnly
          ? "Linked downstream leg observed; outcome unverified"
          : matched.length
            ? "Traversal observed; failure outcome unverified"
            : "No traversal of the selection in this sample",
        failedAt: matched.map((id) => devices.get(id)?.name ?? id),
      };
    },
    path(conv) {
      const a = accessFor(conv.src, ctx);
      const b = accessFor(conv.dst, ctx);
      const nodes = new Map([...a.nodes, ...b.nodes]);
      const trial = trials.get(conv.id);
      for (const id of trial ? observedDevices(trial) : []) {
        const device = devices.get(id);
        if (device)
          nodes.set(id, {
            id,
            label: device.name,
            tier: device.role === "border" ? "leaf" : device.role,
            refs: [id],
            depth: 1,
          });
      }
      return [
        {
          a,
          b,
          nodes,
          edges: [],
          cand: new Set(nodes.keys()),
          groups: [],
          core: [],
          local: false,
        },
      ];
    },
  };
}
