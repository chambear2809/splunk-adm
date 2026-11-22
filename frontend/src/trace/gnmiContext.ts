import type { TraceHop } from "../data/pathTrace";

export interface GnmiContextRequest {
  scope?: string;
  earliest?: number;
  latest?: number;
}

const metricPrefix = "openconfig.interfaces.interface.state.";
const counterNames = {
  [metricPrefix + "counters.in-discards"]: "in-discards",
  [metricPrefix + "counters.out-discards"]: "out-discards",
  [metricPrefix + "counters.carrier-transitions"]: "carrier-transitions",
};
const statusMetric = metricPrefix + "oper-status_state";
// The opt-in reader's 10-second sampling contract tolerates two missed samples.
const maxSampleAge = 30;
const statuses = new Set([
  "UP",
  "DOWN",
  "TESTING",
  "UNKNOWN",
  "DORMANT",
  "NOT_PRESENT",
  "LOWER_LAYER_DOWN",
]);

function text(row: Record<string, unknown>, key: string) {
  const value = row[key];
  return typeof value === "string" && value.length <= 512 ? value : "";
}

function sampleTime(value: unknown) {
  if (typeof value === "number") return value;
  if (typeof value !== "string" || !value.trim()) return NaN;
  const seconds = Number(value);
  return Number.isFinite(seconds) ? seconds : Date.parse(value) / 1000;
}

type Sample = { when: number; value: number; state: string };
type InterfaceSamples = {
  interface: string;
  ifIndex: string;
  authority: string;
  samples: Map<string, Sample>;
};

/** Add interface health to NetFlow observations without creating or ordering hops. */
export function attachGnmiContext(
  hops: readonly TraceHop[],
  rows: readonly unknown[],
  { scope, earliest, latest }: GnmiContextRequest,
): TraceHop[] {
  if (!scope || earliest === undefined || latest === undefined)
    return [...hops];

  const grouped = new Map<string, InterfaceSamples>();
  const ambiguous = new Set<string>();
  for (const value of rows) {
    if (!value || typeof value !== "object") continue;
    const row = value as Record<string, unknown>;
    const endpoint = text(row, "server.address");
    const authority =
      /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(endpoint)?.[1] ??
      /^\[([0-9a-fA-F:]+)\]:\d+$/.exec(endpoint)?.[1];
    const iface = text(row, "atlas.interface");
    const ifIndex = text(row, "atlas.ifindex");
    const metric = text(row, "metric_name");
    const state = text(row, "state");
    const when = sampleTime(row._time);
    const reading = row.value;
    const sample =
      typeof reading === "number" ||
      (typeof reading === "string" && reading.trim())
        ? Number(reading)
        : NaN;
    if (
      row.row_type !== "interface_context" ||
      text(row, "source") !== "atlas:gnmi:pilot" ||
      text(row, "sourcetype") !== "otel:gnmi" ||
      text(row, "atlas.scope") !== scope ||
      !authority ||
      !/^[A-Za-z][A-Za-z0-9/_.:-]{0,63}$/.test(iface) ||
      !/^[1-9]\d{0,9}$/.test(ifIndex) ||
      !Number.isFinite(when) ||
      when < Math.max(earliest, latest - maxSampleAge) ||
      when >= latest ||
      !Number.isFinite(sample) ||
      sample < 0 ||
      (metric === statusMetric
        ? sample !== 1 || !statuses.has(state)
        : !Object.hasOwn(counterNames, metric))
    )
      continue;
    const key = `${authority}|${ifIndex}`;
    const entry = grouped.get(key) ?? {
      interface: iface,
      ifIndex,
      authority,
      samples: new Map<string, Sample>(),
    };
    if (entry.interface !== iface) {
      ambiguous.add(key);
      continue;
    }
    const previous = entry.samples.get(metric);
    if (!previous || when > previous.when)
      entry.samples.set(metric, { when, value: sample, state });
    grouped.set(key, entry);
  }

  return hops.map((hop) => {
    if (
      hop.kind !== "switch" ||
      hop.evidence !== "observed" ||
      !hop.sources.includes("Stream NetFlow") ||
      !hop.device
    )
      return hop;
    const indexes = new Set(
      [hop.in, hop.out, ...hop.seen]
        .flatMap((label) => label?.split(/\s*,\s*/) ?? [])
        .flatMap((label) => /^ifIndex ([1-9]\d{0,9})$/.exec(label)?.[1] ?? []),
    );
    const contexts = [...indexes].flatMap((index) => {
      const key = `${hop.device}|${index}`;
      const entry = grouped.get(key);
      if (!entry || ambiguous.has(key)) return [];
      const { samples, ...identity } = entry;
      const status = samples.get(statusMetric);
      const counters = Object.fromEntries(
        Object.entries(counterNames).flatMap(([name, label]) => {
          const sample = samples.get(name);
          return sample
            ? [[label, { value: sample.value, sampledAt: sample.when }]]
            : [];
        }),
      );
      return [
        {
          ...identity,
          ...(status
            ? { operStatus: { value: status.state, sampledAt: status.when } }
            : {}),
          counters,
        },
      ];
    });
    return contexts.length ? { ...hop, interfaceContext: contexts } : hop;
  });
}
