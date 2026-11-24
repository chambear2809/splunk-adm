import type { Row } from "../rows";
import { fingerprint, isObject, literal } from "../data/evidence";
import { optionalJobs } from "../data/optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import {
  MAX_EVIDENCE_ROWS,
  MAX_INPUT_ROWS,
  type ForwardingEvidence,
  type ForwardingProfile,
  type MulticastAdjacency,
  type MulticastRequest,
  type SourceOutcome,
} from "./contract";
import { parseProfile, validateRequest } from "./inputs";

const MAX_RAW = 65536;
const MAX_DEVICES = 128;
const MAX_INTERFACES = 256;
const MAX_ADJACENCIES = 256;
const name = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length <= 128 &&
  /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.exec(value)?.[0] === value;
const uint = (value: unknown): number | undefined =>
  typeof value === "number" &&
  Number.isSafeInteger(value) &&
  value > 0 &&
  value <= 253402300799
    ? value
    : undefined;
const only = (value: Record<string, unknown>, keys: readonly string[]) =>
  Object.keys(value).every((key) => keys.includes(key));
const count = (value: unknown): number | undefined =>
  (typeof value === "string" || typeof value === "number") &&
  /^\d+$/.test(String(value)) &&
  Number.isSafeInteger(Number(value))
    ? Number(value)
    : undefined;

type Device = { observer: string; input: string; outputs: string[] };
type Endpoint = { observer: string; interface: string };
type Cohort = {
  observedAt: number;
  validUntil: number;
  devices: Device[];
  links: { from: Endpoint; to: Endpoint }[];
};

/** An event is an indivisible, source-qualified snapshot; no device fragments are joined. */
export function buildForwardingSearch(
  input: ForwardingProfile,
  selection: MulticastRequest,
): string {
  const profile = parseProfile(input),
    request = validateRequest(selection);
  if (profile.source !== "multicast_nxos" || !request.sender)
    throw new Error("A forwarding source and sender are required.");
  const index = literal(profile.index),
    observer = literal(profile.observer),
    scope = literal(request.scope),
    group = request.group,
    sender = request.sender;
  return `search index="${index}" sourcetype="atlas:nxos:multicast:v1" host="${observer}"
| eval oversized=if(len(_raw)>${MAX_RAW},1,0)
| where _time<=${request.latest} AND (json_extract(_raw,"scope")="${scope}" AND json_extract(_raw,"group")="${group}" AND json_extract(_raw,"sender")="${sender}")
| sort ${MAX_INPUT_ROWS + 1} - _time
| head ${MAX_INPUT_ROWS + 1}
| eventstats count AS input_count
| head ${MAX_INPUT_ROWS}
| eval payload=if(oversized=1,"{}",_raw)
| eval mc_epoch=_time
| fields mc_epoch index host payload oversized input_count
| fields - _raw _time
| eval kind="record"
| appendpipe [| stats count AS returned_count max(input_count) AS input_count | eval kind="completion",input_count=coalesce(input_count,0)]`;
}

function parseCohort(
  row: Row,
  profile: ForwardingProfile,
  request: MulticastRequest,
): Cohort | undefined {
  if (
    row.index !== profile.index ||
    row.host !== profile.observer ||
    count(row.oversized) !== 0 ||
    typeof row.payload !== "string" ||
    row.payload.length > MAX_RAW
  )
    return;
  let value: unknown;
  try {
    value = JSON.parse(row.payload);
  } catch {
    return;
  }
  if (
    !isObject(value) ||
    !only(value, [
      "schemaVersion",
      "scope",
      "group",
      "sender",
      "observedAt",
      "validUntil",
      "devices",
      "adjacencies",
    ]) ||
    value.schemaVersion !== 1 ||
    value.scope !== request.scope ||
    value.group !== request.group ||
    value.sender !== request.sender
  )
    return;
  const observedAt = uint(value.observedAt),
    validUntil = uint(value.validUntil),
    indexedTime = Number(row.mc_epoch);
  if (
    !observedAt ||
    !validUntil ||
    !Number.isFinite(indexedTime) ||
    indexedTime !== observedAt ||
    observedAt < request.earliest ||
    observedAt > request.latest ||
    validUntil < observedAt ||
    validUntil > profile.validUntil ||
    observedAt < profile.validFrom
  )
    return;
  if (
    !Array.isArray(value.devices) ||
    value.devices.length < 1 ||
    value.devices.length > MAX_DEVICES ||
    !Array.isArray(value.adjacencies) ||
    value.adjacencies.length > MAX_ADJACENCIES
  )
    return;
  const devices: Device[] = [],
    byObserver = new Map<string, Device>();
  let interfaces = 0;
  for (const item of value.devices) {
    if (
      !isObject(item) ||
      !only(item, ["observer", "input", "outputs"]) ||
      !name(item.observer) ||
      !name(item.input) ||
      !Array.isArray(item.outputs) ||
      item.outputs.length > MAX_INTERFACES ||
      !item.outputs.every(name) ||
      new Set(item.outputs).size !== item.outputs.length ||
      item.outputs.includes(item.input) ||
      byObserver.has(item.observer)
    )
      return;
    interfaces += item.outputs.length;
    if (interfaces > MAX_INTERFACES) return;
    const device: Device = {
      observer: item.observer,
      input: item.input,
      outputs: [...item.outputs],
    };
    devices.push(device);
    byObserver.set(device.observer, device);
  }
  const links: Cohort["links"] = [],
    usedFrom = new Set<string>(),
    usedTo = new Set<string>();
  for (const item of value.adjacencies) {
    if (
      !isObject(item) ||
      !only(item, ["from", "to"]) ||
      !isObject(item.from) ||
      !isObject(item.to) ||
      !only(item.from, ["observer", "interface"]) ||
      !only(item.to, ["observer", "interface"]) ||
      !name(item.from.observer) ||
      !name(item.from.interface) ||
      !name(item.to.observer) ||
      !name(item.to.interface)
    )
      return;
    const from = {
        observer: item.from.observer,
        interface: item.from.interface,
      },
      to = { observer: item.to.observer, interface: item.to.interface };
    const fromKey = `${from.observer}\0${from.interface}`,
      toKey = `${to.observer}\0${to.interface}`;
    if (
      from.observer === to.observer ||
      !byObserver.get(from.observer)?.outputs.includes(from.interface) ||
      byObserver.get(to.observer)?.input !== to.interface ||
      usedFrom.has(fromKey) ||
      usedTo.has(toKey)
    )
      return;
    usedFrom.add(fromKey);
    usedTo.add(toKey);
    links.push({ from, to });
  }
  return { observedAt, validUntil, devices, links };
}

export async function loadMulticastForwarding(
  client: SearchClient,
  input: ForwardingProfile,
  selection: MulticastRequest,
  signal: AbortSignal,
): Promise<{
  evidence: ForwardingEvidence[];
  adjacency: MulticastAdjacency[];
  outcome: SourceOutcome;
}> {
  const parsed = parseProfile(input),
    request = validateRequest(selection);
  if (parsed.source !== "multicast_nxos")
    throw new Error("Invalid forwarding profile.");
  const profile = parsed;
  const outcome = (
    state: SourceOutcome["state"],
    detail: string,
  ): SourceOutcome => ({
    source: profile.source,
    profile: profile.id,
    state,
    detail,
  });
  if (
    !request.sender ||
    profile.scope !== request.scope ||
    profile.validFrom > request.earliest ||
    profile.validUntil < request.latest
  )
    return {
      evidence: [],
      adjacency: [],
      outcome: outcome(
        "blocked",
        "Choose one sender and a profile covering the request scope and time window.",
      ),
    };
  try {
    const search = buildForwardingSearch(profile, request),
      key = await fingerprint(["multicast_nxos", profile, request, search]);
    const result = requireNoSearchErrors(
      await optionalJobs.run(profile.source, key, client, {
        search,
        earliest: String(request.earliest),
        latest: String(request.latest + 1),
        maxRows: MAX_INPUT_ROWS + 1,
        allowEmpty: true,
        signal,
      }),
      "Multicast forwarding",
    );
    if (result.warnings.length || result.truncated)
      throw new Error("Unverified search completion.");
    const rows = result.rows.filter((row) => row.kind === "record"),
      meta = result.rows.filter((row) => row.kind === "completion");
    if (meta.length !== 1 || rows.length + 1 !== result.rows.length)
      throw new Error("Invalid search envelope.");
    const inputCount = count(meta[0].input_count),
      returned = count(meta[0].returned_count);
    if (
      inputCount === undefined ||
      inputCount > MAX_INPUT_ROWS ||
      returned !== rows.length ||
      returned !== inputCount
    )
      throw new Error("Forwarding cohort search was capped or inconsistent.");
    if (!rows.length)
      return {
        evidence: [],
        adjacency: [],
        outcome: outcome(
          "complete",
          "No caller-visible forwarding cohort; this does not prove absence or coverage.",
        ),
      };
    const cohorts = rows.map((row) => parseCohort(row, profile, request));
    if (cohorts.some((cohort) => !cohort))
      throw new Error("Malformed or unverified forwarding cohort.");
    const valid = cohorts as Cohort[];
    const newest = Math.max(...valid.map((cohort) => cohort.observedAt));
    const latest = valid.filter((cohort) => cohort.observedAt === newest);
    if (
      latest.some(
        (cohort) => JSON.stringify(cohort) !== JSON.stringify(latest[0]),
      )
    )
      throw new Error("Conflicting forwarding cohorts at the same timestamp.");
    const cohort = latest[0];
    const expired = cohort.validUntil < request.latest;
    const cohortId = await fingerprint([
      profile.id,
      request.scope,
      request.group,
      request.sender,
      cohort,
    ]);
    const evidence: ForwardingEvidence[] = cohort.devices.map((device, i) => ({
      id: `${cohortId}:${i}`,
      kind: "forwarding",
      source: "device_state",
      scope: request.scope,
      group: request.group,
      sender: request.sender,
      observer: device.observer,
      timestamp: cohort.observedAt,
      validUntil: cohort.validUntil,
      input: device.input,
      outputs: device.outputs,
      limits: [
        "Indexed device state is a point-in-time observation; it does not prove packet delivery.",
      ],
    }));
    if (evidence.length > MAX_EVIDENCE_ROWS)
      throw new Error("Forwarding output exceeds the limit.");
    const adjacency = cohort.links.map((link) => ({
      scope: request.scope,
      ...link,
      validFrom: cohort.observedAt,
      validUntil: cohort.validUntil,
    }));
    return {
      evidence,
      adjacency,
      outcome: outcome(
        expired ? "partial" : "complete",
        expired
          ? `A forwarding snapshot is valid only at its anchor (${new Date(cohort.observedAt * 1000).toISOString()}). Set To (UTC) to that time to see its tree.`
          : "The newest caller-visible cohort is valid at the requested time; coverage is not guaranteed.",
      ),
    };
  } catch (error) {
    if (signal.aborted)
      throw new Error(
        "Multicast forwarding investigation cancelled; cleanup may be pending.",
        { cause: error },
      );
    return {
      evidence: [],
      adjacency: [],
      outcome: outcome(
        error instanceof SearchAccessDeniedError ? "blocked" : "unavailable",
        error instanceof SearchAccessDeniedError
          ? "Access to this source was denied."
          : "Forwarding cohort execution, provenance or completeness could not be verified.",
      ),
    };
  }
}
