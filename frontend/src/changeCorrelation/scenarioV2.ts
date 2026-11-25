import { canonicalJson, sha256Hex } from "./canonicalJson";

export interface ConnectedScenarioBundleV2 {
  schema_version: 2;
  kind: "connected_scenario_source_bundle_v2";
  scenario_id: string;
  variant_id: string;
  template_sha256: string;
  execution_id: string;
  anchor_epoch: number;
  application: Record<string, string>;
  connected_services: unknown[];
  identities: Record<string, unknown>;
  events: unknown[];
  phase_proof: unknown[];
  limitations: string[];
  bundle_sha256: string;
}

const forbidden = [
  "indexed_receipt_epoch",
  "event_fingerprint",
  "readback_epoch",
  "received_at",
];
const topLevelKeys = new Set([
  "schema_version",
  "kind",
  "scenario_id",
  "variant_id",
  "template_sha256",
  "execution_id",
  "anchor_epoch",
  "application",
  "connected_services",
  "identities",
  "events",
  "phase_proof",
  "limitations",
]);

export interface ConnectedScenarioContractV2 {
  scenario_id: string;
  variant_id: string;
  template_sha256: string;
  application: Record<string, string>;
  connected_services: unknown[];
  event_ids: string[];
  phase_ids: string[];
  content_sha256: Record<string, string>;
  anchor_epoch: number;
  execution_id: string;
}

function assertSafe(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(assertSafe);
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  if (forbidden.some((key) => key in record))
    throw new Error("Connected bundle contains receipt claims.");
  Object.values(record).forEach(assertSafe);
}

export async function verifyConnectedScenarioBundle(
  bundle: unknown,
  contract: ConnectedScenarioContractV2,
): Promise<ConnectedScenarioBundleV2> {
  if (!bundle || typeof bundle !== "object")
    throw new Error("Connected bundle is not an object.");
  const value = bundle as Record<string, unknown>;
  if (
    value.schema_version !== 2 ||
    value.kind !== "connected_scenario_source_bundle_v2"
  )
    throw new Error("Connected bundle schema is unsupported.");
  const body = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "bundle_sha256"),
  );
  if (Object.keys(body).some((key) => !topLevelKeys.has(key)))
    throw new Error("Connected bundle contains unsupported fields.");
  if (
    typeof value.bundle_sha256 !== "string" ||
    (await sha256Hex(canonicalJson(body))) !== value.bundle_sha256
  )
    throw new Error("Connected bundle hash does not match content.");
  assertSafe(body);
  if (
    typeof value.scenario_id !== "string" ||
    typeof value.variant_id !== "string" ||
    typeof value.template_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.template_sha256) ||
    typeof value.execution_id !== "string" ||
    !Number.isSafeInteger(value.anchor_epoch) ||
    !value.application ||
    typeof value.application !== "object" ||
    !Array.isArray(value.connected_services) ||
    !value.identities ||
    typeof value.identities !== "object" ||
    !Array.isArray(value.events) ||
    value.events.length === 0 ||
    !Array.isArray(value.phase_proof) ||
    value.phase_proof.length === 0 ||
    !Array.isArray(value.limitations)
  )
    throw new Error("Connected bundle evidence is incomplete.");
  if (
    value.scenario_id !== contract.scenario_id ||
    value.variant_id !== contract.variant_id ||
    value.template_sha256 !== contract.template_sha256 ||
    !contract.execution_id ||
    value.execution_id !== contract.execution_id ||
    !Number.isSafeInteger(contract.anchor_epoch) ||
    value.anchor_epoch !== contract.anchor_epoch ||
    !contract.content_sha256.application ||
    !contract.content_sha256.connected_services ||
    (await sha256Hex(canonicalJson(value.application))) !==
      contract.content_sha256.application ||
    (await sha256Hex(canonicalJson(value.connected_services))) !==
      contract.content_sha256.connected_services
  )
    throw new Error("Connected bundle template binding is invalid.");
  for (const key of [
    "application",
    "connected_services",
    "identities",
    "events",
    "phase_proof",
    "limitations",
  ]) {
    const expected = contract.content_sha256[key];
    if (!expected || (await sha256Hex(canonicalJson(value[key]))) !== expected)
      throw new Error("Connected bundle content binding is invalid.");
  }
  if (
    value.events.some((event) => {
      if (!event || typeof event !== "object") return true;
      const item = event as Record<string, unknown>;
      return (
        typeof item.id !== "string" ||
        item.status !== "planned" ||
        !contract.event_ids.includes(item.id)
      );
    })
  )
    throw new Error("Connected bundle event status is invalid.");
  if (
    value.events.length !== contract.event_ids.length ||
    new Set(value.events.map((event) => (event as Record<string, unknown>).id))
      .size !== contract.event_ids.length ||
    value.phase_proof.some(
      (phase) =>
        !phase ||
        typeof phase !== "object" ||
        !contract.phase_ids.includes(
          String((phase as Record<string, unknown>).phase_id),
        ),
    )
  )
    throw new Error("Connected bundle content binding is invalid.");
  return value as unknown as ConnectedScenarioBundleV2;
}
