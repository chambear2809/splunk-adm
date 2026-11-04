import type { Row } from "../rows";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

export const ACI_FABRIC_SCHEMA = "application_atlas.aci_fabric_snapshot.v1";
export const ACI_FABRIC_SOURCE = "atlas:aci_poll";
const ACI_POLL_SOURCETYPES = new Set(["adm:aci_poll:v1", "adm:aci_poll:v2"]);
const MAX_BYTES = 512 * 1024;
const MAX_DEVICES = 4096;
const MAX_LINKS = 8192;
const MAX_ROUTED_INTERFACES = 8192;

export interface AciFabricDevice {
  id: string;
  name: string;
  role: "leaf" | "spine" | "controller" | "unknown";
  serial?: string;
  management_ip?: string;
  oob_management_ip?: string;
  inband_management_ip?: string;
  fabric_address?: string;
}
export interface AciFabricLink {
  id: string;
  source: string;
  target: string;
  source_interface?: string;
  target_interface?: string;
}
export interface AciFabricSnapshot {
  schema: typeof ACI_FABRIC_SCHEMA;
  schema_version: 1;
  source: typeof ACI_FABRIC_SOURCE;
  snapshot_id: string;
  captured_at: number;
  authority: string;
  scope: string;
  devices: AciFabricDevice[];
  links: AciFabricLink[];
  routed_interfaces: AciFabricRoutedInterface[];
}
export interface AciFabricRoutedInterface {
  id: string;
  device: string;
  native_id: string;
  interface: string;
  parent_interface: string;
  dn: string;
  physical_dn: string;
  physical_source: string;
  classification: string;
  traversal: "not_observed";
  source: string;
  encap?: string;
  admin_state?: string;
  oper_state?: string;
  connection_dn?: string;
  routed_out_definition_dn?: string;
}

const text = (value: unknown, label: string, max = 512): string => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error(`Invalid ACI fabric ${label}.`);
  return value;
};
const optionalText = (value: unknown, label: string) =>
  value === undefined ? undefined : text(value, label);
const finiteEpoch = (value: unknown) => {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n < 0)
    throw new Error("Invalid ACI fabric capture time.");
  return n;
};
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

export function normalizeAciFabricSnapshot(
  rows: readonly Row[],
  now = Date.now() / 1000,
): AciFabricSnapshot {
  if (rows.length !== 1)
    throw new Error("ACI fabric snapshot is missing or ambiguous.");
  const rawText = String(rows[0].snapshot ?? rows[0]._raw ?? "");
  if (!rawText || rawText.length > MAX_BYTES)
    throw new Error("ACI fabric snapshot is empty or exceeds its size limit.");
  let raw: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(rawText);
    if (!object(parsed)) throw new Error();
    raw = parsed;
  } catch {
    throw new Error("Invalid ACI fabric snapshot JSON.");
  }
  const provenance = raw.provenance;
  if (
    raw.schema !== ACI_FABRIC_SCHEMA ||
    raw.classification !== "inventory_snapshot" ||
    raw.qualification !== "complete_two_pass_capture" ||
    raw.traversal !== "not_observed" ||
    !object(provenance) ||
    provenance.source !== ACI_FABRIC_SOURCE ||
    typeof provenance.sourcetype !== "string" ||
    !ACI_POLL_SOURCETYPES.has(provenance.sourcetype)
  )
    throw new Error("Unqualified or incomplete ACI fabric snapshot.");
  const snapshotId = text(raw.capture_id, "snapshot identity", 128);
  const captureStarted = finiteEpoch(raw.capture_started);
  const capturedAt = finiteEpoch(raw.capture_completed);
  const asOf = finiteEpoch(raw.as_of);
  if (
    captureStarted > capturedAt ||
    capturedAt > asOf ||
    asOf > now + 300 ||
    now - capturedAt > 24 * 60 * 60
  )
    throw new Error("ACI fabric snapshot is stale or from the future.");
  const authority = text(raw.authority, "authority");
  const scope = text(raw.scope, "scope");
  if (!Array.isArray(raw.devices) || raw.devices.length > MAX_DEVICES)
    throw new Error("ACI fabric device inventory is missing or too large.");
  if (!Array.isArray(raw.links) || raw.links.length > MAX_LINKS)
    throw new Error("ACI fabric link inventory is missing or too large.");
  if (
    !Array.isArray(raw.routed_interfaces) ||
    raw.routed_interfaces.length > MAX_ROUTED_INTERFACES
  )
    throw new Error("ACI routed-interface inventory is missing or too large.");
  const devices = raw.devices.map((value) => {
    if (!object(value)) throw new Error("Invalid ACI fabric device.");
    const role = text(value.role, "device role");
    if (!["leaf", "spine", "controller", "unknown"].includes(role))
      throw new Error("Invalid ACI fabric device role.");
    return {
      id: text(value.id, "device identity"),
      name: text(value.name, "device name"),
      role: role as AciFabricDevice["role"],
      ...(optionalText(value.serial, "device serial")
        ? { serial: optionalText(value.serial, "device serial") }
        : {}),
      ...(optionalText(value.management_ip, "management address")
        ? {
            management_ip: optionalText(
              value.management_ip,
              "management address",
            ),
          }
        : {}),
      ...(optionalText(value.oob_mgmt_ip, "OOB management address")
        ? {
            oob_management_ip: optionalText(
              value.oob_mgmt_ip,
              "OOB management address",
            ),
          }
        : {}),
      ...(optionalText(value.inband_mgmt_ip, "in-band management address")
        ? {
            inband_management_ip: optionalText(
              value.inband_mgmt_ip,
              "in-band management address",
            ),
          }
        : {}),
      ...(optionalText(value.fabric_address, "fabric address")
        ? {
            fabric_address: optionalText(
              value.fabric_address,
              "fabric address",
            ),
          }
        : {}),
    };
  });
  const ids = new Set(devices.map((device) => device.id));
  if (ids.size !== devices.length)
    throw new Error("Duplicate ACI fabric device identity.");
  const links = raw.links.map((value) => {
    if (!object(value)) throw new Error("Invalid ACI fabric physical link.");
    const source = text(value.a_device, "link source");
    const target = text(value.b_device, "link target");
    if (!ids.has(source) || !ids.has(target) || source === target)
      throw new Error("ACI fabric link endpoint is not in the snapshot.");
    return {
      id: text(value.id, "link identity"),
      source,
      target,
      ...(optionalText(value.a_interface, "source interface")
        ? {
            source_interface: optionalText(
              value.a_interface,
              "source interface",
            ),
          }
        : {}),
      ...(optionalText(value.b_interface, "target interface")
        ? {
            target_interface: optionalText(
              value.b_interface,
              "target interface",
            ),
          }
        : {}),
    };
  });
  if (new Set(links.map((link) => link.id)).size !== links.length)
    throw new Error("Duplicate ACI fabric link identity.");
  const routed_interfaces = raw.routed_interfaces.map((value) => {
    if (!object(value)) throw new Error("Invalid ACI routed interface.");
    const deviceId = text(value.device, "routed-interface device");
    if (!ids.has(deviceId))
      throw new Error("ACI routed interface endpoint is not in the snapshot.");
    return {
      id: text(value.id, "routed interface identity"),
      device: deviceId,
      native_id: text(value.native_id, "routed native device"),
      interface: text(value.interface, "routed interface"),
      parent_interface: text(value.parent_interface, "routed parent interface"),
      dn: text(value.dn, "routed interface DN"),
      physical_dn: text(value.physical_dn, "routed physical DN"),
      physical_source: text(value.physical_source, "routed physical source"),
      classification: text(value.classification, "routed classification"),
      traversal:
        value.traversal === "not_observed"
          ? ("not_observed" as const)
          : (() => {
              throw new Error("Invalid routed-interface traversal.");
            })(),
      source: text(value.source, "routed interface source"),
      ...(optionalText(value.encap, "routed encapsulation")
        ? { encap: optionalText(value.encap, "routed encapsulation") }
        : {}),
      ...(optionalText(value.admin_state, "routed admin state")
        ? { admin_state: optionalText(value.admin_state, "routed admin state") }
        : {}),
      ...(optionalText(value.oper_state, "routed oper state")
        ? { oper_state: optionalText(value.oper_state, "routed oper state") }
        : {}),
      ...(optionalText(value.connection_dn, "native L3Out connection DN")
        ? {
            connection_dn: optionalText(
              value.connection_dn,
              "native L3Out connection DN",
            ),
          }
        : {}),
      ...(optionalText(
        value.routed_out_definition_dn,
        "routed L3Out definition DN",
      )
        ? {
            routed_out_definition_dn: optionalText(
              value.routed_out_definition_dn,
              "routed L3Out definition DN",
            ),
          }
        : {}),
    };
  });
  return {
    schema: ACI_FABRIC_SCHEMA,
    schema_version: 1,
    source: ACI_FABRIC_SOURCE,
    snapshot_id: snapshotId,
    captured_at: capturedAt,
    authority,
    scope,
    devices,
    links,
    routed_interfaces,
  };
}

export async function loadAciFabricSnapshot(
  client: SearchClient,
  signal: AbortSignal,
  earliest: string,
  latest?: string,
): Promise<AciFabricSnapshot> {
  const result = requireNoSearchErrors(
    await client.search({
      search: "| admacipoll mode=fabric",
      earliest,
      latest,
      maxRows: 1,
      allowEmpty: false,
      signal,
    }),
    "ACI fabric snapshot",
  );
  return normalizeAciFabricSnapshot(result.rows);
}
