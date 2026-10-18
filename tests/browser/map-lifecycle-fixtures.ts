import capture from "../../fixtures/demo-networking-aci.json" with { type: "json" };
import inventory from "../../fixtures/demo-networking-topology.json" with { type: "json" };
import type { Row } from "../../frontend/src/rows";

// Controlled mutations of the captured normalized search output. These names
// deliberately identify the regression inputs, not additional demo scenarios.
export const lifecycleArgs = capture.args;
export const OLD_CLIENT =
  "network_client:c9d76c4af4c2fbff1499498fa9f86a5395b5c850787bbe9cf81ece79de41e0c5";
export const NEW_CLIENT = `network_client:${"f".repeat(64)}`;
export const OLD_ATTACHMENT =
  "catalyst:5b544d2537038b4e55dd638b0aee15a05adc985963773ea7dec07c754302c04a";
export const NEW_ATTACHMENT = `catalyst:${"f".repeat(64)}`;
export const NEW_OBSERVATION = `traffic-observation:${"e".repeat(64)}`;
export const OLD_CLIENT_LABEL = "02:61:00:00:00:20";
export const NEW_CLIENT_LABEL = "Refresh moved client";
export const NEW_ATTACHMENT_LABEL = "REFRESH-SW-02";
export const CONFLICT_ATTACHMENT_LABEL = "REFRESH-CONFLICT-SW";
export const CLIENT_EDGE =
  "communicates:vm:campus-aci/10.30.40.25>k8s_service:cilium-aci-east/shop/checkout-api/10.50.0.20:8080:8080/tcp";
export const CLIENT_BACKEND =
  "pod:cilium-aci-east/999151a5-7418-5939-b573-6de8631b4ffc";
const cloneRows = (rows: unknown): Row[] => structuredClone(rows) as Row[];

export function lifecycleGraphRows(
  version: number,
  previous?: { earliest: string; latest?: string },
): Row[] {
  let rows = cloneRows(capture.rows);
  if (version >= 2) {
    const client = rows.find(
      (row) => row.row_type === "node" && row.id === OLD_CLIENT,
    )!;
    const observation = rows.find(
      (row) => row.row_type === "edge" && row.source === OLD_CLIENT,
    )!;
    const attachment = JSON.parse(
      String(observation.attachment_evidence),
    ) as Row[];
    const traffic = JSON.parse(
      String(observation.traffic_observations),
    ) as Row[];
    rows = rows.filter(
      (row) =>
        row.id !== OLD_CLIENT &&
        row.source !== OLD_CLIENT &&
        row.target !== OLD_CLIENT,
    );
    rows.push(
      {
        ...client,
        id: NEW_CLIENT,
        label: NEW_CLIENT_LABEL,
        addresses: "10.61.0.21",
        attr_native_id: "02:61:00:00:00:21",
        attr_client_mac: "02:61:00:00:00:21",
        attr_attachment_device_id: NEW_ATTACHMENT,
        attr_attachment_device_name: NEW_ATTACHMENT_LABEL,
      },
      {
        ...observation,
        id: NEW_OBSERVATION,
        source: NEW_CLIENT,
        source_ip: "10.61.0.21",
        source_port: "54121",
        traffic_observation_id: "e".repeat(64),
        attachment_evidence: JSON.stringify(
          attachment.map((record) => ({
            ...record,
            device_id: NEW_ATTACHMENT,
            device_name: NEW_ATTACHMENT_LABEL,
            client_native_id: "02:61:00:00:00:21",
          })),
        ),
        traffic_observations: JSON.stringify(
          traffic.map((record) => ({
            ...record,
            source_ip: "10.61.0.21",
            source_port: 54121,
            record_fingerprint: "e".repeat(64),
          })),
        ),
      },
    );
  }
  if (version >= 3) {
    const client = rows.find((row) => row.id === NEW_CLIENT)!;
    client.attr_attachment_status = "conflict";
    delete client.attr_attachment_device_id;
    delete client.attr_attachment_device_name;
    const observation = rows.find((row) => row.id === NEW_OBSERVATION)!;
    const attachment = JSON.parse(
      String(observation.attachment_evidence),
    ) as Row[];
    observation.attachment_evidence = JSON.stringify([
      { ...attachment[0], status: "conflict" },
      {
        ...attachment[0],
        status: "conflict",
        device_id: `catalyst:${"d".repeat(64)}`,
        device_name: CONFLICT_ATTACHMENT_LABEL,
      },
    ]);
    // The aggregate frontend->backend edge remains valid for other clients.
    // This selected client's represented connections now have partial evidence.
    const edge = rows.find((row) => row.id === CLIENT_EDGE)!;
    edge.client_handoff_coverage = "partial";
    edge.client_handoff_connections = "2";
    edge.client_handoff_determined = "1";
    edge.client_handoff_unresolved = "1";
    delete edge.via_node;
  }
  const meta = rows.find((row) => row.row_type === "meta")!;
  meta.generated_at = String(Number(meta.generated_at) + version);
  meta.nodes = String(rows.filter((row) => row.row_type === "node").length);
  meta.edges = String(rows.filter((row) => row.row_type === "edge").length);
  if (version >= 3)
    meta.warnings = [
      "Lifecycle mutation: conflicting attachment observations and partial client handoff remain unresolved.",
    ];
  if (previous) {
    meta.window_start = previous.earliest;
    meta.window_end = previous.latest;
  }
  return rows;
}

export function lifecycleTopologyRows(version: number): Row[] {
  if (version < 2) return cloneRows(inventory.rows);
  const rows = JSON.parse(
    JSON.stringify(inventory.rows)
      .replaceAll(OLD_ATTACHMENT, NEW_ATTACHMENT)
      .replaceAll("CAMPUS-SW-01", NEW_ATTACHMENT_LABEL),
  ) as Row[];
  if (version >= 3) {
    const attachment = rows.find(
      (row) => row.device_id === NEW_ATTACHMENT && row.row_type === "device",
    )!;
    rows.push({
      ...attachment,
      device_id: `catalyst:${"d".repeat(64)}`,
      name: CONFLICT_ATTACHMENT_LABEL,
    });
  }
  return rows;
}
