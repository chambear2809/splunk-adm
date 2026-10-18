import type { GraphArgs, Row } from "@atlas/rows";

const digest = async (value: unknown) =>
  [
    ...new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(value)),
      ),
    ),
  ]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
const mac = (value: number) =>
  `02:ee:00:${Math.floor(value / 65536)
    .toString(16)
    .padStart(2, "0")}:${Math.floor(value / 256)
    .toString(16)
    .padStart(2, "0")}:${(value % 256).toString(16).padStart(2, "0")}`;

/** Synthetic graph-contract rows, not generated or collected TA telemetry. */
export async function addCiscoEvidence({
  scenario,
  args,
  rows,
  nodes,
  edges,
  topoRows,
  targetNodes,
  targetEdges,
  partial,
}: {
  scenario: string;
  args: GraphArgs;
  rows: Row[];
  nodes: Row[];
  edges: Row[];
  topoRows: Row[];
  targetNodes: number;
  targetEdges: number;
  partial: boolean;
}) {
  const wireless = scenario === "meraki-nxos";
  const clientTemplate = nodes.find(
    (row) => row.endpoint_kind === "network_client",
  )!;
  const trafficTemplate = edges.find(
    (row) =>
      row.relationship === "traffic_observation" && row.attachment_evidence,
  )!;
  const frontend = nodes.find((row) => row.id === trafficTemplate.target)!;
  const handoffTemplate = edges.find(
    (row) =>
      row.target === frontend.id && row.client_handoff_coverage === "complete",
  )!;
  const originalBackend = JSON.parse(String(handoffTemplate.client_handoffs))[0]
    .target as string;
  const backendTemplate = nodes.find((row) => row.id === originalBackend)!;
  const forwardTemplate = edges.find(
    (row) => row.relationship === "forwards_to" && row.source === frontend.id,
  )!;
  const scope = String(clientTemplate.attr_scope);
  const profile = String(clientTemplate.attr_source);
  const meta = rows.find((row) => row.row_type === "meta")!;
  const epoch = Number(meta.window_start) + 60;
  const root = `service:${args.cluster}/${args.namespace}/${args.service}/${args.environment}`;
  const backendCount = targetNodes === 500 ? 64 : 12;
  const backendIds: string[] = [];
  const addEdge = (row: Row) => {
    edges.push(row);
    rows.push(row);
  };
  for (let i = 0; i < backendCount; i++) {
    const id = `pod:${args.cluster}/performance-backend-${i}`;
    const row = {
      ...structuredClone(backendTemplate),
      id,
      label: `perf-backend-${i}`,
      attr_owner: `perf-backend-owner-${i % 8}`,
      attr_node: `node-${String.fromCharCode(97 + (i % 3))}`,
    };
    nodes.push(row);
    rows.push(row);
    backendIds.push(id);
    addEdge({
      row_type: "edge",
      id: `perf:owns:${i}`,
      source: root,
      target: id,
      relationship: "runs_on",
      confidence: "correlated",
      evidence: ["performance-controlled"],
      count: "1",
    });
    addEdge({
      ...structuredClone(forwardTemplate),
      id: `perf:forward:${i}`,
      target: id,
      count: "1",
    });
  }
  const authorities = Array.from({ length: 4 }, (_, i) =>
    wireless
      ? JSON.stringify([`perf-org-${i}`, `perf-network-${i}`])
      : `https://perf-catalyst-${i}.example.invalid`,
  );
  // Shared names, native IDs and IPs across authorities deliberately create ambiguous aliases.
  const accessDevices = await Promise.all(
    authorities.flatMap((authority, authorityIndex) =>
      Array.from({ length: 8 }, async (_, site) => {
        const native = `PERF-ACCESS-${site}`;
        const id = `${wireless ? "meraki" : "catalyst"}:${await digest([wireless ? "meraki_device" : "catalyst_device", authority, native])}`;
        const row: Row = {
          row_type: "device",
          device_id: id,
          device_authority: authority,
          native_device_id: native,
          name: native,
          aliases: [native, `perf-shared-access-${site}`],
          mgmt_ip: `198.19.1.${site + 1}`,
          device_kind: wireless ? "access_point" : "switch",
          sources: [wireless ? "meraki_device" : "catalyst_device"],
          scope,
          cluster: args.cluster,
          mapping_status: "mapped",
          platform: wireless ? "MR synthetic" : "Catalyst synthetic",
          serial: native,
        };
        return { id, authority, authorityIndex, site, row };
      }),
    ),
  );
  topoRows.push(...accessDevices.map((device) => device.row));
  const exporters = await Promise.all(
    authorities.map(async (authority, i) => {
      const ip = `198.19.2.${i + 1}`;
      const id = `${wireless ? "meraki" : "catalyst"}:${await digest([authority, "performance-exporter", ip])}`;
      const row = {
        row_type: "device",
        device_id: id,
        device_authority: authority,
        native_device_id: `PERF-EXPORTER-${i}`,
        name: `PERF-EXPORTER-${i}`,
        mgmt_ip: ip,
        device_kind: "switch",
        sources: [wireless ? "meraki_device" : "catalyst_device"],
        scope,
        cluster: args.cluster,
        mapping_status: "mapped",
      };
      return { id, ip, authority, row };
    }),
  );
  // Commit asynchronously derived identities in input order, never digest completion order.
  for (const exporter of exporters) {
    topoRows.push(exporter.row, {
      row_type: "interface",
      device_id: exporter.id,
      interface: "Ethernet1/1",
      ifindex: "1",
      description: "Synthetic client uplink",
      state: "up",
    });
  }
  const clientCount = targetNodes - nodes.length;
  const clients = await Promise.all(
    Array.from({ length: clientCount }, async (_, i) => {
      const authorityIndex = i % authorities.length;
      const authority = authorities[authorityIndex];
      // Four distinct authority-qualified clients share a native MAC and an IP.
      const nativeIndex = Math.floor(i / authorities.length);
      const native = mac(nativeIndex + 1);
      const ip = `198.18.${Math.floor(nativeIndex / 250)}.${(nativeIndex % 250) + 1}`;
      const id = `network_client:${await digest([profile, authority, native])}`;
      const site = nativeIndex % 8;
      const access = accessDevices[authorityIndex * 8 + site];
      const otherAccess = accessDevices[authorityIndex * 8 + ((site + 1) % 8)];
      const wrongAuthorityAccess =
        accessDevices[((authorityIndex + 1) % 4) * 8 + site];
      const eventTime = epoch + (nativeIndex % 60);
      const row: Row = {
        ...structuredClone(clientTemplate),
        id,
        label: `perf-client-${i} (${native})`,
        addresses: ip,
        attr_native_id: native,
        attr_client_mac: native,
        attr_source_authority: authority,
        attr_routing_domain: String(100 + authorityIndex),
        attr_source_time: String(eventTime),
        attr_received_time: String(eventTime + 2),
        attr_attachment_event_time: String(eventTime),
        attr_attachment_received_time: String(eventTime + 2),
        attr_attachment_collected_time: String(eventTime + 3),
        attr_attachment_device_id: access.id,
        attr_attachment_device_name: String(access.row.name),
        attr_scope: scope,
        attr_mapping_status: "mapped",
      };
      const coverage = partial
        ? (["partial", "partial", "unresolved", "complete"] as const)[i % 4]
        : (["complete", "partial", "unresolved"] as const)[i % 3];
      const recordCount =
        coverage === "unresolved"
          ? 0
          : coverage === "complete" && i % 4 === 0
            ? 2
            : 1;
      const records = Array.from({ length: recordCount }, (_, k) => ({
        target: backendIds[(i + k) % backendIds.length],
        basis: k ? "hubble_xlate" : "hubble_client_tuple",
        connections: 1,
        receiving_nodes: [`node-${String.fromCharCode(97 + ((i + k) % 3))}`],
        observers: [`hubble:node-${String.fromCharCode(97 + ((i + k) % 3))}`],
      }));
      const unresolved = coverage === "complete" ? 0 : 1;
      const conversation: Row = {
        row_type: "edge",
        id: `perf:client-conversation:${i}`,
        source: id,
        target: frontend.id,
        relationship: "communicates_with",
        confidence: coverage === "complete" ? "correlated" : "unresolved",
        evidence: ["performance-controlled", "hubble"],
        sources: ["hubble", profile],
        observers: records.flatMap((record) => record.observers),
        count: String(recordCount + unresolved),
        server_port: "8080",
        transport: "tcp",
        direction_basis: "initiator",
        client_handoff_coverage: coverage,
        client_handoff_connections: String(recordCount + unresolved),
        client_handoff_determined: String(recordCount),
        client_handoff_unresolved: String(unresolved),
        client_handoffs: JSON.stringify(records),
        contract_basis: "not_evaluated",
      };
      return {
        i,
        id,
        ip,
        native,
        row,
        authority,
        authorityIndex,
        access,
        otherAccess,
        wrongAuthorityAccess,
        eventTime,
        conversation,
      };
    }),
  );
  for (const client of clients) {
    nodes.push(client.row);
    rows.push(client.row);
    addEdge(client.conversation);
    topoRows.push({
      row_type: "device",
      device_id: client.id,
      device_authority: client.authority,
      native_device_id: client.native,
      name: client.native,
      mgmt_ip: client.ip,
      device_kind: "network_client",
      sources: [profile],
      scope,
      cluster: args.cluster,
      mapping_status: "mapped",
      client_mac: client.native,
      client_ip: client.ip,
      attachment_device_id: client.access.id,
      attachment_device_name: client.access.row.name,
    });
    // Independent association snapshots, including a subsequent attachment.
    for (const [k, access] of [client.access, client.otherAccess].entries())
      topoRows.push({
        row_type: "link",
        a_device: client.id,
        b_device: access.id,
        a_interface: client.native,
        b_interface: wireless
          ? `SSID ${client.i % 4}`
          : `GigabitEthernet1/0/${(client.i % 48) + 1}`,
        link_kind: wireless ? "wireless_association" : "physical",
        link_source: profile,
        link_time: String(client.eventTime + k * 10),
        scope,
        cluster: args.cluster,
        mapping_status: "mapped",
      });
  }
  for (let i = 0; edges.length < targetEdges; i++) {
    const client = clients[i % clients.length];
    const round = Math.floor(i / clients.length);
    const exporter = exporters[client.authorityIndex];
    const observationId = await digest([
      scenario,
      "synthetic-flow",
      client.id,
      round,
    ]);
    const attachments = [client.access, client.otherAccess].map(
      (access, k) => ({
        basis: wireless
          ? "meraki_association_flow"
          : "catalyst_client_snapshot",
        status: wireless ? "associated" : "observed_snapshot",
        event_time: client.eventTime + k * 10,
        received_time: client.eventTime + k * 10 + 2,
        collected_time: client.eventTime + k * 10 + 3,
        // Include exact, unresolved alias and cross-authority IDs; never claim aliases resolve.
        device_id:
          client.i % 4 === 1 && k === 1
            ? `perf-shared-access-${access.site}`
            : client.i % 4 === 2 && k === 1
              ? client.wrongAuthorityAccess.id
              : access.id,
        device_name: String(access.row.name),
        client_source: profile,
        client_authority: client.authority,
        client_native_id: client.native,
        ...(wireless
          ? {
              device_serial: String(access.row.serial),
              ssid_number: client.i % 4,
            }
          : { device_mac: mac(1000 + access.site) }),
      }),
    );
    const observations = await Promise.all(
      Array.from({ length: 3 }, async (_, k) => ({
        source: "stream_ipfix",
        source_authority: exporter.ip,
        exporter_ip: exporter.ip,
        observation_domain_present: 1,
        observation_domain_id: String(100 + client.authorityIndex * 10 + k),
        routing_domain: String(100 + client.authorityIndex),
        source_mac: client.native,
        source_ip: client.ip,
        destination_ip: String(
          Array.isArray(frontend.addresses)
            ? frontend.addresses[0]
            : frontend.addresses,
        ),
        source_port: 40000 + client.i,
        destination_port: 8080,
        server_port: 8080,
        transport: "tcp",
        raw_bytes: 1024 * (k + 1 + round),
        raw_packets: 3 + k,
        records: 1,
        first_seen: client.eventTime + round + k * 10,
        last_seen: client.eventTime + round + k * 10 + 0.5,
        received_time: client.eventTime + round + k * 10 + 2,
        collected_time: client.eventTime + round + k * 10 + 3,
        counter_semantics: "exporter_directional_view",
        metrics_authoritative: false,
        direction: k % 2 ? "egress" : "ingress",
        interface_in: "ifIndex 1",
        domain_kind: "exporter",
        scope,
        cluster: args.cluster,
        profile: wireless ? "meraki_ms390_ipfix" : "standard_netflow",
        mapping_status: "mapped",
        quality_status: k === 2 ? "accepted_with_warning" : "accepted",
        ...(k === 2 ? { quality_warnings: "unknown_sampling" } : {}),
        event_identity_status: "stable",
        record_fingerprint: await digest([observationId, k]),
      })),
    );
    addEdge({
      ...structuredClone(trafficTemplate),
      id: `traffic-observation:${observationId}`,
      traffic_observation_id: observationId,
      source: client.id,
      target: frontend.id,
      count: "3",
      source_ip: client.ip,
      source_mac: client.native,
      source_port: String(40000 + client.i),
      first_seen: String(client.eventTime + round),
      last_seen: String(client.eventTime + round + 20.5),
      raw_bytes: String(
        observations.reduce(
          (total, observation) => total + observation.raw_bytes,
          0,
        ),
      ),
      raw_packets: String(
        observations.reduce(
          (total, observation) => total + observation.raw_packets,
          0,
        ),
      ),
      records: "3",
      attachment_evidence: JSON.stringify(attachments),
      traffic_observations: JSON.stringify(observations),
    });
  }
  if (nodes.length !== targetNodes || edges.length !== targetEdges)
    throw new Error("Cisco workload did not reach the requested graph size");
}
