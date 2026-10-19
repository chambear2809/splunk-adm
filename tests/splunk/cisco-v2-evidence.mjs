// Qualification-only bindings. Observations do not establish MAC/IP continuity.
import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";

const array = (value) => (Array.isArray(value) ? value : value ? [value] : []);
const interval = (record, start, end) => {
  const values = [record[start], record[end]];
  assert(
    values.every(
      (value) =>
        value !== null &&
        value !== undefined &&
        value !== "" &&
        typeof value !== "boolean",
    ),
    "missing tuple time",
  );
  const [first, last] = values.map(Number);
  assert(
    Number.isFinite(first) &&
      Number.isFinite(last) &&
      0 <= first &&
      first <= last,
    "invalid tuple interval",
  );
  return [first, last];
};

// Independent qualification contract for raw query JSON -> graph JSON.
// Only these identifier fields may change number -> text; only the literal
// metric flags "0"/"1" may change to boolean. Known optional null/"Null"/empty
// values represent absence. Every other retained value, field and order is exact.
const trafficIdentifiers = new Set(
  (
    "source_authority routing_domain observation_domain_id flow_id sequence " +
    "vpn_id ingress_overlay_session_id egress_overlay_session_id"
  ).split(" "),
);
const trafficText = new Set(
  (
    "source source_authority routing_domain observation_domain_id exporter_ip " +
    "flow_id record_fingerprint sequence direction observation_point " +
    "ingress_interface egress_interface exporter_sampling_mode vpn_id " +
    "ingress_overlay_session_id egress_overlay_session_id counter_semantics " +
    "source_mac destination_mac interface_in interface_out domain_kind scope " +
    "cluster profile mapping_status source_ip destination_ip transport " +
    "event_identity_status quality_errors quality_warnings"
  ).split(" "),
);
const trafficNumbers = new Set(
  (
    "first_seen last_seen collected_time bytes_in bytes_out packets_in packets_out " +
    "exporter_sampling_interval records source_port destination_port raw_bytes " +
    "raw_packets raw_bytes_in raw_bytes_out raw_packets_in raw_packets_out " +
    "server_port"
  ).split(" "),
);
const trafficScalars = new Set([
  "observation_domain_present",
  "received_time",
  "raw_sampling",
]);
const attachmentText = new Set(
  (
    "basis status device_id device_name device_mac device_serial client_source " +
    "client_authority client_native_id"
  ).split(" "),
);
const attachmentTimes = new Set([
  "event_time",
  "received_time",
  "collected_time",
]);
const nonnegative = (value) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;

export function normalizeEvidenceRecords(records, kind) {
  assert(["traffic", "attachments"].includes(kind), "unknown evidence kind");
  assert(Array.isArray(records), "evidence records must be an array");
  return records.map((record) => {
    assert(
      record && typeof record === "object" && !Array.isArray(record),
      "evidence record must be an object",
    );
    const normalized = {};
    for (const [field, value] of Object.entries(record)) {
      const text = kind === "traffic" ? trafficText : attachmentText;
      const allowed =
        text.has(field) ||
        (kind === "traffic"
          ? trafficNumbers.has(field) ||
            trafficScalars.has(field) ||
            ["metrics_authoritative", "quality_status"].includes(field)
          : attachmentTimes.has(field) || field === "ssid_number");
      assert(allowed, `unknown ${kind} evidence field: ${field}`);
      if (value === null || value === "Null" || value === "") continue;
      let canonical = value;
      if (
        kind === "traffic" &&
        trafficIdentifiers.has(field) &&
        typeof value === "number"
      ) {
        assert(
          Number.isSafeInteger(value) && value >= 0,
          "numeric evidence identifier must be a safe nonnegative integer",
        );
        canonical = value.toString();
      } else if (kind === "traffic" && field === "metrics_authoritative") {
        assert(
          typeof value === "boolean" || value === "0" || value === "1",
          "invalid metrics-authoritative evidence flag",
        );
        canonical = value === "0" ? false : value === "1" ? true : value;
      }
      if (text.has(field))
        assert.equal(typeof canonical, "string", "invalid evidence text");
      else if (kind === "traffic" && trafficNumbers.has(field))
        assert(nonnegative(canonical), "invalid numeric traffic evidence");
      else if (kind === "traffic" && trafficScalars.has(field))
        assert(
          typeof canonical === "string" || nonnegative(canonical),
          "invalid scalar traffic evidence",
        );
      else if (field === "quality_status")
        assert(
          ["accepted", "accepted_with_warning", "excluded"].includes(canonical),
          "invalid traffic quality status",
        );
      else if (kind === "attachments" && attachmentTimes.has(field)) {
        assert(
          nonnegative(canonical) ||
            (typeof canonical === "string" &&
              /^\d+(?:\.\d+)?$/.test(canonical)),
          "invalid attachment evidence time",
        );
        assert(
          Number(canonical) <= 8_640_000_000_000,
          "attachment evidence time exceeds epoch bound",
        );
      } else if (kind === "attachments" && field === "ssid_number")
        assert(
          typeof canonical === "string" || nonnegative(canonical),
          "invalid attachment SSID number",
        );
      normalized[field] = canonical;
    }
    if (
      kind === "traffic" &&
      normalized.first_seen !== undefined &&
      normalized.last_seen !== undefined
    )
      assert(
        normalized.first_seen <= normalized.last_seen,
        "reversed traffic evidence times",
      );
    return normalized;
  });
}

export function assertOriginalEvidence(actual, raw, kind) {
  // A graph export must already satisfy the canonical contract. Normalizing
  // both sides permissively would hide a broken or malformed frontend export.
  assert.deepEqual(
    actual,
    normalizeEvidenceRecords(actual, kind),
    "export evidence is not canonical",
  );
  assert.deepEqual(
    actual,
    normalizeEvidenceRecords(raw, kind),
    `original ${kind} record changed in export`,
  );
}

function backendTuples(row, nodes) {
  const [start, end] = interval(row, "adm_ct", "adm_cend");
  const service = nodes.get(row.adm_fe_id);
  assert(
    service?.namespace && service.attributes?.service,
    "selected frontend lacks Service identity",
  );
  const candidates = array(row.adm_cands).map((value) => {
    assert.equal(typeof value, "string", "Service candidate must be a string");
    const fields = value.split("|");
    assert.equal(fields.length, 9, "Service candidate has wrong field count");
    const [name, uid, ip, port, node, from, until, , protocol] = fields;
    assert(
      name &&
        uid &&
        ip &&
        node &&
        /^\d+$/.test(port) &&
        Number(port) >= 1 &&
        Number(port) <= 65535,
      "invalid Service candidate identity/port",
    );
    assert(
      /^\d+(?:\.\d+)?$/.test(from) &&
        (until === "-" || /^\d+(?:\.\d+)?$/.test(until)),
      "invalid Service candidate validity",
    );
    const first = Number(from),
      last = until === "-" ? Infinity : Number(until);
    assert(
      Number.isFinite(first) &&
        (until === "-" || Number.isFinite(last)) &&
        last > first &&
        ["tcp", "udp"].includes(protocol),
      "invalid Service candidate interval/protocol",
    );
    return {
      name,
      target: `pod:${service.cluster}/${uid}`,
      ip,
      port: Number(port),
      first,
      last,
      protocol,
    };
  });
  assert(candidates.length > 0, "missing time-qualified Service candidates");
  return array(row.adm_mT).map((value) => {
    assert.equal(typeof value, "string", "backend tuple must be a string");
    const fields = value.split("|");
    assert.equal(fields.length, 7, "backend tuple has wrong field count");
    const [port, first, endpoint, target, receiver, last, transport] = fields;
    assert(
      /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535,
      "invalid backend tuple source port",
    );
    assert.equal(
      Number(port),
      Number(row.adm_cport),
      "backend tuple belongs to another client port",
    );
    assert(
      ["tcp", "udp"].includes(transport) && transport === row.transport,
      "backend tuple transport differs",
    );
    assert(
      /^\d+(?:\.\d+)?$/.test(first) && /^\d+(?:\.\d+)?$/.test(last),
      "invalid backend tuple times",
    );
    const [backendStart, backendEnd] = interval(
      { first, last },
      "first",
      "last",
    );
    assert(
      backendStart <= end && start <= backendEnd,
      "backend tuple time does not overlap selected connection",
    );
    assert(
      array(row.adm_targets).includes(target),
      "backend tuple targets another connection's pod",
    );
    assert(
      receiver && array(row.via_node).includes(receiver),
      "backend tuple receiver differs from selected connection",
    );
    const address = /^(.*):(\d+)$/.exec(endpoint);
    assert(
      address &&
        Number(address[2]) >= 1 &&
        Number(address[2]) <= 65535 &&
        array(nodes.get(target)?.addresses).includes(address[1]),
      "backend tuple endpoint does not belong to selected pod",
    );
    assert(
      candidates.some(
        (candidate) =>
          candidate.name ===
            `${service.namespace}/${service.attributes.service}` &&
          candidate.target === target &&
          candidate.ip === address[1] &&
          candidate.port === Number(address[2]) &&
          candidate.protocol === transport &&
          candidate.first <= Math.min(end, backendEnd) &&
          candidate.last > Math.max(start, backendStart),
      ),
      "backend tuple does not match the selected Service's time-qualified IP/port/protocol/pod mapping",
    );
    return { target, receiver };
  });
}

export function expectedBackendText(connection, graph, separator = "; ") {
  const targets = new Map();
  for (const record of connection.client_handoffs) {
    const previous = targets.get(record.target) ?? {
      label: graph.nodes.find((node) => node.id === record.target).label,
      connections: 0,
    };
    previous.connections += record.connections;
    targets.set(record.target, previous);
  }
  return [...targets.values()]
    .sort((a, b) => a.label.localeCompare(b.label))
    .map(
      ({ label, connections }) =>
        `${label} (${connections} connections; Hubble: same client tuple (${connections}))`,
    )
    .join(separator);
}

export function selectScenarioEvidence(graph, scenario) {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const client = nodes.get(scenario.clientId);
  assert(
    client?.endpoint_kind === "network_client",
    "missing selected MAC identity",
  );
  assert.equal(client.attributes?.client_mac, scenario.clientMac);
  assert.equal(client.attributes?.scope, scenario.scope);
  assert(
    array(client.addresses).includes(scenario.clientIp),
    "MAC observation IP differs",
  );
  const observations = graph.edges.filter(
    (edge) =>
      edge.source === client.id && edge.relationship === "traffic_observation",
  );
  assert(observations.length > 0, "missing selected MAC traffic observations");
  assert.deepEqual(
    new Set(observations.map((edge) => edge.id)),
    new Set(scenario.observationRecords.map((edge) => edge.id)),
    "MAC observation identity differs from public preflight",
  );
  const bindings = [];
  for (const edge of observations) {
    const recorded = scenario.observationRecords.find(
      (item) => item.id === edge.id,
    );
    assert.equal(edge.target, recorded.target);
    assertOriginalEvidence(
      edge.traffic_observations,
      recorded.traffic,
      "traffic",
    );
    assertOriginalEvidence(
      edge.attachment_evidence,
      recorded.attachments,
      "attachments",
    );
    const service = nodes.get(edge.target);
    assert(
      service?.endpoint_kind === "k8s_service" &&
        service.cluster === scenario.cluster,
      "observation targets another service cluster",
    );
    assert.equal(edge.scope, scenario.scope);
    assert.equal(edge.cluster, scenario.cluster);
    assert(
      edge.traffic_observations?.length > 0,
      "missing original tuple records",
    );
    assert(
      edge.attachment_evidence?.some(
        (record) =>
          record.client_authority === scenario.sourceAuthority &&
          record.client_native_id === scenario.clientMac &&
          record.device_id === scenario.attachmentDeviceId &&
          record.basis === scenario.attachmentBasis,
      ),
      "missing exact MAC attachment evidence",
    );
    for (const record of edge.traffic_observations) {
      assert.equal(record.scope, scenario.scope);
      assert.equal(record.cluster, scenario.cluster);
      assert.equal(record.source_ip, scenario.clientIp);
      assert(
        array(service.addresses).includes(record.destination_ip),
        "observation destination differs from selected service",
      );
      assert(
        record.source_authority && record.source && record.record_fingerprint,
        "missing observation provenance",
      );
      assert.equal(String(record.source_port), String(edge.source_port));
      assert.equal(
        String(record.destination_port),
        String(edge.destination_port),
      );
      assert.equal(record.transport, edge.transport);
      const [start, end] = interval(record, "first_seen", "last_seen");
      const matches = scenario.handoffRows.filter((handoff) => {
        const [first, last] = interval(handoff, "adm_ct", "adm_cend");
        return (
          handoff.client_ip === scenario.clientIp &&
          handoff.scope === scenario.scope &&
          handoff.adm_fe_id === edge.target &&
          handoff.handoff_basis === "hubble_client_tuple" &&
          String(handoff.adm_cport) === String(record.source_port) &&
          String(handoff.server_port) === String(record.destination_port) &&
          handoff.transport === record.transport &&
          start <= last &&
          first <= end
        );
      });
      assert(matches.length > 0, "no exact scoped client tuple/time handoff");
      bindings.push({
        observationId: edge.id,
        recordFingerprint: record.record_fingerprint,
        matches,
      });
    }
  }
  const conversations = graph.edges.filter((edge) => {
    const source = nodes.get(edge.source);
    return (
      edge.relationship === "communicates_with" &&
      edge.source !== client.id &&
      source?.endpoint_kind === "unresolved" &&
      source.attributes?.scope === scenario.scope &&
      array(source.addresses).length === 1 &&
      source.addresses[0] === scenario.clientIp &&
      observations.some(
        (observation) =>
          observation.target === edge.target &&
          String(observation.destination_port) === String(edge.server_port) &&
          observation.transport === edge.transport,
      )
    );
  });
  assert.equal(
    conversations.length,
    1,
    "expected one exact scoped IP conversation",
  );
  const connection = conversations[0];
  const ipClient = nodes.get(connection.source);
  assert(ipClient.reason, "unresolved IP reason must remain explicit");
  for (const field of [
    "client_mac",
    "source_authority",
    "attachment_device_id",
  ])
    assert.equal(
      ipClient.attributes?.[field],
      undefined,
      "IP identity must not inherit MAC attachment authority",
    );
  assert.equal(connection.client_handoff_coverage, "complete");
  assert.equal(connection.client_handoff_unresolved, 0);
  assert(
    connection.client_handoffs?.length > 0,
    "missing per-IP handoff metadata",
  );
  const connectionBindings = bindings.filter(
    (binding) =>
      observations.find((edge) => edge.id === binding.observationId)?.target ===
      connection.target,
  );
  const expectedTargets = new Set(
    connectionBindings.flatMap((binding) =>
      binding.matches.flatMap((row) => array(row.adm_targets)),
    ),
  );
  assert.deepEqual(
    new Set(connection.client_handoffs.map((record) => record.target)),
    expectedTargets,
    "per-IP backend differs from exact observed tuples",
  );
  for (const record of connection.client_handoffs) {
    assert.equal(record.basis, "hubble_client_tuple");
    assert(
      record.connections > 0 && record.receiving_nodes?.length > 0,
      "missing per-IP receiver proof",
    );
    assert(
      nodes.get(record.target)?.cluster === scenario.cluster,
      "backend belongs to another cluster",
    );
    const matchedRows = connectionBindings
      .flatMap((binding) => binding.matches)
      .filter((row) => array(row.adm_targets).includes(record.target));
    assert(
      matchedRows.every(
        (row) =>
          row.adm_cid && array(row.via_node).length && array(row.adm_mT).length,
      ),
      "missing original per-IP receiver/connection proof",
    );
    assert.equal(
      record.connections,
      new Set(matchedRows.map((row) => row.adm_cid)).size,
      "per-IP connection count differs from original tuples",
    );
    const originalTuples = matchedRows
      .flatMap((row) => backendTuples(row, nodes))
      .filter((tuple) => tuple.target === record.target);
    assert(
      originalTuples.length > 0,
      "missing original selected backend tuple",
    );
    assert.deepEqual(
      new Set(record.receiving_nodes),
      new Set(matchedRows.flatMap((row) => array(row.via_node))),
      "receiver differs from selected IP tuples",
    );
    assert.deepEqual(
      new Set(record.observers),
      new Set(originalTuples.map((tuple) => "hubble:" + tuple.receiver)),
      "observer differs from selected IP tuples",
    );
    assert(
      graph.edges.some(
        (edge) =>
          edge.relationship === "forwards_to" &&
          edge.source === connection.target &&
          edge.target === record.target &&
          edge.confidence === "observed",
      ),
      "backend has no observed forward evidence",
    );
  }
  return { client, observations, connection, ipClient, bindings };
}

export function csvRecords(text) {
  const rows = [],
    row = [];
  let value = "",
    quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '"') {
      if (quoted && text[i + 1] === '"') {
        value += '"';
        i++;
      } else quoted = !quoted;
    } else if (!quoted && (char === "," || char === "\n" || char === "\r")) {
      row.push(value);
      value = "";
      if (char !== ",") {
        rows.push([...row]);
        row.length = 0;
        if (char === "\r" && text[i + 1] === "\n") i++;
      }
    } else value += char;
  }
  assert(!quoted, "unterminated CSV cell");
  if (value || row.length) {
    row.push(value);
    rows.push([...row]);
  }
  const headers = rows.shift();
  assert(
    headers?.length && new Set(headers).size === headers.length,
    "invalid CSV headers",
  );
  return rows.map((cells) => {
    assert.equal(cells.length, headers.length);
    return Object.fromEntries(
      headers.map((name, index) => [name, cells[index]]),
    );
  });
}

export function assertScenarioCsv(context, flows, selected, graph, scenario) {
  const contextRows = csvRecords(context);
  for (const edge of selected.observations) {
    for (const [kind, values] of [
      ["traffic_observation", edge.traffic_observations],
      ["attachment_evidence", edge.attachment_evidence],
    ]) {
      for (const record of values) {
        assert(
          contextRows.some(
            (row) =>
              row.edge_id === edge.id &&
              row.source_id === selected.client.id &&
              row.target_id === edge.target &&
              row.evidence_kind === kind &&
              isDeepStrictEqual(JSON.parse(row.evidence_json), record),
          ),
          "context export lost exact MAC observation/attachment record",
        );
      }
    }
  }
  const target = graph.nodes.find(
    (node) => node.id === selected.connection.target,
  );
  const matches = csvRecords(flows).filter(
    (row) =>
      row.client_ip === scenario.clientIp &&
      row.client_name === selected.ipClient.label &&
      row.server_name === target.label &&
      row.port === String(selected.connection.server_port) &&
      row.transport === selected.connection.transport,
  );
  assert.equal(
    matches.length,
    1,
    "required flows export lacks exact IP conversation",
  );
  const row = matches[0];
  assert.equal(row.client_kind, "Unknown IP");
  assert.equal(row.identity, "Unknown IP");
  assert.equal(
    row.client_attachment_authority,
    "",
    "IP conversation must not inherit MAC authority",
  );
  assert.equal(
    row.client_attachment_device_id,
    "",
    "IP conversation must not inherit MAC attachment",
  );
  const connections = selected.connection.client_handoffs.reduce(
    (total, record) => total + record.connections,
    0,
  );
  assert.equal(
    row.handoff,
    `Hubble: same client tuple (${connections})`,
    "required flows lost exact per-IP handoff basis/count",
  );
  const normalize = (value) => value.replace(/\s+/g, " ").trim();
  assert.equal(
    normalize(row.backend),
    normalize(expectedBackendText(selected.connection, graph)),
    "required flows backend set differs from selected IP proof",
  );
}
