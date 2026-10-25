import { InfoTip } from "./InfoTip";
import { InspectorTitle } from "./InspectorTitle";
import { Fragment } from "react";
import { ChevronRight, Route, X } from "lucide-react";
import {
  tunnelLabel,
  tunnelOf,
  type GraphEdge,
  type GraphIndex,
  type GraphNode,
  type NatObservation,
  type TrafficObservation,
} from "./graph";
import {
  aclSummary,
  attributeLabels,
  attributeValue,
  handoffConfidence,
  contractSummary,
  policyReason,
  receivedOn,
  directionLabel,
  edgeIdentity,
  handoffExplanation,
  handoffShort,
  identityLabel,
  isUnknown,
  kindLabel,
  plural,
  portLabel,
  prettyBytes,
  relationshipLabel,
  sourceLabel,
  networkClientAttachmentMessage,
  type IdentityState,
} from "./glossary";
import type { Selection } from "./MapView";
import {
  deviceName,
  backendChoices,
  clientBackendChoices,
  clientHandoffResolution,
  clientHandoffReceivingNodes,
  backendChoiceSummary,
  edgeDeviceContext,
  handoffCoverageMessage,
  nodeDeviceContext,
  observationsByDevice,
  type TopologyIndex,
} from "./topology";
import {
  vlanContexts,
  vlanEdges,
  vlanExporter,
  vlanInterface,
  vlanTime,
} from "./vlan";

function VlanEvidence({
  edges,
  topo,
  index,
}: {
  edges: GraphEdge[];
  topo: TopologyIndex;
  index: GraphIndex;
}) {
  const { contexts, truncated } = vlanContexts(edges, index);
  if (!contexts.length && !truncated) return null;
  return (
    <section className="vlan-evidence" aria-label="Observed VLANs — NetFlow">
      <h3>
        Observed VLANs — NetFlow{" "}
        <span className="count">{contexts.length}</span>
      </h3>
      <p className="muted small">
        Observed along conversations; this does not confirm endpoint attachment.
      </p>
      <ul className="seen-list">
        {contexts.map((o) => (
          <li
            key={JSON.stringify([
              o.edgeId,
              o.vlan,
              o.position,
              o.exporter,
              o.interface_index ?? "",
              o.interface ?? "",
              o.src_ip,
              o.dest_ip,
              o.first_seen,
              o.last_seen,
            ])}
          >
            <b>
              VLAN {o.vlan} · {o.position}
            </b>
            <small>
              {vlanExporter(o, topo, {
                scope: o.scope,
                cluster: o.cluster,
                authority: o.authority,
                conflict: o.context_conflict,
              })}
              {vlanInterface(o, topo, {
                scope: o.scope,
                cluster: o.cluster,
                authority: o.authority,
                conflict: o.context_conflict,
              })
                ? ` · ${vlanInterface(o, topo, {
                    scope: o.scope,
                    cluster: o.cluster,
                    authority: o.authority,
                    conflict: o.context_conflict,
                  })}`
                : ""}{" "}
              · {o.src_ip} → {o.dest_ip}
              <br />
              {vlanTime(o.first_seen)} – {vlanTime(o.last_seen)}
            </small>
          </li>
        ))}
      </ul>
      {truncated && (
        <p className="muted small">
          Additional VLAN contexts were omitted because the selected range is
          capped at 32.
        </p>
      )}
    </section>
  );
}

function Facts({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="facts">
      {rows.map(([k, v]) =>
        v === undefined || v === null || v === "" ? null : (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </Fragment>
        ),
      )}
    </dl>
  );
}

const evidenceTime = (raw?: string | number) => {
  if (raw === undefined || raw === "" || !/^\d+(?:\.\d+)?$/.test(String(raw)))
    return undefined;
  const date = new Date(Number(raw) * 1000);
  return Number.isNaN(date.getTime()) ? undefined : date.toLocaleString();
};
function TrafficEvidence({
  observations,
}: {
  observations: TrafficObservation[];
}) {
  if (!observations.length) return null;
  return (
    <section aria-label="Traffic observations">
      <h3>
        Traffic observations{" "}
        <span className="count">{observations.length}</span>
      </h3>
      <p className="muted small">
        Exporter observations are evidence at collection points. They do not
        establish physical adjacency or packet route. Record counts and
        directional counters are shown separately.
      </p>
      <ul className="seen-list">
        {observations.map((o, i) => (
          <li key={`${o.record_fingerprint ?? o.flow_id ?? i}`}>
            <b>
              {sourceLabel(o.source ?? "Flow exporter")}
              {o.direction ? ` · ${o.direction}` : ""}
            </b>
            <small>
              {[
                o.quality_status &&
                  `Quality ${
                    typeof o.quality_status === "string"
                      ? o.quality_status.replaceAll("_", " ")
                      : "unavailable"
                  }`,
                o.exporter_ip && `Exporter ${o.exporter_ip}`,
                o.source_authority && `Authority ${o.source_authority}`,
                o.observation_domain_id && `Domain ${o.observation_domain_id}`,
                o.routing_domain && `Routing domain ${o.routing_domain}`,
                o.vpn_id && `VPN ${o.vpn_id}`,
                o.observation_point && `Point ${o.observation_point}`,
                o.source_ip && `Source IP ${o.source_ip}`,
                o.destination_ip && `Destination IP ${o.destination_ip}`,
                o.source_mac && `Source MAC ${o.source_mac}`,
                o.destination_mac && `Destination MAC ${o.destination_mac}`,
                o.scope && `Scope ${o.scope}`,
                o.profile && `Profile ${o.profile}`,
                o.mapping_status && `Mapping ${o.mapping_status}`,
              ]
                .filter(Boolean)
                .join(" · ")}
              {(o.quality_errors || o.quality_warnings) && (
                <>
                  <br />
                  {o.quality_errors && `Quality errors: ${o.quality_errors}`}
                  {o.quality_errors && o.quality_warnings ? " · " : ""}
                  {o.quality_warnings &&
                    `Quality warnings: ${o.quality_warnings}`}
                </>
              )}
              {(o.ingress_interface ||
                o.egress_interface ||
                o.interface_in ||
                o.interface_out) && (
                <>
                  <br />
                  {[
                    o.ingress_interface && `Ingress ${o.ingress_interface}`,
                    o.egress_interface && `Egress ${o.egress_interface}`,
                    o.interface_in && `Interface in ${o.interface_in}`,
                    o.interface_out && `Interface out ${o.interface_out}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </>
              )}
              {(o.first_seen !== undefined ||
                o.last_seen !== undefined ||
                o.collected_time !== undefined ||
                o.received_time !== undefined) && (
                <>
                  <br />
                  {evidenceTime(
                    o.first_seen === undefined
                      ? undefined
                      : String(o.first_seen),
                  ) ?? "First time unavailable"}{" "}
                  –{" "}
                  {evidenceTime(
                    o.last_seen === undefined ? undefined : String(o.last_seen),
                  ) ?? "last time unavailable"}
                  {o.collected_time !== undefined
                    ? ` · received ${evidenceTime(String(o.collected_time))}`
                    : o.received_time !== undefined
                      ? ` · received ${evidenceTime(String(o.received_time)) ?? "unavailable"}`
                      : ""}
                </>
              )}
              {(o.bytes_in !== undefined ||
                o.bytes_out !== undefined ||
                o.packets_in !== undefined ||
                o.packets_out !== undefined) && (
                <>
                  <br />
                  {[
                    o.bytes_in !== undefined && `Bytes in ${o.bytes_in}`,
                    o.bytes_out !== undefined && `Bytes out ${o.bytes_out}`,
                    o.packets_in !== undefined && `Packets in ${o.packets_in}`,
                    o.packets_out !== undefined &&
                      `Packets out ${o.packets_out}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </>
              )}
              {o.records !== undefined && (
                <>
                  <br />
                  {o.records.toLocaleString()} flow records
                  {o.metrics_authoritative === false
                    ? " · counters are not authoritative"
                    : o.metrics_authoritative === true
                      ? " · counters marked authoritative by source"
                      : " · counter authority unspecified"}
                  {o.counter_semantics ? ` · ${o.counter_semantics}` : ""}
                </>
              )}
              {(o.raw_bytes !== undefined ||
                o.raw_bytes_in !== undefined ||
                o.raw_bytes_out !== undefined ||
                o.raw_packets !== undefined ||
                o.raw_packets_in !== undefined ||
                o.raw_packets_out !== undefined ||
                o.raw_sampling !== undefined) && (
                <>
                  <br />
                  Raw exporter values (non-authoritative):{" "}
                  {[
                    o.raw_bytes !== undefined && `bytes ${o.raw_bytes}`,
                    o.raw_bytes_in !== undefined &&
                      `bytes in ${o.raw_bytes_in}`,
                    o.raw_bytes_out !== undefined &&
                      `bytes out ${o.raw_bytes_out}`,
                    o.raw_packets !== undefined && `packets ${o.raw_packets}`,
                    o.raw_packets_in !== undefined &&
                      `packets in ${o.raw_packets_in}`,
                    o.raw_packets_out !== undefined &&
                      `packets out ${o.raw_packets_out}`,
                    o.raw_sampling !== undefined &&
                      `sampling ${o.raw_sampling}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </>
              )}
              {(o.flow_id || o.sequence || o.record_fingerprint) && (
                <>
                  <br />
                  {[
                    o.flow_id && `Flow ${o.flow_id}`,
                    o.sequence && `Sequence ${o.sequence}`,
                    o.record_fingerprint && `Record ${o.record_fingerprint}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </>
              )}
              {!o.routing_domain && !o.scope && (
                <>
                  <br />
                  Routing domain and source scope unavailable
                  {o.mapping_status ? ` · mapping ${o.mapping_status}` : ""}.
                </>
              )}
              {!o.routing_domain && o.scope && (
                <>
                  <br />
                  Routing domain not reported; source scope is {o.scope}
                  {o.cluster ? ` · ${o.cluster}` : ""}.
                </>
              )}
              {(o.exporter_sampling_mode ||
                o.exporter_sampling_interval !== undefined) && (
                <>
                  <br />
                  Sampling:{" "}
                  {[
                    o.exporter_sampling_mode,
                    o.exporter_sampling_interval !== undefined &&
                      `interval ${o.exporter_sampling_interval}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </>
              )}
              {(o.ingress_overlay_session_id ||
                o.egress_overlay_session_id) && (
                <>
                  <br />
                  Overlay session references (unjoined):{" "}
                  {[
                    o.ingress_overlay_session_id &&
                      `ingress ${o.ingress_overlay_session_id}`,
                    o.egress_overlay_session_id &&
                      `egress ${o.egress_overlay_session_id}`,
                  ]
                    .filter(Boolean)
                    .join(" · ")}{" "}
                  · these references do not establish a tunnel peer or packet
                  route.
                </>
              )}
            </small>
          </li>
        ))}
      </ul>
    </section>
  );
}

function NatEvidence({
  observations,
  truncated,
}: {
  observations: NatObservation[];
  truncated?: boolean;
}) {
  if (!observations.length && !truncated) return null;
  const endpoint = (ip: string, port: number) =>
    `${ip.includes(":") ? `[${ip}]` : ip}:${port}`;
  return (
    <section aria-label="Firewall translation evidence">
      <h3>
        Firewall translation evidence{" "}
        <span className="count">{observations.length}</span>
      </h3>
      <p className="muted small">
        Each item is one Cisco FTD ConnectionEvent reporting both tuples. The
        reported connection tuple is not labeled as original; a reported
        OriginalInitiatorIP is shown separately. This evidence stays attached to
        the conversation and does not establish a load-balancer backend or
        correlate events across observers.
      </p>
      <ul className="seen-list">
        {observations.map((o) => (
          <li key={o.event_fingerprint}>
            <b>{o.protocol.toUpperCase()} · Initiator → Responder</b>
            <small>
              {`Reported tuple ${endpoint(o.reported_initiator_ip, o.reported_initiator_port)} → ${endpoint(o.reported_responder_ip, o.reported_responder_port)}`}
              <br />
              {`NAT translated tuple ${endpoint(o.translated_initiator_ip, o.translated_initiator_port)} → ${endpoint(o.translated_responder_ip, o.translated_responder_port)}`}
              {o.reported_original_initiator_ip && (
                <>
                  <br />
                  {`Cisco reported OriginalInitiatorIP ${o.reported_original_initiator_ip} (separate field)`}
                </>
              )}
              <br />
              {`Authority ${o.source_authority} · Scope ${o.scope} · Device ${o.device_ip}`}
              <br />
              {`Event ${evidenceTime(o.event_time) ?? "unavailable"} · Received ${evidenceTime(o.received_time) ?? "unavailable"}`}
              <br />
              {`Event fingerprint ${o.event_fingerprint}`}
            </small>
          </li>
        ))}
      </ul>
      {truncated && (
        <p className="muted small">
          The source summary or selected graph reached its 32-observation cap;
          additional evidence for this window may have been omitted.
        </p>
      )}
    </section>
  );
}

/** Inputs for a plain-language hand-off explanation of a forwards_to edge. */
export function handoffText(edge: GraphEdge, index: GraphIndex): string {
  const service = index.node.get(edge.source);
  const clients: string[] = [];
  for (const e of index.incident.get(edge.source) ?? [])
    if (e.relationship === "communicates_with" && e.target === edge.source) {
      const n = index.node.get(e.source);
      for (const a of n?.addresses ?? [])
        if (!clients.includes(a)) clients.push(a);
    }
  return handoffExplanation(edge.handoff_basis!, {
    service: service?.attributes?.service ?? service?.label,
    clients,
    node: receivedOn(edge.via_node),
  });
}

export function IdentityBadge({ state }: { state: IdentityState }) {
  return (
    <span
      className={`status ${state === "identified" ? "ok" : state === "external" ? "neutral" : "warn"}`}
    >
      {identityLabel[state]}
    </span>
  );
}

function Device({
  raw,
  topo,
  context,
}: {
  raw: string;
  topo: TopologyIndex;
  context?: Parameters<typeof deviceName>[2];
}) {
  const d = deviceName(raw, topo, context);
  return (
    <>
      {d.name}
      {d.secondary && <small className="secondary"> {d.secondary}</small>}
    </>
  );
}

function ConnectionList({
  title,
  edges,
  self,
  index,
  onSelect,
}: {
  title: string;
  edges: GraphEdge[];
  self: string;
  index: GraphIndex;
  onSelect: (s: Selection) => void;
}) {
  if (!edges.length) return null;
  const node = (id: string) => index.node.get(id);
  const sorted = [...edges].sort(
    (a, b) =>
      (a.traffic_observations?.length || b.traffic_observations?.length
        ? 0
        : (b.bytes ?? -1) - (a.bytes ?? -1) || b.count - a.count) ||
      a.id.localeCompare(b.id),
  );
  return (
    <>
      <h3>
        {title} <span className="count">{edges.length}</span>
      </h3>
      <ul className="edge-list">
        {sorted.map((e) => {
          const peer = node(e.source === self ? e.target : e.source);
          const conv = e.relationship === "communicates_with";
          return (
            <li key={e.id}>
              <button onClick={() => onSelect({ kind: "edge", id: e.id })}>
                <span className="peer">
                  <b>{peer?.label ?? "?"}</b>
                  <small>
                    {conv
                      ? [
                          portLabel(e),
                          e.traffic_observations?.length
                            ? "per-observation counters below"
                            : e.bytes !== undefined
                              ? prettyBytes(e.bytes)
                              : "bytes not reported",
                        ].join(" · ")
                      : e.relationship === "forwards_to"
                        ? `${handoffShort[e.handoff_basis!]} · ${handoffConfidence(e.confidence)}`
                        : `${relationshipLabel[e.relationship]} · ${e.count.toLocaleString()} span${e.count === 1 ? "" : "s"}`}
                  </small>
                </span>
                {conv &&
                  (e.acl_action === "drop" ? (
                    <span className="status blocked">Blocked</span>
                  ) : (
                    <IdentityBadge state={edgeIdentity(e, node)} />
                  ))}
                <ChevronRight size={15} aria-hidden />
              </button>
            </li>
          );
        })}
      </ul>
    </>
  );
}

export function Inspector({
  selection,
  index,
  topo,
  onSelect,
  onClose,
  onShowPath,
  summary,
  pathOpen = false,
}: {
  selection: Selection | null;
  index: GraphIndex;
  topo: TopologyIndex;
  onSelect: (s: Selection | null) => void;
  onClose: () => void;
  onShowPath: (edgeId: string) => void;
  summary: React.ReactNode;
  pathOpen?: boolean;
}) {
  const node =
    selection?.kind === "node" ? index.node.get(selection.id) : undefined;
  const edge =
    selection?.kind === "edge" ? index.edge.get(selection.id) : undefined;
  const close = (
    <button
      className="icon-button"
      aria-label="Clear selection"
      onClick={onClose}
    >
      <X size={16} />
    </button>
  );
  if (node)
    return (
      <NodeDetails
        node={node}
        index={index}
        topo={topo}
        onSelect={onSelect}
        close={close}
      />
    );
  if (!edge) return <div className="inspector-body">{summary}</div>;
  const lookup = (id: string) => index.node.get(id);
  const from = lookup(edge.source),
    to = lookup(edge.target);
  const unknownDir = edge.direction_basis === "unknown";
  const conv = edge.relationship === "communicates_with";
  const trafficObservation = edge.relationship === "traffic_observation";
  const forward = edge.relationship === "forwards_to";
  const context = edgeDeviceContext(edge, index);
  const seen = conv ? observationsByDevice(edge, topo, [], context) : [];
  const clientHandoff =
    conv && to?.endpoint_kind === "k8s_service"
      ? clientHandoffResolution(edge, to, index)
      : undefined;
  const clientHandoffCoverage = clientHandoff?.version2
    ? clientHandoff.message
    : conv && to?.endpoint_kind === "k8s_service"
      ? handoffCoverageMessage(to)
      : undefined;
  const backends =
    conv && to?.endpoint_kind === "k8s_service" && !clientHandoffCoverage
      ? clientHandoff?.version2
        ? clientBackendChoices(index, clientHandoff.records)
        : backendChoices(index, to.id)
      : [];
  const receivedNodes = clientHandoff?.version2
    ? clientHandoff.complete
      ? clientHandoffReceivingNodes(clientHandoff.records)
      : []
    : (edge.via_node ?? []);
  const siblings = forward
    ? (index.outgoing.get(edge.source) ?? []).filter(
        (e) => e.relationship === "forwards_to" && e.target === edge.target,
      )
    : [];
  const contract = conv ? contractSummary(edge) : undefined;
  const acl = conv
    ? aclSummary(
        edge,
        edge.acl_leaf
          ? deviceName(edge.acl_leaf, topo, context).name
          : undefined,
      )
    : undefined;
  return (
    <div className="inspector-body">
      <div className="inspector-head">
        <div>
          <span className={`chip ${edge.relationship}`}>
            {relationshipLabel[edge.relationship]}
          </span>
          <InspectorTitle
            key={edge.id}
            name={`${from?.label ?? edge.source}${trafficObservation ? " · " : unknownDir ? " ↔ " : " → "}${to?.label ?? edge.target}`}
          />
        </div>
        {close}
      </div>
      {conv && !pathOpen && (
        <button
          className="primary-button path-button"
          onClick={() => onShowPath(edge.id)}
        >
          <Route size={15} /> Show candidate path
        </button>
      )}
      <Facts
        rows={[
          [
            trafficObservation
              ? "Observation source"
              : forward
                ? "Service"
                : unknownDir
                  ? "Endpoint A"
                  : "Client",
            from?.label,
          ],
          [
            trafficObservation
              ? "Observed peer"
              : forward
                ? "Backend pod"
                : unknownDir
                  ? "Endpoint B"
                  : "Server",
            to?.label,
          ],
          [
            "Determined by",
            forward && siblings.length <= 1
              ? handoffText(edge, index)
              : undefined,
          ],
          [
            "Confidence",
            forward && siblings.length <= 1 ? (
              <span
                className={`status ${edge.confidence === "inferred" ? "warn" : "ok"}`}
              >
                <InfoTip
                  term={
                    edge.confidence === "inferred" ? "inferred" : "Determined"
                  }
                >
                  {handoffConfidence(edge.confidence)}
                </InfoTip>
              </span>
            ) : undefined,
          ],
          [
            "Received on",
            clientHandoffCoverage ? undefined : receivedOn(receivedNodes),
          ],
          [
            "Identity",
            conv ? (
              <IdentityBadge state={edgeIdentity(edge, lookup)} />
            ) : undefined,
          ],
          [
            "Backend",
            clientHandoffCoverage ??
              (backends.length
                ? backends.map((b) => backendChoiceSummary(b)).join(", ")
                : to?.attributes?.handoff === "service_only"
                  ? `Not determined (${to.attributes.candidates ?? "?"} candidates)`
                  : undefined),
          ],
          ["Service port", conv ? portLabel(edge) : undefined],
          ["Direction", directionLabel(edge)],
          [
            "Encapsulation",
            tunnelOf(edge) ? (
              tunnelOf(edge) === "ipip" ? (
                <>
                  {" "}
                  <InfoTip term="IPIP" /> between nodes (Cilium{" "}
                  <InfoTip term="DSR" /> to a remote backend); the client
                  connection inside is not visible here
                </>
              ) : (
                `${tunnelLabel(tunnelOf(edge)!)} between nodes; pod traffic inside is not visible here`
              )
            ) : undefined,
          ],
          [
            trafficObservation
              ? "Flow records"
              : conv || forward
                ? "Connections"
                : "Spans",
            trafficObservation
              ? (edge.records ?? edge.count).toLocaleString()
              : conv && edge.traffic_observations?.length
                ? "Not aggregated from flow records"
                : (siblings.length > 1
                    ? siblings.reduce((n, s) => n + s.count, 0)
                    : edge.count
                  ).toLocaleString(),
          ],
          [
            "Bytes",
            conv
              ? edge.traffic_observations?.length
                ? "Not aggregated; see per-observation counters"
                : edge.bytes !== undefined
                  ? prettyBytes(edge.bytes)
                  : "Not reported by these sources"
              : undefined,
          ],
          [
            "Application call",
            edge.span_ids?.length && conv
              ? "Matched to an OTel client span by peer address, port and time"
              : undefined,
          ],
        ]}
      />
      {siblings.length > 1 && (
        <>
          <h3>
            How the backend was chosen{" "}
            <span className="count">{siblings.length}</span>
          </h3>
          <ul className="seen-list">
            {[...siblings]
              .sort(
                (a, b) =>
                  Number(a.confidence !== "observed") -
                  Number(b.confidence !== "observed"),
              )
              .map((s) => (
                <li key={s.id}>
                  <b>
                    <span
                      className={`status ${s.confidence === "inferred" ? "warn" : "ok"}`}
                    >
                      <InfoTip
                        term={
                          s.confidence === "inferred"
                            ? "inferred"
                            : "Determined"
                        }
                      >
                        {handoffConfidence(s.confidence)}
                      </InfoTip>
                    </span>{" "}
                    {handoffShort[s.handoff_basis!]}
                  </b>
                  <small>
                    {handoffText(s, index)} · {plural(s.count, "connection")}
                  </small>
                </li>
              ))}
          </ul>
        </>
      )}
      {(contract || acl) && (
        <>
          <h3>Fabric policy</h3>
          {contract && (
            <p className={`policy-line ${edge.contract_basis}`}>
              {contract}
              {edge.contract_basis === "intent" && edge.contract_subject && (
                <small className="muted">
                  {" "}
                  Subject {edge.contract_subject}
                  {edge.contract_filter && ` · filter ${edge.contract_filter}`}
                </small>
              )}
            </p>
          )}
          {edge.contract_basis === "intent" && (
            <p className="muted small">
              <InfoTip term="Intent" /> from collected ACI policy objects, not
              proof the fabric permitted this traffic.
            </p>
          )}
          {policyReason(edge) && (
            <p className="muted small">{policyReason(edge)}</p>
          )}
          {acl && (
            <p
              className={`policy-line ${edge.acl_action === "drop" ? "blocked" : "observed"}`}
            >
              {acl}
            </p>
          )}
        </>
      )}
      {conv && <VlanEvidence edges={[edge]} topo={topo} index={index} />}
      {conv && (
        <NatEvidence
          observations={edge.nat_observations ?? []}
          truncated={edge.nat_observations_truncated}
        />
      )}
      {(conv || trafficObservation) && edge.traffic_observations && (
        <TrafficEvidence observations={edge.traffic_observations} />
      )}
      {edge.attachment_evidence?.length ? (
        <section aria-label="Client attachment evidence">
          <h3>
            Client attachment evidence{" "}
            <span className="count">{edge.attachment_evidence.length}</span>
          </h3>
          <p className="muted small">
            Association records describe attachment evidence at a point in time;
            they do not prove a packet route.
          </p>
          <ul className="seen-list">
            {edge.attachment_evidence.map((a, i) => (
              <li
                key={`${a.client_native_id ?? "client"}-${a.event_time ?? i}`}
              >
                <b>
                  {a.status ?? "Attachment status unavailable"}
                  {a.basis ? ` · ${a.basis}` : ""}
                </b>
                <small>
                  {[
                    a.device_name,
                    a.device_mac,
                    a.device_serial,
                    a.ssid_number ? `SSID ${a.ssid_number}` : undefined,
                    a.client_source,
                    a.client_authority,
                    a.client_native_id,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                  <br />
                  Event{" "}
                  {evidenceTime(
                    a.event_time === undefined
                      ? undefined
                      : String(a.event_time),
                  ) ?? "unavailable"}{" "}
                  · received{" "}
                  {evidenceTime(
                    a.received_time === undefined
                      ? undefined
                      : String(a.received_time),
                  ) ?? "unavailable"}
                  {a.collected_time !== undefined
                    ? ` · collected ${evidenceTime(String(a.collected_time)) ?? "unavailable"}`
                    : ""}
                </small>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {seen.length > 0 && !pathOpen && (
        <>
          <h3>Seen by</h3>
          <ul className="seen-list">
            {seen.map((d) => (
              <li key={d.key}>
                <b>
                  <Device raw={d.label} topo={topo} />
                </b>
                <small>
                  {d.sources.join(" · ")}
                  {d.interfaces.length ? ` · ${d.interfaces.join(", ")}` : ""}
                </small>
              </li>
            ))}
          </ul>
        </>
      )}
      {pathOpen && seen.length > 0 && (
        <p className="muted small">
          Where it was seen is shown in the path below.
        </p>
      )}
      {(edge.sources?.length ?? 0) > 0 && (
        <p className="muted">
          Evidence: {edge.sources!.map(sourceLabel).join(", ")}
        </p>
      )}
      <details className="ids">
        <summary>Identifiers</summary>
        <code>{edge.id}</code>
        {edge.span_ids?.map((s) => (
          <code key={s}>span {s}</code>
        ))}
        {edge.evidence.map((s) => (
          <code key={s}>{s}</code>
        ))}
      </details>
    </div>
  );
}

function NodeDetails({
  node,
  index,
  topo,
  onSelect,
  close,
}: {
  node: GraphNode;
  index: GraphIndex;
  topo: TopologyIndex;
  onSelect: (s: Selection | null) => void;
  close: React.ReactNode;
}) {
  const incident = index.incident.get(node.id) ?? [];
  const links = incident.filter(
    (e) =>
      e.relationship !== "runs_on" && e.relationship !== "traffic_observation",
  );
  const runsOn = incident.filter((e) => e.relationship === "runs_on");
  const unknownDir = links.filter(
    (e) =>
      e.relationship === "communicates_with" && e.direction_basis === "unknown",
  );
  const inbound = links.filter(
    (e) => e.target === node.id && !unknownDir.includes(e),
  );
  const outbound = links.filter(
    (e) => e.source === node.id && !unknownDir.includes(e),
  );
  const unknown = isUnknown(node);
  const attrs = node.attributes ?? {};
  // A node's own name is its title; never repeat it as "Kubernetes node".
  const hidden = new Set([
    "scope",
    "handoff",
    "candidates",
    "service",
    ...(node.endpoint_kind === "k8s_node" ? ["node"] : []),
  ]);
  const frontDoor = node.endpoint_kind === "k8s_service";
  const aggregateHandoffCoverage = frontDoor
    ? handoffCoverageMessage(node)
    : undefined;
  const networkClient = node.endpoint_kind === "network_client";
  const attachmentStatus = attrs.attachment_status;
  const wirelessCorrelated =
    attrs.attachment_basis === "meraki_association_flow" &&
    attachmentStatus === "associated";
  const forwards = frontDoor ? backendChoices(index, node.id) : [];
  const vlan = vlanEdges(index, node.id);
  const displayAttributes = attributeLabels
    .filter(([k]) => {
      if (hidden.has(k)) return false;
      const statusKey =
        k === "vlan"
          ? "vlan_status"
          : k === "bridge_domain"
            ? "bridge_domain_status"
            : undefined;
      if (!statusKey) return attrs[k] !== undefined;
      return (
        (attrs[k] !== undefined && attrs[statusKey] !== "incomplete") ||
        attrs[statusKey] === "varies"
      );
    })
    .map(([k, label]) => [k, label] as [string, string]);
  return (
    <div className="inspector-body">
      <div className="inspector-head">
        <div>
          <span className={`chip ${unknown ? "warn" : node.kind}`}>
            {kindLabel(node)}
          </span>
          <InspectorTitle key={node.id} name={node.label} />
        </div>
        {close}
      </div>
      {unknown && (
        <p className="callout warn">
          {node.endpoint_kind === "ambiguous"
            ? "More than one identity record claims this address in the time range."
            : "No identity record covers this address in the time range. Check the identity saved searches and the observer scope lookup."}
        </p>
      )}
      {networkClient && (
        <>
          {wirelessCorrelated && (
            <p className="callout neutral">
              {networkClientAttachmentMessage(attrs)}
            </p>
          )}
          {!wirelessCorrelated && (
            <p
              className={`callout ${attachmentStatus === "conflict" || attachmentStatus === "stale" || attrs.source_time_status === "stale" || attrs.history_coverage === "unconfirmed" ? "warn" : "neutral"}`}
            >
              {networkClientAttachmentMessage(attrs)}
            </p>
          )}
          <Facts
            rows={[
              ["Source", sourceLabel(attrs.access_platform ?? "") || undefined],
              ["Authority", attrs.source_authority],
              ["Routing domain", attrs.routing_domain],
              ["MAC address", attrs.client_mac],
              ["Attachment status", attachmentStatus],
              ["Evidence basis", attrs.attachment_basis],
              [
                "Source event time",
                evidenceTime(attrs.source_time ?? attrs.attachment_event_time),
              ],
              ["Source time status", attrs.source_time_status],
              [
                "Received time",
                evidenceTime(
                  attrs.received_time ?? attrs.attachment_received_time,
                ),
              ],
              [
                "History coverage",
                attrs.history_coverage === "retained_evidence"
                  ? "Retained evidence only"
                  : attrs.history_coverage === "unconfirmed"
                    ? "Unconfirmed"
                    : attrs.history_coverage,
              ],
              [
                "Source collection time",
                evidenceTime(
                  attrs.collected_time ?? attrs.attachment_collected_time,
                ),
              ],
              ["Access point or device", attrs.attachment_device_name],
              ["Attachment device ID", attrs.attachment_device_id],
              ["Attachment device MAC", attrs.attachment_device_mac],
              ["SSID number", attrs.ssid_number],
            ]}
          />
        </>
      )}
      {attrs.network_history_capped === "1" && (
        <p className="callout neutral">
          Network history is capped; this view may omit older observations.
        </p>
      )}
      {frontDoor && (
        <p className="callout neutral">
          Where clients enter{" "}
          {attrs.service ? <b>{attrs.service}</b> : "this Service"}. Cilium
          translates the frontend to a backend pod; each line to a pod says how
          that pod was identified.
        </p>
      )}
      {aggregateHandoffCoverage && (
        <p className="callout warn">
          {aggregateHandoffCoverage} Any backend links shown here summarize only
          connections with determined handoffs.
        </p>
      )}
      {node.endpoint_kind === "k8s_node_proxy" && (
        <p className="callout neutral">
          Cilium Envoy on {attrs.node ?? "this node"}: Gateway API and Ingress
          connections to backend pods come from this address.
        </p>
      )}
      {node.endpoint_kind === "external" && (
        <p className="callout neutral">
          Public address outside the fabric. External hosts have no identity
          records by design.
        </p>
      )}
      <Facts
        rows={[
          ["Namespace", node.namespace],
          ["Cluster", node.cluster],
          ["Addresses", node.addresses?.join(", ")],
          ...displayAttributes.map(([k, label]): [string, React.ReactNode] => [
            label,
            k === "attach_device" ? (
              <Device
                raw={attrs[k]}
                topo={topo}
                context={nodeDeviceContext(node)}
              />
            ) : k === "traffic_policy" && attrs[k] === "Local" ? (
              <InfoTip term="Local" />
            ) : k === "lb_mode" && attrs[k] === "dsr" ? (
              <InfoTip term="DSR" />
            ) : k === "lb_mode" && attrs[k] === "snat" ? (
              <InfoTip term="SNAT" />
            ) : k === "lb_mode" && attrs[k] === "hybrid" ? (
              <InfoTip term="Hybrid" />
            ) : k === "vlan" && attrs.vlan_status === "varies" ? (
              "Varies in selected range"
            ) : k === "vlan" && attrs.vlan_status === "incomplete" ? (
              "Unavailable: endpoint evidence is incomplete"
            ) : k === "bridge_domain" &&
              attrs.bridge_domain_status === "varies" ? (
              "Varies in selected range"
            ) : k === "bridge_domain" &&
              attrs.bridge_domain_status === "incomplete" ? (
              "Unavailable: endpoint evidence is incomplete"
            ) : (
              attributeValue(k, attrs[k])
            ),
          ]),
          [
            "Backends",
            frontDoor
              ? aggregateHandoffCoverage
                ? forwards.length
                  ? `${forwards.length} aggregate backends for determined connections`
                  : "No determined backend connections"
                : forwards.length
                  ? `${forwards.length} identified`
                  : attrs.handoff === "service_only"
                    ? `Not determined (${attrs.candidates ?? "?"} candidates)`
                    : "None in this time range"
              : undefined,
          ],
          [
            node.kind === "service" ? "Pods" : "Runs",
            runsOn.length
              ? runsOn
                  .map(
                    (e) =>
                      index.node.get(e.source === node.id ? e.target : e.source)
                        ?.label,
                  )
                  .join(", ")
              : undefined,
          ],
        ]}
      />
      <VlanEvidence edges={vlan} topo={topo} index={index} />
      {networkClient &&
        incident.flatMap((e) => e.traffic_observations ?? []).length > 0 && (
          <TrafficEvidence
            observations={incident.flatMap((e) => e.traffic_observations ?? [])}
          />
        )}
      <ConnectionList
        title="Inbound"
        edges={inbound}
        self={node.id}
        index={index}
        onSelect={onSelect}
      />
      <ConnectionList
        title="Outbound"
        edges={outbound}
        self={node.id}
        index={index}
        onSelect={onSelect}
      />
      <ConnectionList
        title="Direction unknown"
        edges={unknownDir}
        self={node.id}
        index={index}
        onSelect={onSelect}
      />
      {!links.length && (
        <p className="muted">No calls or conversations in this time range.</p>
      )}
      <details className="ids">
        <summary>Identifiers</summary>
        <code>{node.id}</code>
        {attrs.scope && <code>Routing scope {attrs.scope}</code>}
        {node.reason && <p className="muted">{node.reason}</p>}
      </details>
    </div>
  );
}
