import { Fragment } from "react";
import { ChevronRight, Route, X } from "lucide-react";
import {
  tunnelLabel,
  tunnelOf,
  type GraphEdge,
  type GraphIndex,
  type GraphNode,
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
  type IdentityState,
} from "./glossary";
import type { Selection } from "./MapView";
import {
  deviceName,
  backendChoices,
  observationsByDevice,
  type TopologyIndex,
} from "./topology";

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

function Device({ raw, topo }: { raw: string; topo: TopologyIndex }) {
  const d = deviceName(raw, topo);
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
      (b.bytes ?? -1) - (a.bytes ?? -1) ||
      b.count - a.count ||
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
                          e.bytes !== undefined
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
  const forward = edge.relationship === "forwards_to";
  const seen = conv ? observationsByDevice(edge, topo) : [];
  const backends =
    conv && to?.endpoint_kind === "k8s_service"
      ? backendChoices(index, to.id)
      : [];
  const siblings = forward
    ? (index.outgoing.get(edge.source) ?? []).filter(
        (e) => e.relationship === "forwards_to" && e.target === edge.target,
      )
    : [];
  const contract = conv ? contractSummary(edge) : undefined;
  const acl = conv
    ? aclSummary(
        edge,
        edge.acl_leaf ? deviceName(edge.acl_leaf, topo).name : undefined,
      )
    : undefined;
  return (
    <div className="inspector-body">
      <div className="inspector-head">
        <div>
          <span className={`chip ${edge.relationship}`}>
            {relationshipLabel[edge.relationship]}
          </span>
          <h2>
            {from?.label ?? edge.source}
            <span className="arrow">{unknownDir ? " ↔ " : " → "}</span>
            {to?.label ?? edge.target}
          </h2>
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
            forward ? "Service" : unknownDir ? "Endpoint A" : "Client",
            from?.label,
          ],
          [
            forward ? "Backend pod" : unknownDir ? "Endpoint B" : "Server",
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
                {handoffConfidence(edge.confidence)}
              </span>
            ) : undefined,
          ],
          ["Received on", receivedOn(edge.via_node)],
          [
            "Identity",
            conv ? (
              <IdentityBadge state={edgeIdentity(edge, lookup)} />
            ) : undefined,
          ],
          [
            "Backend",
            backends.length
              ? backends
                  .map(
                    (b) =>
                      `${b.label}${b.state === "inferred" ? " (inferred)" : ""}`,
                  )
                  .join(", ")
              : to?.attributes?.handoff === "service_only"
                ? `Not determined (${to.attributes.candidates ?? "?"} candidates)`
                : undefined,
          ],
          ["Service port", conv ? portLabel(edge) : undefined],
          ["Direction", directionLabel(edge)],
          [
            "Encapsulation",
            tunnelOf(edge)
              ? tunnelOf(edge) === "ipip"
                ? "IPIP between nodes (Cilium DSR to a remote backend); the client connection inside is not visible here"
                : `${tunnelLabel(tunnelOf(edge)!)} between nodes; pod traffic inside is not visible here`
              : undefined,
          ],
          [
            conv || forward ? "Connections" : "Spans",
            (siblings.length > 1
              ? siblings.reduce((n, s) => n + s.count, 0)
              : edge.count
            ).toLocaleString(),
          ],
          [
            "Bytes",
            conv
              ? edge.bytes !== undefined
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
                      {handoffConfidence(s.confidence)}
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
              Intent from collected ACI policy objects, not proof the fabric
              permitted this traffic.
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
  const links = incident.filter((e) => e.relationship !== "runs_on");
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
  const forwards = frontDoor
    ? (index.outgoing.get(node.id) ?? []).filter(
        (e) => e.relationship === "forwards_to",
      )
    : [];
  return (
    <div className="inspector-body">
      <div className="inspector-head">
        <div>
          <span className={`chip ${unknown ? "warn" : node.kind}`}>
            {kindLabel(node)}
          </span>
          <h2>{node.label}</h2>
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
      {frontDoor && (
        <p className="callout neutral">
          Where clients enter{" "}
          {attrs.service ? <b>{attrs.service}</b> : "this Service"}. Cilium
          translates the frontend to a backend pod; each line to a pod says how
          that pod was identified.
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
          ...attributeLabels
            .filter(([k]) => !hidden.has(k) && attrs[k])
            .map(([k, label]): [string, React.ReactNode] => [
              label,
              k === "attach_device" ? (
                <Device raw={attrs[k]} topo={topo} />
              ) : (
                attributeValue(k, attrs[k])
              ),
            ]),
          [
            "Backends",
            frontDoor
              ? forwards.length
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
