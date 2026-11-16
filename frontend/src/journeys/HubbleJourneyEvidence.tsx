import type { GraphIndex } from "../graph";
import type { EvidenceWindow } from "../data/evidence";
import { buildHubbleJourney } from "./hubble";
import { JourneyDownload } from "./JourneyEvidence";

export function HubbleJourneyEvidence({
  edgeId,
  index,
  window,
}: {
  edgeId: string;
  index: GraphIndex;
  window?: EvidenceWindow;
}) {
  const journey = buildHubbleJourney(edgeId, index);
  if (!journey) return null;
  const edge = index.edge.get(edgeId)!;
  const name = (id: string) => index.node.get(id)?.label ?? id;
  return (
    <section
      className="atlas-journeys"
      aria-label="Service forwarding evidence"
    >
      <h3>Service forwarding</h3>
      <p>
        Client-specific handoff records are shown separately from aggregate
        Service routing. These are reported associations, not ordered packet
        hops.
      </p>
      {journey.message && <p className="callout warn">{journey.message}</p>}
      {journey.candidates.length > 1 && (
        <p className="callout warn">
          Multiple backend associations. The records do not identify retries or
          request order.
        </p>
      )}
      {journey.candidates.map((candidate, i) => (
        <article
          className="atlas-journey"
          key={`${candidate.backendId}:${candidate.basis}:${i}`}
        >
          <h4>
            {candidate.relation === "inferred"
              ? "Inferred candidate"
              : "Client-specific association"}{" "}
            · {candidate.basisLabel}
          </h4>
          <ol className="atlas-journey-legs">
            <li>
              <strong>Selected client → Service</strong>
              <div>
                {name(journey.clientId)} → {name(journey.serviceId)}
              </div>
            </li>
            <li>
              <strong>
                Service →{" "}
                {candidate.relation === "inferred"
                  ? "Candidate backend"
                  : "Reported backend"}
              </strong>
              <div>
                {name(journey.serviceId)} → {candidate.backendLabel}
              </div>
            </li>
          </ol>
          <p>
            {candidate.connections}{" "}
            {candidate.connections === 1 ? "connection" : "connections"}{" "}
            represented by this{" "}
            {candidate.relation === "inferred" ? "candidate" : "association"}.
            Counts from other sources are not combined.
          </p>
          <p>
            Native event times, per-request identity and retry attempts are not
            retained in this handoff summary.
          </p>
          <details>
            <summary>Source details</summary>
            <dl>
              <dt>Basis</dt>
              <dd>{candidate.basis}</dd>
              <dt>Client identity</dt>
              <dd>{journey.clientId}</dd>
              <dt>Service identity</dt>
              <dd>{journey.serviceId}</dd>
              <dt>Backend identity</dt>
              <dd>{candidate.backendId}</dd>
              <dt>Receiving nodes</dt>
              <dd>{candidate.receivingNodes.join(", ") || "Not reported"}</dd>
              <dt>Observers</dt>
              <dd>{candidate.observers.join(", ") || "Not reported"}</dd>
              <dt>Scope</dt>
              <dd>
                {index.edge.get(edgeId)?.scope ||
                  "Not reported in handoff metadata"}
              </dd>
              <dt>Selected graph window</dt>
              <dd>
                {window
                  ? `${new Date(window.start * 1000).toISOString()} – ${new Date(window.end * 1000).toISOString()}`
                  : "Unavailable"}
              </dd>
            </dl>
          </details>
        </article>
      ))}
      <JourneyDownload
        disabled={!journey.candidates.length || !window}
        evidence={{
          selectedWindow: window,
          scope: edge.scope ?? null,
          cluster:
            edge.cluster ?? index.node.get(journey.serviceId)?.cluster ?? null,
          reportedContexts: {
            clientScope:
              index.node.get(journey.clientId)?.attributes?.scope ?? null,
            serviceScope:
              index.node.get(journey.serviceId)?.attributes?.scope ?? null,
            backends: journey.candidates.map((candidate) => ({
              id: candidate.backendId,
              scope:
                index.node.get(candidate.backendId)?.attributes?.scope ?? null,
              cluster: index.node.get(candidate.backendId)?.cluster ?? null,
            })),
          },
          handoffMetadata: {
            edgeId,
            clientId: edge.source,
            serviceId: edge.target,
            coverage: edge.client_handoff_coverage,
            connections: edge.client_handoff_connections,
            determined: edge.client_handoff_determined,
            unresolved: edge.client_handoff_unresolved,
            records: edge.client_handoffs,
          },
          journey,
          limitation:
            "Client-specific aggregate metadata does not reconstruct event time, packet order or retries. Missing scope and authority remain unknown.",
        }}
      />
    </section>
  );
}
