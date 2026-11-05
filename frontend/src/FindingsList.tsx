import { useState } from "react";
import { X } from "lucide-react";
import type { Graph, GraphEdge, GraphIndex } from "./graph";
import type { Finding } from "./findings";
import { evidenceSearch, flowRequest, searchUrl } from "./drilldown";
import { pageURL } from "./app/urlState";

export function EvidenceActions({
  edge,
  index,
  graph,
  live,
  onShowPath,
}: {
  edge: GraphEdge;
  index: GraphIndex;
  graph: Graph;
  live: boolean;
  onShowPath: (edge: GraphEdge) => void;
}) {
  const [message, setMessage] = useState("");
  let href: string | undefined;
  let unavailable = "";
  try {
    const search = evidenceSearch(edge, index);
    href = searchUrl(search, {
      start: String(Date.parse(graph.window.start) / 1000),
      end: String(Date.parse(graph.window.end) / 1000),
    });
  } catch (error) {
    unavailable =
      error instanceof Error
        ? error.message
        : "Evidence search is unavailable.";
  }
  const canShowPath =
    edge.relationship === "communicates_with" ||
    (edge.relationship === "forwards_to" &&
      (index.incident.get(edge.source) ?? []).some(
        (e) =>
          e.relationship === "communicates_with" && e.target === edge.source,
      ));
  const canCopy = edge.relationship === "communicates_with";
  const searchHint = !live
    ? "Demo evidence is not searchable"
    : unavailable ||
      (edge.relationship === "calls"
        ? "Opens the first collected trace in this window."
        : edge.relationship === "traffic_observation"
          ? "Opens this exact source observation with its tuple and provenance."
          : "Search includes this tuple across visible observation scopes.");
  return (
    <section className="evidence-actions" aria-label="Evidence actions">
      <div className="finding-buttons">
        {live && href ? (
          <a
            className="secondary-button"
            title={searchHint}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open in Search
          </a>
        ) : (
          <button className="secondary-button" disabled title={searchHint}>
            Open in Search
          </button>
        )}
        <button
          className="secondary-button"
          disabled={!canCopy}
          title={canCopy ? undefined : "Needs a network conversation"}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(flowRequest(edge, index));
              setMessage(
                "Request copied. Review policy and identity before making changes.",
              );
            } catch {
              setMessage(
                "Could not copy the request. Check clipboard access and try again.",
              );
            }
          }}
        >
          Copy request
        </button>
        <button
          className="secondary-button"
          onClick={() => onShowPath(edge)}
          disabled={!canShowPath}
          title={canShowPath ? undefined : "Needs a network conversation"}
        >
          Show path
        </button>
      </div>
      {live && href && <p className="atlas-visually-hidden">{searchHint}</p>}
      {live && unavailable && <p className="muted small">{unavailable}</p>}
      {message && (
        <p role="status" className="small">
          {message}
        </p>
      )}
    </section>
  );
}

export function FindingsList({
  findings,
  graph,
  index,
  live,
  onShowPath,
  onClose,
}: {
  findings: Finding[];
  graph: Graph;
  index: GraphIndex;
  live: boolean;
  onShowPath: (edge: GraphEdge) => void;
  onClose?: () => void;
}) {
  return (
    <section className="findings" aria-label="Map findings">
      <div className="inspector-head">
        <h2 className="summary-title">
          Findings <span className="muted">({findings.length})</span>
        </h2>
        {onClose && (
          <button
            className="icon-button"
            aria-label="Close findings"
            onClick={onClose}
          >
            <X size={16} />
          </button>
        )}
      </div>
      {!live && findings.length > 0 && (
        <p className="muted small">Demo evidence · not searchable</p>
      )}
      {findings.length === 0 && <p className="muted">No findings</p>}
      {findings.map((finding) => {
        const edge = finding.edgeId
          ? index.edge.get(finding.edgeId)
          : undefined;
        return (
          <article
            className="finding-card"
            key={finding.id}
            aria-label={finding.title}
          >
            <h3>{finding.title}</h3>
            <p>{finding.detail}</p>
            {edge && (
              <p className="muted small">
                {index.node.get(edge.source)?.label ?? edge.source} →{" "}
                {index.node.get(edge.target)?.label ?? edge.target}
              </p>
            )}
            {edge ? (
              <EvidenceActions
                edge={edge}
                graph={graph}
                index={index}
                live={live}
                onShowPath={onShowPath}
              />
            ) : (
              <a className="secondary-button" href={pageURL("data_health")}>
                Check data health
              </a>
            )}
          </article>
        );
      })}
    </section>
  );
}
