import { useState } from "react";
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
  return (
    <section className="evidence-actions" aria-label="Evidence actions">
      <div className="finding-buttons">
        {live && href ? (
          <a
            className="secondary-button"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open in Search
          </a>
        ) : (
          <button className="secondary-button" disabled>
            Open in Search
          </button>
        )}
        <button
          className="secondary-button"
          disabled={!canCopy}
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
        >
          Show path
        </button>
      </div>
      {live && href && (
        <p className="muted small">
          {edge.relationship === "calls"
            ? "Opens the first collected trace in this window."
            : "Search includes this tuple across visible observation scopes."}
        </p>
      )}
      {!live && (
        <p className="muted small">
          Synthetic demo evidence cannot be searched in your live indexes.
        </p>
      )}
      {unavailable && <p className="muted small">{unavailable}</p>}
      {!canShowPath && (
        <p className="muted small">
          No network conversation is available for a candidate path.
        </p>
      )}
      {!canCopy && (
        <p className="muted small">
          A firewall request needs a network conversation.
        </p>
      )}
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
}: {
  findings: Finding[];
  graph: Graph;
  index: GraphIndex;
  live: boolean;
  onShowPath: (edge: GraphEdge) => void;
}) {
  return (
    <section className="findings" aria-label="Map findings">
      <h2 className="summary-title">
        Findings <span className="muted">({findings.length})</span>
      </h2>
      <p className="muted small">
        Observations from this map’s window. Missing identity or policy is a
        limit of the collected evidence.
      </p>
      {findings.some((finding) => finding.kind === "stale_source") && (
        <p className="muted small">
          Source findings use the last app-wide pipeline health check,
          independent of map filters. Quiet sources or missing index access can
          explain missing data.
        </p>
      )}
      {findings.length === 0 && (
        <p>
          No findings in the collected evidence. This does not establish
          complete coverage.
        </p>
      )}
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
