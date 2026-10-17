import { useEffect, useRef, useState } from "react";
import { diffGraphs, type GraphDiff } from "./diff";
import type { Graph, GraphEdge } from "./graph";
import { loadLive } from "./provider";
import type { SearchClient } from "./data/searchClient";
import { previousDemoGraph } from "./data/demoClient";
import type { DemoScenario } from "./data/demoClient";
import { formatInZone } from "./time";

/** Anchor to the loaded snapshot, never to the editable picker or a new 'now'. */
export function previousWindow(graph: Graph) {
  const start = Date.parse(graph.window.start) / 1000;
  const end = Date.parse(graph.window.end) / 1000;
  if (
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    end <= start ||
    start - (end - start) < 0
  )
    throw new Error("The loaded map has no valid comparison window.");
  return { earliest: String(start - (end - start)), latest: String(start) };
}

export function ChangePanel({
  graph,
  client,
  timezone,
  scenario,
}: {
  graph: Graph;
  client?: SearchClient;
  timezone?: string;
  scenario: DemoScenario;
}) {
  const [result, setResult] = useState<{ previous: Graph; diff: GraphDiff }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const active = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => active.current?.abort(), []);
  const compare = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    setResult(undefined);
    try {
      const bounds = previousWindow(graph);
      const previous = graph.demo
        ? await previousDemoGraph(scenario, controller.signal)
        : client
          ? await loadLive(
              client,
              { ...graph.boundary, ...bounds, timezone },
              controller.signal,
            )
          : undefined;
      if (!previous)
        throw new Error(
          "A previous captured window is not available for this demo. Choose the ACI demo to compare windows.",
        );
      if (
        Date.parse(previous.window.start) / 1000 !== Number(bounds.earliest) ||
        Date.parse(previous.window.end) / 1000 !== Number(bounds.latest)
      )
        throw new Error(
          "The previous result does not match the requested comparison window.",
        );
      if (!controller.signal.aborted)
        setResult({ previous, diff: diffGraphs(previous, graph) });
    } catch (e) {
      if (!controller.signal.aborted)
        setError(e instanceof Error ? e.message : "Comparison failed.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  };

  return (
    <section className="atlas-changes" aria-label="Changes between windows">
      <h2>Changes between windows</h2>
      <p>
        Compare the loaded map with the immediately preceding window of the same
        length. Connections are matched by ID; pod groups by owner or service. A
        changed pod ID can still change a connection ID. Pods without stable
        owner or service metadata are matched by exact ID and may appear as an
        addition and removal when they are replaced.
      </p>
      <button className="secondary-button" onClick={compare} disabled={busy}>
        {busy ? "Comparing…" : "Compare previous window"}
      </button>
      {busy && (
        <button
          className="secondary-button"
          onClick={() => {
            active.current?.abort();
            setBusy(false);
          }}
        >
          Cancel comparison
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {result && (
        <div role="status">
          <p>
            Previous: {formatInZone(result.previous.window.start, timezone)} –{" "}
            {formatInZone(result.previous.window.end, timezone)}
          </p>
          <p>
            Current: {formatInZone(graph.window.start, timezone)} –{" "}
            {formatInZone(graph.window.end, timezone)}
          </p>
          <p>
            {result.diff.addedEdges.length} connections added ·{" "}
            {result.diff.removedEdges.length} removed ·{" "}
            {result.diff.changedEdges.length} changed
          </p>
          <p>
            {result.diff.addedNodes.length} entities added ·{" "}
            {result.diff.removedNodes.length} removed ·{" "}
            {result.diff.changedNodes.length} entity groups changed
          </p>
          <p>
            Differences describe collected evidence, not proof that traffic
            started or stopped. Counts and bytes can vary between windows.
          </p>
          {[...result.previous.coverage.warnings, ...graph.coverage.warnings]
            .length > 0 && (
            <p>
              Coverage warnings apply:{" "}
              {[
                ...new Set([
                  ...result.previous.coverage.warnings,
                  ...graph.coverage.warnings,
                ]),
              ].join(" · ")}
            </p>
          )}
          {(
            [
              ["Added connections", result.diff.addedEdges, graph],
              [
                "Removed connections",
                result.diff.removedEdges,
                result.previous,
              ],
              [
                "Changed connections",
                result.diff.changedEdges.map((c) => c.current),
                graph,
              ],
            ] as const
          ).map(
            ([title, edges, source]) =>
              edges.length > 0 && (
                <details key={title}>
                  <summary>
                    {title} ({edges.length})
                  </summary>
                  <ul>
                    {edges.slice(0, 50).map((edge) => (
                      <li key={edge.id}>{changeEdgeLabel(edge, source)}</li>
                    ))}
                  </ul>
                  {edges.length > 50 && (
                    <p>Showing the first 50 connections.</p>
                  )}
                </details>
              ),
          )}
        </div>
      )}
    </section>
  );
}

export function changeEdgeLabel(edge: GraphEdge, source: Graph) {
  const name = (id: string) =>
    source.nodes.find((n) => n.id === id)?.label ?? id;
  return `${name(edge.source)} ${edge.relationship === "communicates_with" && edge.direction_basis === "unknown" ? "↔" : "→"} ${name(edge.target)}${edge.server_port ? ` · ${edge.server_port}/${edge.transport ?? "unknown"}` : ""}`;
}
