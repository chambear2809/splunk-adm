import type { Graph } from "../graph";
import type { Facets, FocusDirection } from "../filters";
import { observedPort } from "../glossary";

/** Number of active facets, shown on the Filters button. */
export const activeFacetCount = (facets: Facets) =>
  [
    facets.identity,
    facets.port,
    facets.source,
    facets.blocked || undefined,
    facets.hideInfrastructure || undefined,
    facets.hideInferred || undefined,
  ].filter((value) => value !== undefined).length;

export function FilterBar({
  graph,
  facets,
  onChange,
  network = true,
}: {
  graph: Graph;
  facets: Facets;
  onChange: (facets: Facets) => void;
  network?: boolean;
}) {
  const ports = availablePorts(graph);
  const sources = [
    ...new Set(graph.edges.flatMap((e) => e.sources ?? [])),
  ].sort();
  if (!network)
    return (
      <div className="atlas-map-filters" aria-label="Map filters">
        <p className="muted small">No filters for Services</p>
      </div>
    );
  return (
    <div className="atlas-map-filters" aria-label="Map filters">
      {network && (
        <>
          <label>
            Identity
            <select
              aria-label="Filter identity"
              value={facets.identity ?? ""}
              onChange={(e) =>
                onChange({
                  ...facets,
                  identity: (e.target.value || undefined) as Facets["identity"],
                })
              }
            >
              <option value="">All identities</option>
              <option value="identified">Identified</option>
              <option value="external">External</option>
              <option value="unknown">Unknown or multiple owners</option>
            </select>
          </label>
          <label>
            Port
            <select
              aria-label="Filter port"
              value={facets.port ?? ""}
              onChange={(e) =>
                onChange({
                  ...facets,
                  port: e.target.value ? Number(e.target.value) : undefined,
                })
              }
            >
              <option value="">All ports</option>
              {ports.map((port) => (
                <option key={port} value={port}>
                  {port}
                </option>
              ))}
            </select>
          </label>
          <label>
            Source
            <select
              aria-label="Filter source"
              value={facets.source ?? ""}
              onChange={(e) =>
                onChange({ ...facets, source: e.target.value || undefined })
              }
            >
              <option value="">All sources</option>
              {sources.map((source) => (
                <option key={source}>{source}</option>
              ))}
            </select>
          </label>
          <label className="atlas-filter-check">
            <input
              type="checkbox"
              checked={!!facets.blocked}
              onChange={(e) =>
                onChange({ ...facets, blocked: e.target.checked })
              }
            />
            Blocked only
          </label>
          <label className="atlas-filter-check">
            <input
              type="checkbox"
              checked={!!facets.hideInfrastructure}
              onChange={(e) =>
                onChange({ ...facets, hideInfrastructure: e.target.checked })
              }
            />
            Hide infrastructure
          </label>
          <label className="atlas-filter-check">
            <input
              type="checkbox"
              checked={!!facets.hideInferred}
              onChange={(e) =>
                onChange({ ...facets, hideInferred: e.target.checked })
              }
            />
            Hide inferred
          </label>
        </>
      )}
    </div>
  );
}

/** Neighborhood focus for the selected card; compact enough for the toolbar. */
export function FocusSelect({
  focus,
  onFocus,
  canFocus,
}: {
  focus: { hops: number; direction: FocusDirection };
  onFocus: (hops: number, direction: FocusDirection) => void;
  canFocus: boolean;
}) {
  return (
    <label className="atlas-focus">
      <span className="atlas-visually-hidden">Focus</span>
      <select
        aria-label="Focus around selected card"
        title={
          canFocus || focus.hops
            ? undefined
            : "Select a card on the map to focus on its connections"
        }
        value={
          focus.direction === "any"
            ? String(focus.hops)
            : `${focus.direction}:${focus.hops}`
        }
        disabled={!canFocus && !focus.hops}
        onChange={(e) => {
          const [direction, hops] = e.target.value.includes(":")
            ? e.target.value.split(":")
            : ["any", e.target.value];
          onFocus(Number(hops), direction as FocusDirection);
        }}
      >
        <option value="0">Focus: off</option>
        <optgroup label="Any direction">
          {[1, 2, 3].map((hops) => (
            <option key={hops} value={String(hops)}>
              {hops === 1 ? "1 hop" : `${hops} hops`}
            </option>
          ))}
        </optgroup>
        <optgroup label="Callers: observed reaching the selection">
          {[1, 2, 3].map((hops) => (
            <option key={hops} value={`callers:${hops}`}>
              Callers · {hops === 1 ? "1 hop" : `${hops} hops`}
            </option>
          ))}
        </optgroup>
        <optgroup label="Dependencies: observed from the selection">
          {[1, 2, 3].map((hops) => (
            <option key={hops} value={`dependencies:${hops}`}>
              Dependencies · {hops === 1 ? "1 hop" : `${hops} hops`}
            </option>
          ))}
        </optgroup>
      </select>
    </label>
  );
}

/** Ports exposed by the facet, preserving both orientations of observations. */
export function availablePorts(graph: Graph): number[] {
  return [
    ...new Set(
      graph.edges.flatMap((edge) => {
        if (edge.relationship !== "traffic_observation") {
          const port = observedPort(edge);
          return port === undefined ? [] : [port];
        }
        const nativePorts = (edge.traffic_observations ?? []).flatMap(
          (observation) =>
            [observation.source_port, observation.destination_port].filter(
              (port): port is number => port !== undefined,
            ),
        );
        if (nativePorts.length) return nativePorts;
        const rawPorts = [edge.source_port, edge.destination_port].filter(
          (port): port is number => port !== undefined,
        );
        if (rawPorts.length) return rawPorts;
        const fallback = observedPort(edge);
        return fallback === undefined ? [] : [fallback];
      }),
    ),
  ].sort((a, b) => a - b);
}
