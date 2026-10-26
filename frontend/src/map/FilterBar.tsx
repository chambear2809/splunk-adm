import type { Graph } from "../graph";
import type { Facets, FocusDirection } from "../filters";

export function FilterBar({
  graph,
  facets,
  onChange,
  focus,
  onFocus,
  canFocus,
  network = true,
}: {
  graph: Graph;
  facets: Facets;
  onChange: (facets: Facets) => void;
  focus: { hops: number; direction: FocusDirection };
  onFocus: (hops: number, direction: FocusDirection) => void;
  canFocus: boolean;
  network?: boolean;
}) {
  const ports = [
    ...new Set(
      graph.edges.flatMap((e) =>
        e.server_port === undefined ? [] : [e.server_port],
      ),
    ),
  ].sort((a, b) => a - b);
  const sources = [
    ...new Set(graph.edges.flatMap((e) => e.sources ?? [])),
  ].sort();
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
        </>
      )}
      <label>
        Focus
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
          <option value="0">All connections</option>
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
    </div>
  );
}
