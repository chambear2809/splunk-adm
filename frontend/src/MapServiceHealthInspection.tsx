import { useCallback, useEffect, useRef, useState } from "react";
import type { Graph, GraphIndex } from "./graph";
import type { Selection } from "./MapView";
import { O11yDetectorEventsPanel } from "./O11yDetectorEventsPanel";
import { O11yHealthPanel } from "./O11yHealthPanel";
import {
  evidenceConfigClient,
  type EvidenceConfiguration,
} from "./data/evidenceConfig";
import type { ServiceHealthSelection } from "./data/evidence";
import {
  serviceEvidenceScopes,
  serviceHealthSelection,
} from "./data/serviceHealthSelection";
import type { SearchClient } from "./data/searchClient";

/** Health belongs to the exact boundary service; graph labels alone are insufficient. */
export function MapServiceHealthInspection({
  graph,
  index,
  selection,
  client,
  live,
}: {
  graph: Graph;
  index: GraphIndex;
  selection: Selection;
  client?: SearchClient;
  live: boolean;
}) {
  const root = index.node.get(graph.boundary.root_node_id);
  const supported =
    selection.kind === "node" &&
    selection.id === graph.boundary.root_node_id &&
    root?.kind === "service";
  const [config, setConfig] = useState<EvidenceConfiguration>();
  const [scope, setScope] = useState("");
  const [healthSelection, setHealthSelection] =
    useState<ServiceHealthSelection>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController>();
  const generation = useRef(0);
  const identity = JSON.stringify([graph.snapshot_id, selection, live]);
  const cancel = useCallback(() => {
    generation.current++;
    active.current?.abort();
  }, []);
  const cancelCurrent = () => {
    cancel();
    setBusy(false);
    setError("Scope read cancelled. You can refresh the health scope again.");
  };
  useEffect(() => {
    cancel();
    setConfig(undefined);
    setScope("");
    setHealthSelection(undefined);
    setError(undefined);
    setBusy(false);
    return cancel;
  }, [identity, cancel]);
  if (!live || !client || !supported) return null;
  const scopes = config
    ? serviceEvidenceScopes(config, graph.boundary.cluster)
    : [];
  const prepare = async () => {
    cancel();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setBusy(true);
    setError(undefined);
    setHealthSelection(undefined);
    try {
      const next = await evidenceConfigClient.read(controller.signal);
      if (controller.signal.aborted || current !== generation.current) return;
      setConfig(next);
      const options = serviceEvidenceScopes(next, graph.boundary.cluster);
      if (options.length === 1) setScope(options[0]);
      if (!options.length)
        setError(
          "No verified Observability health or detector binding maps to this service cluster.",
        );
    } catch {
      if (current === generation.current)
        setError(
          "Service health scope configuration is unavailable to this caller.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  const inspect = async () => {
    if (!config || !scopes.includes(scope) || !client) return;
    cancel();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setBusy(true);
    setError(undefined);
    setHealthSelection(undefined);
    try {
      const latest = await evidenceConfigClient.read(controller.signal);
      const next = serviceHealthSelection(graph, selection.id, scope, latest);
      if (controller.signal.aborted || current !== generation.current) return;
      setHealthSelection(next);
    } catch {
      if (current === generation.current)
        setError(
          "Service identity, scope or configuration changed. Refresh the map or choose a narrower window.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  return (
    <section className="inspector-body" aria-label="Service health evidence">
      <h3>Service health evidence</h3>
      <p>
        Measured service health is time-aligned context; it does not establish a
        network cause.
      </p>
      <button type="button" onClick={() => void prepare()} disabled={busy}>
        Refresh health scope
      </button>
      {scopes.length > 0 && (
        <>
          <label>
            Routing scope
            <select
              aria-label="Service health routing scope"
              value={scope}
              onChange={(event) => {
                setScope(event.target.value);
                setHealthSelection(undefined);
              }}
            >
              <option value="">Choose scope</option>
              {scopes.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void inspect()}
            disabled={busy || !scope}
          >
            Inspect service health
          </button>
        </>
      )}
      {busy && (
        <button type="button" onClick={cancelCurrent}>
          Cancel scope read
        </button>
      )}
      {error && <p role="alert">{error}</p>}
      {healthSelection && (
        <div key={JSON.stringify(healthSelection)}>
          <O11yHealthPanel selection={healthSelection} client={client} />
          <O11yDetectorEventsPanel
            selection={healthSelection}
            client={client}
          />
        </div>
      )}
    </section>
  );
}
