import { useCallback, useEffect, useRef, useState } from "react";
import type { Graph, GraphIndex } from "./graph";
import type { Selection } from "./MapView";
import { DnsEvidencePanel } from "./DnsEvidencePanel";
import { revalidatesOwner } from "./data/ownership";
import { evidenceConfigClient } from "./data/evidenceConfig";
import {
  normalizeIp,
  routingScope,
  validateWindow,
  type EvidenceSelection,
} from "./data/evidence";
import {
  runEndpointInvestigation,
  endpointEvidenceSelection,
} from "./data/endpointInvestigation";
import type { SearchClient } from "./data/searchClient";
import { endpointUrl } from "./data/endpointInvestigation";

/** Re-resolve actual scoped observations; never form products of graph address arrays. */
export function MapDnsInspection({
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
  const [scopes, setScopes] = useState<string[]>([]),
    [scope, setScope] = useState(""),
    [address, setAddress] = useState("");
  const [evidence, setEvidence] = useState<EvidenceSelection>(),
    [error, setError] = useState<string>(),
    [busy, setBusy] = useState(false);
  const [start, setStart] = useState(""),
    [end, setEnd] = useState("");
  const active = useRef<AbortController>(),
    generation = useRef(0);
  const edge =
    selection.kind === "edge" ? index.edge.get(selection.id) : undefined;
  const node =
    selection.kind === "node"
      ? index.node.get(selection.id)
      : edge
        ? index.node.get(edge.source)
        : undefined;
  const addresses = (node?.addresses ?? []).flatMap((ip) => {
    try {
      return [normalizeIp(ip)];
    } catch {
      return [];
    }
  });
  const supported =
    node &&
    ["workload", "endpoint", "client"].includes(node.kind) &&
    (!edge ||
      ["communicates_with", "traffic_observation"].includes(edge.relationship));
  const key = JSON.stringify([graph.snapshot_id, selection, live]);
  const invalidate = useCallback(() => {
    generation.current++;
    active.current?.abort();
  }, []);
  useEffect(() => {
    generation.current++;
    active.current?.abort();
    setEvidence(undefined);
    setScopes([]);
    setScope("");
    setAddress("");
    setError(undefined);
    setBusy(false);
    setStart("");
    setEnd("");
    return invalidate;
  }, [key, invalidate]);
  if (!live || !client || !supported) return null;
  const prepare = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setBusy(true);
    setError(undefined);
    setEvidence(undefined);
    try {
      const config = await evidenceConfigClient.read(controller.signal);
      if (current !== generation.current || controller.signal.aborted) return;
      const options = [
        ...new Set(
          config.mappings
            .filter((m) => m.mapping_status === "verified")
            .flatMap((m) => {
              try {
                return [routingScope(m.scope)];
              } catch {
                return [];
              }
            }),
        ),
      ].sort();
      setScopes(options);
      if (options.length === 1) setScope(options[0]);
      if (addresses.length === 1) setAddress(addresses[0]);
      if (!options.length)
        throw Error("No verified routing scope is configured.");
    } catch {
      if (current === generation.current)
        setError(
          "Evidence scope configuration is unavailable. Ask an administrator to verify mappings.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  const load = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setBusy(true);
    setError(undefined);
    setEvidence(undefined);
    try {
      const graphWindow = {
        start: Date.parse(graph.window.start) / 1000,
        end: Date.parse(graph.window.end) / 1000,
      };
      const window =
        start && end
          ? { start: Date.parse(start) / 1000, end: Date.parse(end) / 1000 }
          : validateWindow(graphWindow);
      validateWindow(window);
      if (window.start < graphWindow.start || window.end > graphWindow.end)
        throw Error(
          "Choose an evidence subwindow inside the displayed graph window.",
        );
      if (!addresses.includes(address) || !scopes.includes(scope))
        throw Error(
          "Choose one displayed address and one verified routing scope.",
        );
      const result = await runEndpointInvestigation(
        client,
        evidenceConfigClient,
        { address, scope, start: window.start, end: window.end },
        controller.signal,
      );
      let next = endpointEvidenceSelection(result);
      const peerAddresses = edge
        ? (index.node.get(edge.target)?.addresses ?? []).flatMap((ip) => {
            try {
              return [normalizeIp(ip)];
            } catch {
              return [];
            }
          })
        : undefined;
      if (edge)
        next = {
          ...next,
          contexts: endpointEvidenceSelection({
            ...result,
            conversations: result.conversations.filter(
              (c) =>
                c.port === edge.server_port && c.transport === edge.transport,
            ),
          }).contexts.filter(
            (c) => c.client === address && peerAddresses?.includes(c.server),
          ),
        };
      // Only stable workload UIDs can be rechecked against the original selection.
      // Address-based VM graph identifiers alone do not retain historical owner identity.
      const uid = node?.id.startsWith("pod:")
        ? node.id.slice(node.id.indexOf("/") + 1)
        : undefined;
      const config = await evidenceConfigClient.read(
        controller.signal,
        [address],
        scope,
      );
      if (config.fingerprint !== next.configurationFingerprint)
        throw Error("Configuration changed during evidence capture.");
      let verified =
        config.identityAvailable &&
        revalidatesOwner(
          config.identities,
          address,
          scope,
          uid,
          window.start,
          window.end,
          config.clockUncertaintySeconds,
        );
      if (edge) {
        const target = index.node.get(edge.target);
        const targetUid = target?.id.startsWith("pod:")
          ? target.id.slice(target.id.indexOf("/") + 1)
          : undefined;
        const actualPeers = [...new Set(next.contexts.map((c) => c.server))];
        if (actualPeers.length > 8)
          throw Error(
            "Narrow the connection to at most eight actual peer addresses.",
          );
        const identityAddresses = [address, ...actualPeers];
        const full = await evidenceConfigClient.read(
          controller.signal,
          identityAddresses,
          scope,
        );
        verified =
          verified &&
          full.identityAvailable &&
          revalidatesOwner(
            full.identities,
            address,
            scope,
            uid,
            window.start,
            window.end,
            full.clockUncertaintySeconds,
          ) &&
          !!targetUid &&
          next.contexts.length > 0 &&
          next.contexts.every((c) =>
            revalidatesOwner(
              full.identities,
              c.server,
              scope,
              targetUid,
              c.first,
              c.last,
              full.clockUncertaintySeconds,
            ),
          );
        next = {
          ...next,
          identityAddresses,
          configurationFingerprint: full.fingerprint,
        };
      }
      next = {
        ...next,
        workflow: "application",
        selectionId: `${graph.snapshot_id}:${selection.kind}:${selection.id}`,
        identityBasis: verified
          ? "Original workload UID revalidated against current scoped history; independent observation capture."
          : "Context only: original graph identity/tuple history cannot be fully revalidated. Snapshot ID is a client identifier.",
        contexts: verified
          ? next.contexts.map((c) => ({ ...c, clientOwner: uid }))
          : [],
      };
      if (current === generation.current && !controller.signal.aborted)
        setEvidence(next);
    } catch (reason) {
      if (current === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Evidence context unavailable.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  return (
    <section className="inspector-body" aria-label="DNS selection context">
      <h3>Optional DNS investigation</h3>
      <p>
        Choose one scoped address. Evidence is captured independently of this
        map; flow observation time does not establish a connection opening.
      </p>
      {!scopes.length ? (
        <button type="button" disabled={busy} onClick={() => void prepare()}>
          Choose evidence context
        </button>
      ) : (
        <>
          <label>
            Observed address
            <select
              value={address}
              onChange={(e) => {
                active.current?.abort();
                setEvidence(undefined);
                setAddress(e.target.value);
              }}
            >
              <option value="">Choose an address</option>
              {addresses.map((ip) => (
                <option key={ip}>{ip}</option>
              ))}
            </select>
          </label>
          <label>
            Verified routing scope
            <select
              value={scope}
              onChange={(e) => {
                active.current?.abort();
                setEvidence(undefined);
                setScope(e.target.value);
              }}
            >
              <option value="">Choose a scope</option>
              {scopes.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <p>
            For maps longer than 24 hours, select an explicit evidence
            subwindow.
          </p>
          <label>
            Evidence start
            <input
              type="datetime-local"
              value={start}
              onChange={(e) => {
                active.current?.abort();
                setEvidence(undefined);
                setStart(e.target.value);
              }}
            />
          </label>
          <label>
            Evidence end
            <input
              type="datetime-local"
              value={end}
              onChange={(e) => {
                active.current?.abort();
                setEvidence(undefined);
                setEnd(e.target.value);
              }}
            />
          </label>
          <button
            type="button"
            disabled={busy || !scope || !address}
            onClick={() => void load()}
          >
            Resolve observed evidence context
          </button>
          {busy && (
            <button type="button" onClick={() => active.current?.abort()}>
              Cancel
            </button>
          )}
        </>
      )}
      {error && <p role="alert">{error}</p>}
      {busy && <p role="status">Resolving scoped observations…</p>}
      {evidence && (
        <>
          <p>{evidence.identityBasis}</p>
          <a
            href={endpointUrl({
              address: evidence.addresses[0],
              scope: evidence.scope,
              start: evidence.window.start,
              end: evidence.window.end,
            })}
          >
            Open scoped endpoint investigation
          </a>
          <DnsEvidencePanel selection={evidence} client={client} />
        </>
      )}
    </section>
  );
}
