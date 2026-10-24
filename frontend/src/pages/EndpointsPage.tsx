import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { EvidenceSelection } from "../data/evidence";
import type { EvidenceConfigClient } from "../data/evidenceConfig";
import { evidenceConfigClient } from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import { fitText } from "../MapView";
import { csvRow } from "../csv";
import { downloadBlob } from "../download";
import { peerEndpointUrl } from "./endpointPeerLink";
import { pageURL, parseUrlState, stateParams } from "../app/urlState";
import {
  endpointEvidenceSelection,
  parseEndpointUrl,
  runEndpointInvestigation,
  validateEndpointInput,
  type EndpointInput,
  type EndpointResult,
} from "../data/endpointInvestigation";

const localDate = (seconds: number) => {
  const d = new Date(seconds * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    .toISOString()
    .replace(/Z$/, "");
};
const fromLocalDate = (value: string) => new Date(value).getTime() / 1000;
export function returnApplicationURL(
  referrer: string,
  origin: string,
  pathname: string,
): string | undefined {
  try {
    const url = new URL(referrer, origin);
    if (
      url.origin !== origin ||
      !/^\/(?:[^/]+\/)*app\/splunk_adm\/map\/?$/.test(url.pathname)
    )
      return undefined;
    const required = ["service", "environment", "cluster", "namespace"];
    if (required.some((key) => !url.searchParams.has(key))) return undefined;
    return pageURL(
      "map",
      stateParams(parseUrlState(url.searchParams, true)),
      pathname,
    );
  } catch {
    return undefined;
  }
}
function pageInitial(initial?: EndpointInput): {
  input?: EndpointInput;
  error?: string;
} {
  if (initial) return { input: initial };
  if (typeof window === "undefined") return {};
  try {
    return {
      input: parseEndpointUrl(new URLSearchParams(window.location.search)),
    };
  } catch (reason) {
    return {
      error:
        reason instanceof Error ? reason.message : "Invalid endpoint link.",
    };
  }
}
export function EndpointsPage({
  initial,
  client,
  live = false,
  configurationClient,
  renderEvidence,
}: {
  initial?: EndpointInput;
  client?: SearchClient;
  live: boolean;
  configurationClient?: EvidenceConfigClient;
  renderEvidence?: (selection: EvidenceSelection) => ReactNode;
}) {
  const now = Math.floor(Date.now() / 1000);
  const [link] = useState(() => pageInitial(initial));
  const [address, setAddress] = useState(link.input?.address ?? "");
  const [scope, setScope] = useState(link.input?.scope ?? "");
  const [start, setStart] = useState(
    localDate(link.input?.start ?? now - 3600),
  );
  const [end, setEnd] = useState(localDate(link.input?.end ?? now));
  const [startEdited, setStartEdited] = useState(false);
  const [endEdited, setEndEdited] = useState(false);
  const [result, setResult] = useState<EndpointResult>();
  const [error, setError] = useState(link.error ?? "");
  const [loading, setLoading] = useState(false);
  const controllerRef = useRef<AbortController>();
  const revisionRef = useRef(0);
  const input = useMemo(
    () => ({
      address,
      scope,
      start:
        !startEdited && link.input ? link.input.start : fromLocalDate(start),
      end: !endEdited && link.input ? link.input.end : fromLocalDate(end),
    }),
    [address, scope, start, end, startEdited, endEdited, link.input],
  );
  useEffect(() => {
    setLoading(false);
    setResult(undefined);
    return () => {
      revisionRef.current += 1;
      controllerRef.current?.abort();
    };
  }, [address, scope, start, end, live]);
  const run = useCallback(
    async (override = input) => {
      const selectedConfigClient = configurationClient ?? evidenceConfigClient;
      if (!client) {
        setError("Endpoint search is unavailable.");
        return;
      }
      let valid: EndpointInput;
      try {
        valid = validateEndpointInput(override);
      } catch (reason) {
        setError(
          reason instanceof Error
            ? reason.message
            : "Invalid endpoint selection.",
        );
        return;
      }
      controllerRef.current?.abort();
      const revision = ++revisionRef.current;
      setLoading(true);
      setError("");
      const controller = new AbortController();
      controllerRef.current = controller;
      try {
        const next = await runEndpointInvestigation(
          client,
          selectedConfigClient,
          valid,
          controller.signal,
        );
        if (revision === revisionRef.current && !controller.signal.aborted)
          setResult(next);
      } catch (reason) {
        if (revision === revisionRef.current && !controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Endpoint search failed.",
          );
      } finally {
        if (revision === revisionRef.current) setLoading(false);
      }
    },
    [client, configurationClient, input],
  );
  const endpointPath =
    typeof window === "undefined"
      ? "/app/splunk_adm/endpoints"
      : pageURL(
          "endpoints",
          new URLSearchParams(),
          window.location.pathname,
        ).split("?")[0];
  const peerLink = (peer: string) =>
    result ? peerEndpointUrl(result.selection, peer, endpointPath) : "#";
  const nav = (peer: string) => window.location.assign(peerLink(peer));
  const identityConflict =
    result?.identityHistory.some((left, index) =>
      result.identityHistory
        .slice(index + 1)
        .some(
          (right) =>
            left.entity_id !== right.entity_id &&
            left.valid_from < (right.valid_end ?? Number.POSITIVE_INFINITY) &&
            right.valid_from < (left.valid_end ?? Number.POSITIVE_INFINITY),
        ),
    ) ?? false;
  const download = (format: "json" | "csv") => {
    if (!result) return;
    const content =
      format === "json"
        ? JSON.stringify(result, null, 2)
        : [
            [
              "kind",
              "scope",
              "root",
              "client",
              "server",
              "peer",
              "port",
              "transport",
              "direction_basis",
              "source",
              "observer",
              "first",
              "last",
              "records",
              "connections_represented",
              "bytes_client_to_server",
              "bytes_server_to_client",
              "packets",
              "sampled",
              "tuple_history_capped",
              "counter_semantics",
              "configuration_fingerprint",
              "traffic_contract",
              "captured_at",
              "identity_status",
              "observation_status",
              "details",
            ],
            [
              "metadata",
              result.selection.scope,
              result.selection.address,
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              result.selection.start,
              result.selection.end,
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              result.selection.configurationFingerprint,
              result.selection.trafficContract,
              result.capturedAt,
              result.identityAvailable ? "available" : "unavailable",
              result.observationState,
              [
                result.warnings.join(" "),
                result.observationError ?? "",
                result.peerCapped ? "Peer list capped" : "",
                result.relationshipCapped
                  ? "Conversation relationships capped"
                  : "",
                result.observationCapped ? "Traffic observations capped" : "",
                result.identityHistoryCapped ? "Identity history capped" : "",
              ]
                .filter(Boolean)
                .join(" "),
            ],
            ...result.conversations.map((c) => [
              "conversation",
              c.scope,
              c.root,
              c.client,
              c.server,
              c.peer,
              c.port,
              c.transport,
              c.directionBasis,
              c.source,
              c.observer,
              c.first,
              c.last,
              c.records,
              c.conversations,
              c.bytesClientToServer,
              c.bytesServerToClient,
              c.packets,
              c.sampled,
              c.contextCapped,
              "",
              "",
              "",
              "",
              "",
              "",
            ]),
            ...result.observations.map((o) => [
              "non_authoritative_observation",
              o.scope,
              "",
              o.sourceIp,
              o.destinationIp,
              "",
              `${o.sourcePort}>${o.destinationPort}`,
              o.transport,
              "",
              o.source,
              o.observer,
              o.first,
              o.last,
              o.records,
              "",
              "",
              "",
              "",
              "",
              "",
              o.counterSemantics,
              "",
              "",
              "",
              "",
              "",
              result.observationError ?? "",
            ]),
            ...result.identityHistory.map((i) => [
              "identity_history",
              i.scope,
              i.ip,
              "",
              "",
              i.entity_id,
              "",
              i.entity_kind,
              "time-bounded",
              "identity",
              "",
              i.valid_from,
              i.valid_end ?? "open",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              "",
              result.identityHistoryCapped ? "history cap" : "",
            ]),
          ]
            .map((row) => csvRow(row))
            .join("\r\n");
    downloadBlob(
      `endpoint-investigation.${format}`,
      format === "json" ? "application/json" : "text/csv",
      content,
    );
  };
  const diagramPeers = result
    ? [
        ...new Set([
          ...result.conversations.map((c) => c.peer),
          ...result.observations.map((o) =>
            o.sourceIp === result.selection.address
              ? o.destinationIp
              : o.sourceIp,
          ),
        ]),
      ].slice(0, 20)
    : [];
  return (
    <main className="page endpoints-page">
      <header>
        <h1>Endpoint investigation</h1>
        <p>
          Inspect observed conversations for one scoped address and time window.
        </p>
      </header>
      {!live && (
        <p role="status">Endpoint investigations require live summary data.</p>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
      >
        <label>
          IP address
          <input
            aria-label="IP address"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            required
          />
        </label>
        <label>
          Verified routing scope
          <input
            aria-label="Verified routing scope"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            required
          />
        </label>
        <label>
          Start (local time)
          <input
            type="datetime-local"
            step="any"
            aria-label="Start time"
            value={start}
            onChange={(e) => {
              setStart(e.target.value);
              setStartEdited(true);
            }}
            required
          />
        </label>
        <label>
          End (local time)
          <input
            type="datetime-local"
            step="any"
            aria-label="End time"
            value={end}
            onChange={(e) => {
              setEnd(e.target.value);
              setEndEdited(true);
            }}
            required
          />
        </label>
        <button type="submit" disabled={!live || loading}>
          {loading ? "Searching…" : "Investigate"}
        </button>
        {loading && (
          <button type="button" onClick={() => controllerRef.current?.abort()}>
            Cancel search
          </button>
        )}
      </form>
      {error && <p role="alert">{error}</p>}
      {result && (
        <section aria-label="Endpoint results">
          <div aria-label="Endpoint result downloads">
            <button type="button" onClick={() => download("json")}>
              Download endpoint JSON
            </button>
            <button type="button" onClick={() => download("csv")}>
              Download endpoint CSV
            </button>
          </div>
          <p>
            One hop from <strong>{result.selection.address}</strong> in{" "}
            <strong>{result.selection.scope}</strong>. Captured{" "}
            {new Date(result.capturedAt * 1000).toISOString()}.
          </p>
          {result.warnings.map((warning, i) => (
            <p role="note" key={i}>
              {warning}
            </p>
          ))}
          {(result.peerCapped || result.relationshipCapped) && (
            <p role="status">
              {result.peerCapped
                ? "Peer list reached its 100 peer limit. "
                : ""}
              {result.relationshipCapped
                ? "Conversation relationships reached a result cap; this view may omit additional rows."
                : ""}
            </p>
          )}
          <p role="note">
            The diagram shows up to 20 peers; the table lists all returned
            conversation rows for up to 100 peers.
          </p>
          <p role="note">
            Directional byte and packet counters are shown per summary observer
            and are not combined across observers.
          </p>
          {!result.identityAvailable ? (
            <p role="status">
              Identity history is unavailable; this endpoint remains identified
              only by its scoped address.
            </p>
          ) : result.identityHistory.length ? (
            <section aria-label="Endpoint identity history">
              <h2>Identity history</h2>
              <p>
                {identityConflict
                  ? "Conflicting identity claims overlap in time; attribution is ambiguous."
                  : "These time-bounded records do not establish one owner for the full investigation window."}
              </p>
              {result.identityHistoryCapped && (
                <p role="status">Identity history is capped at 256 records.</p>
              )}
              {result.identityHistory.map((identity, i) => (
                <p key={`${identity.entity_id}:${identity.valid_from}:${i}`}>
                  {identity.entity_kind}: {identity.entity_id}, valid from{" "}
                  {new Date(identity.valid_from * 1000).toISOString()} to{" "}
                  {identity.valid_end === undefined
                    ? "open"
                    : new Date(identity.valid_end * 1000).toISOString()}
                </p>
              ))}
            </section>
          ) : (
            <p>
              No scoped identity history is available for this address and
              window.
            </p>
          )}
          <svg
            role="img"
            aria-label="One-hop conversation diagram"
            viewBox="0 0 640 240"
            className="endpoint-diagram"
          >
            <title>Root endpoint {result.selection.address}</title>
            {diagramPeers.map((peer, i) => {
              const conversationPeer = result.conversations.some(
                (c) => c.peer === peer,
              );
              const angle =
                (2 * Math.PI * i) / Math.max(1, diagramPeers.length);
              const x = 320 + Math.cos(angle) * 220,
                y = 120 + Math.sin(angle) * 82;
              return (
                <a
                  key={`${peer}:${i}`}
                  href={peerLink(peer)}
                  aria-label={`Investigate peer ${peer}`}
                >
                  <title>
                    {peer} —{" "}
                    {conversationPeer
                      ? "Conversation peer. Activate to start a new scoped investigation."
                      : "V2 source observation peer; not a conversation total. Activate to start a new scoped investigation."}
                  </title>
                  <g>
                    <line
                      x1="320"
                      y1="120"
                      x2={x}
                      y2={y}
                      strokeDasharray={conversationPeer ? undefined : "5 4"}
                    />
                    <circle cx={x} cy={y} r="28" />
                    <text x={x} y={y + 4} textAnchor="middle">
                      {fitText(peer, 48)}
                    </text>
                  </g>
                </a>
              );
            })}
            <circle cx="320" cy="120" r="38" />
            <text x="320" y="124" textAnchor="middle">
              {fitText(result.selection.address, 68)}
            </text>
          </svg>
          {result.observations.length > 0 && (
            <p role="note">
              Dashed diagram edges come from separate V2 source observations;
              they do not add conversation totals.
            </p>
          )}
          <div
            className="endpoint-table-scroll"
            role="region"
            aria-label="Observed one-hop conversations table"
            tabIndex={0}
          >
            <table>
              <caption>Observed one-hop conversations</caption>
              <thead>
                <tr>
                  <th>Peer</th>
                  <th>Observed client → server</th>
                  <th>Port / transport</th>
                  <th>Direction basis</th>
                  <th>Source</th>
                  <th>Observer</th>
                  <th>Records</th>
                  <th>Connections represented</th>
                  <th>Bytes client → server</th>
                  <th>Bytes server → client</th>
                  <th>Packets</th>
                  <th>Tuple history capped</th>
                  <th>Sampled</th>
                  <th>Navigate</th>
                </tr>
              </thead>
              <tbody>
                {result.conversations.map((c, i) => (
                  <tr key={`${c.peer}:${c.port ?? "no-port"}:${i}`}>
                    <td>
                      <a href={peerLink(c.peer)}>{c.peer}</a>
                    </td>
                    <td>
                      {c.client} → {c.server}
                    </td>
                    <td>
                      {c.port === undefined ? "—" : c.port} / {c.transport}
                    </td>
                    <td>{c.directionBasis}</td>
                    <td>{c.source}</td>
                    <td>{c.observer}</td>
                    <td>{c.records}</td>
                    <td>{c.conversations}</td>
                    <td>{c.bytesClientToServer ?? "Unknown"}</td>
                    <td>{c.bytesServerToClient ?? "Unknown"}</td>
                    <td>{c.packets ?? "Unknown"}</td>
                    <td>{c.contextCapped ? "Yes" : "No"}</td>
                    <td>
                      {c.sampled === undefined
                        ? "Unknown"
                        : c.sampled
                          ? "Yes"
                          : "No"}
                    </td>
                    <td>
                      <button type="button" onClick={() => nav(c.peer)}>
                        Investigate peer
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {result.conversations.length === 0 && (
            <p>
              No conversations were observed in this window. Optional DNS
              evidence may still be available.
            </p>
          )}
          {result.observations.length > 0 && (
            <section aria-label="Non-authoritative V2 traffic observations">
              <h2>Additional traffic observations (non-authoritative)</h2>
              <p>
                These source observations are separate from conversation totals
                and do not create extra conversation counts.
                {result.observationCapped
                  ? " The observation list reached its 100-row cap."
                  : ""}
              </p>
              <div
                className="endpoint-table-scroll"
                role="region"
                aria-label="Additional V2 traffic observations table"
                tabIndex={0}
              >
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Observer</th>
                      <th>Observed tuple</th>
                      <th>Peer navigation</th>
                      <th>Counter semantics</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.observations.map((o, i) => (
                      <tr key={`${o.source}:${o.observer}:${i}`}>
                        <td>{o.source}</td>
                        <td>{o.observer}</td>
                        <td>
                          {o.sourceIp}:{o.sourcePort} → {o.destinationIp}:
                          {o.destinationPort} / {o.transport}
                        </td>
                        <td>
                          <a
                            href={peerLink(
                              o.sourceIp === result.selection.address
                                ? o.destinationIp
                                : o.sourceIp,
                            )}
                          >
                            Investigate peer
                          </a>
                        </td>
                        <td>{o.counterSemantics}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {result.observationState === "unavailable" && (
            <p role="status">
              V2 traffic observations are unavailable
              {result.observationError
                ? `: ${result.observationError}`
                : "."}{" "}
              Conversation summaries remain available.
            </p>
          )}
          {renderEvidence?.(endpointEvidenceSelection(result))}
          <button type="button" onClick={() => history.back()}>
            Back
          </button>
          {typeof document !== "undefined" &&
            typeof location !== "undefined" &&
            (() => {
              const target = returnApplicationURL(
                document.referrer,
                location.origin,
                location.pathname,
              );
              return target ? <a href={target}>Return to application</a> : null;
            })()}
        </section>
      )}
    </main>
  );
}
