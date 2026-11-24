import { useEffect, useRef, useState } from "react";
import type { SearchClient } from "../data/searchClient";
import type {
  MulticastConfiguration,
  MulticastEvidence,
  MulticastResult,
} from "./contract";
import { multicastLink, parseMulticastLink, validateRequest } from "./inputs";
import {
  investigateMulticast,
  MulticastConfigurationChangedError,
  readMulticastConfiguration,
} from "./investigation";
import { ForwardingTree } from "./ForwardingTree";
import "./multicast.css";

interface Props {
  client?: SearchClient;
  live: boolean;
  timezone?: string;
  initialParams?: URLSearchParams;
}

type ConfigurationState =
  | { status: "loading" }
  | { status: "ready"; value: MulticastConfiguration }
  | { status: "error"; message: string };
type InvestigationState =
  | { status: "idle" | "loading" | "cancelled" | "stale" }
  | { status: "error"; message: string }
  | { status: "done"; value: MulticastResult };

const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The investigation could not be completed.";
export const utcInput = (seconds: number) =>
  new Date(seconds * 1000).toISOString().slice(0, 19);
export const utcSeconds = (value: string) => Date.parse(`${value}Z`) / 1000;
const formatTime = (seconds: number, timezone?: string) => {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium",
      timeZone: timezone,
    }).format(new Date(seconds * 1000));
  } catch {
    return new Date(seconds * 1000).toISOString();
  }
};

const sourceLabel = {
  multicast_igmp: "Stream IGMP",
  multicast_netflow: "Stream NetFlow",
  multicast_nxos: "NX-OS forwarding snapshots",
  device_state: "Device forwarding state",
} as const;

function EvidenceDetails({
  evidence,
  timezone,
}: {
  evidence: MulticastEvidence;
  timezone?: string;
}) {
  return (
    <>
      <strong>
        {evidence.kind === "igmp"
          ? `IGMP ${evidence.operation}`
          : evidence.kind === "flow"
            ? "Multicast flow"
            : "Forwarding state"}
      </strong>
      {evidence.kind === "igmp" && (
        <div>
          Reporter: {evidence.reporter ?? "unknown"} ({evidence.reporterKind});
          sources: {evidence.sources.join(", ") || "none reported"}
        </div>
      )}
      {evidence.kind === "flow" && (
        <div>
          Sender: {evidence.sender}; {evidence.direction}; domain{" "}
          {evidence.observationDomain}, template {evidence.template}; sampling
          1:{evidence.samplingInterval}; replication {evidence.replication};
          counters {evidence.counters}
          {evidence.packets !== undefined
            ? `; ${evidence.packets} packets`
            : ""}
          {evidence.bytes !== undefined ? `; ${evidence.bytes} bytes` : ""}
        </div>
      )}
      {evidence.kind === "forwarding" && (
        <div>
          Input: {evidence.input ?? "unknown"}; outputs:{" "}
          {evidence.outputs.join(", ") || "none"}; valid until{" "}
          {formatTime(evidence.validUntil, timezone)}
        </div>
      )}
      <div>
        Source: {sourceLabel[evidence.source]}; observer: {evidence.observer};
        interface: {evidence.interface ?? "unknown"}; observed:{" "}
        {formatTime(evidence.timestamp, timezone)}
      </div>
      {evidence.segment && (
        <div>
          Segment: {evidence.segment.kind} {evidence.segment.id} (domain{" "}
          {evidence.segment.domain})
        </div>
      )}
      <div>
        Limits:{" "}
        {evidence.limits.length ? evidence.limits.join("; ") : "None recorded"}
      </div>
    </>
  );
}

export function MulticastResults({
  result,
  timezone,
}: {
  result: MulticastResult;
  timezone?: string;
}) {
  const [selected, setSelected] = useState<string | undefined>();
  const chosen = result.evidence.find((item) => item.id === selected);
  const receiverSegments = new Map<string, typeof result.receivers>();
  for (const receiver of result.receivers) {
    const { domain, kind, id } = receiver.segment;
    const key = JSON.stringify([domain, kind, id]);
    const segment = receiverSegments.get(key);
    if (segment) segment.push(receiver);
    else receiverSegments.set(key, [receiver]);
  }
  return (
    <section className="multicast-results" aria-label="Investigation results">
      <div className="multicast-summary">
        <div>
          <h2>Observed multicast evidence</h2>
          <p>
            {result.evidence.length === 0 &&
              `${result.request.group} · ${result.request.scope} · `}
            {formatTime(result.request.earliest, timezone)} –{" "}
            {formatTime(result.request.latest, timezone)}
          </p>
        </div>
        <p>Captured {formatTime(result.capturedAt, timezone)}</p>
      </div>
      {result.outcomes.some((item) => item.state !== "complete") && (
        <p className="multicast-notice" role="status">
          Coverage is incomplete. Missing evidence cannot establish that a
          sender, receiver, or path is absent.
        </p>
      )}
      {result.capped && (
        <p className="multicast-notice" role="status">
          Evidence was capped. Narrow the time window or scope to investigate
          further.
        </p>
      )}
      {result.evidence.length === 0 ? (
        <p>
          No evidence was returned for this selection. Check source coverage
          before drawing conclusions.
        </p>
      ) : (
        <>
          <div className="multicast-map-board">
            <header className="multicast-map-heading">
              <div>
                <h3>Multicast tree</h3>
                <p>
                  Group <strong>{result.request.group}</strong> ·{" "}
                  {result.request.scope}
                </p>
              </div>
              {result.branches.some(
                (branch) => branch.state === "supported",
              ) && (
                <span>Solid tree links show supported device branches.</span>
              )}
            </header>
            <div
              className="multicast-map"
              role="group"
              aria-label="Observed evidence map"
            >
              <section>
                <h4>Senders</h4>
                {result.senders.length ? (
                  result.senders.map((sender) => (
                    <button
                      key={sender.address}
                      type="button"
                      aria-label={sender.address}
                      onClick={() => setSelected(sender.evidenceIds[0])}
                    >
                      <strong>{sender.address}</strong>
                      <small>
                        {sender.evidenceIds.length} flow{" "}
                        {sender.evidenceIds.length === 1
                          ? "observation"
                          : "observations"}
                      </small>
                    </button>
                  ))
                ) : (
                  <p>None observed</p>
                )}
              </section>
              <section>
                <h4>Forwarding branches</h4>
                <ForwardingTree result={result} inspect={setSelected} />
              </section>
              <section>
                <h4>Receiver interest</h4>
                {receiverSegments.size ? (
                  [...receiverSegments].map(([key, receivers]) => {
                    const { kind, id, domain } = receivers[0].segment;
                    return (
                      <div className="multicast-segment" key={key}>
                        <h5>
                          {kind.toUpperCase()} {id} <span>· {domain}</span>
                        </h5>
                        {receivers.map((receiver) => (
                          <button
                            key={receiver.evidenceId}
                            type="button"
                            onClick={() => setSelected(receiver.evidenceId)}
                          >
                            <strong>{receiver.reporter}</strong>
                            <small>
                              {receiver.state === "observed"
                                ? "Interest observed"
                                : "Interest uncertain"}
                            </small>
                          </button>
                        ))}
                      </div>
                    );
                  })
                ) : (
                  <p>None observed</p>
                )}
              </section>
            </div>
            <p className="multicast-map-note">
              Sender traffic and receiver interest are separate observations.
              Delivery remains unverified.
            </p>
          </div>
          {chosen && (
            <aside className="multicast-selected" aria-live="polite">
              <button
                type="button"
                onClick={() => setSelected(undefined)}
                aria-label="Close selected evidence"
              >
                ×
              </button>
              <EvidenceDetails evidence={chosen} timezone={timezone} />
            </aside>
          )}
          <h3>Evidence records</h3>
          <div className="multicast-table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Evidence</th>
                  <th scope="col">Details and limitations</th>
                </tr>
              </thead>
              <tbody>
                {result.evidence.map((item, index) => (
                  <tr key={item.id}>
                    <td>
                      <button
                        type="button"
                        onClick={() => setSelected(item.id)}
                        aria-label={`Inspect evidence record ${index + 1}`}
                      >
                        Inspect
                      </button>
                    </td>
                    <td>
                      <EvidenceDetails evidence={item} timezone={timezone} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <details open>
        <summary>Coverage and source status</summary>
        <ul>
          {result.outcomes.map((item, index) => (
            <li key={`${item.source}-${item.profile ?? ""}-${index}`}>
              <strong>
                {sourceLabel[item.source]}
                {item.profile ? ` / ${item.profile}` : ""}: {item.state}
              </strong>
              {item.detail ? ` — ${item.detail}` : ""}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}

export function MulticastPage({
  client,
  live,
  timezone,
  initialParams,
}: Props) {
  const [initial] = useState(() => {
    try {
      return {
        request: parseMulticastLink(
          initialParams ??
            new URLSearchParams(
              typeof window === "undefined" ? "" : window.location.search,
            ),
        ),
      };
    } catch (error) {
      return { error: message(error) };
    }
  });
  const now = Math.floor(Date.now() / 1000);
  const [scope, setScope] = useState(initial.request?.scope ?? "");
  const [group, setGroup] = useState(initial.request?.group ?? "");
  const [sender, setSender] = useState(initial.request?.sender ?? "");
  const [earliest, setEarliest] = useState(
    utcInput(initial.request?.earliest ?? now - 900),
  );
  const [latest, setLatest] = useState(
    utcInput(initial.request?.latest ?? now),
  );
  const [configuration, setConfiguration] = useState<ConfigurationState>({
    status: "loading",
  });
  const [investigation, setInvestigation] = useState<InvestigationState>({
    status: "idle",
  });
  const [error, setError] = useState(initial.error ?? "");
  const active = useRef<AbortController>();
  const [configurationRevision, setConfigurationRevision] = useState(0);
  const [revision, setRevision] = useState(0);
  const [resultRevision, setResultRevision] = useState(0);
  useEffect(() => {
    if (!live) return;
    const controller = new AbortController();
    readMulticastConfiguration(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted)
          setConfiguration({ status: "ready", value });
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted)
          setConfiguration({ status: "error", message: message(err) });
      });
    return () => controller.abort();
  }, [live, configurationRevision]);
  useEffect(() => () => active.current?.abort(), []);
  const scopes =
    configuration.status === "ready"
      ? [
          ...new Set(
            configuration.value.profiles.map((profile) => profile.scope),
          ),
        ].sort()
      : [];
  const edit = (setter: (value: string) => void, value: string) => {
    active.current?.abort();
    active.current = undefined;
    setInvestigation((current) =>
      current.status === "loading" ? { status: "cancelled" } : current,
    );
    setter(value);
    setRevision((current) => current + 1);
  };
  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!client || configuration.status !== "ready") return;
    try {
      const request = validateRequest({
        version: 1,
        scope,
        group,
        ...(sender.trim() ? { sender: sender.trim() } : {}),
        earliest: utcSeconds(earliest),
        latest: utcSeconds(latest),
      });
      if (!scopes.includes(request.scope))
        throw new Error("Choose a scope with a verified multicast profile.");
      active.current?.abort();
      const controller = new AbortController();
      active.current = controller;
      setError("");
      setInvestigation({ status: "loading" });
      setResultRevision(revision);
      const params = multicastLink(request);
      const mode = (
        initialParams ?? new URLSearchParams(window.location.search)
      ).get("mode");
      if (mode) params.set("mode", mode);
      window.history.replaceState(
        window.history.state,
        "",
        `${window.location.pathname}?${params.toString()}${window.location.hash}`,
      );
      try {
        const value = await investigateMulticast(
          client,
          request,
          configuration.value,
          controller.signal,
        );
        if (!controller.signal.aborted)
          setInvestigation({ status: "done", value });
      } catch (err) {
        if (!controller.signal.aborted)
          setInvestigation(
            err instanceof MulticastConfigurationChangedError
              ? { status: "stale" }
              : { status: "error", message: message(err) },
          );
      }
    } catch (err) {
      setError(message(err));
    }
  };
  const refreshSources = () => {
    setConfiguration({ status: "loading" });
    setInvestigation({ status: "idle" });
    setConfigurationRevision((current) => current + 1);
  };
  const cancel = () => {
    active.current?.abort();
    setInvestigation({ status: "cancelled" });
  };
  return (
    <main className="multicast-page">
      <header>
        <h1>Multicast</h1>
        <p>
          Find multicast senders, receiver interest, and gaps in forwarding
          visibility.
        </p>
      </header>
      {!live || !client ? (
        <p className="multicast-notice">
          Multicast investigation is available with a live Splunk connection.
        </p>
      ) : configuration.status === "loading" ? (
        <p role="status">Loading verified multicast profiles…</p>
      ) : configuration.status === "error" ? (
        <div role="alert">
          <p>Multicast configuration unavailable: {configuration.message}</p>
          <button type="button" onClick={refreshSources}>
            Refresh sources
          </button>
        </div>
      ) : configuration.value.profiles.length === 0 ? (
        <div className="multicast-notice">
          <p>
            Setup required: ask an administrator to configure verified Stream
            IGMP, NetFlow, or NX-OS forwarding profiles before investigating.
          </p>
          <button type="button" onClick={refreshSources}>
            Refresh sources
          </button>
        </div>
      ) : (
        <>
          <form onSubmit={run} className="multicast-form">
            <label>
              Scope
              <select
                value={scope}
                onChange={(event) => edit(setScope, event.target.value)}
                required
              >
                <option value="">Select a scope</option>
                {scopes.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Multicast group
              <input
                value={group}
                onChange={(event) => edit(setGroup, event.target.value)}
                placeholder="239.1.2.3"
                required
              />
            </label>
            <label>
              Sender (optional)
              <input
                value={sender}
                onChange={(event) => edit(setSender, event.target.value)}
                placeholder="192.0.2.1"
              />
            </label>
            <label>
              From (UTC)
              <input
                type="datetime-local"
                step="1"
                value={earliest}
                onChange={(event) => edit(setEarliest, event.target.value)}
                required
              />
            </label>
            <label>
              To (UTC)
              <input
                type="datetime-local"
                step="1"
                value={latest}
                onChange={(event) => edit(setLatest, event.target.value)}
                required
              />
            </label>
            <div className="multicast-actions">
              <button
                type="submit"
                disabled={
                  investigation.status === "loading" ||
                  investigation.status === "stale"
                }
              >
                Investigate
              </button>
              {investigation.status === "loading" && (
                <button type="button" onClick={cancel}>
                  Cancel
                </button>
              )}
            </div>
          </form>
          <p>Times are entered in UTC. Maximum window: one hour.</p>
          {error && <p role="alert">{error}</p>}
          {investigation.status === "loading" && (
            <p role="status">Investigating multicast evidence…</p>
          )}
          {investigation.status === "cancelled" && (
            <p role="status">
              Investigation cancelled. Run it again for the current selection.
            </p>
          )}
          {investigation.status === "stale" && (
            <div className="multicast-notice" role="alert">
              Source verification changed during the investigation. Refresh
              sources and investigate again.
              <button type="button" onClick={refreshSources}>
                Refresh sources
              </button>
            </div>
          )}
          {investigation.status === "error" && (
            <p role="alert">
              Investigation unavailable: {investigation.message}
            </p>
          )}
          {investigation.status === "done" && (
            <>
              {(revision !== resultRevision ||
                investigation.value.configurationFingerprint !==
                  configuration.value.fingerprint) && (
                <p className="multicast-notice" role="status">
                  These results are stale for the current selection or
                  configuration. Run the investigation again.
                </p>
              )}
              <MulticastResults
                result={investigation.value}
                timezone={timezone}
              />
            </>
          )}
        </>
      )}
    </main>
  );
}
