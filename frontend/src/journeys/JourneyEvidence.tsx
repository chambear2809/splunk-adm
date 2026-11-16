import { useState } from "react";
import type { NatObservation } from "../graph";
import type { EvidenceWindow } from "../data/evidence";
import type { ProxyObservation } from "../data/proxyEvidence";
import type { JourneyResult } from "./model";
import "./journeys.css";

const when = (seconds: number) => new Date(seconds * 1000).toISOString();
const endpoint = (value?: { ip: string; port?: number }) =>
  value
    ? `${value.ip.includes(":") ? `[${value.ip}]` : value.ip}${value.port === undefined ? " (port not reported)" : `:${value.port}`}`
    : "Not reported";

export function JourneyDownload({
  evidence,
  disabled = false,
}: {
  evidence: object;
  disabled?: boolean;
}) {
  const signature = JSON.stringify(evidence);
  const [consent, setConsent] = useState<string>();
  const include = consent === signature;
  const [status, setStatus] = useState("");
  const download = () => {
    if (!include || disabled) return;
    let url: string | undefined;
    try {
      const json = JSON.stringify(
        {
          format: "application-atlas-journeys",
          version: 1,
          capturedAt: new Date().toISOString(),
          ...evidence,
        },
        null,
        2,
      );
      if (new TextEncoder().encode(json).length > 8 * 1024 * 1024)
        throw new Error("Journey evidence exceeds the 8 MiB export limit.");
      url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "atlas-journey-evidence-v1.json";
      link.click();
      setStatus(
        "Evidence download requested. Recipient access is not granted by this file.",
      );
    } catch (reason) {
      setStatus(
        reason instanceof Error ? reason.message : "Evidence download failed.",
      );
    } finally {
      if (url) {
        const value = url;
        setTimeout(() => URL.revokeObjectURL(value), 1000);
      }
    }
  };
  return (
    <details className="atlas-journey-download">
      <summary>Download journey evidence</summary>
      <p>
        The file includes only the records shown in this section, their source
        evidence, scope, times and limitations.
      </p>
      <label>
        <input
          type="checkbox"
          checked={include}
          onChange={(event) =>
            setConsent(event.target.checked ? signature : undefined)
          }
        />{" "}
        Include source evidence containing addresses and identities.
      </label>
      <button
        type="button"
        className="secondary-button"
        disabled={!include || disabled}
        onClick={download}
      >
        Download journey evidence
      </button>
      {status && <p role="status">{status}</p>}
    </details>
  );
}

/** Every card is one source event, never a route assembled by matching addresses. */
export function JourneyEvidence({
  title,
  result,
  window,
}: {
  title: string;
  result: JourneyResult;
  window?: EvidenceWindow;
}) {
  if (!result.journeys.length && !result.gaps.length) return null;
  const specificGaps = result.gaps.filter(
    (gap) => !gap.startsWith("Proxy association is unknown:"),
  );
  const visibleGaps = specificGaps.length ? specificGaps : result.gaps;
  return (
    <section className="atlas-journeys" aria-label={title}>
      <h3>
        {title} <span className="count">{result.journeys.length}</span>
      </h3>
      <p>
        Each card retains one source event. Separate cards are not connected
        paths, and missing observations do not prove missing traffic.
      </p>
      {[...new Set(visibleGaps)].map((gap) => (
        <p className="callout warn" key={gap}>
          {gap}
        </p>
      ))}
      {result.journeys.map((journey, i) => {
        const nat =
          journey.source === "cisco:sfw:estreamer"
            ? (journey.evidence as NatObservation)
            : undefined;
        const proxy =
          journey.source === "proxy_envoy"
            ? (journey.evidence as ProxyObservation)
            : undefined;
        const proof =
          journey.relation === "same_event"
            ? "Same firewall event"
            : journey.relation === "request_reported"
              ? "Same request event"
              : "Association unavailable";
        return (
          <article
            className="atlas-journey"
            key={`${journey.source}:${journey.observer}:${journey.fingerprint}:${i}`}
          >
            <h4>
              {nat ? "Firewall translation" : "Proxy request"} · {proof}
            </h4>
            <p>{when(journey.nativeTime)}</p>
            {nat && (
              <p>
                Reported and translated tuples are two representations in one
                event; they are not additional packet hops.
              </p>
            )}
            <ol className="atlas-journey-legs">
              {journey.legs.map((leg) => (
                <li key={leg.kind}>
                  <strong>
                    {leg.kind === "reported"
                      ? "Reported tuple"
                      : leg.kind === "translated"
                        ? "NAT translated tuple"
                        : leg.kind === "downstream"
                          ? "Direct peer → Listener"
                          : "Upstream local → Selected upstream"}
                  </strong>
                  <div>
                    {endpoint(leg.from)} → {endpoint(leg.to)}
                  </div>
                  {leg.protocol && (
                    <small>
                      {leg.protocol.toUpperCase()} · Initiator → Responder
                    </small>
                  )}
                </li>
              ))}
            </ol>
            {proxy && (
              <p>
                HTTP {proxy.responseCode ?? "status not reported"} ·{" "}
                {proxy.durationMilliseconds === undefined
                  ? "Duration not reported"
                  : `${proxy.durationMilliseconds} ms`}
                .
              </p>
            )}
            {[...new Set(journey.gaps)].map((gap) => (
              <p className="callout warn" key={gap}>
                {gap}
              </p>
            ))}
            <details>
              <summary>Source details</summary>
              <dl>
                <dt>Source</dt>
                <dd>{journey.source}</dd>
                <dt>Scope</dt>
                <dd>{journey.scope}</dd>
                <dt>Observer</dt>
                <dd>{journey.observer}</dd>
                <dt>Native event time</dt>
                <dd>{when(journey.nativeTime)}</dd>
                <dt>{nat ? "Received time" : "Indexed time"}</dt>
                <dd>{when(journey.indexedTime)}</dd>
                <dt>Selected window</dt>
                <dd>
                  {window
                    ? `${when(window.start)} – ${when(window.end)}`
                    : "Unavailable"}
                </dd>
                <dt>Event fingerprint</dt>
                <dd>{journey.fingerprint}</dd>
                {nat?.reported_original_initiator_ip && (
                  <>
                    <dt>Reported OriginalInitiatorIP (separate field)</dt>
                    <dd>{nat.reported_original_initiator_ip}</dd>
                  </>
                )}
                {proxy && (
                  <>
                    <dt>Index</dt>
                    <dd>{proxy.index}</dd>
                    <dt>Stream ID (reference only)</dt>
                    <dd>{proxy.streamId ?? "Not reported"}</dd>
                    <dt>Upstream attempts</dt>
                    <dd>{proxy.upstreamAttemptCount ?? "Not reported"}</dd>
                    <dt>Upstream cluster (routing context)</dt>
                    <dd>{proxy.upstream?.cluster ?? "Not reported"}</dd>
                  </>
                )}
              </dl>
              {!!journey.limitations?.length && (
                <>
                  <h5>Source limitations</h5>
                  <ul>
                    {journey.limitations.map((limitation) => (
                      <li key={limitation}>{limitation}</li>
                    ))}
                  </ul>
                </>
              )}
              {journey.conflictingEvidence && (
                <details>
                  <summary>
                    Conflicting source records (
                    {journey.conflictingEvidence.length})
                  </summary>
                  <p>
                    These versions share a source record identity but disagree.
                    No version establishes an association.
                  </p>
                  {journey.conflictingEvidence.map((variant, variantIndex) => (
                    <pre key={variantIndex}>
                      {JSON.stringify(variant, null, 2)}
                    </pre>
                  ))}
                </details>
              )}
            </details>
          </article>
        );
      })}
      <JourneyDownload
        disabled={!result.journeys.length}
        evidence={{
          selectedWindow: window,
          ...result,
          limitation:
            "Source events are not a correlated cross-source route. No packet order or recipient access is established.",
        }}
      />
    </section>
  );
}
