import { useEffect, useRef, useState } from "react";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import {
  PROXY_COVERAGE,
  buildProxySearch,
  normalizeProxyEvidence,
  proxySearchWindow,
  type ProxyObservation,
} from "./data/proxyEvidence";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "./data/supplementalEvidence";
import type { EvidenceSelection } from "./data/evidence";
import type { SearchClient } from "./data/searchClient";

function addressText(address?: { ip: string; port?: number }): string {
  if (!address) return "Not supplied";
  const ip = address.ip.includes(":") ? `[${address.ip}]` : address.ip;
  return address.port === undefined ? ip : `${ip}:${address.port}`;
}

function safeTime(value: number): string {
  try {
    return new Date(value * 1000).toISOString();
  } catch {
    return "Invalid source time";
  }
}

export function ProxyEvidencePanel({
  result,
}: {
  result: SupplementalResult<ProxyObservation>;
}) {
  const qualified =
    result.state === "complete" &&
    result.schemaQualified &&
    !result.configurationChanged &&
    !result.inputCapped;
  const status =
    result.state === "complete"
      ? `${result.records.length} Envoy request observations returned${result.outputCapped ? "; output capped" : ""}${result.inputCapped ? "; input capped, any association is suppressed" : ""}${result.configurationChanged ? "; configuration changed, any association is suppressed" : ""}${!result.schemaQualified ? "; source schema is not qualified" : ""}.`
      : result.state === "not_selected"
        ? "Proxy evidence is off. An administrator must select and qualify an Envoy source before a search can run."
        : result.state === "staged"
          ? "The Envoy source is staged and was not searched."
          : result.state === "unavailable" && !result.schemaQualified
            ? "The Envoy source is not schema-qualified and was not searched."
            : (result.error ??
              "Proxy evidence is unavailable. Check source configuration, permissions and search completion.");
  return (
    <section
      className="dns-evidence proxy-evidence"
      aria-label="Optional Envoy proxy evidence"
    >
      <h3>Proxy evidence</h3>
      <p>
        One source-qualified Envoy HTTP request event per DownstreamEnd log. The
        direct peer and selected upstream are separate transport legs; this view
        does not identify an original client through X-Forwarded-For.
      </p>
      <p role="status">{status}</p>
      {result.state === "complete" && result.records.length > 0 && (
        <>
          {!qualified && (
            <p>
              These rows are source context only. A verified observer mapping,
              qualified schema and complete bounded input are required before
              using any row to support an association.
            </p>
          )}
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Request start</th>
                  <th scope="col">Downstream direct peer</th>
                  <th scope="col">Envoy listener</th>
                  <th scope="col">Selected upstream</th>
                  <th scope="col">Cluster</th>
                  <th scope="col">Duration (ms)</th>
                  <th scope="col">HTTP status</th>
                  <th scope="col">Observer</th>
                  <th scope="col">Stream ID</th>
                </tr>
              </thead>
              <tbody>
                {result.records.map((record) => (
                  <tr key={`${record.index}:${record.eventFingerprint}`}>
                    <td>{safeTime(record.eventTime)}</td>
                    <td>{addressText(record.downstream.directPeer)}</td>
                    <td>{addressText(record.downstream.listener)}</td>
                    <td>{addressText(record.selectedBackend)}</td>
                    <td>{record.upstream?.cluster ?? "Not supplied"}</td>
                    <td>{record.durationMilliseconds ?? "Not supplied"}</td>
                    <td>{record.responseCode ?? "Not supplied"}</td>
                    <td>{record.observer}</td>
                    <td>{record.streamId ?? "Not supplied"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            The selected upstream address is Envoy's reported remote endpoint. A
            cluster name describes configured routing, not backend membership;
            retries do not expose every attempted endpoint here.
          </p>
        </>
      )}
      <details>
        <summary>Coverage and limits</summary>
        <ul>
          {PROXY_COVERAGE.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}

/** User-triggered wrapper; it never starts an optional search on mount. */
export function ProxyEvidenceInspection({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<SupplementalResult<ProxyObservation>>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const active = useRef<AbortController>();
  const activeRequest = useRef<symbol>();
  const selectionKey = JSON.stringify(selection);

  useEffect(() => {
    activeRequest.current = undefined;
    active.current?.abort();
    active.current = undefined;
    setResult(undefined);
    setError(undefined);
    setBusy(false);
    return () => {
      activeRequest.current = undefined;
      active.current?.abort();
    };
  }, [selectionKey, client, configurationClient]);

  const inspect = async () => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const requestId = Symbol();
    activeRequest.current = requestId;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await loadSupplementalEvidence(
        client,
        selection,
        controller.signal,
        "proxy_envoy",
        buildProxySearch,
        normalizeProxyEvidence,
        configurationClient,
        false,
        proxySearchWindow,
        PROXY_COVERAGE,
      );
      if (requestId === activeRequest.current && !controller.signal.aborted)
        setResult(next);
    } catch {
      if (requestId === activeRequest.current)
        setError(
          controller.signal.aborted
            ? "Search cancelled. Native cleanup may remain pending."
            : "Proxy evidence unavailable. Refresh the selection or check the selected Envoy source configuration and permissions.",
        );
    } finally {
      if (requestId === activeRequest.current) setBusy(false);
    }
  };

  return (
    <div className="proxy-evidence-inspection">
      {result ? (
        <ProxyEvidencePanel result={result} />
      ) : (
        <section
          className="dns-evidence proxy-evidence"
          aria-label="Optional Envoy proxy evidence"
        >
          <h3>Proxy evidence</h3>
          <p>
            Inspect bounded Envoy HTTP request observations for the selected
            endpoint. The source remains off unless an administrator has
            selected and qualified it.
          </p>
          <button type="button" onClick={() => void inspect()} disabled={busy}>
            {busy ? "Searching proxy logs…" : "Inspect proxy evidence"}
          </button>
          {busy && (
            <button type="button" onClick={() => active.current?.abort()}>
              Cancel proxy search
            </button>
          )}
          <p role="status">
            {busy
              ? "Loading optional Envoy evidence…"
              : (error ??
                "No proxy search has run. An administrator must select and qualify this source first.")}
          </p>
        </section>
      )}
      {result && (
        <button type="button" onClick={() => void inspect()} disabled={busy}>
          {busy ? "Searching proxy logs…" : "Refresh proxy evidence"}
        </button>
      )}
      {busy && result && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel proxy search
        </button>
      )}
      {error && result && <p role="status">{error}</p>}
    </div>
  );
}
