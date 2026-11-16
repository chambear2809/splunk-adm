import { useEffect, useRef, useState } from "react";
import { JourneyLazyEvidence } from "./JourneyLazyEvidence";
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

export function ProxyEvidencePanel({
  result,
}: {
  result: SupplementalResult<ProxyObservation>;
}) {
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
        One Envoy DownstreamEnd request record per card. Direct peer is the
        adjacent transport peer.
      </p>
      <p role="status">{status}</p>
      {result.state === "complete" && (
        <JourneyLazyEvidence kind="proxy" result={result} />
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
