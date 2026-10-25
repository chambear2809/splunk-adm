import { useEffect, useRef, useState } from "react";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import {
  APPDYNAMICS_COVERAGE,
  loadAppDynamicsEvidence,
  type AppDynamicsBackendCandidate,
  type AppDynamicsEvidenceResult,
  type AppDynamicsInventoryContext,
} from "./data/appdynamicsEvidence";
import type { EvidenceSelection } from "./data/evidence";
import type { SearchClient } from "./data/searchClient";

function safeTime(value: number): string {
  try {
    return new Date(value * 1000).toISOString();
  } catch {
    return "Invalid source time";
  }
}

function backendAssociation(backend: AppDynamicsBackendCandidate): string {
  if (backend.associatedWithMatchedNode)
    return "Controller IDs match this selected node in the same snapshot";
  if (backend.associationStatus === "application_scope_only")
    return "Application-scoped; no verified node association";
  if (backend.associationStatus === "unverified_reported_ids")
    return "Reported association IDs are unverified";
  return "Controller-reported node association; selected node differs";
}

function contextStatus(result: AppDynamicsEvidenceResult): string {
  if (result.state === "complete") {
    const cap = result.outputCapped
      ? "; the focused result cap was reached, so associations are suppressed"
      : "";
    const rejected = result.rejected
      ? `; ${result.rejected} malformed or conflicting rows were rejected`
      : "";
    const schema = result.schemaQualified ? "" : "; schema is not qualified";
    const changed = result.configurationChanged
      ? "; configuration changed during the search"
      : "";
    return `${result.records.length} complete Controller snapshot context record(s) returned${cap}${rejected}${schema}${changed}.`;
  }
  if (result.state === "not_selected")
    return "AppDynamics evidence is off. An administrator must select and qualify an AppDynamics Controller source before searching.";
  if (result.state === "staged")
    return "The AppDynamics source is staged and was not searched.";
  if (result.state === "unavailable" && !result.schemaQualified)
    return "The AppDynamics source is not schema-qualified and was not searched.";
  return (
    result.error ??
    "AppDynamics evidence is unavailable. Check source configuration, permissions and search completion."
  );
}

export function AppDynamicsEvidencePanel({
  result,
}: {
  result: AppDynamicsEvidenceResult;
}) {
  const useRelations =
    result.state === "complete" &&
    result.schemaQualified &&
    !result.configurationChanged &&
    !result.inputCapped &&
    !result.outputCapped &&
    result.rejected === 0;
  return (
    <section
      className="dns-evidence appdynamics-evidence"
      aria-label="Optional AppDynamics Controller inventory evidence"
    >
      <h3>AppDynamics inventory evidence</h3>
      <p>
        Current Controller application model context for nodes whose reported IP
        addresses exactly match the selected endpoint. It is not traffic or
        historical address ownership evidence.
      </p>
      <p role="status">{contextStatus(result)}</p>
      {result.state === "complete" && result.records.length > 0 && (
        <>
          {!useRelations && (
            <p>
              These rows are source context only. The bounded scan, focused
              result, schema, configuration and row validation must all be
              complete before interpreting any relationship.
            </p>
          )}
          {result.records.map((context) => (
            <SnapshotContext
              key={`${context.authority}:${context.snapshotId}`}
              context={context}
              showRelations={useRelations}
            />
          ))}
        </>
      )}
      <details>
        <summary>Coverage and limits</summary>
        <ul>
          {APPDYNAMICS_COVERAGE.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}

function SnapshotContext({
  context,
  showRelations,
}: {
  context: AppDynamicsInventoryContext;
  showRelations: boolean;
}) {
  const matchedNodes = showRelations ? context.nodes : [];
  const backends = showRelations ? context.backends : [];
  return (
    <article className="appdynamics-snapshot" aria-label="AppDynamics snapshot">
      <h4>Controller {context.authority}</h4>
      <dl>
        <dt>Scope</dt>
        <dd>{context.scope}</dd>
        <dt>Snapshot ID</dt>
        <dd>{context.snapshotId}</dd>
        <dt>Observed</dt>
        <dd>{safeTime(context.snapshotAt)}</dd>
        <dt>Collection interval</dt>
        <dd>
          {safeTime(context.collectionStartedAt)} to{" "}
          {safeTime(context.collectionCompletedAt)}
        </dd>
        <dt>Collection skew</dt>
        <dd>{context.collectionSkewSeconds.toFixed(3)} seconds</dd>
        <dt>Records verified</dt>
        <dd>
          {context.indexedRecordCount} of {context.expectedRecordCount}
        </dd>
      </dl>
      {context.controllerOrigin && (
        <p>
          <a href={context.controllerOrigin} target="_blank" rel="noreferrer">
            Open configured AppDynamics Controller
          </a>
          <span> — use the IDs below to locate the objects in its UI.</span>
        </p>
      )}
      {showRelations && matchedNodes.length > 0 ? (
        <>
          <h5>Nodes matching selected endpoint</h5>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Application</th>
                  <th scope="col">Tier</th>
                  <th scope="col">Node</th>
                  <th scope="col">Reported IPs</th>
                  <th scope="col">Selected IP match</th>
                </tr>
              </thead>
              <tbody>
                {matchedNodes.map((node) => (
                  <tr
                    key={`${node.applicationId}:${node.tierId}:${node.nodeId}`}
                  >
                    <td>
                      {node.applicationName} (ID {node.applicationId})
                    </td>
                    <td>
                      {node.tierName} (ID {node.tierId})
                    </td>
                    <td>
                      {node.nodeName} (ID {node.nodeId})
                      {node.machineName ? `; machine ${node.machineName}` : ""}
                    </td>
                    <td>{node.addresses.join(", ") || "No matchable IPs"}</td>
                    <td>{node.matchedAddresses.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : showRelations ? (
        <p>
          No current node IP in this snapshot exactly matches the selected
          endpoint.
        </p>
      ) : null}
      {showRelations && backends.length > 0 && (
        <>
          <h5>Backend inventory candidates</h5>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Application</th>
                  <th scope="col">Backend</th>
                  <th scope="col">Controller association</th>
                  <th scope="col">Endpoint candidates</th>
                </tr>
              </thead>
              <tbody>
                {backends.map((backend) => (
                  <tr key={`${backend.applicationId}:${backend.backendId}`}>
                    <td>
                      {backend.applicationName} (ID {backend.applicationId})
                    </td>
                    <td>
                      {backend.name} (ID {backend.backendId})
                      {backend.exitPointType
                        ? `; ${backend.exitPointType}`
                        : ""}
                    </td>
                    <td>
                      {backendAssociation(backend)}
                      {backend.tierId || backend.nodeId
                        ? ` (reported tier ${backend.tierId ?? "unknown"}, node ${backend.nodeId ?? "unknown"})`
                        : ""}
                    </td>
                    <td>
                      {backend.endpointCandidates.length
                        ? backend.endpointCandidates.map((candidate) => (
                            <span
                              key={`${candidate.property}:${candidate.kind}:${candidate.value}`}
                            >
                              {candidate.property}: {candidate.value}
                              {candidate.port ? `:${candidate.port}` : ""}
                              {candidate.matchesSelection
                                ? " (candidate equals selected IP)"
                                : ""}
                              {candidate.kind === "hostname_unresolved"
                                ? " (name not resolved)"
                                : ""}
                              {"; "}
                            </span>
                          ))
                        : "No endpoint candidate extracted"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            Backend entries are configuration inventory. A candidate address
            match does not prove a request or connection used that backend.
          </p>
        </>
      )}
    </article>
  );
}

/** User-triggered wrapper; it does not dispatch a search during mount. */
export function AppDynamicsEvidenceInspection({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<AppDynamicsEvidenceResult>();
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
      const next = await loadAppDynamicsEvidence(
        client,
        selection,
        controller.signal,
        configurationClient,
      );
      if (requestId === activeRequest.current && !controller.signal.aborted)
        setResult(next);
    } catch {
      if (requestId === activeRequest.current)
        setError(
          controller.signal.aborted
            ? "Search cancelled. Native cleanup may remain pending."
            : "AppDynamics evidence unavailable. Refresh the selection or check the selected Controller source configuration and permissions.",
        );
    } finally {
      if (requestId === activeRequest.current) setBusy(false);
    }
  };

  return (
    <div className="appdynamics-evidence-inspection">
      {result ? (
        <AppDynamicsEvidencePanel result={result} />
      ) : (
        <section
          className="dns-evidence appdynamics-evidence"
          aria-label="Optional AppDynamics Controller inventory evidence"
        >
          <h3>AppDynamics inventory evidence</h3>
          <p>
            Inspect a bounded current Controller snapshot for exact node-IP
            matches and modeled backend candidates. No historical time window is
            applied to this inventory.
          </p>
          <button type="button" onClick={() => void inspect()} disabled={busy}>
            {busy
              ? "Searching AppDynamics inventory…"
              : "Inspect AppDynamics inventory"}
          </button>
          {busy && (
            <button type="button" onClick={() => active.current?.abort()}>
              Cancel AppDynamics search
            </button>
          )}
          <p role="status">
            {busy
              ? "Loading optional AppDynamics evidence…"
              : (error ??
                "No AppDynamics search has run. An administrator must select and qualify this source first.")}
          </p>
        </section>
      )}
      {result && (
        <button type="button" onClick={() => void inspect()} disabled={busy}>
          {busy
            ? "Searching AppDynamics inventory…"
            : "Refresh AppDynamics evidence"}
        </button>
      )}
      {busy && result && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel AppDynamics search
        </button>
      )}
      {error && result && <p role="status">{error}</p>}
    </div>
  );
}
