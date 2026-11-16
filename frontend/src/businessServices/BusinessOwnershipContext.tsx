import { useEffect, useMemo, useState } from "react";
import "./BusinessOwnershipContext.css";
import {
  resolveBusinessOwnership,
  type BindingResolution,
  type NativeServiceIdentity,
} from "./bindings";
import {
  browserLocalStorage,
  readLocalImport,
  type LocalImportResult,
} from "./localImport";
import type { ObservationTime } from "./ownership";

const MAX_REFERENCES = 100;
const MAX_REFERENCE_BYTES = 128_000;
const validText = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 512 &&
  value.trim() === value &&
  ![...value].some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127;
  });

/** Only the supplied authorized native context is exported; imports never create references. */
export function nativeReferenceDocument(
  nativeIdentities: NativeServiceIdentity[],
): string | undefined {
  if (!nativeIdentities.length || nativeIdentities.length > MAX_REFERENCES)
    return undefined;
  const references = [];
  for (const n of nativeIdentities) {
    if (
      n === null ||
      typeof n !== "object" ||
      n.contract !== "qualified_v2" ||
      n.kind !== "service" ||
      ![
        n.authority,
        n.scope,
        n.configRevision,
        n.key?.service,
        n.key?.environment,
        n.key?.cluster,
        n.key?.namespace,
      ].every(validText) ||
      !Number.isFinite(n.observedWindow?.start) ||
      !Number.isFinite(n.observedWindow?.end) ||
      n.observedWindow.start < 0 ||
      n.observedWindow.end <= n.observedWindow.start
    )
      return undefined;
    references.push({
      kind: "service",
      contract: "qualified_v2",
      authority: n.authority,
      scope: n.scope,
      configRevision: n.configRevision,
      key: {
        service: n.key.service,
        environment: n.key.environment,
        cluster: n.key.cluster,
        namespace: n.key.namespace,
      },
      observedWindow: {
        start: n.observedWindow.start,
        end: n.observedWindow.end,
      },
    });
  }
  const value = JSON.stringify({ schema_version: 1, references }, null, 2);
  return new TextEncoder().encode(value).length <= MAX_REFERENCE_BYTES
    ? value
    : undefined;
}

function downloadReference(value: string) {
  const url = URL.createObjectURL(
    new Blob([value], { type: "application/json" }),
  );
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "qualified-service-references.json";
    document.body.appendChild(anchor);
    try {
      anchor.click();
    } finally {
      anchor.remove();
    }
  } finally {
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

function describeCoverage(value: BindingResolution["coverage"]) {
  return value === "covers"
    ? "covers the selected time"
    : value === "partial"
      ? "covers only part of the selected time"
      : "does not establish ownership for the selected time";
}

export function BusinessOwnershipContext({
  nativeIdentities,
  time,
  unavailableReason,
  compact = false,
}: {
  nativeIdentities: NativeServiceIdentity[];
  time: ObservationTime;
  unavailableReason?: string;
  compact?: boolean;
}) {
  const [local, setLocal] = useState<LocalImportResult>();
  const [consentReference, setConsentReference] = useState<string>();
  const [downloadError, setDownloadError] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const availableIdentities = useMemo(
    () => (unavailableReason ? [] : nativeIdentities),
    [nativeIdentities, unavailableReason],
  );
  const references = useMemo(
    () => nativeReferenceDocument(availableIdentities),
    [availableIdentities],
  );
  const consent = references !== undefined && consentReference === references;
  useEffect(() => {
    setConsentReference(undefined);
    setDownloadError(false);
  }, [references]);
  const resolutions = useMemo(
    () =>
      local?.status === "ready"
        ? resolveBusinessOwnership(
            local.preview.claims,
            local.preview.bindings,
            availableIdentities,
            time,
          )
        : [],
    [local, availableIdentities, time],
  );
  const timeKey =
    time.kind === "point"
      ? `point:${time.at}`
      : `interval:${time.from}:${time.to}`;
  useEffect(() => {
    setShowAll(false);
  }, [references, local, timeKey]);
  const resolved = resolutions.filter(
    (r) => r.status === "resolved" && r.claim,
  );
  const groups = new Map<string, BindingResolution[]>();
  const visibleResolved =
    compact && !showAll ? resolved.slice(0, 20) : resolved;
  for (const result of visibleResolved) {
    const claim = result.claim!;
    const key = JSON.stringify([claim.authority, claim.serviceId]);
    groups.set(key, [...(groups.get(key) ?? []), result]);
  }
  const unresolved = resolutions.filter((r) => r.status !== "resolved");
  const unknown = resolutions.filter((r) => r.coverage === "unknown").length;
  const current = resolutions.filter(
    (r) =>
      r.binding.validity.basis === "snapshot_current" ||
      r.claim?.validity.basis === "snapshot_current",
  ).length;
  const conflicts = resolutions.filter((r) => r.conflict).length;
  const stale = resolutions.filter(
    (r) => r.status === "stale_configuration",
  ).length;
  const claimKey = (item: {
    authority: string;
    recordId: string;
    revision: number;
    scope: string;
    memberKind: string;
    memberId: string;
  }) =>
    JSON.stringify([
      item.authority,
      item.recordId,
      item.revision,
      item.scope,
      item.memberKind,
      item.memberId,
    ]);
  const claimLatest = new Map<string, number>();
  if (local?.status === "ready")
    for (const claim of local.preview.claims) {
      const key = JSON.stringify([claim.authority, claim.recordId]);
      claimLatest.set(
        key,
        Math.max(claimLatest.get(key) ?? -1, claim.revision),
      );
    }
  const bindingLatest = new Map<string, number>();
  if (local?.status === "ready")
    for (const binding of local.preview.bindings) {
      const key = JSON.stringify([binding.authority, binding.recordId]);
      bindingLatest.set(
        key,
        Math.max(bindingLatest.get(key) ?? -1, binding.revision),
      );
    }
  const boundClaims = new Set(
    local?.status === "ready"
      ? local.preview.bindings
          .filter(
            (binding) =>
              bindingLatest.get(
                JSON.stringify([binding.authority, binding.recordId]),
              ) === binding.revision,
          )
          .map((binding) => claimKey(binding.claim))
      : [],
  );
  const unbound =
    local?.status === "ready"
      ? local.preview.claims.filter(
          (claim) =>
            claimLatest.get(
              JSON.stringify([claim.authority, claim.recordId]),
            ) === claim.revision && !boundClaims.has(claimKey(claim)),
        ).length
      : 0;
  const load = () => setLocal(readLocalImport(browserLocalStorage()));
  const exportReferences = () => {
    if (!consent || !references) return;
    try {
      downloadReference(references);
      setDownloadError(false);
    } catch {
      setDownloadError(true);
    }
    setConsentReference(undefined);
  };
  return (
    <section
      aria-label="Business ownership context"
      className="atlas-business-ownership-context"
    >
      <h3>Business ownership</h3>
      <p>
        Imported assertions; not verified ownership or an access grant.
        Technical priority is unchanged.
      </p>
      {!availableIdentities.length && (
        <p role="status">
          Qualified native service context unavailable
          {unavailableReason ? `: ${unavailableReason}` : "."}
        </p>
      )}
      <button type="button" onClick={load}>
        {local ? "Refresh local assertions" : "Load local assertions"}
      </button>
      {!local && !compact && (
        <p>
          Load a validated browser-local import to review any matching
          assertions.
        </p>
      )}
      {local?.status === "empty" && (
        <p>No browser-local import is available.</p>
      )}
      {local?.status === "unavailable" && (
        <p role="status">
          Browser-local storage is unavailable; ownership remains unknown.
        </p>
      )}
      {local?.status === "uncertain" && (
        <p role="status">
          The local import could not be validated; ownership remains unknown.
        </p>
      )}
      {local?.status === "ready" && (
        <>
          <p role="status">
            Loaded {local.preview.claims.length} claims and{" "}
            {local.preview.bindings.length} bindings from this browser.
          </p>
          {local.preview.bindings.length === 0 && (
            <p>
              Claims have no explicit technical bindings; membership is
              unresolved.
            </p>
          )}
          {local.preview.bindings.length > 0 && groups.size === 0 && (
            <p>
              No assertion resolves to an available qualified service identity
              for this selection.
            </p>
          )}
          {compact && !showAll && resolved.length > 20 && (
            <p>Showing 20 of {resolved.length} resolved assertions.</p>
          )}
          {[...groups.entries()].map(([key, matches]) => {
            const claim = matches[0].claim!;
            return (
              <section
                key={key}
                aria-label={`Business service ${claim.serviceName}`}
              >
                <strong>{claim.serviceName}</strong> ({claim.serviceId})
                <ul>
                  {matches.map((result, index) => {
                    const item = result.claim!;
                    return (
                      <li
                        key={`${result.binding.authority}:${result.binding.recordId}:${result.binding.revision}:${index}`}
                      >
                        {item.teamName} ({item.teamId}) · business criticality:{" "}
                        {item.criticality} · {describeCoverage(result.coverage)}
                        {result.conflict ? " · conflict requires review" : ""}
                        <details>
                          <summary>
                            Assertion and technical binding details
                          </summary>
                          <p>
                            Claim source: {item.authority} · record:{" "}
                            {item.recordId} · revision: {item.revision} ·
                            snapshot: {item.snapshotId} at{" "}
                            {new Date(item.snapshotAt * 1000).toISOString()}
                          </p>
                          <p>
                            Claim member: {item.memberKind} · {item.memberId} ·
                            scope: {item.scope}
                          </p>
                          <p>
                            Binding source: {result.binding.authority} · record:{" "}
                            {result.binding.recordId} · revision:{" "}
                            {result.binding.revision} · snapshot:{" "}
                            {result.binding.snapshotId} at{" "}
                            {new Date(
                              result.binding.snapshotAt * 1000,
                            ).toISOString()}{" "}
                            · proof reference: {result.binding.proofReference}
                          </p>
                          <p>
                            Native source: {result.binding.target.authority} ·
                            scope: {result.binding.target.scope} ·
                            configuration:{" "}
                            {result.binding.target.configRevision}
                          </p>
                          <p>
                            Technical service:{" "}
                            {result.binding.target.key.service} · environment:{" "}
                            {result.binding.target.key.environment} · cluster:{" "}
                            {result.binding.target.key.cluster} · namespace:{" "}
                            {result.binding.target.key.namespace}
                          </p>
                          {(item.validity.basis === "snapshot_current" ||
                            result.binding.validity.basis ===
                              "snapshot_current") && (
                            <p>
                              Current-only assertion; historical membership is
                              not established.
                            </p>
                          )}
                          {item.runbook && (
                            <p>
                              Runbook: {item.runbook.label} ({item.runbook.url})
                            </p>
                          )}
                          {item.escalation && (
                            <p>
                              Escalation: {item.escalation.label} (
                              {item.escalation.url})
                            </p>
                          )}
                          {result.reasons.map((reason) => (
                            <p key={reason}>{reason}</p>
                          ))}
                        </details>
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}
          {compact && resolved.length > 20 && (
            <button type="button" onClick={() => setShowAll(!showAll)}>
              {showAll ? "Show fewer assertions" : "Show all assertions"}
            </button>
          )}
          <details>
            <summary>Uncertainty and unresolved assertions</summary>
            <p>
              {unbound} claims without a binding · {unresolved.length}{" "}
              unresolved bindings · {stale} stale configuration · {unknown} with
              unknown time coverage · {current} current-only · {conflicts}{" "}
              conflicting
            </p>
            {unbound > 0 && (
              <p>
                Claims without a binding cannot be connected to this technical
                selection.
              </p>
            )}
            {unresolved.slice(0, 50).map((r, index) => (
              <p key={`${r.binding.authority}:${r.binding.recordId}:${index}`}>
                Binding {r.binding.authority} / {r.binding.recordId}:{" "}
                {r.reasons.join(" ")}
              </p>
            ))}
            {unresolved.length > 50 && (
              <p>Showing the first 50 unresolved bindings.</p>
            )}
          </details>
        </>
      )}
      {references && (
        <details>
          <summary>Export technical identity references</summary>
          <p>
            Contains only qualified native identity and observation context. It
            is not a business claim or access grant.
          </p>
          <label>
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) =>
                setConsentReference(
                  event.currentTarget.checked ? references : undefined,
                )
              }
            />{" "}
            I intend to include these identifiers in a local file.
          </label>{" "}
          <button type="button" onClick={exportReferences} disabled={!consent}>
            Download references
          </button>
          {downloadError && (
            <p role="status">Could not download the references.</p>
          )}
        </details>
      )}
      {availableIdentities.length > 0 && !references && (
        <p>
          Technical references are unavailable for export because the selection
          is invalid or exceeds the export limit.
        </p>
      )}
    </section>
  );
}
