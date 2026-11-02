import { useEffect, useState } from "react";
import { pageURL, stateParams, type UrlState } from "./app/urlState";
import {
  loadControllerCatalog,
  type ControllerCatalog,
} from "./data/appDynamicsCatalog";
import type { DevicePathResult } from "./data/devicePathEvidence";
import type { SearchClient } from "./data/searchClient";

function useCatalog(client?: SearchClient, live = false) {
  const [catalog, setCatalog] = useState<ControllerCatalog>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!client || !live) return;
    const controller = new AbortController();
    void loadControllerCatalog(client, controller.signal)
      .then(setCatalog)
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Controller inventory unavailable.",
          );
      });
    return () => controller.abort();
  }, [client, live]);
  return { catalog, error };
}

export function ControllerCatalogSection({
  state,
  client,
}: {
  state: UrlState;
  client?: SearchClient;
}) {
  const { catalog, error } = useCatalog(client, state.mode === "live");
  return (
    <section aria-label="AppDynamics Controller catalog">
      <h2>AppDynamics Controller catalog</h2>
      <p>
        Controller applications are a separate inventory from OpenTelemetry
        Kubernetes services.
      </p>
      {state.mode !== "live" || !client ? (
        <p>
          Available when a qualified Controller source is configured in Splunk.
        </p>
      ) : error ? (
        <p role="status">Controller inventory unavailable: {error}</p>
      ) : !catalog ? (
        <p role="status">Loading Controller inventory…</p>
      ) : (
        <>
          <p>
            Controller authority: {catalog.authority} · Routing scope:{" "}
            {catalog.scope} · Snapshot:{" "}
            {new Date(catalog.snapshotAt * 1000).toISOString()}
          </p>
          <ul>
            {catalog.applications.map((app) => (
              <li key={app.id}>
                <a
                  href={pageURL(
                    "map",
                    stateParams({
                      ...state,
                      appd: {
                        applicationId: app.id,
                        snapshotId: catalog.snapshotId,
                        snapshotAt: String(catalog.snapshotAt),
                        authority: catalog.authority,
                        scope: catalog.scope,
                      },
                    }),
                  )}
                >
                  {app.name}
                </a>{" "}
                · Controller application ID {app.id} · {app.tiers.length} tiers
                · {app.tiers.reduce((n, t) => n + t.nodes.length, 0)} nodes
              </li>
            ))}
          </ul>
          <p>
            Node addresses are point-in-time claims, not historical IP
            ownership.
          </p>
        </>
      )}
    </section>
  );
}

/** The resolver supplies alternatives only when complete qualified attachments exist. */
export function ControllerPath({ result }: { result?: DevicePathResult }) {
  return (
    <section aria-label="Device path evidence">
      <h2>Device path</h2>
      {!result ? (
        <p>
          Unknown: complete, source-qualified attachment evidence is
          unavailable. ACI evidence is quarantined.
        </p>
      ) : (
        <>
          <p>
            Status:{" "}
            {result.status === "candidate" ? "Topology candidates" : "Unknown"}{" "}
            · {result.reason}
          </p>
          <p>Packet traversal is not observed.</p>
          {result.endpoints.map((item, i) => (
            <div key={i}>
              <h3>Endpoint {item.endpoint.address}</h3>
              <p>
                Identity: {item.endpoint.identitySource} /{" "}
                {item.endpoint.identityAuthority} / {item.endpoint.identityId}
              </p>
              {item.owners.length === 0 && <p>Owner evidence unavailable.</p>}
              {item.owners.map((owner, j) => (
                <p key={j}>
                  Owner: {owner.identitySource} / {owner.identityAuthority} /{" "}
                  {owner.identityId} · {owner.provenance.source} /{" "}
                  {owner.provenance.snapshotId} / {owner.provenance.recordId}
                </p>
              ))}
              {item.attachments.length === 0 && (
                <p>Attachment evidence unavailable.</p>
              )}
              {item.attachments.map((attachment, j) => (
                <p key={j}>
                  Attachment: {attachment.device} {attachment.interface} ·{" "}
                  {attachment.provenance.source} /{" "}
                  {attachment.provenance.snapshotId} /{" "}
                  {attachment.provenance.recordId}
                </p>
              ))}
            </div>
          ))}
          {result.issues.length > 0 && (
            <ul>
              {result.issues.map((issue, i) => (
                <li key={i}>{issue.code}</li>
              ))}
            </ul>
          )}
          {result.alternatives.map((path, i) => (
            <div key={i}>
              <h3>Candidate {i + 1}</h3>
              <ul>
                {path.map((hop, j) => (
                  <li key={j}>
                    {hop.device} {hop.interface} → {hop.peerDevice}{" "}
                    {hop.peerInterface} · {hop.provenance.source} /{" "}
                    {hop.provenance.snapshotId} / {hop.provenance.recordId}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </>
      )}
    </section>
  );
}

export function ControllerMap({
  state,
  client,
}: {
  state: UrlState;
  client?: SearchClient;
}) {
  const { catalog, error } = useCatalog(client, state.mode === "live");
  const selection = state.appd!;
  const same =
    catalog &&
    catalog.authority === selection.authority &&
    catalog.scope === selection.scope &&
    catalog.snapshotId === selection.snapshotId &&
    catalog.snapshotAt === Number(selection.snapshotAt);
  const app = same
    ? catalog.applications.find((a) => a.id === selection.applicationId)
    : undefined;
  return (
    <main className="atlas-page atlas-page-wide">
      <p>
        <a
          href={pageURL(
            "applications",
            stateParams({ ...state, appd: undefined }),
          )}
        >
          Applications
        </a>
      </p>
      <h1>AppDynamics Controller map</h1>
      <p>
        Requested traffic window: {state.earliest} to {state.latest}. Controller
        inventory is a point-in-time snapshot; historical inventory and IP
        ownership are unavailable.
      </p>
      {!client || state.mode !== "live" ? (
        <p>Controller inventory requires a qualified live source.</p>
      ) : error ? (
        <p role="alert">Controller inventory unavailable: {error}</p>
      ) : !catalog ? (
        <p role="status">Loading Controller inventory…</p>
      ) : !same ? (
        <p role="alert">
          The linked snapshot is no longer the latest complete snapshot. Return
          to the catalog for the current snapshot; historical replay is
          unavailable.
        </p>
      ) : !app ? (
        <p role="alert">
          The selected application is absent from this snapshot.
        </p>
      ) : (
        <>
          <h2>
            {app.name} · Controller application ID {app.id}
          </h2>
          <p>
            Authority: {catalog.authority} · Routing scope: {catalog.scope} ·
            Snapshot {catalog.snapshotId} at{" "}
            {new Date(catalog.snapshotAt * 1000).toISOString()}
          </p>
          <p>
            Controller dependency and calls-per-minute evidence are separate
            from network traffic. No network traversal is established by this
            inventory.
          </p>
          {app.tiers.length === 0 ? (
            <p>No tiers in this snapshot.</p>
          ) : (
            app.tiers.map((tier) => (
              <section key={tier.id}>
                <h3>
                  {tier.name} · tier ID {tier.id}
                </h3>
                {tier.nodes.length === 0 ? (
                  <p>No nodes reported in this snapshot.</p>
                ) : (
                  <ul>
                    {tier.nodes.map((node) => (
                      <li key={node.id}>
                        <strong>{node.name}</strong> · node ID {node.id}
                        {node.machine && <> · machine {node.machine}</>} ·{" "}
                        {node.addresses.length
                          ? node.addresses.join(", ")
                          : "No matchable addresses"}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            ))
          )}
          <section>
            <h2>Controller-modeled backends</h2>
            <p>
              These are modeled candidates, not observed network connections.
              Calls per minute are unavailable in this inventory snapshot.
            </p>
            {app.backends.length ? (
              <ul>
                {app.backends.map((backend) => (
                  <li key={backend.id}>
                    {backend.name} · backend ID {backend.id}
                    {backend.exitPointType && <> · {backend.exitPointType}</>}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No modeled backends reported in this snapshot.</p>
            )}
          </section>
          <ControllerPath />
        </>
      )}
    </main>
  );
}
