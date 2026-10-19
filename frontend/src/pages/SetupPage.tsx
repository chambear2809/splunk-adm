import { DeploymentWriteError } from "../data/deploymentClient";
import { useEffect, useRef, useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import TableExport from "@splunk/react-ui/Table";
import TextExport from "@splunk/react-ui/Text";
import { toolkitDefault } from "../app/interop";
import { jobRunAssessment } from "../health";
import { useHealthStatus } from "../data/healthStatus";
import {
  SOURCE_DEFINITIONS,
  defaultExpectations,
  validateExpectations,
  type DeploymentExpectations,
  type DeploymentSnapshot,
} from "../data/deploymentHealth";
import type { DeploymentClient } from "../data/deploymentHealth";
import {
  indexName,
  indexNames,
  setupReadiness,
  validateIndexName,
  type SetupClient,
  type SetupMacro,
  type SetupSnapshot,
} from "../data/setupClient";

const Button = toolkitDefault(ButtonExport);
const Table = toolkitDefault(TableExport);
const Text = toolkitDefault(TextExport);
const recoveryURL =
  "https://github.com/chambear2809/splunk-adm/blob/main/docs/RECOVERY.md";
const acsURL =
  "https://help.splunk.com/en/splunk-cloud-platform/administer/admin-config-service-manual/10.2.2510/administer-splunk-cloud-platform-using-the-admin-config-service-acs-api/manage-indexes-in-splunk-cloud-platform";
const editableExpectations = (
  saved?: DeploymentExpectations,
): DeploymentExpectations => {
  const defaults = defaultExpectations();
  return {
    ...defaults,
    ...saved,
    sources: { ...defaults.sources, ...saved?.sources },
  };
};
function MacroEditor({
  macro,
  disabled,
  save,
}: {
  macro: SetupMacro;
  disabled: boolean;
  save: (name: string, value: string) => void;
}) {
  const currentNames = indexNames(macro);
  const currentValue =
    indexName(macro) ??
    (currentNames.length > 1
      ? `(${currentNames.map((name) => `index=${name}`).join(" OR ")})`
      : "");
  const [value, setValue] = useState(currentValue);
  useEffect(() => setValue(currentValue), [currentValue]);
  return (
    <Table.Row>
      <Table.Cell>{macro.name}</Table.Cell>
      <Table.Cell>{macro.error ?? macro.definition ?? "Unknown"}</Table.Cell>
      <Table.Cell>
        {currentNames.length > 1 && (
          <small>
            Multiple indexes are configured; enter one index to replace this
            expression.
          </small>
        )}
        <Text
          className="atlas-index-input"
          aria-label={`Index for ${macro.name}`}
          value={value}
          disabled={disabled || !macro.canWrite}
          onChange={(_, { value: next }) => setValue(next)}
        />
      </Table.Cell>
      <Table.Cell>
        <Button
          disabled={
            disabled ||
            !macro.canWrite ||
            !!validateIndexName(value) ||
            value === indexName(macro)
          }
          onClick={() => save(macro.name, value)}
        >
          Save {macro.name}
        </Button>
      </Table.Cell>
    </Table.Row>
  );
}
export function SetupPage({
  client,
  live,
  deploymentClient,
}: {
  client?: SetupClient;
  live: boolean;
  deploymentClient?: DeploymentClient;
}) {
  const [snapshot, setSnapshot] = useState<SetupSnapshot>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [revision, setRevision] = useState(0);
  const mutation = useRef(false);
  const controller = useRef<AbortController>();
  const health = useHealthStatus();
  const [deployment, setDeployment] = useState<DeploymentSnapshot>();
  const [settings, setSettings] = useState<DeploymentExpectations>();
  const dirtyDraft = useRef(false);
  const draftRevision = useRef<string>();
  const [draftDirty, setDraftDirty] = useState(false);
  const [draftConflict, setDraftConflict] = useState<string>();
  const receiveDeployment = (
    next: DeploymentSnapshot,
    discardDraft = false,
  ) => {
    setDeployment(next);
    if (dirtyDraft.current && !discardDraft) {
      if (next.state === "configured" || next.state === "absent")
        setDraftConflict(
          next.settings?.revision !== draftRevision.current
            ? "Deployment settings changed since this draft began. Discard the draft and reload before saving."
            : undefined,
        );
      return;
    }
    dirtyDraft.current = false;
    setDraftDirty(false);
    draftRevision.current = next.settings?.revision;
    setDraftConflict(undefined);
    setSettings(editableExpectations(next.settings));
  };
  useEffect(() => {
    if (health?.deployment) receiveDeployment(health.deployment);
  }, [health?.deployment]);
  useEffect(() => {
    setSnapshot(undefined);
    setError(undefined);
    if (!client || !live) {
      setBusy(false);
      setDeployment(undefined);
      if (!dirtyDraft.current) setSettings(undefined);
      return;
    }
    const request = new AbortController();
    controller.current = request;
    setBusy(true);
    if (deploymentClient && !health)
      void deploymentClient
        .read(request.signal)
        .then((result) => {
          if (!request.signal.aborted) {
            receiveDeployment(result);
          }
        })
        .catch(() => {
          if (!request.signal.aborted)
            setDeployment({ state: "unavailable", canWrite: false });
        });
    client
      .read(request.signal)
      .then((result) => {
        if (!request.signal.aborted) setSnapshot(result);
      })
      .catch(() => {
        if (!request.signal.aborted)
          setError(
            "Setup information could not be read. Check your administrator access and try again.",
          );
      })
      .finally(() => {
        if (!request.signal.aborted) setBusy(false);
      });
    return () => request.abort();
  }, [client, live, revision, deploymentClient, health === undefined]);
  const perform = async (
    action: () => Promise<void>,
    verified: (state: SetupSnapshot) => boolean,
  ) => {
    if (!client || !live || !snapshot?.authorized || mutation.current) return;
    const signal = controller.current?.signal;
    mutation.current = true;
    setBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      await action();
      if (signal?.aborted) return;
      setNotice("Change saved. Checking the current configuration…");
      setSnapshot(undefined);
      const refreshed = await client.read(signal);
      if (signal?.aborted) return;
      if (!verified(refreshed))
        throw new Error("Change could not be verified.");
      setSnapshot(refreshed);
      setNotice("Change saved and configuration refreshed.");
      health?.refresh();
    } catch {
      if (signal?.aborted) return;
      setNotice(undefined);
      setError(
        "The change or its verification failed. Refresh the checklist before trying again.",
      );
      setSnapshot(undefined);
    } finally {
      mutation.current = false;
      if (!signal?.aborted) setBusy(false);
    }
  };
  const scopes = snapshot?.observerScopes;
  const reader = snapshot?.macros.find(
    (macro) => macro.name === "adm_index_summary",
  );
  const writer = snapshot?.macros.find(
    (macro) => macro.name === "adm_summary_index_name",
  );
  const summaryMatches =
    !!reader &&
    !!writer &&
    !!indexName(reader) &&
    indexName(reader) === indexName(writer);
  const uppercase =
    scopes?.rows.filter(
      (row) =>
        row.observer !== row.observer.toLowerCase() ||
        row.observer_kind !== row.observer_kind.toLowerCase(),
    ) ?? [];
  const invalidScopes = scopes?.rows.some(
    (row) =>
      !row.observer.trim() || !row.observer_kind.trim() || !row.scope.trim(),
  );
  const readiness = snapshot
    ? setupReadiness(
        snapshot,
        deployment ?? { state: "unavailable", canWrite: false },
      )
    : undefined;
  const prerequisites = readiness?.ready === true;
  let settingsError: string | undefined;
  if (settings)
    try {
      validateExpectations(settings);
    } catch (reason) {
      settingsError =
        reason instanceof Error
          ? reason.message
          : "Invalid deployment expectations.";
    }
  return (
    <main className="atlas-page" aria-labelledby="setup-title">
      <h1 id="setup-title">Setup</h1>
      <p>
        Administrator access is required. Review the checklist before enabling
        scheduled builders.
      </p>
      {!live || !client ? (
        <p role="status">
          Setup is unavailable in Demo. Open this page inside Splunk with
          administrator access to read and change live configuration.
        </p>
      ) : (
        <>
          <Button
            disabled={busy}
            onClick={() => {
              setRevision((value) => value + 1);
              health?.refresh();
            }}
          >
            Refresh checklist
          </Button>
          {busy && <p role="status">Checking configuration…</p>}
          {error && <p role="alert">{error}</p>}
          {notice && <p role="status">{notice}</p>}
          {snapshot && (
            <>
              {!snapshot.authorized && (
                <p role="alert">
                  Administrator access could not be established. All setup
                  actions are disabled.
                </p>
              )}
              {snapshot.warnings.map((warning, i) => (
                <p role="alert" key={i}>
                  {warning}
                </p>
              ))}
              {readiness?.optionalWarnings.map((warning) => (
                <p role="status" key={warning}>
                  {warning}
                </p>
              ))}
              <h2>Deployment expectations</h2>
              <p>
                Choose the sources this deployment collects. Cadence is the
                expected collection interval; freshness is the longest allowed
                receipt age. These settings do not activate a data contract or a
                scheduled writer.
              </p>
              <p>
                {deployment?.state === "configured"
                  ? `Saved expectations; active data contract: ${deployment.activeContract ?? "unknown"}.`
                  : deployment?.state === "absent"
                    ? "No deployment expectations have been saved."
                    : "Deployment expectations are unavailable."}
              </p>
              {deployment?.error && <p role="alert">{deployment.error}</p>}
              {deployment?.writeUnavailableReason && (
                <p role="status">{deployment.writeUnavailableReason}</p>
              )}
              {settings && (
                <>
                  <Table
                    horizontalOverflow="scroll"
                    aria-label="Deployment sources"
                  >
                    <Table.Head>
                      <Table.HeadCell>Source</Table.HeadCell>
                      <Table.HeadCell>Expectation</Table.HeadCell>
                      <Table.HeadCell>Cadence (seconds)</Table.HeadCell>
                      <Table.HeadCell>Freshness (seconds)</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                      {SOURCE_DEFINITIONS.filter(
                        (source) => source.selectable,
                      ).map((source) => {
                        const expectation = settings.sources[source.id];
                        if (!expectation) return null;
                        const disabled =
                          busy || !snapshot.authorized || !deployment?.canWrite;
                        const update = (
                          change: Partial<typeof expectation>,
                        ) => {
                          dirtyDraft.current = true;
                          setDraftDirty(true);
                          setSettings({
                            ...settings,
                            sources: {
                              ...settings.sources,
                              [source.id]: { ...expectation, ...change },
                            },
                          });
                        };
                        return (
                          <Table.Row key={source.id}>
                            <Table.Cell>{source.label}</Table.Cell>
                            <Table.Cell>
                              <select
                                aria-label={`Expectation for ${source.label}`}
                                value={expectation.state}
                                disabled={disabled}
                                onChange={(event) =>
                                  update({
                                    state: event.target
                                      .value as typeof expectation.state,
                                  })
                                }
                              >
                                <option value="not_selected">
                                  Not selected
                                </option>
                                <option value="staged">Staged</option>
                                <option value="active">Active</option>
                              </select>
                            </Table.Cell>
                            <Table.Cell>
                              <input
                                aria-label={`Cadence for ${source.label}`}
                                type="number"
                                min={60}
                                max={604800}
                                value={expectation.cadenceSeconds}
                                disabled={disabled}
                                onChange={(event) =>
                                  update({
                                    cadenceSeconds: Number(event.target.value),
                                  })
                                }
                              />
                            </Table.Cell>
                            <Table.Cell>
                              <input
                                aria-label={`Freshness for ${source.label}`}
                                type="number"
                                min={expectation.cadenceSeconds}
                                max={604800}
                                value={expectation.staleAfterSeconds}
                                disabled={disabled}
                                onChange={(event) =>
                                  update({
                                    staleAfterSeconds: Number(
                                      event.target.value,
                                    ),
                                  })
                                }
                              />
                            </Table.Cell>
                          </Table.Row>
                        );
                      })}
                    </Table.Body>
                  </Table>
                  {draftDirty && (
                    <p role="status">
                      Unsaved deployment changes are preserved across background
                      checks.
                    </p>
                  )}
                  {draftConflict && <p role="alert">{draftConflict}</p>}
                  {settingsError && <p role="alert">{settingsError}</p>}
                  <Button
                    disabled={busy || !draftDirty || !deploymentClient}
                    onClick={() => {
                      if (!deploymentClient || mutation.current) return;
                      const signal = controller.current?.signal;
                      mutation.current = true;
                      setBusy(true);
                      setError(undefined);
                      void deploymentClient
                        .read(signal)
                        .then((result) => {
                          if (!signal?.aborted) receiveDeployment(result, true);
                        })
                        .catch(() => {
                          if (!signal?.aborted)
                            setError(
                              "Deployment settings could not be reloaded. The draft was preserved.",
                            );
                        })
                        .finally(() => {
                          mutation.current = false;
                          if (!signal?.aborted) setBusy(false);
                        });
                    }}
                  >
                    Discard draft and reload
                  </Button>
                  <Button
                    disabled={
                      busy ||
                      !!settingsError ||
                      !!draftConflict ||
                      !snapshot.authorized ||
                      !deployment?.canWrite ||
                      !deploymentClient
                    }
                    onClick={() => {
                      if (!deploymentClient || mutation.current) return;
                      const signal = controller.current?.signal;
                      mutation.current = true;
                      setBusy(true);
                      setError(undefined);
                      setNotice(undefined);
                      void deploymentClient
                        .write(settings, draftRevision.current, signal)
                        .then((result) => {
                          if (signal?.aborted) return;
                          receiveDeployment(result, true);
                          setNotice(
                            "Deployment expectations saved and verified.",
                          );
                          health?.refresh();
                        })
                        .catch((reason: unknown) => {
                          if (
                            reason instanceof DeploymentWriteError &&
                            reason.code === "conflict"
                          ) {
                            setDraftConflict(reason.message);
                            void deploymentClient
                              .read(signal)
                              .then((next) => {
                                if (!signal?.aborted) receiveDeployment(next);
                              })
                              .catch(() => {
                                /* The draft and conflict remain visible. */
                              });
                          }
                          if (!signal?.aborted)
                            setError(
                              reason instanceof Error
                                ? reason.message
                                : "Deployment expectations could not be saved.",
                            );
                        })
                        .finally(() => {
                          mutation.current = false;
                          if (!signal?.aborted) setBusy(false);
                        });
                    }}
                  >
                    Save deployment expectations
                  </Button>
                </>
              )}
              <h2>Index macros</h2>
              <p>
                Enter one lowercase index name per macro. Existing definitions
                are shown for review. The summary reader and writer must name
                the same index.
              </p>
              <Table horizontalOverflow="scroll" aria-label="Index macros">
                <Table.Head>
                  <Table.HeadCell>Macro</Table.HeadCell>
                  <Table.HeadCell>Current definition</Table.HeadCell>
                  <Table.HeadCell>Index name</Table.HeadCell>
                  <Table.HeadCell>Action</Table.HeadCell>
                </Table.Head>
                <Table.Body>
                  {snapshot.macros.map((macro) => (
                    <MacroEditor
                      key={macro.name}
                      macro={macro}
                      disabled={busy || !snapshot.authorized}
                      save={(name, value) =>
                        void perform(
                          () =>
                            client.setIndexMacro(
                              name,
                              value,
                              controller.current?.signal,
                            ),
                          (result) =>
                            result.macros.some(
                              (row) =>
                                row.name === name &&
                                !row.error &&
                                indexName(row) === value,
                            ),
                        )
                      }
                    />
                  ))}
                </Table.Body>
              </Table>
              <h2>Summary index</h2>
              <p>
                {snapshot.summaryIndex.exists === true
                  ? `Available: ${snapshot.summaryIndex.name}`
                  : (snapshot.summaryIndex.error ??
                    "Summary index availability is unknown.")}
              </p>
              <p>
                {summaryMatches
                  ? "Summary reader and writer match."
                  : "Summary reader and writer do not match or could not be verified. Fix both macros before enabling builders."}
              </p>
              <h2>Observer scope</h2>
              {invalidScopes && (
                <p role="alert">
                  Observer mappings have empty matching or scope keys. Correct
                  them before enabling builders.
                </p>
              )}
              <p>
                {!scopes?.complete
                  ? (scopes?.error ??
                    "Observer mappings could not be fully read.")
                  : scopes.rows.length === 0
                    ? "No observer mappings are configured."
                    : `${scopes.rows.length} stored mappings checked; ${uppercase.length} contain uppercase observer or observer_kind keys.`}
              </p>
              <p>
                Configure mappings through the{" "}
                <a
                  href="https://github.com/chambear2809/splunk-adm/blob/main/docs/operators/splunk-platform.md#application-atlas-configuration"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  operator guide
                </a>
                . Stored observer and observer_kind values must be lowercase;
                this checklist reads the stored keys without changing them.
              </p>
              {uppercase.length > 0 && (
                <ul>
                  {uppercase.slice(0, 10).map((row) => (
                    <li key={row._key}>
                      {row.observer_kind} / {row.observer}
                    </li>
                  ))}
                </ul>
              )}
              {!!scopes?.rows.length && (
                <>
                  <p>
                    Showing {Math.min(20, scopes.rows.length)} of{" "}
                    {scopes.rows.length} mappings read.
                  </p>
                  <Table
                    aria-label="Observer mappings"
                    horizontalOverflow="scroll"
                  >
                    <Table.Head>
                      <Table.HeadCell>Observer kind</Table.HeadCell>
                      <Table.HeadCell>Observer</Table.HeadCell>
                      <Table.HeadCell>Scope</Table.HeadCell>
                      <Table.HeadCell>Cluster</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                      {scopes.rows.slice(0, 20).map((row) => (
                        <Table.Row key={row._key}>
                          <Table.Cell>{row.observer_kind}</Table.Cell>
                          <Table.Cell>{row.observer}</Table.Cell>
                          <Table.Cell>{row.scope}</Table.Cell>
                          <Table.Cell>{row.cluster || "Not set"}</Table.Cell>
                        </Table.Row>
                      ))}
                    </Table.Body>
                  </Table>
                </>
              )}
              <h2>Cisco integration status</h2>
              <p>
                {snapshot.ciscoIntegration.state === "active"
                  ? "Version 2 selectors and scheduled writer configuration were observed. This is a read-only configuration check; review Data health for receipt and run evidence."
                  : snapshot.ciscoIntegration.state === "staged"
                    ? "All requested Cisco settings were read. Cisco v2 remains staged and does not change the active v1 reader or writer."
                    : snapshot.ciscoIntegration.state === "incomplete"
                      ? "Cisco integration configuration is incomplete or needs operator review. No v2 readiness is claimed."
                      : "Cisco integration state is unavailable. Check administrator permissions and the operator guide. No v2 readiness is claimed."}
              </p>
              {!!snapshot.ciscoIntegration.reasons.length && (
                <ul>
                  {snapshot.ciscoIntegration.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              )}
              <p>
                This section only reads configuration. Review exact source
                profiles and cluster rows through the{" "}
                <a
                  href="https://github.com/chambear2809/splunk-adm/blob/main/docs/operators/cisco-enterprise-networking.md"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Cisco networking operator handout
                </a>
                . The documented migration and bounded validation steps are
                required before any reader or scheduled writer cutover.
              </p>
              <h3>Contract and v2 reader/writer</h3>
              <Table
                horizontalOverflow="scroll"
                aria-label="Cisco integration macros"
              >
                <Table.Head>
                  <Table.HeadCell>Setting</Table.HeadCell>
                  <Table.HeadCell>Current value</Table.HeadCell>
                  <Table.HeadCell>Access</Table.HeadCell>
                </Table.Head>
                <Table.Body>
                  {snapshot.ciscoIntegration.macros.map((macro) => (
                    <Table.Row key={macro.name}>
                      <Table.Cell>{macro.name}</Table.Cell>
                      <Table.Cell>
                        {macro.error ?? macro.definition ?? "Unknown"}
                      </Table.Cell>
                      <Table.Cell>
                        {macro.error
                          ? "Unavailable"
                          : macro.canWrite
                            ? "Readable; writable by this role"
                            : "Readable; read-only for this role"}
                      </Table.Cell>
                    </Table.Row>
                  ))}
                  <Table.Row>
                    <Table.Cell>
                      adm_index_summary_v2 / adm_summary_index_v2_name
                    </Table.Cell>
                    <Table.Cell>
                      {snapshot.ciscoIntegration.summaryIndex.error ??
                        snapshot.ciscoIntegration.summaryIndex.name ??
                        "Unknown"}
                    </Table.Cell>
                    <Table.Cell>
                      {snapshot.ciscoIntegration.summaryIndex.exists === true
                        ? "Index available"
                        : "Unavailable"}
                    </Table.Cell>
                  </Table.Row>
                </Table.Body>
              </Table>
              <h3>Source scope profiles</h3>
              {!snapshot.ciscoIntegration.sourceProfiles.complete && (
                <p role="alert">
                  {snapshot.ciscoIntegration.sourceProfiles.error ??
                    "The complete source-profile collection could not be read."}
                </p>
              )}
              {snapshot.ciscoIntegration.sourceProfiles.complete && (
                <p>
                  {snapshot.ciscoIntegration.sourceProfiles.rows.length} source
                  scope profile
                  {snapshot.ciscoIntegration.sourceProfiles.rows.length === 1
                    ? ""
                    : "s"}{" "}
                  read across the full collection.
                </p>
              )}
              {snapshot.ciscoIntegration.sourceProfiles.complete &&
              snapshot.ciscoIntegration.sourceProfiles.rows.length === 0 ? (
                <p>No source scope profiles are configured.</p>
              ) : (
                !!snapshot.ciscoIntegration.sourceProfiles.rows.length && (
                  <Table
                    horizontalOverflow="scroll"
                    aria-label="Cisco source scope profiles"
                  >
                    <Table.Head>
                      <Table.HeadCell>Source / authority</Table.HeadCell>
                      <Table.HeadCell>
                        Domain / observation domain
                      </Table.HeadCell>
                      <Table.HeadCell>VPN / routing domain</Table.HeadCell>
                      <Table.HeadCell>Scope / cluster</Table.HeadCell>
                      <Table.HeadCell>
                        Profile / mapping candidates
                      </Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                      {snapshot.ciscoIntegration.sourceProfiles.rows.map(
                        (row) => (
                          <Table.Row key={row._key}>
                            <Table.Cell>
                              {row.source} / {row.source_authority}
                            </Table.Cell>
                            <Table.Cell>
                              {row.domain_kind} /{" "}
                              {row.observation_domain_present === "1"
                                ? row.observation_domain_id
                                : "absent"}
                            </Table.Cell>
                            <Table.Cell>
                              {row.vpn_id || "Not set"} / {row.routing_domain}
                            </Table.Cell>
                            <Table.Cell>
                              {row.scope} / {row.cluster}
                            </Table.Cell>
                            <Table.Cell>
                              {row.profile} / {row.mapping_status} /{" "}
                              {row.duplicate_count} candidate
                              {row.duplicate_count === 1 ? "" : "s"}
                            </Table.Cell>
                          </Table.Row>
                        ),
                      )}
                    </Table.Body>
                  </Table>
                )
              )}
              <h3>Cilium cluster settings</h3>
              {!snapshot.ciscoIntegration.clusterSettings.complete && (
                <p role="alert">
                  {snapshot.ciscoIntegration.clusterSettings.error ??
                    "The complete cluster-settings collection could not be read."}
                </p>
              )}
              {snapshot.ciscoIntegration.clusterSettings.complete && (
                <p>
                  {snapshot.ciscoIntegration.clusterSettings.rows.length}{" "}
                  cluster setting
                  {snapshot.ciscoIntegration.clusterSettings.rows.length === 1
                    ? ""
                    : "s"}{" "}
                  read across the full collection.
                </p>
              )}
              {snapshot.ciscoIntegration.clusterSettings.complete &&
              snapshot.ciscoIntegration.clusterSettings.rows.length === 0 ? (
                <p>No cluster settings are configured.</p>
              ) : (
                !!snapshot.ciscoIntegration.clusterSettings.rows.length && (
                  <Table
                    horizontalOverflow="scroll"
                    aria-label="Cilium cluster settings"
                  >
                    <Table.Head>
                      <Table.HeadCell>Cluster</Table.HeadCell>
                      <Table.HeadCell>LB mode</Table.HeadCell>
                      <Table.HeadCell>Ingress mode</Table.HeadCell>
                      <Table.HeadCell>L2 announcements</Table.HeadCell>
                      <Table.HeadCell>Mapping</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                      {snapshot.ciscoIntegration.clusterSettings.rows.map(
                        (row) => (
                          <Table.Row key={row._key}>
                            <Table.Cell>{row.cluster}</Table.Cell>
                            <Table.Cell>{row.lb_mode}</Table.Cell>
                            <Table.Cell>{row.ingress_mode}</Table.Cell>
                            <Table.Cell>
                              {row.l2announcements_enabled}
                            </Table.Cell>
                            <Table.Cell>{row.mapping_status}</Table.Cell>
                          </Table.Row>
                        ),
                      )}
                    </Table.Body>
                  </Table>
                )
              )}
              <h3>Client history and v2 writer schedules</h3>
              <Table
                horizontalOverflow="scroll"
                aria-label="Cisco staged builder schedules"
              >
                <Table.Head>
                  <Table.HeadCell>Saved search</Table.HeadCell>
                  <Table.HeadCell>State</Table.HeadCell>
                  <Table.HeadCell>Access</Table.HeadCell>
                </Table.Head>
                <Table.Body>
                  {snapshot.ciscoIntegration.searches.map((job) => (
                    <Table.Row key={job.name}>
                      <Table.Cell>{job.name}</Table.Cell>
                      <Table.Cell>
                        {job.error ??
                          (job.disabled === true && job.scheduled === false
                            ? "Disabled; no schedule configured"
                            : job.disabled === true && job.scheduled === true
                              ? "Disabled; schedule configured (staged)"
                              : job.disabled === false && job.scheduled === true
                                ? snapshot.ciscoIntegration.state === "active"
                                  ? "Enabled and scheduled"
                                  : "Enabled and scheduled; operator review required"
                                : "Unknown")}
                      </Table.Cell>
                      <Table.Cell>
                        {job.error
                          ? "Unavailable"
                          : job.canWrite
                            ? "Readable; writable by this role"
                            : "Readable; read-only for this role"}
                      </Table.Cell>
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
              <h2>Builder schedules</h2>
              {health?.busy && (
                <p role="status">Checking scheduled run evidence…</p>
              )}
              {health?.error && <p role="alert">{health.error}</p>}
              {health?.report?.warnings.map((warning) => (
                <p role="alert" key={warning}>
                  {warning}
                </p>
              ))}
              {!prerequisites && (
                <p>
                  Enable actions require saved deployment expectations and each
                  builder’s selected source macros and dependencies. Observer
                  mappings and summary index checks apply to builders that use
                  them.
                </p>
              )}
              <p>
                Enable schedule uses each search’s existing cadence. Last runs
                come from adm_health_jobs; unavailable evidence stays unknown.
              </p>
              <Table horizontalOverflow="scroll" aria-label="Builder schedules">
                <Table.Head>
                  <Table.HeadCell>Saved search</Table.HeadCell>
                  <Table.HeadCell>Schedule</Table.HeadCell>
                  <Table.HeadCell>Run observation</Table.HeadCell>
                  <Table.HeadCell>Last run / success (UTC)</Table.HeadCell>
                  <Table.HeadCell>Action</Table.HeadCell>
                </Table.Head>
                <Table.Body>
                  {snapshot.savedSearches.map((job) => {
                    const run = health?.report?.jobs.find(
                      (row) => row.name === job.name,
                    );
                    const runStatus = health?.busy
                      ? "Checking scheduled run evidence…"
                      : run
                        ? jobRunAssessment(
                            run,
                            health?.report?.checkedAt ?? Date.now() / 1000,
                          ).label
                        : "Run evidence unavailable";
                    const runTime = (value?: number) =>
                      value !== undefined && Number.isFinite(value)
                        ? new Date(value * 1000).toISOString()
                        : "Unknown";
                    const jobReady = setupReadiness(
                      snapshot,
                      deployment ?? { state: "unavailable", canWrite: false },
                      job.name,
                    );
                    const active =
                      job.disabled === false && job.scheduled === true;
                    return (
                      <Table.Row key={job.name}>
                        <Table.Cell>{job.name}</Table.Cell>
                        <Table.Cell>
                          {job.error ??
                            (active
                              ? "Enabled"
                              : job.disabled === true
                                ? "Disabled"
                                : job.scheduled === false
                                  ? "Not scheduled"
                                  : "Unknown")}
                        </Table.Cell>
                        <Table.Cell>{runStatus}</Table.Cell>
                        <Table.Cell>
                          {runTime(run?.lastRun)} / {runTime(run?.lastSuccess)}
                        </Table.Cell>
                        <Table.Cell>
                          {!jobReady.ready && (
                            <small>{jobReady.missingRequired.join(", ")}</small>
                          )}
                          <Button
                            disabled={
                              busy ||
                              !jobReady.ready ||
                              !snapshot.authorized ||
                              !job.canWrite ||
                              active ||
                              job.disabled === undefined ||
                              job.scheduled === undefined
                            }
                            onClick={() =>
                              void perform(
                                () =>
                                  client.setBuilderEnabled(
                                    job.name,
                                    true,
                                    controller.current?.signal,
                                  ),
                                (result) =>
                                  result.savedSearches.some(
                                    (row) =>
                                      row.name === job.name &&
                                      !row.error &&
                                      row.disabled === false &&
                                      row.scheduled === true,
                                  ),
                              )
                            }
                          >
                            Enable schedule for {job.name}
                          </Button>
                        </Table.Cell>
                      </Table.Row>
                    );
                  })}
                </Table.Body>
              </Table>
            </>
          )}
        </>
      )}
      <p>
        Prune searches must remain disabled until recovery policy is reviewed.{" "}
        <a href={recoveryURL} target="_blank" rel="noopener noreferrer">
          Read the recovery policy
        </a>
        .
      </p>
      <p>
        On Splunk Cloud, an operator creates indexes through{" "}
        <a href={acsURL} target="_blank" rel="noopener noreferrer">
          Admin Config Service (ACS)
        </a>
        . Refresh this checklist after index creation.
      </p>
    </main>
  );
}
