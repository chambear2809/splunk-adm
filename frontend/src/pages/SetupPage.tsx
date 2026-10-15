import { useEffect, useRef, useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import TableExport from "@splunk/react-ui/Table";
import TextExport from "@splunk/react-ui/Text";
import { toolkitDefault } from "../app/interop";
import { useHealthStatus } from "../data/healthStatus";
import {
  indexName,
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
function MacroEditor({
  macro,
  disabled,
  save,
}: {
  macro: SetupMacro;
  disabled: boolean;
  save: (name: string, value: string) => void;
}) {
  const [value, setValue] = useState(indexName(macro) ?? "");
  useEffect(() => setValue(indexName(macro) ?? ""), [macro]);
  return (
    <Table.Row>
      <Table.Cell>{macro.name}</Table.Cell>
      <Table.Cell>{macro.error ?? macro.definition ?? "Unknown"}</Table.Cell>
      <Table.Cell>
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
}: {
  client?: SetupClient;
  live: boolean;
}) {
  const [snapshot, setSnapshot] = useState<SetupSnapshot>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [revision, setRevision] = useState(0);
  const mutation = useRef(false);
  const controller = useRef<AbortController>();
  const health = useHealthStatus();
  useEffect(() => {
    setSnapshot(undefined);
    setError(undefined);
    if (!client || !live) {
      setBusy(false);
      return;
    }
    const request = new AbortController();
    controller.current = request;
    setBusy(true);
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
  }, [client, live, revision]);
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
  const scopes = snapshot?.observerScopes;
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
  const prerequisites =
    !!snapshot &&
    snapshot.macros.every((macro) => !!indexName(macro) && !macro.error) &&
    summaryMatches &&
    snapshot.summaryIndex.exists === true &&
    scopes?.complete === true &&
    scopes.rows.length > 0 &&
    uppercase.length === 0 &&
    !invalidScopes;
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
            onClick={() => setRevision((value) => value + 1)}
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
              <h2>Builder schedules</h2>
              {!prerequisites && (
                <p>
                  Enable actions require valid index macros, an available
                  matching summary index, and a complete, nonempty observer
                  mapping check with lowercase keys.
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
                  <Table.HeadCell>Last run (UTC)</Table.HeadCell>
                  <Table.HeadCell>Action</Table.HeadCell>
                </Table.Head>
                <Table.Body>
                  {snapshot.savedSearches.map((job) => {
                    const lastRun = health?.report?.jobs.find(
                      (row) => row.name === job.name,
                    )?.lastRun;
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
                        <Table.Cell>
                          {lastRun !== undefined && Number.isFinite(lastRun)
                            ? new Date(lastRun * 1000).toISOString()
                            : "Unknown"}
                        </Table.Cell>
                        <Table.Cell>
                          <Button
                            disabled={
                              busy ||
                              !prerequisites ||
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
