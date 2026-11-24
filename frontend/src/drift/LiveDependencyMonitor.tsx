import { useEffect, useMemo, useState } from "react";
import { username } from "@splunk/splunk-utils/config";
import { DependencyMonitor } from "./DependencyMonitor";
import {
  splunkDependencyClient,
  type DependencySelection,
  type MonitorCapabilities,
} from "./network";

/** Opt-in native persistence; the displayed map is never promoted to evidence. */
export function LiveDependencyMonitor({
  window,
  mapWarnings,
  selection,
  nativePersistence = false,
}: {
  window: { start: number; end: number };
  mapWarnings?: string[];
  selection: DependencySelection;
  nativePersistence?: boolean;
}) {
  const { service, environment, cluster, namespace } = selection;
  const connection = useMemo(
    () =>
      nativePersistence && username
        ? splunkDependencyClient({ service, environment, cluster, namespace })
        : undefined,
    [nativePersistence, service, environment, cluster, namespace],
  );
  const [state, setState] = useState<{
    connection: typeof connection;
    value?: MonitorCapabilities;
    failed?: boolean;
  }>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!connection) return;
    const controller = new AbortController();
    connection
      .capabilities(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setState({ connection, value });
      })
      .catch(() => {
        if (!controller.signal.aborted) setState({ connection, failed: true });
      });
    return () => controller.abort();
  }, [connection, attempt]);
  const current = state?.connection === connection ? state : undefined;
  const capabilities = current?.value;
  return (
    <>
      {connection && (!current || current.failed) && (
        <p role="status">
          {current?.failed
            ? "Dependency service availability could not be checked."
            : "Checking dependency service availability…"}
        </p>
      )}
      {connection &&
        (current?.failed ||
          (capabilities &&
            (!capabilities.available || !capabilities.sourceAvailable))) && (
          <button
            type="button"
            onClick={() => {
              setState(undefined);
              setAttempt((n) => n + 1);
            }}
          >
            Retry dependency availability
          </button>
        )}
      {capabilities && (
        <>
          <p>
            {capabilities.available
              ? "Baseline storage is available."
              : "Baseline storage is unavailable."}{" "}
            {capabilities.sourceAvailable
              ? "Qualified dependency source is available."
              : "A qualified dependency source is unavailable; sampling, loss and lateness coverage have not been established."}
          </p>
          {capabilities.qualificationReasons.length > 0 && (
            <details>
              <summary>Availability details</summary>
              <ul>
                {capabilities.qualificationReasons.map((reason, index) => (
                  <li key={`${reason}-${index}`}>
                    {reason === "runtime_unqualified"
                      ? "This Splunk deployment has not been qualified for baseline storage."
                      : reason === "source_unavailable"
                        ? "Collection completeness and late-arrival handling have not been verified."
                        : reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
      <DependencyMonitor
        window={window}
        contextKey={JSON.stringify([
          username,
          service,
          environment,
          cluster,
          namespace,
        ])}
        mapWarnings={mapWarnings}
        source={capabilities?.sourceAvailable ? connection?.source : undefined}
        repository={
          capabilities?.available ? connection?.repository : undefined
        }
      />
    </>
  );
}
