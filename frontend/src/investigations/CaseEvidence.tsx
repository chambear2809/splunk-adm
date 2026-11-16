import type { CaseRecord } from "./caseClient";

/** Only bounded source selectors and windows can leave the browser as a reference. */
export function isComparisonReference(reference?: string): reference is string {
  if (!reference || new TextEncoder().encode(reference).length > 4096)
    return false;
  try {
    const value: unknown = JSON.parse(reference);
    const object = (v: unknown): v is Record<string, unknown> =>
      !!v && typeof v === "object" && !Array.isArray(v);
    const keys = (v: Record<string, unknown>, expected: string[]) =>
      Object.keys(v).sort().join(",") === [...expected].sort().join(",");
    if (
      !object(value) ||
      !keys(value, ["schema", "scope", "windows"]) ||
      value.schema !== 1 ||
      !object(value.scope) ||
      !keys(value.scope, ["service", "environment", "cluster", "namespace"]) ||
      !Object.values(value.scope).every(
        (v) => typeof v === "string" && v.length > 0 && v.length <= 256,
      ) ||
      !Array.isArray(value.windows) ||
      value.windows.length < 2 ||
      value.windows.length > 3
    )
      return false;
    let priorEnd = 0;
    for (const window of value.windows) {
      if (
        !object(window) ||
        !keys(window, ["start", "end"]) ||
        !Number.isSafeInteger(window.start) ||
        !Number.isSafeInteger(window.end)
      )
        return false;
      const start = window.start as number,
        end = window.end as number;
      if (start < priorEnd || start < 0 || end <= start || end - start > 300)
        return false;
      priorEnd = end;
    }
    return true;
  } catch {
    return false;
  }
}

type Summary = {
  scope: {
    service: string;
    environment: string;
    cluster: string;
    namespace: string;
  };
  windows: { start: number; end: number }[];
};
function summary(value: unknown): Summary | undefined {
  if (!value || typeof value !== "object") return;
  const data = value as Record<string, unknown>;
  if (
    !data.scope ||
    typeof data.scope !== "object" ||
    Array.isArray(data.scope) ||
    !Array.isArray(data.windows)
  )
    return;
  const scope = data.scope as Record<string, unknown>;
  if (
    ![scope.service, scope.environment, scope.cluster, scope.namespace].every(
      (v) => typeof v === "string",
    ) ||
    data.windows.length < 2 ||
    data.windows.length > 3
  )
    return;
  const windows: Summary["windows"] = [];
  for (const item of data.windows) {
    if (!item || typeof item !== "object") return;
    const { start, end } = item as Record<string, unknown>;
    if (
      typeof start !== "number" ||
      typeof end !== "number" ||
      !Number.isFinite(start) ||
      !Number.isFinite(end) ||
      Math.abs(start) > 8640000000000 ||
      Math.abs(end) > 8640000000000
    )
      return;
    windows.push({ start, end });
  }
  return { scope: scope as Summary["scope"], windows };
}
export function ComparisonSummary({ data }: { data: unknown }) {
  const value = summary(data);
  if (!value)
    return <p>Comparison scope and windows are unavailable in this capture.</p>;
  return (
    <div>
      <p>
        Service: {value.scope.service} · Environment: {value.scope.environment}{" "}
        · Cluster: {value.scope.cluster} · Namespace: {value.scope.namespace}
      </p>
      <ul>
        {value.windows.map((window, index) => (
          <li key={index}>
            {["Baseline", "Incident", "Recovery"][index]}:{" "}
            {new Date(window.start * 1000).toISOString()} –{" "}
            {new Date(window.end * 1000).toISOString()} UTC
          </li>
        ))}
      </ul>
    </div>
  );
}

export function CaseEvidence({ record }: { record: CaseRecord }) {
  return (
    <section aria-label="Saved comparison evidence">
      <h5 style={{ fontSize: "1rem" }}>Saved comparison evidence</h5>
      <p>
        Each saved capture is immutable. Its source is rechecked when saved, and
        the selected capture is rechecked when read or exported. Case membership
        alone does not grant source access.
      </p>
      {record.redactions ? (
        <p>
          {record.redactions.captures} captures and{" "}
          {record.redactions.attachments} attachments withheld from this
          response; they may be unselected or source access could not be
          confirmed.
        </p>
      ) : (
        <p>Source redaction counts are unavailable for this response.</p>
      )}
      {!record.captures.length ? (
        <p>No visible comparison captures.</p>
      ) : (
        record.captures.map((capture) => (
          <details key={capture.id}>
            <summary>
              {capture.label} · captured {capture.captured_at}
            </summary>
            <p>
              Added by {capture.author} at {capture.created_at} · revision{" "}
              {capture.revision}
            </p>
            <ComparisonSummary data={capture.data} />
            {capture.data.source_contract === "admqualified-comparison-v1" && (
              <p>
                Observations were indexed by each window end; later arrivals are
                excluded. Exact indexed times are not retained for all
                aggregates.
              </p>
            )}
            <details>
              <summary>Show source rows and metadata</summary>
              <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                {JSON.stringify(capture.data, null, 2)}
              </pre>
            </details>
          </details>
        ))
      )}
    </section>
  );
}
