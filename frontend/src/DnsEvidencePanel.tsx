import { useCallback, useEffect, useRef, useState } from "react";
import { dnsEvidenceCSV, dnsEvidenceJSON, downloadEvidence } from "./dnsExport";
import { loadDnsEvidence } from "./data/dnsEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import type { DnsEvidenceResult, EvidenceSelection } from "./data/evidence";
import { optionalJobs } from "./data/optionalJobs";
import { inspectDnsRecord } from "./data/dnsDrilldown";
import { useHealthStatus } from "./data/healthStatus";
import type { SearchClient } from "./data/searchClient";

export function DnsEvidencePanel({
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const [result, setResult] = useState<DnsEvidenceResult>();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string>(),
    [cleanup, setCleanup] = useState(optionalJobs.cleanupPending),
    [unverified, setUnverified] = useState(optionalJobs.cleanupUnverified);
  const [rawStatus, setRawStatus] = useState<string>();
  const generation = useRef(0),
    active = useRef<AbortController>();
  const health = useHealthStatus();
  const identity = JSON.stringify([
    selection,
    health?.deployment?.settings?.revision,
  ]);
  const invalidate = useCallback(() => {
    generation.current++;
    active.current?.abort();
  }, []);
  useEffect(() => {
    generation.current++;
    active.current?.abort();
    setResult(undefined);
    setError(undefined);
    setRawStatus(undefined);
    setBusy(false);
    return invalidate;
  }, [identity, client, configurationClient, invalidate]);
  useEffect(
    () =>
      optionalJobs.subscribe(() => {
        setCleanup(optionalJobs.cleanupPending);
        setUnverified(optionalJobs.cleanupUnverified);
      }),
    [],
  );
  const load = async (diagnostics = false) => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setResult(undefined);
    setError(undefined);
    setBusy(true);
    try {
      const next = await loadDnsEvidence(
        client,
        selection,
        controller.signal,
        configurationClient,
        diagnostics ? ["dns_stream", "dns_hubble"] : [],
      );
      if (current === generation.current && !controller.signal.aborted)
        setResult(next);
    } catch {
      if (current === generation.current)
        setError(
          controller.signal.aborted
            ? "Cancelled. Native cleanup may remain pending."
            : "DNS evidence unavailable. Refresh the selection or check optional source configuration and permissions.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  const inspect = async (record: DnsEvidenceResult["records"][number]) => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const current = ++generation.current;
    setBusy(true);
    setRawStatus("Checking the exact caller-visible source record…");
    try {
      const found = await inspectDnsRecord(
        client,
        selection,
        record,
        controller.signal,
        configurationClient,
      );
      if (current === generation.current && !controller.signal.aborted)
        setRawStatus(
          found
            ? "Exact source record verified. The normalized observation is displayed below; payload text is excluded."
            : "Source record not found or no longer available. No broader search was run.",
        );
    } catch {
      if (current === generation.current)
        setRawStatus(
          "Exact source record unavailable. Access, configuration or completion could not be verified.",
        );
    } finally {
      if (current === generation.current) setBusy(false);
    }
  };
  return (
    <section
      className="dns-evidence inspector-body"
      aria-label="Optional DNS evidence"
    >
      <h3>DNS evidence</h3>
      <p>
        Supplemental caller-visible resolution observations. Names do not
        establish ownership, actual name use, selected backends or traffic.
      </p>
      <button type="button" onClick={() => void load()} disabled={busy}>
        {result ? "Refresh DNS evidence" : "Inspect DNS evidence"}
      </button>
      <button type="button" onClick={() => void load(true)} disabled={busy}>
        Check staged DNS sources
      </button>
      {busy && (
        <button type="button" onClick={() => active.current?.abort()}>
          Cancel DNS search
        </button>
      )}
      <p role="status">
        {busy
          ? "Loading optional evidence…"
          : (error ??
            (result
              ? `${result.records.length} visible DNS records. ${result.outputCapped ? "This is a capped subset." : ""}`
              : "DNS remains off unless an administrator selects an active source."))}
      </p>
      {rawStatus && <p role="status">{rawStatus}</p>}
      {cleanup > 0 && !busy && (
        <p role="status">
          Optional execution slots: {cleanup} occupied; replacements wait for
          confirmed completion or cleanup.
        </p>
      )}
      {unverified > 0 && (
        <p role="status">
          Splunk could not confirm cleanup of {unverified} earlier optional DNS
          search{unverified === 1 ? "" : "es"}; the execution slot remains
          occupied until Splunk confirms completion or cancellation.
        </p>
      )}
      {result && (
        <>
          {result.configurationChanged && (
            <p role="alert">
              Configuration changed or became unreadable. Results are context
              only; refresh required.
            </p>
          )}
          <ul>
            {result.sources.map((s) => (
              <li key={s.source}>
                {s.source}: {s.state}
                {s.intent === "staged" && s.state === "complete"
                  ? " · staged diagnostic only"
                  : ""}
                {s.state === "complete"
                  ? ` · ${s.inputCount} matching observations`
                  : ""}
                {s.durationMilliseconds !== undefined
                  ? ` · ${(s.durationMilliseconds / 1000).toFixed(2)} seconds`
                  : ""}
                {s.errorCode ? ` · ${s.errorCode}` : ""}
                {s.inputCapped ? " · input incomplete" : ""}
                {s.outputCapped ? " · display subset" : ""}
                {s.rejected ? ` · ${s.rejected} rejected records` : ""}
                {s.expansionCapped
                  ? ` · ${s.expansionCapped} expansion caps`
                  : ""}
                {s.error ? ` · ${s.error}` : ""}
              </li>
            ))}
          </ul>
          <p>
            Retrieved {new Date(result.capturedAt * 1000).toISOString()};
            configuration {result.configurationFingerprint.slice(0, 12)}. This
            capture is independent of the application graph.
          </p>
          <button
            type="button"
            onClick={() => downloadEvidence(dnsEvidenceJSON(result), "json")}
          >
            Export loaded DNS JSON
          </button>{" "}
          <button
            type="button"
            onClick={() => downloadEvidence(dnsEvidenceCSV(result), "csv")}
          >
            Export loaded DNS CSV
          </button>
          {!result.records.length ? (
            <p>
              No visible DNS evidence. This does not prove no queries or index
              access.
            </p>
          ) : (
            <div className="dns-table-scroll">
              <table>
                <caption>DNS resolution observations</caption>
                <thead>
                  <tr>
                    <th>Query / type</th>
                    <th>Source / client</th>
                    <th>Outcome / measured latency</th>
                    <th>Answers</th>
                    <th>Attribution / limitations</th>
                  </tr>
                </thead>
                <tbody>
                  {result.records.map((r, i) => (
                    <tr key={`${r.source}:${r.eventFingerprint}:${i}`}>
                      <td>
                        {r.query}
                        <br />
                        {r.queryType} · {r.shape}
                        <br />
                        <button
                          type="button"
                          disabled={busy || result.configurationChanged}
                          onClick={() => void inspect(r)}
                        >
                          Inspect exact source record
                        </button>
                        <br />
                        {new Date(r.eventTime * 1000).toISOString()}
                        <br />
                        {r.sourceTimeBasis ?? "Source event time"}
                        {r.responseInterval && (
                          <>
                            <br />
                            Response interval: {r.responseInterval.start}–
                            {r.responseInterval.end}
                          </>
                        )}
                        <br />
                        Indexed: {new Date(r.indexedTime * 1000).toISOString()}
                      </td>
                      <td>
                        {r.source} / {r.authority}
                        {r.authorityNode && (
                          <>
                            <br />
                            Node: {r.authorityNode}
                          </>
                        )}
                        <br />
                        {r.client ?? "Client unknown"}
                        <br />
                        Resolver: {r.resolver ?? "unknown"}
                      </td>
                      <td>
                        {r.responseCode ??
                          (r.shape === "request"
                            ? "Request; response not established"
                            : "Outcome unknown")}
                        {r.policy ? ` · ${r.policy}` : ""}
                        <br />
                        {r.latencySeconds !== undefined
                          ? `${r.latencySeconds} seconds`
                          : "Latency not supplied"}
                      </td>
                      <td>
                        <ul>
                          {r.answers.map((a, j) => (
                            <li key={j}>
                              {a.address} ({a.type}; TTL {a.ttl ?? "unknown"})
                            </li>
                          ))}
                        </ul>
                        {!!r.reportedAddresses?.length && (
                          <p>
                            Supplied addresses: {r.reportedAddresses.join(", ")}
                            . Address/type/TTL relationships may be unavailable.
                          </p>
                        )}
                        {!!r.reportedTtls?.length && (
                          <p>
                            Supplied TTL values (unpaired):{" "}
                            {r.reportedTtls.join(", ")} seconds.
                          </p>
                        )}
                        {r.ttlSeconds !== undefined && (
                          <p>
                            TTL: {r.ttlSeconds} seconds (
                            {r.ttlBasis ?? "supplied; relationship unqualified"}
                            ).
                          </p>
                        )}
                        {r.aliases.length > 0 && (
                          <p>Supplied aliases: {r.aliases.join(", ")}</p>
                        )}
                      </td>
                      <td>
                        {r.attribution}: {r.attributionReason}
                        <ul>
                          {r.limitations.map((reason, j) => (
                            <li key={j}>{reason}</li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <details>
            <summary>Visibility and interpretation</summary>
            <ul>
              {result.coverage.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
            <p>
              Routine NXDOMAIN search-suffix attempts do not establish an
              application failure. No response is different from a measured
              timeout or explicit policy rejection.
            </p>
          </details>
        </>
      )}
    </section>
  );
}
