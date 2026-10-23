import { csvRow } from "./csv";
import { downloadBlob } from "./download";
import { validateDnsResult, type DnsEvidenceResult } from "./data/evidence";

export function dnsEvidenceJSON(result: DnsEvidenceResult): string {
  return JSON.stringify(validateDnsResult(result), null, 2) + "\n";
}
export function dnsEvidenceCSV(result: DnsEvidenceResult): string {
  validateDnsResult(result);
  const metadata = JSON.stringify({
    schemaVersion: result.schemaVersion,
    selection: result.selection,
    capturedAt: result.capturedAt,
    inspectedWindow: result.inspectedWindow,
    configurationFingerprint: result.configurationFingerprint,
    configurationChanged: result.configurationChanged,
    sources: result.sources,
    outputCapped: result.outputCapped,
    coverage: result.coverage,
  });
  return (
    [
      csvRow([
        "result_metadata",
        "source",
        "authority",
        "scope",
        "client",
        "resolver",
        "query",
        "type",
        "shape",
        "rcode",
        "event_time",
        "indexed_time",
        "latency_seconds",
        "answers",
        "aliases",
        "attribution",
        "attribution_reason",
        "limitations",
        "event_fingerprint",
        "reported_addresses",
        "reported_ttls",
        "ttl_seconds",
        "ttl_basis",
        "policy",
        "response_interval",
        "request_start",
        "source_time_basis",
        "authority_node",
      ]),
      ...(result.records.length
        ? result.records.map((r) =>
            csvRow([
              metadata,
              r.source,
              r.authority,
              r.scope,
              r.client,
              r.resolver,
              r.query,
              r.queryType,
              r.shape,
              r.responseCode,
              r.eventTime,
              r.indexedTime,
              r.latencySeconds,
              JSON.stringify(r.answers),
              JSON.stringify(r.aliases),
              r.attribution,
              r.attributionReason,
              JSON.stringify(r.limitations),
              r.eventFingerprint,
              JSON.stringify(r.reportedAddresses),
              JSON.stringify(r.reportedTtls),
              r.ttlSeconds,
              r.ttlBasis,
              r.policy,
              JSON.stringify(r.responseInterval),
              r.requestStart,
              r.sourceTimeBasis,
              r.authorityNode,
            ]),
          )
        : [csvRow([metadata])]),
    ].join("\r\n") + "\r\n"
  );
}
export function downloadEvidence(contents: string, extension: "json" | "csv") {
  downloadBlob(
    `atlas-dns-evidence.${extension}`,
    extension === "json" ? "application/json" : "text/csv;charset=utf-8",
    contents,
  );
}
