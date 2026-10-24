import type { DnsObservation, EvidenceSelection } from "./evidence";
import { fingerprint, validateSelection } from "./evidence";
import {
  buildDnsSearch,
  eventFingerprintExpression,
  parseDnsEnvelope,
} from "./dnsEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./evidenceConfig";
import { normalizeDns } from "./dnsAdapters";
import { optionalJobs } from "./optionalJobs";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

/** A typed reference is reconstructed through current configuration; no stored SPL/URL. */
export async function inspectDnsRecord(
  client: SearchClient,
  selection: EvidenceSelection,
  record: DnsObservation,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<DnsObservation | undefined> {
  validateSelection(selection);
  if (
    !/^[a-f0-9]{64}$/.test(record.eventFingerprint) ||
    record.scope !== selection.scope ||
    record.eventTime < selection.window.start - 86400 ||
    record.eventTime > selection.window.end
  )
    throw new Error("Invalid DNS event reference.");
  const config = await configurationClient.read(
    signal,
    selection.identityAddresses ?? selection.addresses,
    selection.scope,
  );
  if (config.fingerprint !== selection.configurationFingerprint)
    throw new Error(
      "Configuration changed; refresh before inspecting a source record.",
    );
  const source = config.dns.find((s) => s.source === record.source);
  if (
    !source ||
    source.state !== "active" ||
    source.error ||
    !source.indexes.includes(record.index) ||
    !source.authorities.includes(record.authority)
  )
    throw new Error("DNS source reference is unavailable.");
  // Replace only the reviewed initial pipeline, retaining its validated literal base.
  const template = buildDnsSearch(source, selection);
  const first = template.split("\n")[0];
  const narrow = `${first}\n| eval event_fingerprint=${eventFingerprintExpression}\n| where event_fingerprint="${record.eventFingerprint}"`;
  const search = template.replace(first, narrow);
  const searchTime = record.rowTime ?? record.eventTime;
  const result = requireNoSearchErrors(
    await optionalJobs.run(
      record.source,
      await fingerprint([config.fingerprint, search]),
      client,
      {
        search,
        earliest: String(Math.max(0, Math.floor(searchTime) - 1)),
        latest: String(Math.ceil(searchTime) + 1),
        maxRows: 65,
        signal,
      },
    ),
    "DNS source record",
  );
  if (result.warnings.length)
    throw new Error("DNS source record completion unavailable.");
  const envelope = parseDnsEnvelope(result.rows);
  if (envelope.inputCount > 1 || envelope.inputCapped)
    throw new Error("DNS event reference is ambiguous.");
  const normalized = await normalizeDns(
    record.source,
    envelope.rows,
    {
      scope: selection.scope,
      authorities: source.authorities,
      maxAgeSeconds: config.maxAgeSeconds,
      schemaQualified: source.schemaQualified,
      clockUncertaintySeconds: config.clockUncertaintySeconds,
    },
    selection,
    config.identities,
  );
  const after = await configurationClient.read(
    signal,
    selection.identityAddresses ?? selection.addresses,
    selection.scope,
  );
  if (after.fingerprint !== config.fingerprint)
    throw new Error(
      "Configuration changed while inspecting the source record.",
    );
  return normalized.records.find(
    (r) => r.eventFingerprint === record.eventFingerprint,
  );
}
