import {
  FIREWALL_CONTRACTS,
  firewallDecisionSummary,
  loadFirewallTrafficEvidence,
  type FirewallSource,
  type FirewallTrafficObservation,
} from "./firewallTrafficEvidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "../data/evidenceConfig";
import type { EvidenceSelection } from "../data/evidence";
import type { SearchClient } from "../data/searchClient";
import type { SupplementalResult } from "../data/supplementalEvidence";
import {
  CoverageList,
  OnDemandEvidencePanel,
  ResultHeader,
  socketText as socket,
  timestamp,
} from "./EvidenceFrame";

const DECISION_TEXT: Record<
  FirewallTrafficObservation["policyDecision"],
  string
> = {
  allow: "Allowed at this firewall",
  deny: "Denied or dropped at this firewall",
  not_reported: "No policy decision stated",
};

export function FirewallTrafficEvidencePanel({
  source,
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  source: FirewallSource;
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const contract = FIREWALL_CONTRACTS[source];
  return (
    <OnDemandEvidencePanel
      label={contract.label}
      noun="firewall"
      resetKey={source + JSON.stringify(selection)}
      client={client}
      configurationClient={configurationClient}
      load={(signal) =>
        loadFirewallTrafficEvidence(
          client,
          source,
          selection,
          signal,
          configurationClient,
        )
      }
      summary={(result) =>
        `${result.records.length} visible firewall records; ${result.inputCount} inputs.`
      }
    >
      {(result) => (
        <FirewallTrafficResultView label={contract.label} result={result} />
      )}
    </OnDemandEvidencePanel>
  );
}

/** Presentation of one captured result; performs no search. */
export function FirewallTrafficResultView({
  label,
  result,
}: {
  label: string;
  result: SupplementalResult<FirewallTrafficObservation>;
}) {
  const summary = firewallDecisionSummary(result);
  return (
    <>
      <ResultHeader
        result={result}
        rejectedHint="Rejected rows can mean missing add-on extraction, an unsupported action or log format, a time mismatch, or an unmapped host."
      />
      {summary && result.state === "complete" && (
        <p>
          Visible policy decisions: {summary.allow} allowed, {summary.deny}{" "}
          denied or dropped, {summary.notReported} without a stated decision
          {summary.lowerBound
            ? " (lower bounds: the result is capped, partial or has rejected rows)."
            : "."}{" "}
          Denies are this firewall's decision only and are not added to the
          map's blocked-flow edges.
        </p>
      )}
      {result.records.length ? (
        <div className="dns-table-scroll">
          <table>
            <caption>{label} source records</caption>
            <thead>
              <tr>
                <th>Session / interval</th>
                <th>Reported tuple</th>
                <th>NAT translation (same event)</th>
                <th>Action / decision</th>
                <th>Session counters</th>
                <th>Observer / limits</th>
              </tr>
            </thead>
            <tbody>
              {result.records.map((record, index) => (
                <tr
                  key={
                    record.authority +
                    ":" +
                    record.eventFingerprint +
                    ":" +
                    index
                  }
                >
                  <td>
                    {record.logSubtype} log · {record.protocol.toUpperCase()}
                    <br />
                    {timestamp(record.interval.start)} –{" "}
                    {timestamp(record.interval.end)}
                    <br />
                    <small>
                      {record.intervalBasis === "log_time_only"
                        ? "Log time only; session start not reported"
                        : record.intervalBasis === "log_time_minus_duration"
                          ? "Log time minus reported duration"
                          : "Reported session start and elapsed time"}
                    </small>
                  </td>
                  <td>
                    {socket(record.original.source)} →{" "}
                    {socket(record.original.destination)}
                    <br />
                    <small>
                      Selected address matched{" "}
                      {record.matchedAddressFields
                        .map((field) => field.replace("_", " "))
                        .join(", ")}
                    </small>
                  </td>
                  <td>
                    {record.translated ? (
                      <>
                        {record.translated.source && (
                          <>
                            Source → {socket(record.translated.source)}
                            <br />
                          </>
                        )}
                        {record.translated.destination && (
                          <>
                            Destination →{" "}
                            {socket(record.translated.destination)}
                            <br />
                          </>
                        )}
                        {record.translated.disposition &&
                          `Disposition ${record.translated.disposition}. `}
                        {record.translated.natFlag !== undefined &&
                          `NAT flag ${record.translated.natFlag ? "set" : "not set"}. `}
                        <small>
                          Translation evidence, not endpoint identity or a
                          separate hop.
                        </small>
                      </>
                    ) : (
                      "No translation reported"
                    )}
                  </td>
                  <td>
                    {record.vendorAction} ·{" "}
                    {DECISION_TEXT[record.policyDecision]}
                    <br />
                    <small>{record.actionMeaning}</small>
                    {record.rule && (
                      <>
                        <br />
                        Rule / policy {record.rule}
                      </>
                    )}
                    {record.sessionEndReason && (
                      <>
                        <br />
                        End reason {record.sessionEndReason}
                      </>
                    )}
                  </td>
                  <td>
                    {record.counters.bytes ??
                      (record.counters.bytesSent !== undefined ||
                      record.counters.bytesReceived !== undefined
                        ? `${record.counters.bytesSent ?? "—"} sent / ${record.counters.bytesReceived ?? "—"} received`
                        : "—")}{" "}
                    bytes
                    <br />
                    {record.counters.packets ??
                      `${record.counters.packetsSent ?? "—"} / ${record.counters.packetsReceived ?? "—"}`}{" "}
                    packets
                    {record.repeatCount !== undefined &&
                      record.repeatCount > 1 && (
                        <>
                          <br />
                          Repeat count {record.repeatCount}
                        </>
                      )}
                  </td>
                  <td>
                    {record.authority} · {record.scope}
                    <br />
                    {record.device.name ?? "device name not reported"}
                    {record.device.virtualSystem &&
                      ` · ${record.device.virtualSystem}`}
                    <br />
                    <small>
                      {record.sourcetype} · {record.index}
                      {record.inferredZoneOffsetSeconds !== undefined &&
                        ` · zone offset ${record.inferredZoneOffsetSeconds}s inferred`}
                    </small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>
          No firewall records returned. This does not prove the traffic was
          absent or allowed.
        </p>
      )}
      <CoverageList items={result.coverage} />
    </>
  );
}
