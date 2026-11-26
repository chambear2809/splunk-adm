import {
  CLOUD_FLOW_CONTRACTS,
  loadCloudFlowEvidence,
  type CloudFlowObservation,
  type CloudFlowSource,
} from "./cloudFlowLogEvidence";
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
  socketText,
  timestamp,
} from "./EvidenceFrame";

const DECISION_TEXT: Record<CloudFlowObservation["policyDecision"], string> = {
  allow: "Permitted at this capture point",
  deny: "Denied or dropped at this capture point",
  not_reported: "No decision stated",
};

export function CloudFlowEvidencePanel({
  source,
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  source: CloudFlowSource;
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const contract = CLOUD_FLOW_CONTRACTS[source];
  return (
    <OnDemandEvidencePanel
      label={contract.label}
      noun="flow log"
      resetKey={source + JSON.stringify(selection)}
      client={client}
      configurationClient={configurationClient}
      load={(signal) =>
        loadCloudFlowEvidence(
          client,
          source,
          selection,
          signal,
          configurationClient,
        )
      }
      summary={(result) =>
        `${result.records.length} visible flow log records; ${result.inputCount} inputs.`
      }
    >
      {(result) => (
        <CloudFlowResultView label={contract.label} result={result} />
      )}
    </OnDemandEvidencePanel>
  );
}

/** Presentation of one captured result; performs no search. */
export function CloudFlowResultView({
  label,
  result,
}: {
  label: string;
  result: SupplementalResult<CloudFlowObservation>;
}) {
  return (
    <>
      <ResultHeader
        result={result}
        rejectedHint="Rejected rows can mean an unsupported event shape or flow log version, a time mismatch, or an unmapped host."
      />
      <p>
        Decisions are this capture point&apos;s only and are not added to the
        map&apos;s blocked-flow edges.
      </p>
      {result.records.length ? (
        <div className="dns-table-scroll">
          <table>
            <caption>{label} source records</caption>
            <thead>
              <tr>
                <th>Interval</th>
                <th>Reported tuple</th>
                <th>NAT translation (same record)</th>
                <th>Decision</th>
                <th>Counters</th>
                <th>Observer / context</th>
              </tr>
            </thead>
            <tbody>
              {result.records.map((record, index) => (
                <tr key={record.eventFingerprint + ":" + index}>
                  <td>
                    {record.protocol.toUpperCase()} · {record.vantage}
                    <br />
                    {timestamp(record.interval.start)} –{" "}
                    {timestamp(record.interval.end)}
                    <small>
                      {record.intervalBasis === "tuple_time"
                        ? "Tuple time"
                        : "Aggregation interval"}
                    </small>
                  </td>
                  <td>
                    {socketText(record.original.source)} →{" "}
                    {socketText(record.original.destination)}
                    <small>
                      Matched {record.matchedAddressFields.join(", ")}
                    </small>
                  </td>
                  <td>
                    {record.translated ? (
                      <>
                        {record.translated.kind === "cloud_nat"
                          ? "Cloud NAT"
                          : "Private Link SNAT"}{" "}
                        source → {socketText(record.translated.source)}
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
                    {DECISION_TEXT[record.policyDecision]}
                    <small>{record.actionMeaning}</small>
                    {record.encryption && (
                      <small>Encryption {record.encryption}</small>
                    )}
                  </td>
                  <td>
                    {Object.entries(record.counters)
                      .map(([name, value]) => `${name} ${value}`)
                      .join(" · ") || "—"}
                    <small>{record.countersBasis}</small>
                  </td>
                  <td>
                    {record.authority} · {record.scope}
                    {record.context.map((item) => (
                      <small key={item.label}>
                        {item.label}: {item.value}
                      </small>
                    ))}
                    <small>
                      {record.sourcetype} · {record.index} ·{" "}
                      {record.recordShape}
                    </small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>
          No flow log records returned. This does not prove the traffic was
          absent or allowed.
        </p>
      )}
      <CoverageList items={result.coverage} />
    </>
  );
}
