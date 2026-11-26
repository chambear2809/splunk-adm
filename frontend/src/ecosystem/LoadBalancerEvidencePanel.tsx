import {
  LOAD_BALANCER_CONTRACTS,
  loadLoadBalancerEvidence,
  type LegEndpoint,
  type LoadBalancerObservation,
  type LoadBalancerSource,
  type TransportLeg,
} from "./loadBalancerEvidence";
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

const ROLE_TEXT: Record<LegEndpoint["role"], string> = {
  client: "Client",
  virtual_server_address: "Virtual server address (balancer-owned)",
  load_balancer_node: "Load balancer node (balancer-owned)",
  listener_or_endpoint: "Listener or VPC endpoint (balancer-owned)",
  load_balancer_source: "Balancer source",
  pool_member: "Pool member",
  target: "Target",
};

function LegEnd({ value }: { value: LegEndpoint }) {
  return (
    <>
      {ROLE_TEXT[value.role]}: {value.ip ? socketText(value) : "not reported"}
      {value.routeDomain !== undefined &&
        ` · route domain ${value.routeDomain}`}
      {value.notReported && <small>{value.notReported}</small>}
    </>
  );
}

function Leg({ leg }: { leg: TransportLeg | { notReported: string } }) {
  if ("notReported" in leg) return <>Not reported. {leg.notReported}</>;
  return (
    <>
      <LegEnd value={leg.source} />
      <br />→ <LegEnd value={leg.destination} />
    </>
  );
}

export function LoadBalancerEvidencePanel({
  source,
  selection,
  client,
  configurationClient = evidenceConfigClient,
}: {
  source: LoadBalancerSource;
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  const contract = LOAD_BALANCER_CONTRACTS[source];
  return (
    <OnDemandEvidencePanel
      label={contract.label}
      noun="load balancer"
      resetKey={source + JSON.stringify(selection)}
      client={client}
      configurationClient={configurationClient}
      load={(signal) =>
        loadLoadBalancerEvidence(
          client,
          source,
          selection,
          signal,
          configurationClient,
        )
      }
      summary={(result) =>
        `${result.records.length} visible load balancer records; ${result.inputCount} inputs.`
      }
    >
      {(result) => (
        <LoadBalancerResultView label={contract.label} result={result} />
      )}
    </OnDemandEvidencePanel>
  );
}

/** Presentation of one captured result; performs no search. */
export function LoadBalancerResultView({
  label,
  result,
}: {
  label: string;
  result: SupplementalResult<LoadBalancerObservation>;
}) {
  return (
    <>
      <ResultHeader
        result={result}
        rejectedHint="Rejected rows can mean an unconfigured or modified iRule, an unsupported access-log version, a time mismatch, or an unmapped host."
      />
      <p>
        Client-side and server-side legs are shown separately from the same
        record. Balancer-owned addresses are not endpoint identity, and records
        are not added to the map&apos;s dependency or blocked-flow edges.
      </p>
      {result.records.length ? (
        <div className="dns-table-scroll">
          <table>
            <caption>{label} source records</caption>
            <thead>
              <tr>
                <th>Request / interval</th>
                <th>Client-side leg</th>
                <th>Server-side leg</th>
                <th>Outcome</th>
                <th>Bytes</th>
                <th>Observer / limits</th>
              </tr>
            </thead>
            <tbody>
              {result.records.map((record, index) => (
                <tr key={record.eventFingerprint + ":" + index}>
                  <td>
                    {record.recordType} · {record.protocol}
                    <br />
                    {timestamp(record.interval.start)} –{" "}
                    {timestamp(record.interval.end)}
                    {record.balancer && <small>{record.balancer}</small>}
                    {record.targetGroup && <small>{record.targetGroup}</small>}
                    {record.listener && (
                      <small>Listener {record.listener}</small>
                    )}
                  </td>
                  <td>
                    <Leg leg={record.clientLeg} />
                  </td>
                  <td>
                    <Leg leg={record.serverLeg} />
                  </td>
                  <td>
                    {record.outcomeText}
                    {record.status.balancer && (
                      <small>Balancer status {record.status.balancer}</small>
                    )}
                    {record.status.server && (
                      <small>Server status {record.status.server}</small>
                    )}
                  </td>
                  <td>
                    {record.counters.requestBytes ?? "—"} in /{" "}
                    {record.counters.responseBytes ?? "—"} out
                    <small>{record.counters.basis}</small>
                  </td>
                  <td>
                    {record.authority} · {record.scope}
                    <small>
                      Matched {record.matchedAddressFields.join(", ")}
                    </small>
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
          No load balancer records returned. This does not prove the traffic was
          absent.
        </p>
      )}
      <CoverageList items={result.coverage} />
    </>
  );
}
