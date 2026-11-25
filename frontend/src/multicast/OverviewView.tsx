import { useId } from "react";
import type { FlowGroupSummary, IgmpGroupSummary } from "./contract";
import {
  FLAG_LABEL,
  scopeCoverageNotices,
  type FlagId,
  type GroupRow,
} from "./flags";
import {
  cappedNotice,
  emptyScopeNotice,
  flowEvidenceLine,
  formatTime,
} from "./format";
import type { ScopeOverviewResult } from "./scopeOverview";
import { SourceCoverage } from "./SourceCoverage";
import { MULTICAST_TERMS } from "./terms";

interface Props {
  result: ScopeOverviewResult;
  onSelectGroup(group: string): void;
  onCompare(): void;
  comparing: boolean;
  timezone?: string;
}

const LIST_LIMIT = 3;

function limited(values: string[]): string {
  const shown = values.slice(0, LIST_LIMIT).join(", ");
  return values.length > LIST_LIMIT
    ? `${shown} +${values.length - LIST_LIMIT} more`
    : shown;
}

function FlagBadge({ flag }: { flag: FlagId }) {
  const id = useId();
  const label = FLAG_LABEL[flag];
  return (
    <span className="mc-flag">
      {label}
      <button
        type="button"
        className="mc-hint"
        aria-label={`About ${label}`}
        aria-describedby={id}
      >
        ?
      </button>
      <span role="tooltip" id={id} className="mc-hint-text">
        {MULTICAST_TERMS[flag]}
      </span>
    </span>
  );
}

function Senders({ flows }: { flows: FlowGroupSummary[] }) {
  const senders = [...new Set(flows.flatMap((summary) => summary.senders))];
  return <>{senders.length ? limited(senders) : "None observed"}</>;
}

function ReceiverInterest({ igmp }: { igmp: IgmpGroupSummary[] }) {
  const reporting = igmp.filter((summary) => summary.reports > 0);
  if (!reporting.length) return <>None observed</>;
  const endpoints = [
    ...new Set(reporting.flatMap((summary) => summary.endpointReporters)),
  ];
  const others = reporting.reduce(
    (total, summary) => total + summary.otherReporters,
    0,
  );
  if (!endpoints.length && !others) {
    const reports = reporting.reduce(
      (total, summary) => total + summary.reports,
      0,
    );
    return (
      <>
        {reports} {reports === 1 ? "report" : "reports"}, reporters not reported
      </>
    );
  }
  return (
    <>
      {endpoints.length > 0 && <div>{limited(endpoints)}</div>}
      {others > 0 && <div>+{others} other reports</div>}
    </>
  );
}

function FlowEvidence({ flows }: { flows: FlowGroupSummary[] }) {
  if (!flows.length) return <>None observed</>;
  return (
    <>
      {flows.map((flow) => (
        <div key={flow.profile}>{flowEvidenceLine(flow)}</div>
      ))}
    </>
  );
}

function OverviewRow({
  row,
  onSelectGroup,
  timezone,
}: {
  row: GroupRow;
  onSelectGroup(group: string): void;
  timezone?: string;
}) {
  const flows = row.summaries.filter(
    (summary): summary is FlowGroupSummary => summary.kind === "flow",
  );
  const igmp = row.summaries.filter(
    (summary): summary is IgmpGroupSummary => summary.kind === "igmp",
  );
  const first = Math.min(...row.summaries.map((summary) => summary.firstSeen));
  const last = Math.max(...row.summaries.map((summary) => summary.lastSeen));
  return (
    <tr>
      <th scope="row">
        <button type="button" onClick={() => onSelectGroup(row.group)}>
          {row.group}
        </button>
      </th>
      <td>
        <Senders flows={flows} />
      </td>
      <td>
        <ReceiverInterest igmp={igmp} />
      </td>
      <td>
        <FlowEvidence flows={flows} />
      </td>
      <td>
        <ul className="mc-flags">
          {row.flags.map((flag) => (
            <li key={flag}>
              <FlagBadge flag={flag} />
            </li>
          ))}
        </ul>
      </td>
      <td>
        {formatTime(first, timezone)} – {formatTime(last, timezone)}
      </td>
    </tr>
  );
}

export function OverviewView({
  result,
  onSelectGroup,
  onCompare,
  comparing,
  timezone,
}: Props) {
  const capped = result.profiles.filter((profile) => profile.droppedGroups > 0);
  return (
    <section className="mc-overview">
      <div className="multicast-actions">
        <button
          type="button"
          onClick={onCompare}
          disabled={comparing}
          aria-busy={comparing}
        >
          Compare with previous window
        </button>
      </div>
      {result.comparison.state === "unavailable" && (
        <p className="multicast-notice">
          Comparison unavailable: {result.comparison.reason}
        </p>
      )}
      <SourceCoverage
        outcomes={result.profiles.map((profile) => profile.outcome)}
        notices={scopeCoverageNotices(result.profiles)}
      />
      {capped.map((profile, index) => (
        <p key={index} className="multicast-notice">
          {cappedNotice(profile)}
        </p>
      ))}
      {result.rows.length === 0 ? (
        <p className="multicast-notice">{emptyScopeNotice(result.profiles)}</p>
      ) : (
        <div className="multicast-table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Group</th>
                <th scope="col">Senders</th>
                <th scope="col">Receiver interest</th>
                <th scope="col">Flow evidence</th>
                <th scope="col">Flags</th>
                <th scope="col">First / last seen</th>
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row) => (
                <OverviewRow
                  key={row.group}
                  row={row}
                  onSelectGroup={onSelectGroup}
                  timezone={timezone}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
