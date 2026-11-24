import type {
  GroupSummary,
  MulticastConfiguration,
  StreamProfile,
} from "./contract";
import { scopeCoverageNotices, type GroupRow } from "./flags";
import { emptyScopeNotice } from "./format";
import type { ScopeOverviewResult } from "./scopeOverview";
import { SourceCoverage } from "./SourceCoverage";

interface Props {
  result: ScopeOverviewResult;
  configuration: MulticastConfiguration;
  onSelectCell(group: string, profile: string): void;
}

type CellState =
  "Sender traffic" | "Receiver interest" | "None observed" | "Not covered";

/** Seconds before the window end within which evidence counts as recent. */
const RECENT_SECONDS = 300;

interface Column {
  profile: StreamProfile;
  label: string;
  covered: boolean;
}

function columns(
  result: ScopeOverviewResult,
  configuration: MulticastConfiguration,
): Column[] {
  const outcomes = new Map(
    result.profiles.map(({ outcome }) => [outcome.profile, outcome.state]),
  );
  const stream = configuration.profiles.filter(
    (profile): profile is StreamProfile =>
      profile.source !== "multicast_nxos" &&
      profile.scope === result.window.scope &&
      outcomes.has(profile.id),
  );
  return [
    ...stream.filter((profile) => profile.source === "multicast_igmp"),
    ...stream.filter((profile) => profile.source === "multicast_netflow"),
  ].map((profile) => ({
    profile,
    label:
      profile.source === "multicast_igmp"
        ? `${profile.segment.kind} ${profile.segment.id} · ${profile.segment.domain}`
        : `${profile.observer} · ${profile.direction}`,
    covered: outcomes.get(profile.id) === "complete",
  }));
}

function cellState(column: Column, summary?: GroupSummary): CellState {
  if (!column.covered) return "Not covered";
  if (summary?.kind === "flow") return "Sender traffic";
  if (summary?.kind === "igmp" && summary.reports > 0)
    return "Receiver interest";
  return "None observed";
}

function Cell({
  row,
  column,
  latest,
  onSelectCell,
}: {
  row: GroupRow;
  column: Column;
  latest: number;
  onSelectCell(group: string, profile: string): void;
}) {
  const summary = row.summaries.find(
    (candidate) => candidate.profile === column.profile.id,
  );
  const state = cellState(column, summary);
  // Recency styling and the accessible recency suffix apply only to states
  // that carry usable evidence; "None observed" and "Not covered" never
  // claim a recency they don't have.
  const hasEvidence =
    state === "Sender traffic" || state === "Receiver interest";
  const recent = hasEvidence && summary!.lastSeen >= latest - RECENT_SECONDS;
  const recencyClass = hasEvidence ? (recent ? " recent" : " older") : "";
  const recencyLabel = hasEvidence
    ? ` · ${recent ? "recent" : "older"} evidence`
    : "";
  return (
    <td>
      <button
        type="button"
        className={`mc-cell${recencyClass}`}
        aria-label={`${row.group} at ${column.label}: ${state}${recencyLabel}`}
        onClick={() => onSelectCell(row.group, column.profile.id)}
      >
        {state}
      </button>
    </td>
  );
}

export function MatrixView({ result, configuration, onSelectCell }: Props) {
  const cols = columns(result, configuration);
  const coverage = (
    <SourceCoverage
      outcomes={result.profiles.map((profile) => profile.outcome)}
      notices={scopeCoverageNotices(result.profiles)}
    />
  );
  if (result.rows.length === 0)
    return (
      <section className="mc-matrix">
        {coverage}
        <p className="multicast-notice">{emptyScopeNotice(result.profiles)}</p>
      </section>
    );
  return (
    <section className="mc-matrix">
      {coverage}
      <div className="multicast-table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Group</th>
              {cols.map((column) => (
                <th scope="col" key={column.profile.id}>
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.rows.map((row) => (
              <tr key={row.group}>
                <th scope="row">{row.group}</th>
                {cols.map((column) => (
                  <Cell
                    key={column.profile.id}
                    row={row}
                    column={column}
                    latest={result.window.latest}
                    onSelectCell={onSelectCell}
                  />
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
