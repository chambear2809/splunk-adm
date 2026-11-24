import type {
  GroupSummary,
  MulticastConfiguration,
  StreamProfile,
} from "./contract";
import type { GroupRow } from "./flags";
import type { ScopeOverviewResult } from "./scopeOverview";

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
  const recency = summary
    ? summary.lastSeen >= latest - RECENT_SECONDS
      ? " recent"
      : " older"
    : "";
  return (
    <td>
      <button
        type="button"
        className={`mc-cell${recency}`}
        aria-label={`${row.group} at ${column.label}: ${state}`}
        onClick={() => onSelectCell(row.group, column.profile.id)}
      >
        {state}
      </button>
    </td>
  );
}

export function MatrixView({ result, configuration, onSelectCell }: Props) {
  const cols = columns(result, configuration);
  if (result.rows.length === 0)
    return (
      <p className="multicast-notice">
        No caller-visible multicast groups in this window. This does not
        establish that none exist.
      </p>
    );
  return (
    <div className="multicast-table-wrap mc-matrix">
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
  );
}
