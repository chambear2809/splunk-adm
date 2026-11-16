import type {
  CSSProperties,
  MouseEvent,
  ReactNode,
  TdHTMLAttributes,
  ThHTMLAttributes,
} from "react";
import { ArrowDown, ArrowUp } from "lucide-react";

/**
 * A plain semantic table with the subset of the Splunk UI Table API used by
 * the Explore, Setup, and Health pages. Kept in-repo so the bundle does not
 * carry @splunk/react-ui/Table for a handful of static tables.
 */
export type SortDir = "asc" | "desc" | "none";

type TableProps = {
  children: ReactNode;
  "aria-label"?: string;
  /** "scroll" wraps the table in a horizontally scrolling container. */
  horizontalOverflow?: "scroll";
  className?: string;
};

function Table({
  children,
  horizontalOverflow,
  className,
  "aria-label": label,
}: TableProps) {
  const table = (
    <table className={className ?? "atlas-table"} aria-label={label}>
      {children}
    </table>
  );
  return horizontalOverflow === "scroll" ? (
    <div className="atlas-table-scroll">{table}</div>
  ) : (
    table
  );
}

function Head({ children }: { children: ReactNode }) {
  return (
    <thead>
      <tr>{children}</tr>
    </thead>
  );
}

type HeadCellProps = Omit<ThHTMLAttributes<HTMLTableCellElement>, "onClick"> & {
  width?: number;
  sortKey?: string;
  sortDir?: SortDir;
  onSort?: (
    event: MouseEvent<HTMLButtonElement>,
    data: { sortKey: string; sortDir: Exclude<SortDir, "none"> },
  ) => void;
};

function HeadCell({
  children,
  width,
  sortKey,
  sortDir = "none",
  onSort,
  style,
  scope = "col",
  ...rest
}: HeadCellProps) {
  const cellStyle: CSSProperties | undefined =
    width === undefined ? style : { width, minWidth: width, ...style };
  const sortable = sortKey !== undefined && onSort !== undefined;
  return (
    <th
      {...rest}
      scope={scope}
      style={cellStyle}
      aria-sort={
        sortable
          ? sortDir === "asc"
            ? "ascending"
            : sortDir === "desc"
              ? "descending"
              : "none"
          : undefined
      }
    >
      {sortable ? (
        <button
          type="button"
          className="atlas-table-sort"
          onClick={(event) =>
            onSort(event, {
              sortKey,
              sortDir: sortDir === "asc" ? "desc" : "asc",
            })
          }
        >
          {children}
          {/* Matches the Splunk UI Table sort hint so headers keep their name. */}
          <span className="atlas-visually-hidden">
            {sortDir === "asc"
              ? " Press to sort descending"
              : sortDir === "desc"
                ? " Press to sort ascending"
                : " Click to sort"}
          </span>
          {sortDir === "asc" ? (
            <ArrowUp size={12} aria-hidden="true" />
          ) : sortDir === "desc" ? (
            <ArrowDown size={12} aria-hidden="true" />
          ) : null}
        </button>
      ) : (
        children
      )}
    </th>
  );
}

function Body({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

function Row({ children }: { children: ReactNode }) {
  return <tr>{children}</tr>;
}

function Cell(props: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td {...props} />;
}

export default Object.assign(Table, { Head, HeadCell, Body, Row, Cell });
