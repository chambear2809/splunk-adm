import {
  useDeferredValue,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import "./scale.css";

export interface VirtualColumn<T> {
  key: string;
  header: string;
  /** One-line header tooltip. */
  headerTitle?: string;
  num?: boolean;
  render: (row: T) => ReactNode;
  /** Sort key; columns without one are not sortable. */
  sortValue?: (row: T) => string | number;
  /** Text matched by the filter box; defaults to the sort key. */
  filterText?: (row: T) => string;
  /** Relative column width (grid fr units); numeric columns default to 0.7. */
  width?: number;
}
type Sort = { key: string; dir: 1 | -1 };

const OVERSCAN = 8;
const collator = new Intl.Collator(undefined, { numeric: true });

/** Rows to render for a scroll offset: [first, last) plus overscan. */
export function windowRange(
  scrollTop: number,
  viewport: number,
  rowHeight: number,
  total: number,
): [number, number] {
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const last = Math.min(
    total,
    Math.ceil((scrollTop + viewport) / rowHeight) + OVERSCAN,
  );
  return [first, Math.max(first, last)];
}

/** One grid template shared by the header and every row keeps cells aligned. */
export function columnTemplate(
  columns: readonly { num?: boolean; width?: number }[],
): string {
  return columns
    .map((c) => `minmax(0, ${c.width ?? (c.num ? 0.7 : 1)}fr)`)
    .join(" ");
}

export function sortRows<T>(
  rows: readonly T[],
  value: (row: T) => string | number,
  dir: 1 | -1,
): T[] {
  // Decorate once: sort keys can be costly (labels, device lookups).
  const keyed = rows.map((row, i) => ({ row, i, v: value(row) }));
  keyed.sort((a, b) => {
    const c =
      typeof a.v === "number" && typeof b.v === "number"
        ? a.v - b.v
        : collator.compare(String(a.v), String(b.v));
    return c * dir || a.i - b.i;
  });
  return keyed.map((k) => k.row);
}

/**
 * A windowed table: only the rows in view (plus overscan) are in the DOM, so
 * 100k rows scroll smoothly. Columns sort on header click and a text box
 * filters rows; native table semantics are kept with aria-rowcount/rowindex.
 */
export function VirtualTable<T>({
  caption,
  rows,
  columns,
  rowKey,
  selected,
  rowHeight = 34,
  viewportHeight = 420,
  empty = "No rows.",
}: {
  caption: string;
  rows: readonly T[];
  columns: VirtualColumn<T>[];
  rowKey: (row: T) => string;
  selected?: string;
  rowHeight?: number;
  viewportHeight?: number;
  empty?: string;
}) {
  const id = useId();
  const [sort, setSort] = useState<Sort | undefined>();
  const [query, setQuery] = useState("");
  const deferred = useDeferredValue(query.trim().toLowerCase());
  const [scrollTop, setScrollTop] = useState(0);
  const scroller = useRef<HTMLDivElement>(null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((c) => c.key === sort.key);
    return column?.sortValue
      ? sortRows(rows, column.sortValue, sort.dir)
      : rows;
  }, [rows, columns, sort]);
  const filtering = deferred !== "";
  const haystack = useMemo(
    () =>
      filtering
        ? sorted.map((row) =>
            columns
              .map((c) => (c.filterText ?? c.sortValue)?.(row) ?? "")
              .join(" ")
              .toLowerCase(),
          )
        : undefined,
    // Built once when filtering starts, not per keystroke.
    [sorted, columns, filtering],
  );
  const visible = useMemo(
    () =>
      haystack
        ? sorted.filter((_, i) => haystack[i].includes(deferred))
        : sorted,
    [sorted, haystack, deferred],
  );
  const height = Math.min(
    viewportHeight,
    Math.max(1, visible.length) * rowHeight + rowHeight,
  );
  const [first, last] = windowRange(
    scrollTop,
    height,
    rowHeight,
    visible.length,
  );
  const toggle = (key: string) =>
    setSort((cur) =>
      cur?.key !== key
        ? { key, dir: 1 }
        : cur.dir === 1
          ? { key, dir: -1 }
          : undefined,
    );
  const filterId = `${id}-filter`;
  const template = useMemo(() => columnTemplate(columns), [columns]);
  return (
    <section className="atlas-vtable" aria-labelledby={`${id}-caption`}>
      <div className="atlas-vtable-bar">
        <h3 id={`${id}-caption`}>{caption}</h3>
        <span className="muted small" aria-live="polite">
          {visible.length === rows.length
            ? `${rows.length.toLocaleString()} ${rows.length === 1 ? "row" : "rows"}`
            : `${visible.length.toLocaleString()} of ${rows.length.toLocaleString()} ${rows.length === 1 ? "row" : "rows"}`}
        </span>
        <label htmlFor={filterId} className="sr-only">
          Filter {caption}
        </label>
        <input
          id={filterId}
          type="search"
          placeholder="Filter"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            if (scroller.current) scroller.current.scrollTop = 0;
            setScrollTop(0);
          }}
        />
      </div>
      <div
        ref={scroller}
        className="atlas-vtable-scroll"
        data-scroll-region
        style={{ height }}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <table
          role="table"
          aria-rowcount={visible.length + 1}
          style={{ ["--atlas-vtable-cols" as string]: template }}
        >
          <thead role="rowgroup">
            <tr role="row" aria-rowindex={1} style={{ height: rowHeight }}>
              {columns.map((c) => {
                const active = sort?.key === c.key;
                return (
                  <th
                    key={c.key}
                    role="columnheader"
                    scope="col"
                    className={c.num ? "num" : undefined}
                    title={c.headerTitle}
                    aria-sort={
                      active
                        ? sort.dir === 1
                          ? "ascending"
                          : "descending"
                        : c.sortValue
                          ? "none"
                          : undefined
                    }
                  >
                    {c.sortValue ? (
                      <button
                        type="button"
                        className="atlas-vtable-sort"
                        onClick={() => toggle(c.key)}
                      >
                        {c.header}
                        {active &&
                          (sort.dir === 1 ? (
                            <ArrowUp size={12} aria-hidden />
                          ) : (
                            <ArrowDown size={12} aria-hidden />
                          ))}
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody role="rowgroup">
            {first > 0 && (
              <tr
                aria-hidden="true"
                className="atlas-vtable-spacer"
                style={{ height: first * rowHeight }}
              >
                <td colSpan={columns.length} />
              </tr>
            )}
            {visible.slice(first, last).map((row, i) => {
              const key = rowKey(row);
              return (
                <tr
                  key={key}
                  role="row"
                  aria-rowindex={first + i + 2}
                  className={selected === key ? "selected" : undefined}
                  style={{ height: rowHeight }}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      role="cell"
                      className={c.num ? "num" : undefined}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              );
            })}
            {last < visible.length && (
              <tr
                aria-hidden="true"
                className="atlas-vtable-spacer"
                style={{ height: (visible.length - last) * rowHeight }}
              >
                <td colSpan={columns.length} />
              </tr>
            )}
            {!visible.length && (
              <tr role="row" className="atlas-vtable-spacer">
                <td role="cell" colSpan={columns.length} className="muted">
                  {rows.length ? "No rows match the filter." : empty}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
