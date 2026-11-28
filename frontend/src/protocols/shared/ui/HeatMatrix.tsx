import { useRef, useState, type KeyboardEvent } from "react";
import {
  STATUS_LABELS,
  type ProtocolMatrixCell,
  type ProtocolStatus,
} from "../contract";
import { StatusChip } from "./StatusChip";

export function HeatMatrix({
  title,
  rowHeader,
  rows,
  columns,
  cells,
  missingStatus = "unknown",
  selectedCell,
  onSelectCell,
}: {
  title: string;
  rowHeader: string;
  rows: readonly string[];
  columns: readonly string[];
  cells: readonly ProtocolMatrixCell[];
  /**
   * Explicit status for row×column pairs absent from `cells`.
   * Defaults to `"unknown"` so missing pairs never masquerade as `"none_observed"`.
   */
  missingStatus?: ProtocolStatus;
  selectedCell?: { row: string; col: string };
  onSelectCell?: (cell: ProtocolMatrixCell) => void;
}) {
  const byKey = new Map<string, ProtocolMatrixCell>();
  for (const cell of cells) byKey.set(`${cell.row}\0${cell.col}`, cell);
  const refs = useRef<(HTMLButtonElement | null)[][]>([]);
  const [activePos, setActivePos] = useState<{ r: number; c: number }>({
    r: 0,
    c: 0,
  });

  const focusCell = (r: number, c: number) => {
    const nextR = Math.max(0, Math.min(rows.length - 1, r));
    const nextC = Math.max(0, Math.min(columns.length - 1, c));
    setActivePos({ r: nextR, c: nextC });
    refs.current[nextR]?.[nextC]?.focus();
  };

  const handleKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    r: number,
    c: number,
  ) => {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      focusCell(r, c + 1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      focusCell(r, c - 1);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      focusCell(r + 1, c);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      focusCell(r - 1, c);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusCell(r, 0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusCell(r, columns.length - 1);
    }
  };

  if (!rows.length || !columns.length) {
    return (
      <div className="pl-empty-inline" data-testid="protocol-matrix-empty">
        No matrix dimensions observed.
      </div>
    );
  }

  return (
    <div className="pl-matrix-scroll" data-testid="protocol-heat-matrix">
      <table className="pl-matrix-table" aria-label={title}>
        <thead>
          <tr>
            <th scope="col">{rowHeader}</th>
            {columns.map((col) => (
              <th key={col} scope="col" className="pl-mono">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, r) => (
            <tr key={row}>
              <th scope="row" className="pl-mono pl-matrix-row-head">
                {row}
              </th>
              {columns.map((col, c) => {
                const cell: ProtocolMatrixCell = byKey.get(
                  `${row}\0${col}`,
                ) ?? {
                  row,
                  col,
                  status: missingStatus,
                  value: STATUS_LABELS[missingStatus],
                };
                const isSelected =
                  selectedCell?.row === row && selectedCell?.col === col;
                const isTabStop = activePos.r === r && activePos.c === c;
                return (
                  <td
                    key={col}
                    className={`pl-cell pl-cell-${cell.status}${isSelected ? " pl-cell-selected" : ""}`}
                  >
                    <button
                      ref={(el) => {
                        refs.current[r] ??= [];
                        refs.current[r][c] = el;
                      }}
                      type="button"
                      tabIndex={isTabStop ? 0 : -1}
                      aria-pressed={isSelected}
                      className="pl-cell-btn"
                      aria-label={`${row} to ${col}: ${cell.value || STATUS_LABELS[cell.status]} (${STATUS_LABELS[cell.status]})`}
                      title={cell.detail}
                      onFocus={() => setActivePos({ r, c })}
                      onKeyDown={(e) => handleKeyDown(e, r, c)}
                      onClick={() => onSelectCell?.(cell)}
                    >
                      <StatusChip status={cell.status} label={cell.value} />
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
