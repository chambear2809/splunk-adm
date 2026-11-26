import type { SearchClient } from "../data/searchClient";
import type { WindowBasis } from "./model";

/**
 * Change windows from one snow:change_request record (Splunk Add-on for
 * ServiceNow, Splunkbase 1928). Fields are ServiceNow change_request table
 * columns; dates are the API "value" form, UTC "YYYY-MM-DD hh:mm:ss".
 */
export const CHANGE_NUMBER = /^[A-Za-z]{2,10}[0-9]{1,16}$/;
export const CHANGE_LOOKBACK = "-90d@d";

export interface ChangeRecord {
  number: string;
  sysId: string;
  state?: string;
  start: number;
  end: number;
  basis: Exclude<WindowBasis, "manual">;
  updated: string;
}

export function changeRequestSearch(number: string): string {
  if (!CHANGE_NUMBER.test(number))
    throw new Error("Enter one change number, such as CHG0030001.");
  return `| \`adm_change_request_window(${number})\``;
}

const UTC = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/;

/** Strict UTC parse; anything else (display values, time zones, blanks) is rejected. */
export function parseServiceNowUtc(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const m = UTC.exec(value);
  if (!m) return undefined;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  if (
    back.getUTCFullYear() !== y ||
    back.getUTCMonth() !== mo - 1 ||
    back.getUTCDate() !== d ||
    back.getUTCHours() !== h ||
    back.getUTCMinutes() !== mi ||
    back.getUTCSeconds() !== s
  )
    return undefined;
  return ms / 1000;
}

const text = (value: unknown) =>
  typeof value === "string" && value !== "" ? value : undefined;

/** Fails closed: no record, several sys_ids, capped reads or open work all throw. */
export function parseChangeRows(number: string, rows: unknown[]): ChangeRecord {
  const records = rows.filter(
    (r): r is Record<string, unknown> =>
      !!r &&
      typeof r === "object" &&
      (r as Record<string, unknown>).row_type === "change_request",
  );
  if (!records.length)
    throw new Error(
      `No usable snow:change_request record for ${number} in the last 90 days.`,
    );
  if (records.some((r) => r.records_capped === "1" || r.records_capped === 1))
    throw new Error(
      `More than 500 events for ${number}; enter the window manually.`,
    );
  if (records.length > 1)
    throw new Error(
      `${number} matches ${records.length} ServiceNow records (sys_id); enter the window manually.`,
    );
  const r = records[0];
  const sysId = text(r.sys_id);
  if (text(r.number) !== number || !sysId)
    throw new Error(`The ServiceNow record for ${number} is incomplete.`);
  const workStart = parseServiceNowUtc(r.work_start);
  const workEnd = parseServiceNowUtc(r.work_end);
  const state = text(r.dv_state) ?? text(r.state);
  const base = {
    number,
    sysId,
    ...(state ? { state } : {}),
    updated: String(r.sys_updated_on),
  };
  if (workStart !== undefined || text(r.work_start)) {
    if (
      workStart === undefined ||
      workEnd === undefined ||
      workEnd <= workStart
    )
      throw new Error(
        `${number} has work started but no valid work end; the after window is not known yet.`,
      );
    return {
      ...base,
      start: workStart,
      end: workEnd,
      basis: "servicenow_actual",
    };
  }
  const start = parseServiceNowUtc(r.start_date);
  const end = parseServiceNowUtc(r.end_date);
  if (start === undefined || end === undefined || end <= start)
    throw new Error(`${number} has no valid planned or actual start and end.`);
  return { ...base, start, end, basis: "servicenow_planned" };
}

export async function lookupChange(
  client: SearchClient,
  number: string,
  signal: AbortSignal,
): Promise<ChangeRecord> {
  const result = await client.search({
    search: changeRequestSearch(number),
    earliest: CHANGE_LOOKBACK,
    latest: "now",
    maxRows: 4,
    overflow: "error",
    allowEmpty: true,
    signal,
  });
  if (result.errors.length)
    throw new Error(`ServiceNow lookup failed: ${result.errors[0]}`);
  return parseChangeRows(number, result.rows);
}
