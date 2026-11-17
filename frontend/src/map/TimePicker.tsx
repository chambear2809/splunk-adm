import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import DropdownExport from "@splunk/react-time-range/Dropdown";
import PresetsExport from "@splunk/react-time-range/presets";
import { AdvancedInputType } from "@splunk/react-time-range/Dialog";
import type { ParseTimeResult } from "@splunk/react-time-range/Dialog/Panel";
import convertExport from "@splunk/moment/convertSplunkTimezone";
import { serverTimezoneInfo } from "@splunk/splunk-utils/config";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { toolkitDefault } from "../app/interop";
import { resolveTime, timeError } from "../data/timeBounds";
import { createTimePreview } from "../data/timePreview";
import { NarrowAtlas } from "../app/mountWidth";
const Dropdown = toolkitDefault(DropdownExport);
const presets = toolkitDefault(PresetsExport);
const convert = toolkitDefault(convertExport);
// Date/Date-time panels emit offset-qualified ISO. Only epoch values enter URLs/searches.
export function pickerBound(value: string): string {
  if (
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(
      value,
    )
  ) {
    const epoch = Date.parse(value) / 1000;
    if (Number.isFinite(epoch)) return String(epoch);
  }
  return value;
}
// The toolkit runtime requires an explicit null; its TypeScript type omits it.
const parsedTime = (time: string, iso: string): ParseTimeResult =>
  ({ time, iso, error: null }) as unknown as ParseTimeResult;

const validPreviewIso = (value: unknown): value is string => {
  if (typeof value !== "string") return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) return false;
  const [
    ,
    year,
    month,
    day,
    hour,
    minute,
    second,
    ,
    ,
    offsetHour,
    offsetMinute,
  ] = match;
  const y = Number(year),
    m = Number(month),
    d = Number(day);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    m >= 1 &&
    m <= 12 &&
    d >= 1 &&
    d <= days[m - 1] &&
    Number(hour) <= 23 &&
    Number(minute) <= 59 &&
    Number(second) <= 59 &&
    Number(offsetHour ?? 0) <= 23 &&
    Number(offsetMinute ?? 0) <= 59 &&
    Number.isFinite(Date.parse(value))
  );
};

export async function parseTimePreview(
  raw: string,
  timezone: string | undefined,
  live: boolean,
  signal: AbortSignal,
): Promise<ParseTimeResult> {
  const value = pickerBound(raw);
  const epoch = resolveTime(value, timezone);
  if (epoch === undefined)
    return { time: raw, error: { message: "Unsupported time." } };
  if (!live) return parsedTime(raw, new Date(epoch * 1000).toISOString());
  try {
    const response = await fetch(
      createRESTURL("search/timeparser") +
        "?" +
        new URLSearchParams({ output_mode: "json", time: value }),
      { ...getDefaultFetchInit(), signal },
    );
    if (!response.ok) throw new Error("Unable to preview this time.");
    const data: unknown = await response.json();
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      !Object.prototype.hasOwnProperty.call(data, value)
    )
      throw new Error("Missing parsed time.");
    const iso = (data as Record<string, unknown>)[value];
    if (!validPreviewIso(iso)) throw new Error("Invalid parsed time.");
    return parsedTime(raw, iso);
  } catch (error) {
    if (signal.aborted) throw error;
    return { time: raw, error: { message: "Unable to preview this time." } };
  }
}
export function TimePicker({
  earliest,
  latest,
  onChange,
  timezone,
  live,
  disabled = false,
}: {
  earliest: string;
  latest: string;
  onChange: (earliest: string, latest: string) => void;
  timezone?: string;
  live: boolean;
  disabled?: boolean;
}) {
  const narrow = useContext(NarrowAtlas);
  const [parseEarliest, setParseEarliest] = useState<ParseTimeResult>();
  const [parseLatest, setParseLatest] = useState<ParseTimeResult>();
  const [error, setError] = useState<string>();
  const zone = useMemo(() => {
    if (!live || !serverTimezoneInfo) return undefined;
    try {
      return convert(serverTimezoneInfo, timezone ?? "Atlas user timezone");
    } catch {
      return undefined;
    }
  }, [live, timezone]);
  const parse = useCallback(
    (raw: string, signal: AbortSignal): Promise<ParseTimeResult> =>
      parseTimePreview(raw, timezone, live, signal),
    [live, timezone],
  );
  const preview = useMemo(() => createTimePreview(parse), [parse]);
  useEffect(() => () => preview.cancel(), [preview]);
  useEffect(() => {
    if (narrow) preview.cancel();
  }, [narrow, preview]);
  const zoneIndex = zone?.untils.findIndex((until) => until > Date.now()) ?? -1;
  const timezoneOffset =
    zone?.offsets[zoneIndex < 0 ? zone.offsets.length - 1 : zoneIndex] ??
    new Date().getTimezoneOffset();
  const timezoneName =
    zone?.name ?? timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
  const requestEarliest = useCallback(
    (value: string) => {
      void preview.request("earliest", value, setParseEarliest, () =>
        setParseEarliest({
          time: value,
          error: { message: "Unable to preview this time." },
        }),
      );
    },
    [preview],
  );
  const requestLatest = useCallback(
    (value: string) => {
      void preview.request("latest", value, setParseLatest, () =>
        setParseLatest({
          time: value,
          error: { message: "Unable to preview this time." },
        }),
      );
    },
    [preview],
  );
  return (
    <div
      className="atlas-time-picker"
      aria-label="Time range"
      data-atlas-timezone-offset={timezoneOffset}
      data-atlas-timezone-name={timezoneName}
    >
      <span>Time range</span>
      {!narrow && (
        <Dropdown
          data-atlas-time-range="true"
          earliest={earliest}
          latest={latest}
          disabled={disabled}
          presets={presets.filter(
            (preset) => !preset.earliest.startsWith("rt"),
          )}
          realTimeDisabled
          advancedInputTypes={[
            AdvancedInputType.relative,
            AdvancedInputType.allTime,
            AdvancedInputType.dateTime,
          ]}
          momentTimeZone={zone}
          parseEarliest={parseEarliest}
          parseLatest={parseLatest}
          onRequestParseEarliest={requestEarliest}
          onRequestParseLatest={requestLatest}
          onChange={(_e, data) => {
            if (
              typeof data?.earliest !== "string" ||
              typeof data?.latest !== "string"
            )
              return;
            const start = pickerBound(data.earliest),
              end = pickerBound(data.latest);
            const invalid = timeError(start, end, timezone);
            setError(invalid);
            if (!invalid) onChange(start, end);
          }}
        />
      )}
      <small>
        {timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone}
      </small>
      {error && <p role="alert">{error}</p>}
    </div>
  );
}
