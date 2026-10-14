import { useCallback, useEffect, useMemo, useState } from "react";
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
    async (raw: string, signal: AbortSignal): Promise<ParseTimeResult> => {
      const value = pickerBound(raw);
      const epoch = resolveTime(value, timezone);
      if (epoch === undefined) {
        return { time: raw, error: { message: "Unsupported time." } };
      }
      if (!live) {
        return { time: raw, iso: new Date(epoch * 1000).toISOString() };
      }
      try {
        const response = await fetch(
          createRESTURL("search/timeparser") +
            "?" +
            new URLSearchParams({ output_mode: "json", time: value }),
          { ...getDefaultFetchInit(), signal },
        );
        if (!response.ok) throw new Error("Unable to preview this time.");
        const data = await response.json();
        const iso = Object.values(data).find(
          (value) => typeof value === "string",
        );
        if (typeof iso !== "string") throw new Error("Missing parsed time.");
        return { time: raw, iso };
      } catch (error) {
        if (signal.aborted) throw error;
        return {
          time: raw,
          error: { message: "Unable to preview this time." },
        };
      }
    },
    [live, timezone],
  );
  const preview = useMemo(() => createTimePreview(parse), [parse]);
  useEffect(() => () => preview.cancel(), [preview]);
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
      <Dropdown
        earliest={earliest}
        latest={latest}
        disabled={disabled}
        presets={presets.filter((preset) => !preset.earliest.startsWith("rt"))}
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
      <small>
        {timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone}
      </small>
      {error && <p role="alert">{error}</p>}
    </div>
  );
}
