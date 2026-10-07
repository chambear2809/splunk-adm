const ISO_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;
/** ISO 8601 timestamp with an explicit UTC offset; local-time strings are rejected. */
export const isoTime = (v: unknown): v is string =>
  typeof v === "string" && ISO_TIME.test(v) && Number.isFinite(Date.parse(v));
const utc = (value: string) => {
  const t = new Date(value).toISOString();
  return { day: t.slice(0, 10), time: t.slice(11, 19).replace(/:00$/, "") };
};
/** UTC instant as "YYYY-MM-DD HH:MM[:SS]". */
export function formatUtc(value: string): string {
  const { day, time } = utc(value);
  return `${day} ${time}`;
}
/** UTC range; the end date is omitted only when both ends share a day. */
export function formatUtcRange(start: string, end: string): string {
  const a = utc(start),
    b = utc(end);
  return `${a.day} ${a.time} → ${a.day === b.day ? "" : `${b.day} `}${b.time}`;
}
