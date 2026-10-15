const MAX_EPOCH_SECONDS = 253402300799;
const UNITS = "(?:mon|[smhdwqy])";
const TOKEN = new RegExp(`[+-]\\d+${UNITS}`);
const SNAP = /^(?:mon|s|m|h|d|w[0-7]?|q|y)$/;
const SNAP_TEXT = "(?:mon|s|m|h|d|w[0-7]?|q|y)";
const OFFSET_TEXT = `[+-]\\d+${UNITS}`;
const RELATIVE_RE = new RegExp(
  `^(?:now|${OFFSET_TEXT}|@${SNAP_TEXT})(?:${OFFSET_TEXT}|@${SNAP_TEXT})*$`,
);
const DEFAULT_TIMEZONE =
  Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

type Civil = {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
};

const parts = (epoch: number, timezone: string): Civil | undefined => {
  try {
    const values = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      calendar: "gregory",
      numberingSystem: "latn",
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
      .formatToParts(new Date(epoch * 1000))
      .reduce<Record<string, string>>((result, item) => {
        if (item.type !== "literal") result[item.type] = item.value;
        return result;
      }, {});
    return {
      year: Number(values.year),
      month: Number(values.month),
      day: Number(values.day),
      hour: Number(values.hour) % 24,
      minute: Number(values.minute),
      second: Number(values.second),
    };
  } catch {
    return undefined;
  }
};

const offset = (epoch: number, timezone: string): number | undefined => {
  const local = parts(epoch, timezone);
  if (!local) return undefined;
  const utc = Date.UTC(
    local.year,
    local.month - 1,
    local.day,
    local.hour,
    local.minute,
    local.second,
  );
  return utc - Math.trunc(epoch * 1000);
};

const fromCivil = (civil: Civil, timezone: string): number | undefined => {
  const utc = Date.UTC(
    civil.year,
    civil.month - 1,
    civil.day,
    civil.hour,
    civil.minute,
    civil.second,
  );
  let epoch = utc / 1000;
  for (let index = 0; index < 3; index += 1) {
    const zoneOffset = offset(epoch, timezone);
    if (zoneOffset === undefined) return undefined;
    epoch = (utc - zoneOffset) / 1000;
  }
  return epoch;
};

const daysInMonth = (year: number, month: number) =>
  new Date(Date.UTC(year, month, 0)).getUTCDate();

const add = (
  epoch: number,
  amount: number,
  unit: string,
  timezone: string,
): number | undefined => {
  if (unit === "s") return epoch + amount;
  if (unit === "m") return epoch + amount * 60;
  if (unit === "h") return epoch + amount * 3600;
  const local = parts(epoch, timezone);
  if (!local) return undefined;
  if (unit === "d" || unit === "w") {
    const date = new Date(Date.UTC(local.year, local.month - 1, local.day));
    date.setUTCDate(date.getUTCDate() + amount * (unit === "w" ? 7 : 1));
    return fromCivil(
      {
        ...local,
        year: date.getUTCFullYear(),
        month: date.getUTCMonth() + 1,
        day: date.getUTCDate(),
      },
      timezone,
    );
  }
  const months = amount * (unit === "mon" ? 1 : unit === "q" ? 3 : 12);
  const whole = Math.trunc(months);
  const fraction = months - whole;
  const index = local.year * 12 + local.month - 1 + whole;
  const year = Math.floor(index / 12);
  const month = (((index % 12) + 12) % 12) + 1;
  const day = Math.min(local.day, daysInMonth(year, month));
  const result = fromCivil({ ...local, year, month, day }, timezone);
  return result === undefined || fraction === 0
    ? result
    : result + fraction * 30 * 86400;
};

const snap = (
  epoch: number,
  value: string,
  timezone: string,
): number | undefined => {
  const local = parts(epoch, timezone);
  if (!local) return undefined;
  let { year, month, day } = local;
  if (value === "s") return Math.floor(epoch);
  if (value === "m") local.second = 0;
  if (value === "h") {
    local.minute = 0;
    local.second = 0;
  }
  if (value === "d") {
    local.hour = 0;
    local.minute = 0;
    local.second = 0;
  }
  if (value.startsWith("w")) {
    const weekday = new Date(Date.UTC(year, month - 1, day)).getUTCDay();
    const target = value.length === 1 ? 0 : Number(value[1]) % 7;
    const delta = (weekday - target + 7) % 7;
    const date = new Date(Date.UTC(year, month - 1, day - delta));
    year = date.getUTCFullYear();
    month = date.getUTCMonth() + 1;
    day = date.getUTCDate();
    local.hour = 0;
    local.minute = 0;
    local.second = 0;
  }
  if (value === "mon") {
    day = 1;
    local.hour = 0;
    local.minute = 0;
    local.second = 0;
  }
  if (value === "q") {
    month = Math.floor((month - 1) / 3) * 3 + 1;
    day = 1;
    local.hour = 0;
    local.minute = 0;
    local.second = 0;
  }
  if (value === "y") {
    month = 1;
    day = 1;
    local.hour = 0;
    local.minute = 0;
    local.second = 0;
  }
  const target = { ...local, year, month, day };
  const initial = fromCivil(target, timezone);
  if (initial === undefined) return undefined;
  let result: number = initial;
  // During a fall-back fold, Intl resolves an ambiguous civil time to the
  // earlier occurrence. Prefer the latest occurrence that does not move
  // forward from the value being snapped (Splunk's nearest prior boundary).
  for (
    let index = 0;
    index < 8 && initial + (index + 1) * 1800 <= epoch;
    index += 1
  ) {
    const candidate: number = initial + (index + 1) * 1800;
    const candidateParts = parts(candidate, timezone);
    if (
      !candidateParts ||
      candidateParts.year !== target.year ||
      candidateParts.month !== target.month ||
      candidateParts.day !== target.day ||
      candidateParts.hour !== target.hour ||
      candidateParts.minute !== target.minute ||
      candidateParts.second !== target.second
    )
      continue;
    result = candidate;
  }
  return result;
};

export function resolveTime(
  value: string,
  timezone = DEFAULT_TIMEZONE,
  nowSeconds = Date.now() / 1000,
): number | undefined {
  if (!isSafeTime(value)) return undefined;
  if (/^\d+(?:\.\d+)?$/.test(value)) {
    const epoch = Number(value);
    return Number.isFinite(epoch) && epoch >= 0 && epoch <= MAX_EPOCH_SECONDS
      ? epoch
      : undefined;
  }
  let cursor = 0;
  let epoch = nowSeconds;
  if (value.startsWith("now")) cursor = 3;
  else if (value.startsWith("@")) cursor = 0;
  else if (!value.startsWith("+") && !value.startsWith("-")) return undefined;
  while (cursor < value.length) {
    if (value[cursor] === "@") {
      const match = value.slice(cursor + 1).match(/^(mon|s|m|h|d|w[0-7]?|q|y)/);
      if (!match || !SNAP.test(match[1])) return undefined;
      epoch = snap(epoch, match[1], timezone) ?? NaN;
      cursor += match[0].length + 1;
      continue;
    }
    const match = value.slice(cursor).match(TOKEN);
    if (!match) return undefined;
    const token = match[0];
    const unit = token.replace(/[+-]?\d+(?:\.\d+)?/, "");
    epoch =
      add(epoch, Number(token.slice(0, -unit.length)), unit, timezone) ?? NaN;
    cursor += token.length;
  }
  return Number.isFinite(epoch) && epoch >= 0 && epoch <= MAX_EPOCH_SECONDS
    ? epoch
    : undefined;
}

/** Validate Splunk time syntax without consulting a timezone or current time. */
export function isSafeTime(value: string): boolean {
  if (value.length > 128 || /[^a-z0-9@.+-]/.test(value)) return false;
  if (/^\d+(?:\.\d+)?$/.test(value)) return Number(value) <= MAX_EPOCH_SECONDS;
  return RELATIVE_RE.test(value);
}

export function timeError(
  earliest: string,
  latest = "now",
  timezone?: string,
  nowSeconds?: number,
): string | undefined {
  const zone = timezone ?? DEFAULT_TIMEZONE;
  const now = nowSeconds ?? Date.now() / 1000;
  if (
    resolveTime(earliest, zone, now) === undefined ||
    resolveTime(latest, zone, now) === undefined
  )
    return "Unsupported time window.";
  if (
    (resolveTime(earliest, zone, now) ?? 0) >=
    (resolveTime(latest, zone, now) ?? 0)
  )
    return "Earliest must precede latest.";
  return undefined;
}

export function isIncompleteWindow(
  latest: string,
  timezone?: string | number,
  nowSeconds?: number,
): boolean {
  const zone = typeof timezone === "string" ? timezone : DEFAULT_TIMEZONE;
  const now =
    typeof timezone === "number" ? timezone : (nowSeconds ?? Date.now() / 1000);
  const value = resolveTime(latest, zone, now);
  return value !== undefined && value >= now - 600;
}
