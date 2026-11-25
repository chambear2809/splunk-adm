const MAX_SAFE_MAGNITUDE = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_EPOCH = 253_402_300_799;
const MAX_CANONICAL_PAYLOAD_BYTES = 1024 * 1024;
const NUMBER_TOKEN =
  /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

function canonicalDecimal(token: string): string {
  const match = NUMBER_TOKEN.exec(token);
  if (!match) throw new Error("Unsupported canonical JSON number.");
  const [, sign, whole, fraction = "", exponentText = "0"] = match;
  const exponent = Number(exponentText);
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 1024)
    throw new Error("Canonical JSON number is outside the supported range.");

  let digits = `${whole}${fraction}`.replace(/^0+/, "");
  if (!digits) return "0";
  let scale = fraction.length - exponent;

  if (scale > 3) {
    const extraPlaces = scale - 3;
    if (
      digits.length < extraPlaces ||
      !digits.endsWith("0".repeat(extraPlaces))
    )
      throw new Error(
        "Canonical JSON numbers must have no finer than millisecond precision.",
      );
    digits = digits.slice(0, -extraPlaces);
    scale = 3;
  }

  let normalized: string;
  if (scale <= 0) {
    normalized = `${digits}${"0".repeat(-scale)}`;
  } else if (digits.length <= scale) {
    normalized = `0.${"0".repeat(scale - digits.length)}${digits}`;
  } else {
    normalized = `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
  }

  if (normalized.includes("."))
    normalized = normalized.replace(/0+$/, "").replace(/\.$/, "");
  const unsigned = normalized.startsWith(".") ? `0${normalized}` : normalized;
  const integerPart = unsigned.split(".")[0];
  const integerMagnitude = BigInt(integerPart);
  if (integerMagnitude > MAX_SAFE_MAGNITUDE)
    throw new Error("Canonical JSON integer exceeds the safe range.");
  const numeric = Number(`${sign}${unsigned}`);
  if (!Number.isFinite(numeric))
    throw new Error("Canonical JSON number must be finite.");
  if (numeric === 0) return "0";
  if (Number.isInteger(numeric)) {
    if (!Number.isSafeInteger(numeric))
      throw new Error("Canonical JSON integer exceeds the safe range.");
    return `${sign}${unsigned}`;
  }
  if (Math.abs(numeric) > MAX_EPOCH)
    throw new Error("Canonical JSON number is outside the timestamp range.");
  const milliseconds = Math.round(numeric * 1000);
  if (!Number.isSafeInteger(milliseconds) || numeric !== milliseconds / 1000)
    throw new Error(
      "Canonical JSON numbers must have exact millisecond precision.",
    );
  const absoluteMilliseconds = BigInt(Math.abs(milliseconds));
  const millisecondsWhole = absoluteMilliseconds / 1000n;
  const remainder = absoluteMilliseconds % 1000n;
  const fractionText = remainder.toString().padStart(3, "0").replace(/0+$/, "");
  return `${milliseconds < 0 ? "-" : ""}${millisecondsWhole.toString()}${fractionText ? `.${fractionText}` : ""}`;
}

function wellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string") {
    if (!wellFormedUnicode(value))
      throw new Error("Canonical JSON strings must contain valid Unicode.");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new Error("Canonical JSON numbers must be finite.");
    return canonicalDecimal(String(value));
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("Canonical JSON cannot be cyclic.");
    seen.add(value);
    const result = `[${value.map((item) => serialize(item, seen)).join(",")}]`;
    seen.delete(value);
    return result;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (
      Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null
    )
      throw new Error("Canonical JSON must use plain objects.");
    if (seen.has(record)) throw new Error("Canonical JSON cannot be cyclic.");
    seen.add(record);
    const keys = Object.keys(record);
    if (
      keys.some((key) =>
        Array.from(key).some((character) => character.codePointAt(0)! > 127),
      )
    )
      throw new Error("Canonical JSON object keys must be ASCII.");
    keys.sort();
    const entries = keys.map((key) => {
      if (!wellFormedUnicode(key))
        throw new Error("Canonical JSON keys must contain valid Unicode.");
      return `${JSON.stringify(key)}:${serialize(record[key], seen)}`;
    });
    seen.delete(record);
    return `{${entries.join(",")}}`;
  }
  throw new Error("Canonical JSON contains an unsupported value.");
}

/** bounded-decimal-json-v1 serializer shared with the history exporter. */
export function canonicalJson(value: unknown): string {
  return serialize(value, new Set());
}

/** Parse a stored projected row and reject non-canonical or duplicate-key JSON. */
export function parseCanonicalJson(value: unknown): unknown {
  if (
    typeof value !== "string" ||
    new TextEncoder().encode(value).byteLength > MAX_CANONICAL_PAYLOAD_BYTES
  )
    throw new Error("Generation row payload is missing or too large.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("Generation row payload is invalid JSON.");
  }
  if (canonicalJson(parsed) !== value)
    throw new Error("Generation row payload is not canonical JSON.");
  return parsed;
}

export async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle)
    throw new Error(
      "Generation hash verification is unavailable in this browser.",
    );
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export const HASH_ID = /^[a-f0-9]{64}$/;

export function withoutKeys<T extends object>(
  value: T,
  excluded: readonly string[],
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !excluded.includes(key)),
  );
}
