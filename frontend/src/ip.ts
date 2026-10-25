const full = (pattern: RegExp, value: string) =>
  pattern.exec(value)?.[0] === value;
const ipv4 = (value: string) =>
  full(/(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}/, value) &&
  value.split(".").every((part) => Number(part) <= 255);

function ipv6Words(value: string): number[] | undefined {
  let normalized = value.toLowerCase();
  if (normalized.includes(".")) {
    const tail = /^(.*:)([^:]+)$/.exec(normalized);
    if (!tail || !ipv4(tail[2])) return undefined;
    const octets = tail[2].split(".").map(Number);
    normalized = `${tail[1]}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const pieces = normalized.split("::");
  if (pieces.length > 2) return undefined;
  const left = pieces[0] ? pieces[0].split(":") : [];
  const right = pieces.length === 2 && pieces[1] ? pieces[1].split(":") : [];
  const explicitWords = left.length + right.length;
  if (explicitWords > 8 || (pieces.length === 2 && explicitWords >= 8))
    return undefined;
  const words = [
    ...left,
    ...Array(pieces.length === 2 ? 8 - explicitWords : 0).fill("0"),
    ...right,
  ];
  if (words.length !== 8 || words.some((word) => !full(/[0-9a-f]{1,4}/, word)))
    return undefined;
  return words.map((word) => Number.parseInt(word, 16));
}

/** Compare IP literals by address value, including equivalent IPv6 spellings. */
export const sameNatIp = (left: string, right: string): boolean => {
  const leftIsV4 = ipv4(left);
  const rightIsV4 = ipv4(right);
  if (leftIsV4 || rightIsV4) {
    if (!leftIsV4 || !rightIsV4) return false;
    const leftOctets = left.split(".");
    const rightOctets = right.split(".");
    return leftOctets.every(
      (octet, index) => Number(octet) === Number(rightOctets[index]),
    );
  }
  const leftWords = ipv6Words(left);
  const rightWords = ipv6Words(right);
  return Boolean(
    leftWords &&
    rightWords &&
    leftWords.every((word, index) => word === rightWords[index]),
  );
};

export const strictIp = (value: string): boolean =>
  typeof value === "string" &&
  value.length >= 2 &&
  value.length <= 45 &&
  (ipv4(value) || ipv6Words(value) !== undefined);

/** Reject non-unicast/sentinel values that cannot identify a NAT endpoint. */
export const usableNatIp = (value: unknown): value is string => {
  if (typeof value !== "string" || !strictIp(value)) return false;
  if (ipv4(value)) {
    const octets = value.split(".").map(Number);
    return (
      octets[0] !== 0 &&
      !(octets[0] >= 224 && octets[0] <= 255) &&
      value !== "255.255.255.255"
    );
  }
  const words = ipv6Words(value)!;
  const unspecified = words.every((word) => word === 0);
  const multicast = words[0] >= 0xff00;
  const ipv4Mapped =
    words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
  return !unspecified && !multicast && !ipv4Mapped;
};
